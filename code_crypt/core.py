"""Module to encrypt and decrypt app secrets asymmetrically via KMS."""

import boto3
import json
import logging
import os

from base64 import b64encode, b64decode

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from code_crypt import defaults
from code_crypt import errors

log = logging.getLogger(__name__)


class Decryptor:
        '''Helper class which creates a decryptor object with default
        padding.'''
        def __init__(self, private_key_obj, padding=defaults.RSA_PADDING):
            self.private_key_obj = private_key_obj
            self.padding = padding

        def decrypt(self, data):
            plaintext = self.private_key_obj.decrypt(data, self.padding)
            return plaintext


class Encryptor:
    '''Helper class which creates a encryptor object with default
    padding.'''
    def __init__(self, public_key_obj, padding=defaults.RSA_PADDING):
        self.public_key_obj = public_key_obj
        self.padding = padding

    def encrypt(self, data):
        ciphertext = self.public_key_obj.encrypt(data, self.padding)
        return ciphertext


class CodeCrypt:
    '''CodeCrypt object which handles the setup of RSA and AES cryptgraphic
    facilities, secret and key storange and communication with KMS.'''
    def __init__(
            self,
            kms_key_id=None,
            aws_region=defaults.AWS_REGION,
            app_root=defaults.APP_ROOT,
            env=None,
            ciphertext_ext=defaults.CIPHERTEXT_EXT,
            encrypted_private_key_file=None,
            rsa_key_size=defaults.RSA_KEY_SIZE):
        self.kms_key_id = kms_key_id
        self.ciphertext_ext = ciphertext_ext
        self.rsa_key_size = rsa_key_size
        self.ext_len = len(self.ciphertext_ext)

        # (RSA ciphertext length == RSA key size in bytes)
        # divide by 8 is for bit to byte conversion
        self.offset = self.rsa_key_size // 8

        self._init_env(env)

        data_dir = os.path.join(app_root, defaults.DATA_DIR)
        self._init_dirs(data_dir)

        self.encrypted_private_key_file = os.path.join(
                self.environment_keys_dir, 'encrypted_private_key.pem')
        if encrypted_private_key_file:
            self.encrypted_private_key_file = encrypted_private_key_file

        self.public_key_file = os.path.join(
            self.environment_keys_dir, 'public_key.asc')

        self.encryption_context = {'app_environment': self.app_environment}
        self._init_kms_client(aws_region)
        self.encryptor = None
        self.decryptor = None

    def _init_kms_client(self, aws_region):
        '''Initializes a kms boto3 client.'''
        self.kms = boto3.client('kms', region_name=aws_region)

    def _init_dirs(self, data_dir):
        '''Sets and create the Code Crypt data directory which contains secrets
        and keys based on environment.'''
        self.environment_keys_dir = os.path.join(
            data_dir, 'keys', self.app_environment)
        self.environment_secrets_dir = os.path.join(
            data_dir, 'secrets', self.app_environment)

        if not os.path.exists(self.environment_secrets_dir):
            os.makedirs(self.environment_secrets_dir)
        if not os.path.exists(self.environment_keys_dir):
            os.makedirs(self.environment_keys_dir)

    def _init_env(self, env):
        if env:
            if env in defaults.ENV_MAP.keys():
                env = defaults.ENV_MAP[env]
            self.app_environment = env
            return

        self.app_environment = defaults.DEFAULT_ENV

    def _get_plaintext_private_key(
            self, ciphertext_blob, encryption_context={}):
        '''Return a plaintext RSA private key by performing a KMS decrypt on
        the stored encrypted private key'''
        try:
            response = self.kms.decrypt(
                CiphertextBlob=b64decode(ciphertext_blob),
                EncryptionContext=encryption_context)
        except Exception as e:
            raise errors.KmsError(
                "Could not decrypt private key using KMS "
                "key '%s' (Reason: %s)" % (self.kms_key_id, str(e)))

        return response[u'Plaintext']

    def _set_encryptor(self, public_key):
        '''Creates a OAEP decryptor based on a RSA private key.'''
        if self.encryptor is not None:
            return

        if not public_key:
            try:
                with open(self.public_key_file, 'rb') as f:
                    public_key = f.read()
            except IOError as e:
                raise errors.InputError(
                    "public key '%s' does not exist." % self.public_key_file)

        try:
            public_key_obj = serialization.load_pem_public_key(
                public_key,
                backend=default_backend())

            self.encryptor = Encryptor(public_key_obj)
        except Exception as e:
            raise errors.EncryptorError(
                "public key is malformed. (Reason: %s)" % (str(e)))

    def _set_decryptor(
            self,
            plaintext_private_key=None,
            encrypted_private_key=None):
        '''Creates a OAEP decryptor based on a RSA private key.'''
        if self.decryptor is not None:
            return

        if not plaintext_private_key:
            if not encrypted_private_key:
                try:
                    with open(self.encrypted_private_key_file, 'rb') as f:
                        encrypted_private_key = f.read()
                except IOError as e:
                    raise errors.InputError(
                        "private key '%s' does not exist." % (
                            self.encrypted_private_key_file))

            plaintext_private_key = self._get_plaintext_private_key(
                encrypted_private_key,
                encryption_context=self.encryption_context)

        try:
            private_key_obj = serialization.load_pem_private_key(
                plaintext_private_key,
                password=None,
                backend=default_backend())

            self.decryptor = Decryptor(private_key_obj)
        except Exception as e:
            raise errors.DecryptorError(
                "private key is malformed. (Reason: %s)" % (str(e)))

    def _validate_secret(self, secret_name, secret, blob_mode):
        if not blob_mode:
            # secret must have a value
            if len(secret_name) == 0:
                raise errors.InputError(
                    "secret name '%s' must be greather than length of 0" % (
                        secret_name))

            # secret name can only contain ascii characters
            if not self._is_ascii(secret_name):
                raise errors.InputError(
                    "secret name '%s' must contain only ASCII chars" % (
                        secret_name))

        # warn when secret value contains non-ascii chars
        if not self._is_ascii(secret):
            log.warn("Secret '%s' contains non-ASCII chars." % (
                secret_name))

    def _encrypt(self, secret_name, secret, blob_mode=False):
        '''Encrypt a single secret name and value pair into the data
        directory by environment.'''
        self._validate_secret(secret_name, secret, blob_mode)
        secret = secret.encode('utf-8')

        ciphertext_bin = self._encrypt_with_aes_session_key(secret)
        ciphertext_bin_b64 = b64encode(ciphertext_bin)

        if blob_mode:
            return ciphertext_bin_b64

        # if not a blob_encrypt, then write to file
        filename = secret_name + self.ciphertext_ext
        secret_filepath = os.path.join(self.environment_secrets_dir, filename)

        with open(secret_filepath, 'wb') as f:
            f.write(ciphertext_bin_b64)

    def _encrypt_with_aes_session_key(self, secret):
        '''Creates a AES-CBC 128 bit session key and to encrypt secrets with
        and packages that session key (encrypted with the RSA public key)
        along with the ciphertext as a binary.'''
        session_key = Fernet.generate_key()
        encrypted_session_key = self.encryptor.encrypt(session_key)

        fernet_cipher = Fernet(session_key)
        ciphertext = fernet_cipher.encrypt(secret)

        ciphertext_bin = encrypted_session_key + ciphertext

        return ciphertext_bin

    def _encrypt_all_secrets(self, secrets_json):
        '''Helper function to encrypt all secrets from a JSON string'''
        try:
            secrets = json.loads(secrets_json)
        except ValueError:
            raise errors.InputError('input is not valid JSON')

        for secret_name, secret in secrets.items():
            log.info(secret_name)
            self._encrypt(secret_name, secret)

    def _convert_blob_to_bin(self, secret_blob):
        try:
            ciphertext_bin = b64decode(secret_blob)
        except Exception:
            raise errors.InputError("ciphertext blob is not base64 encoded")

        if self.offset > len(ciphertext_bin):
            raise errors.InputError(
                "RSA ciphertext length is larger than the "
                "secret ciphertext binary length")

        return ciphertext_bin

    def _decrypt_secret_blob(self, secret_blob):
        '''Decrypts a binary blob which contains an RSA encrypted AES session
        key and AES encrypted data.'''

        # Break out base64 encoded binary to encrypted session key and data
        ciphertext_bin = self._convert_blob_to_bin(secret_blob)
        encrypted_session_key = ciphertext_bin[:self.offset]
        ciphertext = ciphertext_bin[self.offset:]

        secret = None

        try:
            # decrypt aes session key with rsa private key
            session_key = self.decryptor.decrypt(encrypted_session_key)
            fernet_cipher = Fernet(session_key)

            secret = fernet_cipher.decrypt(ciphertext).decode('utf-8')
        # A number of ciphertext issues could cause AES-RSA decryption to fail
        except Exception:
            raise errors.InputError("ciphertext binary is corrupt")

        return secret

    def _decrypt_aes_wrapped_file(self, secret_file):
        '''Decrypts a binary file which a base64 encoded secrets blob.'''
        try:
            with open(secret_file, 'rb') as f:
                secret_blob = f.read()

            secret = self._decrypt_secret_blob(secret_blob)
        except Exception as e:
            log.error(
                "Could not decrypt AES wrapped secret '%s' (Reason: %s)" % (
                    os.path.basename(secret_file), str(e)))
            secret = None

        return secret

    def _decrypt_secret(self, secret_name):
        '''Decrypt a single secret by name and return the value as a string.'''
        secret = None

        if secret_name in self.secrets_dict:
            secret_path = self.secrets_dict[secret_name]
            if os.path.basename(secret_path).endswith('.bin'):
                secret = self._decrypt_aes_wrapped_file(secret_path)

        return secret

    def _decrypt_all_secrets(self):
        '''Decrypt all secrets for the current environment and return a
        dict object'''
        secrets = {}

        for secret_name, secret_path in self.secrets_dict.items():
            secret = self._decrypt_secret(secret_name)
            if secret is not None:
                secrets[secret_name] = secret

        return secrets

    def _get_secrets_dict(self):
        '''Returns a dict of all secrets available for the current environment.

        key: secret_name
        value: absolute path of the secret file
        '''
        secrets_dict = {}

        for file in os.listdir(self.environment_secrets_dir):
            if file.endswith(defaults.CIPHERTEXT_EXT):
                secret_name = self._chomp_ext(file)
                secrets_dict[secret_name] = os.path.join(
                    self.environment_secrets_dir, file)

        return secrets_dict

    def _chomp_ext(self, string):
        '''Remove the extension of a filename.'''
        return os.path.splitext(string)[0]

    def _is_ascii(self, string):
        try:
            string.encode('ascii')
        except UnicodeEncodeError:
            return False

        return True

    def generate_key_pair(self):
        '''RSA key generation

        Sets up a project or application with asymmetric keys used for all Code
        Crypt operations. If only one of two of the key pair already exists an
        an exception is raised. If both already exist, no action is taken.

        KMS encrypt is needed to encrypt the RSA private key and save it.
        '''
        public_key_file_exists = os.path.exists(self.public_key_file)
        private_key_file_exists = os.path.exists(
            self.encrypted_private_key_file)

        if public_key_file_exists and private_key_file_exists:
            log.info('Public key and private key already exist.')
            return
        elif public_key_file_exists and not private_key_file_exists:
            raise errors.CodeCryptError(
                'public key exists but private key is missing.')
        elif private_key_file_exists and not public_key_file_exists:
            raise errors.CodeCryptError(
                'private key exists but public key is missing.')

        log.info('Generating key pair...')
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size,
            backend=default_backend())
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())

        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        try:
            response = self.kms.encrypt(
                KeyId=self.kms_key_id,
                Plaintext=private_key_pem,
                EncryptionContext=self.encryption_context)
        except Exception as e:
            raise errors.KmsError(
                "Could not encrypt private key using KMS "
                "key '%s' (Reason: %s)" % (self.kms_key_id, str(e)))

        ciphertext_blob = response['CiphertextBlob']

        with open(self.encrypted_private_key_file, 'wb') as f:
            f.write(b64encode(ciphertext_blob))

        with open(self.public_key_file, 'wb') as f:
            f.write(public_key_pem)

    def encrypt(self, secret_name, secret, public_key=None):
        '''Single secret encrypt

        Takes in a single key-value pair secret and encrypts it with AES. The
        AES session key is then encrypted asymmetrically with RSA so that
        access to this key via KMS will allows decrypts on each individual
        secret.

        Secret names will be stored as filenames in the data directory.

        Args:
            secret_name: secret name
            secret: secret value
            public_key: public RSA to encrypt secrets
        '''
        self._set_encryptor(public_key)
        self.secrets_dict = self._get_secrets_dict()

        log.info('Encrypting...')
        self._encrypt(secret_name, secret)

    def blob_encrypt(self, secret, public_key=None):
        '''Single secret encrypt that returns an encrypted blob

        Takes in a single value and encrypts with it RSA-AES hybrid and returns
        an encrypted base64 encrypted binary blob.

        Args:
            secret: secret value
            public_key: public RSA to encrypt secrets
        '''
        self._set_encryptor(public_key)
        return self._encrypt(None, secret, blob_mode=True)

    def import_secrets(self, secrets_json, public_key=None):
        '''Secrets JSON encryption

        Takes in a JSON object in the form of key-value pairs, initializes an
        encryptor based on a public key and writes it to into the data
        directory.

        Args:
            secrets_json: JSON string with secrets to be encrypted
            public_key: public RSA to encrypt AES session keys with
        '''
        self._set_encryptor(public_key)
        self._get_secrets_dict()

        log.info('Importing...')
        self._encrypt_all_secrets(secrets_json)

    def decrypt(
            self,
            secret_name=None,
            plaintext_private_key=None,
            encrypted_private_key=None):
        '''Decrypt secrets to JSON

        Takes in a single secret to decrypt, or none to decrypt all of them to
        produce a dict result of key-value pairs.

        Either a plaintext RSA private key can be provided, or a KMS encrypted
        RSA private key. In the latter case, a KMS decrypt operation will need
        to be allowed on the derived KMS key.

        NOTE: no secret_name being provided will result in all of the secrets
        in the environment context to be decrypted and returned.

        Args:
            secret name: JSON string with secrets to be encrypted
            plaintext_private_key: private RSA key to decrypt AES session keys
            encrypted_private_key: encrypted version of the the private key

        Returns:
            decrypted secrets in dict form
        '''
        if plaintext_private_key and encrypted_private_key:
            raise errors.CodeCryptError(
                'both plaintext and encrypted private keys cannot be provided')

        self._set_decryptor(
            plaintext_private_key=plaintext_private_key,
            encrypted_private_key=encrypted_private_key)
        self.secrets_dict = self._get_secrets_dict()

        log.info('Decrypting...')
        if secret_name:
            return self._decrypt_secret(secret_name)

        return self._decrypt_all_secrets()

    def blob_decrypt(
            self,
            secret_blob,
            plaintext_private_key=None,
            encrypted_private_key=None):
        '''Decrypts a base64 encoded encrypted binary to a plaintext secret

        Either a plaintext RSA private key can be provided, or a KMS encrypted
        RSA private key. In the latter case, a KMS decrypt operation will need
        to be allowed on the derived KMS key.

        Args:
            secret blob: base64 encoded encrypted binary
            plaintext_private_key: private RSA key to decrypt AES session keys
            encrypted_private_key: encrypted version of the the private key

        Returns:
            decrypted secret string
        '''
        if plaintext_private_key and encrypted_private_key:
            raise errors.CodeCryptError(
                'both plaintext and encrypted private keys cannot be provided')

        # We perform this here to validate the secret blob early
        self._convert_blob_to_bin(secret_blob)

        self._set_decryptor(
            plaintext_private_key=plaintext_private_key,
            encrypted_private_key=encrypted_private_key)

        return self._decrypt_secret_blob(secret_blob)
