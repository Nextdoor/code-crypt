"""Module to encrypt and decrypt app secrets asymmetrically via KMS."""

import boto3
import io
import json
import logging
import shutil
import os

from base64 import b64encode, b64decode

from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP

from zuul_alpha import defaults
from zuul_alpha import errors

log = logging.getLogger(__name__)


class Zuul:
    '''Zuul object which handles the setup of RSA based cryptgraphic facilities,
    secret and key storange and communication with KMS.'''
    def __init__(
            self,
            kms_key_id=None,
            aws_region=defaults.AWS_REGION,
            data_dir=defaults.ZUUL_DATA_DIR,
            env=None,
            ciphertext_ext=defaults.DEFAULT_CIPHERTEXT_EXT,
            encrypted_private_key_file=None,
            rsa_key_size=defaults.DEFAULT_RSA_KEY_SIZE,
            encrypted_chunk_size=defaults.CHUNK_SIZE):
        self.kms_key_id = kms_key_id
        self.ciphertext_ext = ciphertext_ext
        self.rsa_key_size = rsa_key_size
        self.encrypted_chunk_size = encrypted_chunk_size
        self.ext_len = len(self.ciphertext_ext)

        self.app_environment = self._app_environment()
        if env:
            self.app_environment = env

        self._init_dirs(data_dir)

        self.encrypted_private_key_file = os.path.join(
                self.environment_keys_dir, 'encrypted_private_key.pem')
        if encrypted_private_key_file:
            self.encrypted_private_key_file = encrypted_private_key_file

        self.public_key_file = os.path.join(
            self.environment_keys_dir, 'public_key.asc')

        self.encryption_context = {'app_environment': self.app_environment}
        self._init_kms_client(aws_region)

    def _init_kms_client(self, aws_region):
        '''Initializes a kms boto3 client.'''
        self.kms = boto3.client('kms', region_name=aws_region)

    def _init_dirs(self, data_dir):
        '''Sets and create the Zuul data directory which contains secrets and
        keys based on environment.'''
        self.environment_keys_dir = os.path.join(
            data_dir, 'keys', self.app_environment)
        self.environment_secrets_dir = os.path.join(
            data_dir, 'secrets', self.app_environment)

        if not os.path.exists(self.environment_secrets_dir):
            os.makedirs(self.environment_secrets_dir)
        if not os.path.exists(self.environment_keys_dir):
            os.makedirs(self.environment_keys_dir)

    def _get_plaintext_private_key(
            self, ciphertext_blob, encryption_context={}):
        '''Return a plaintext private key by performing a KMS decrypt on the
        stored encrypted private key'''
        try:
            response = self.kms.decrypt(
                CiphertextBlob=b64decode(ciphertext_blob),
                EncryptionContext=encryption_context)
        except Exception as e:
            raise errors.KmsError(
                "Could not encrypt private key using KMS "
                "key '%s' (Reason: %s)" % (self.kms_key_id, e.message))

        return response[u'Plaintext']

    def _set_encryptor(self, public_key):
        '''Creates a PKCS1_OAEP encryptor based on a RSA public s key.'''
        if not public_key:
            try:
                with open(self.public_key_file, 'r') as f:
                    public_key = f.read()
            except IOError as e:
                raise errors.InputError(
                    "public key '%s' does not exist." % self.public_key_file)

        try:
            public_key_obj = RSA.import_key(public_key).publickey()
            self.encryptor = PKCS1_OAEP.new(public_key_obj)
        except Exception as e:
            raise errors.EncryptorError(
                "public key is malformed. (Reason: %s)" % (e.message))

    def _set_decryptor(
            self,
            plaintext_private_key=None,
            encrypted_private_key=None):
        '''Creates a PKCS1_OAEP decryptor based on a RSA private key.'''
        if not plaintext_private_key:
            if not encrypted_private_key:
                try:
                    with open(self.encrypted_private_key_file, 'r') as f:
                        encrypted_private_key = f.read()
                except IOError as e:
                    raise errors.InputError(
                        "private key '%s' does not exist." % (
                            self.encrypted_private_key_file))

            plaintext_private_key = self._get_plaintext_private_key(
                encrypted_private_key,
                encryption_context=self.encryption_context)

        try:
            private_key_obj = RSA.import_key(plaintext_private_key)
            self.decryptor = PKCS1_OAEP.new(private_key_obj)
        except Exception as e:
            raise errors.DecryptorError(
                "private key is malformed. (Reason: %s)" % (e.message))

    def _validate_secret(self, secret_name, secret):
        if len(secret_name) == 0:
            raise errors.InputError(
                "secret name '%s' must be greather than length of 0" % (
                    secret_name))
        if not self._is_ascii(secret_name):
            raise errors.InputError(
                "secret name '%s' must contain only ASCII chars" % (
                    secret_name))
        if not self._is_ascii(secret):
            log.warn("Secret '%s' contains non-ASCII chars: '%s'" % (
                secret_name, secret))

    def _encrypt(self, secret_name, secret, secret_dir=None):
        '''Encrypt a single secret name and value pair into the data
        directory by environment.'''
        self._validate_secret(secret_name, secret)

        if not secret_dir:
            secret_dir = self.environment_secrets_dir

        filename = secret_name + self.ciphertext_ext
        secret_filepath = os.path.join(secret_dir, filename)

        try:
            encrypted_secret = self.encryptor.encrypt(secret.encode('utf-8'))
            with open(secret_filepath, 'w') as f:
                f.write(b64encode(encrypted_secret))

            secret_location = secret_filepath
        except ValueError:
            if secret_name == 'SESSION_KEY':
                raise errors.ZuulError

            log.info("Secret '%s' is too large for RSA,"
                " wrapping AES sessions key." % (
                secret_name))
            secret_location = self._encrypt_with_aes_session_key(secret_name, secret)

        return secret_location

    def _chunkstring(self, string, length):
        '''Partitions the string into strings no greater than the provided
        length and return a list of strings.'''
        return (string[0+i:length+i] for i in range(0, len(string), length))

    def _encrypt_with_aes_session_key(self, secret_name, secret):
        secret_dir = os.path.join(
            self.environment_secrets_dir, secret_name)
        if os.path.exists(secret_dir):
            shutil.rmtree(secret_dir)

        os.makedirs(secret_dir)

        session_key = get_random_bytes(16)
        b4_session_key = b64encode(session_key)

        self._encrypt('SESSION_KEY', b64encode(session_key), secret_dir)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext = cipher_aes.encrypt(secret.encode('utf-8'))

        ciphertext_bin_file = os.path.join(secret_dir, 'CIPHERTEXT.bin')

        with open(ciphertext_bin_file, 'w') as f:
            ciphertext_bin = cipher_aes.nonce + ciphertext
            f.write(b64encode(ciphertext_bin))

        return secret_dir

    def _encrypt_in_chunks(self, secret_name, secret):
        '''Breaks down large secrets into RSA valid chunks.'''
        secret_dir = os.path.join(
            self.environment_secrets_dir, secret_name)
        if os.path.exists(secret_dir):
            shutil.rmtree(secret_dir)

        os.makedirs(secret_dir)

        chunk_num = 0
        for chunk in self._chunkstring(secret, self.encrypted_chunk_size):
            secret_filepath = os.path.join(
                secret_dir, str(chunk_num).zfill(3) + self.ciphertext_ext)

            encrypted_secret = self.encryptor.encrypt(chunk.encode('utf-8'))
            with open(secret_filepath, 'w') as f:
                f.write(b64encode(encrypted_secret))

            chunk_num += 1

        return secret_dir

    def _encrypt_all_secrets(self, secrets_json):
        '''Helper function to encrypt all secrets from a JSON string'''
        try:
            secrets = json.loads(secrets_json)
        except ValueError:
            raise errors.InputError('input is not valid JSON')

        for secret_name, secret in secrets.iteritems():
            log.info(secret_name)
            self._encrypt(secret_name, secret)

    def _decrypt_aes_wrapped(self, secret_dir):
        '''Decrypts a folder full of chunks of a single secret.'''
        secret = ''
        ciphertext_bin = os.path.join(secret_dir, 'CIPHERTEXT.bin')
        session_key_ciphertext = os.path.join(secret_dir, 'SESSION_KEY' + self.ciphertext_ext)

        session_key = b64decode(self._decrypt_file(session_key_ciphertext))

        with open(ciphertext_bin, 'r') as f:
            ciphertext_bin = b64decode(f.read())

        nonce = ciphertext_bin[:16]
        ciphertext = ciphertext_bin[16:]

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        secret = cipher_aes.decrypt(ciphertext)

        return secret

    def _decrypt_chunks(self, secret_dir):
        '''Decrypts a folder full of chunks of a single secret.'''
        secret = ''
        secret_files = sorted(os.listdir(secret_dir))

        for file in secret_files:
            if file.endswith(self.ciphertext_ext):
                secret += self._decrypt_file(os.path.join(secret_dir, file))

        return secret

        # TODO: how to fail with a secret decrypt error?
    def _decrypt_file(self, secret_file):
        '''Decrypt a single ciphertext file by file path.'''
        plaintext = ''

        try:
            with open(secret_file) as f:
                plaintext = self.decryptor.decrypt(b64decode(f.read()))
        except IOError:
            log.error("No secret found for %s, returning ''" % (
                os.path.basename(self._chomp_secret_ext(secret_file))))

        return plaintext

    def _decrypt_secret(self, file, found=False):
        '''Decrypt a single secret by name and return the value as a string.'''
        secret = ''
        filepath = os.path.join(self.environment_secrets_dir, file)

        if not found:
            if os.path.exists(filepath):
                pass
            elif os.path.exists(filepath + self.ciphertext_ext):
                filepath = filepath + self.ciphertext_ext
            else:
                return secret

        if os.path.isdir(filepath):
            #secret = self._decrypt_chunks(filepath)
            secret = self._decrypt_aes_wrapped(filepath)
        else:
            secret = self._decrypt_file(filepath)

        return secret

    def _decrypt_all_secrets(self):
        '''Decrypt all secrets for a particular environment and return a
        dict object'''
        secrets = {}
        for file in os.listdir(self.environment_secrets_dir):
            secret_name = self._chomp_secret_ext(file)
            secrets[secret_name] = self._decrypt_secret(file, found=True)

        return secrets

    def _app_environment(self):
        '''Derive and a return the application environment based on the
        APP_PROPERTIES environment variable.

        Note: This is for ECS based applications only.'''
        if os.getenv('APP_PROPERTIES') is not None:
            app_properties = os.getenv('APP_PROPERTIES').split('\n')
            app_tag = 'app_environment'
            app_environment = [
                y for y in app_properties if y.startswith(app_tag)][0]
            return app_environment.split('=')[1]

        return defaults.DEFAULT_ENV

    def _chomp_secret_ext(self, string):
        '''Remove the extension of a filename based on the global ciphertext
        extension.'''
        if string.endswith(self.ciphertext_ext):
            string = string[:-self.ext_len]
        return string

    def _is_ascii(self, string):
        try:
            string.decode('ascii')
        except UnicodeEncodeError:
            return False
        except UnicodeDecodeError:
            return False

        return True

    def _utf8_len(self, string):
        '''Returns UTF byte length of string'''
        return len(string.encode('utf-8'))

    def generate_key_pair(self):
        '''RSA key generation

        Sets up a project or application with asymmetric keys used for all Zuul
        operations. If only one of two of the key pair already exists an
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
            raise errors.ZuulError(
                'public key exists but private key is missing.')
        elif private_key_file_exists and not public_key_file_exists:
            raise errors.ZuulError(
                'private key exists but public key is missing.')

        log.info('Generating key pair...')
        key = RSA.generate(self.rsa_key_size)
        private_key = key.exportKey()
        public_key = key.publickey().exportKey()

        try:
            response = self.kms.encrypt(
                KeyId=self.kms_key_id,
                Plaintext=private_key,
                EncryptionContext=self.encryption_context)
        except Exception as e:
            raise errors.KmsError(
                "Could not encrypt private key using KMS "
                "key '%s' (Reason: %s)" % (self.kms_key_id, e.message))

        ciphertext_blob = response['CiphertextBlob']

        with open(self.encrypted_private_key_file, 'w') as f:
            f.write(b64encode(ciphertext_blob))

        with open(self.public_key_file, 'w') as f:
            f.write(public_key)

    def encrypt(self, secret_name, secret, public_key=None):
        '''Single secret encryptor

        Takes in a single key-value pair secret and encrypts it with the RSA
        public key.

        Secret names will be stored as filenames in the data directory.

        Args:
            secret_name: secret name
            secret: secret value
            public_key: public RSA to encrypt secrets
        '''
        self._set_encryptor(public_key)
        return self._encrypt(secret_name, secret)

    def import_secrets(self, secrets_json, public_key=None):
        '''Secrets JSON enrypter

        Takes in a JSON object in the form of key-value pairs, initializes an
        encryptor based on a public key and writes it to into the data
        directory.

        Args:
            secrets_json: JSON string with secrets to be encrypted
            public_key: public RSA to encrypt secrets
        '''
        self._set_encryptor(public_key)
        log.info('Encrypting...')
        self._encrypt_all_secrets(secrets_json)

    def decrypt(
            self,
            secret_name=None,
            plaintext_private_key=None,
            encrypted_private_key=None):
        '''Secrets decrypter to JSON

        Takes in a single secret to decrypt, or none to decrypt all of them to
        produce a dict result of key-value pairs.

        Either a plaintext RSA private key can be provided, or a KMS encrypted
        RSA private key. In the latter case, a KMS decrypt operation will need
        to be allowed on the derived KMS key.

        NOTE: no secret_name being provided will result in all of the secrets
        in the environment context to be decrypted and returned.

        Args:
            secret name: JSON string with secrets to be encrypted
            plaintext_private_key: private RSA key o decrypt secrets
            encrypted_private_key: KMS encrypted RSA key o decrypt secrets

        Returns:
            decrypted secrets in dict form
        '''
        if plaintext_private_key and encrypted_private_key:
            raise errors.ZuulError(
                'both plaintext and encrypted private keys cannot be provided')

        self._set_decryptor(
            plaintext_private_key=plaintext_private_key,
            encrypted_private_key=encrypted_private_key)
        log.info('Decrypting...')
        if secret_name:
            return self._decrypt_secret(secret_name)

        return self._decrypt_all_secrets()
