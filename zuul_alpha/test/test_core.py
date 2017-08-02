# coding: utf8

import mock
import os
import shutil
import tempfile
import unittest

from base64 import b64decode, b64encode

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

from zuul_alpha import core as zuul_alpha
from zuul_alpha import errors


DATA_DIR = tempfile.mkdtemp()
ENV = 'test'
EXT = '.enc'
RSA_KEY_SIZE = 1024
CHUNK_SIZE = 86
KMS_KEY_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

TEST_VALID_JSON = """{
  "SECRET_NAME_A": "AAA",
  "SECRET_NAME_B": "BBB"
}"""

TEST_PUBLIC_KEY = """-----BEGIN RSA PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHka7JNmKajUcRdCDPXZZ44pRe
neKMZFPP+rSEU4Gt2hUz0gXeSJIFGd9aTiEN2cfYKSaNQSSgbH+PKY12PRnSWzMU
bULV4zITOjq/FjsWIhyCFM60vt3Sj6jYYPYrcTcKq+9aJkA9eCiVQ61jxiUttDSi
WjXYXmxPxX23dg1h6QIDAQAB
-----END RSA PUBLIC KEY-----"""

TEST_PLAINTEXT_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCHka7JNmKajUcRdCDPXZZ44pReneKMZFPP+rSEU4Gt2hUz0gXe
SJIFGd9aTiEN2cfYKSaNQSSgbH+PKY12PRnSWzMUbULV4zITOjq/FjsWIhyCFM60
vt3Sj6jYYPYrcTcKq+9aJkA9eCiVQ61jxiUttDSiWjXYXmxPxX23dg1h6QIDAQAB
AoGAPDuwCtpNCRoIH2sXQMr2FhOllDxV8caJrnhXSAvKLDIfBX0k+lQH/Jg4MmlQ
KlU+g34VEOGGonhSXIs7vPL8y2II5ABOEExtLf8oWSIUtU6G/fRbiEMONHfNg/bO
juA9pWnEXJtmnROcAYEVjRD5H7CFBuYZ/cweXUYs/GENzFkCQQC4kD2pzK57Pw9p
xOIN6msNSxZSWN03qUNc8hDmMw9eAGJdzwrmN9HqLFGWsQ22kBlfT88geYMLQqh6
rF5c1W2HAkEAvArCARvx0w5EC1hNgttWkEUicQ16RupcVB9946TVXUDpZ6jcV92V
DM58AQsxaXfZf/wp5yM3SoKYx/DIXgoRDwJBAIikAYMcznDglwCviszSqL8GwFfn
AqCa6AyACpLjapUlo63gAym+WeMNPLpcCtMGjEJMTAS28ZX8m892ncYNHTECQQCP
crl69SFue0SHTw6aU87ecg8LJVfxf1l9xyRXI+isohcsP9IPqXbJ9T794NcJ+SbQ
DsK8k83bJnN8m3+O1akbAkBTjNS3OSNxU+tpylMjnMjsX3r85gjXHo/TRgGF09Nd
uPstcE/4smb+OfUeo3v+g7AHiVmT9wNdjMsKd5/O8cKn
-----END RSA PRIVATE KEY-----"""

TEST_ENCRYPTED_PRIVATE_KEY = """AQICAHhiG23RsuSTqwlDgwSBWuBR8vtuEXp93gSa1U3HT2B
6gwELXt1bQkxxr5geTtATUksrAAAD3jCCA9oGCSqGSIb3DQEHBqCCA8swggPHAgEAMIIDwAYJKoZIhv
cNAQcBMB4GCWCGSAFlAwQBLjARBAxKOUPOFAuu6+hrSswCARCAggOR3DXvk7k8dBKQSYxo9J97lmvsl
vBe8ycD4Bqz732AvITsht20sphKBNb+4CghVN9EVafSRwDtC7KPZy3OGW//w4rN+2o2jNhwx6XeV4T/
H4C8V5/CsErzBDOSx/VgcVzWUi9VWU2LWb0gyWdUouPvHAoimbhzJ3F4EIZK0Y3AmeZ0aWqt1xNgsqI
Su+5fdan06Rl5bQ30TNAAH9MU3v/+7WXudfjvwl/iklPW8JJKVYdGjcfHniNhoc3x1mdpV5QgcuT7AK
ngc6dIkAWFMKyJFDu8IvVr5yrqhzrT8uCsOITemjwcLkpkvZqEWC7a0zbI9CKC6s51UB4fa+GMFEXvZ
XO3t6DUzqi2Q+mIFfpNp3ftYmgiHFZYM1N0uDHJ/i4aLB7qImukPhwFK+/KCKCCHhvZKEIJtcYe/JBV
h4feJlqZHozH5s3RkECpjy8n7BIEgSXZiaKxoponnbUX0cU8CQ4RlYqAbMV8hQLNlawlDocThdHLMi7
JDWX0QulJaDa1kWrecL49ZLj0w3pf6FDLmcl00eGnBgrwzorCyrAHCm+ImEvne+ZCYHr/LoLBDo068G
jANphSwmy+kqRwOwiYfJeCTTP29/61MoNCi1M8pfO1lsm5281CfKUYtWqaUJ1OzOxyNjK1j8sLmauDN
Cc11UTLIGLjOP54kDshTnPNCWQXP4LBx1/zxq30qBB+wT78ve+dLhl606KruOzYkR6YScdnZXmeWYa8
ZJYFkeQupsr+sD5a8mdLFOJIwF5S1OrvafGEPpHpcsDO8FEbTSNPVT5MYJq/t5fSvdnF7pKPXgdqtY+
51VczuV1aZ2gpmatQvpHYA2ym0ony4Or7LkCpTBLFA6stoa7TkCV23O3UXa43k7rZoJEsXEBtcYygPX
i+cwSea5xsiQyunMH83Kd1T6i7WYbIpD/uR1DlVq72XIuuXfzibzLAOwi7Wro5P2n/a4vG2SJ53oQwB
8Hie/uQup7npkyyCuCCaCvOgQ6cPCEmyHyE2bh8Ot3Btt5Gap4kBAqa8NpR2e9lamews0x7slYd1+60
CPnruX3rsO07qAmw9oI4wnbw9vNaZXBXSnIBqEH4pQbAmvIAgSW8TPB4rLgqG6ggkn1DQD7GB3kMOWs
Kdc1LG8Q/7xcAxpbYQADhxiyjMycHeFLkksDK/y9Yv4j5MK6aFrHYls41/ATklPH/wqjRZfcsS/ZeTU
lDNU8tcQ=="""

# Sample RSA Private Key
LARGE_SECRET = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=
-----END RSA PRIVATE KEY-----"""


class TestGenerateKeyPair(unittest.TestCase):

    def setUp(self):
        self.zuul = zuul_alpha.Zuul(
            kms_key_id=KMS_KEY_ID,
            data_dir=DATA_DIR,
            env=ENV,
            ciphertext_ext=EXT,
            rsa_key_size=RSA_KEY_SIZE)

        self.expected_public_key_file = os.path.join(
            DATA_DIR, 'keys', ENV, 'public_key.asc')

        self.expected_private_key_file = os.path.join(
            DATA_DIR, 'keys', ENV, 'encrypted_private_key.pem')

    def test_generate_key_pair_with_missing_private_key(self):
        with open(self.expected_public_key_file, 'w') as f:
            f.write('')

        self.assertRaises(
            errors.ZuulError,
            lambda: self.zuul.generate_key_pair())

    def test_generate_key_pair_with_missing_public_key_only(self):
        with open(self.expected_private_key_file, 'w') as f:
            f.write('')

        self.assertRaises(
            errors.ZuulError,
            lambda: self.zuul.generate_key_pair())

    # TODO: mock and test for write out of keys instead of exiting
    @mock.patch("boto3.client")
    def test_generate_key_pair_with_no_existing_keys(
            self, mock_client):
        mock_client.return_value = mock.MagicMock()

        self.zuul = zuul_alpha.Zuul(
            kms_key_id=KMS_KEY_ID,
            data_dir=DATA_DIR,
            env=ENV,
            ciphertext_ext=EXT,
            rsa_key_size=RSA_KEY_SIZE)

        self.zuul.kms.encrypt.return_value = {
                'CiphertextBlob': TEST_PLAINTEXT_PRIVATE_KEY}

        self.zuul.generate_key_pair()

        mock_client.assert_called_with('kms', region_name='us-east-1')

        # try:
        #     with open(self.expected_public_key_file, 'r') as f:
        #         public_key = f.read()

        #     with open(self.expected_private_key_file, 'r') as f:
        #         private_key = f.read()

        # except IOError as e:
        #     print('Missing generated keys')
        #     exit(1)

    def tearDown(self):
        shutil.rmtree(DATA_DIR)


class TestImportSecrets(unittest.TestCase):

    def _decrypt_helper(self, private_key, secret_name):
        secret_file = os.path.join(
            DATA_DIR, 'secrets', ENV, secret_name + EXT)

        decryptor = PKCS1_OAEP.new(RSA.import_key(private_key))

        with open(secret_file) as f:
            plaintext_secret = decryptor.decrypt(b64decode(f.read()))

        return plaintext_secret

    def setUp(self):
        self.zuul = zuul_alpha.Zuul(
            kms_key_id=KMS_KEY_ID,
            data_dir=DATA_DIR,
            env=ENV,
            ciphertext_ext=EXT,
            rsa_key_size=RSA_KEY_SIZE)

    def test_import_secrets_with_invalid_secrets_json(self):
        self.assertRaises(
            errors.InputError,
            lambda: self.zuul.import_secrets(
                '{foo=bar}', TEST_PUBLIC_KEY))

    def test_import_secrets_with_valid_data(self):
        self.zuul.import_secrets(TEST_VALID_JSON, TEST_PUBLIC_KEY)

        decrypted_result = self._decrypt_helper(
            TEST_PLAINTEXT_PRIVATE_KEY, 'SECRET_NAME_A')
        self.assertEqual(decrypted_result, 'AAA')

        decrypted_result = self._decrypt_helper(
            TEST_PLAINTEXT_PRIVATE_KEY, 'SECRET_NAME_B')
        self.assertEqual(decrypted_result, 'BBB')

    def tearDown(self):
        shutil.rmtree(DATA_DIR)


class TestDecrypt(unittest.TestCase):

    def _encrypt_helper(self, public_key, secret_name, secret):
        secret_file = os.path.join(
            DATA_DIR, 'secrets', ENV, secret_name + EXT)

        encryptor = PKCS1_OAEP.new(RSA.import_key(public_key))
        encrypted_secret = encryptor.encrypt(secret.encode('utf-8'))

        with open(secret_file, 'w') as f:
            f.write(b64encode(encrypted_secret))

        return secret_file

    def setUp(self):
        self.zuul = zuul_alpha.Zuul(
            kms_key_id=KMS_KEY_ID,
            data_dir=DATA_DIR,
            env=ENV,
            ciphertext_ext=EXT,
            rsa_key_size=RSA_KEY_SIZE)

    def test_decrypt_with_missing_private_key_file(self):
        self.assertRaises(errors.InputError, lambda: self.zuul.decrypt('FOO'))

    def test_decrypt_with_malformed_private_key(self):
        self.assertRaises(
            errors.DecryptorError,
            lambda: self.zuul.decrypt('FOO', 'bar'))

    def test_decrypt_with_missing_secret(self):
        decrypted_result = self.zuul.decrypt('FOO', TEST_PLAINTEXT_PRIVATE_KEY)
        self.assertEquals(decrypted_result, '')

    def test_decrypt_secret_with_plaintext_private_key(self):
        self._encrypt_helper(TEST_PUBLIC_KEY, 'SECRET_NAME_CCC', 'CCC')

        decrypted_result = self.zuul.decrypt(
            'SECRET_NAME_CCC', TEST_PLAINTEXT_PRIVATE_KEY)
        self.assertEqual(decrypted_result, 'CCC')

    def test_decrypt_secret_with_invalid_kms_context(self):
        self.assertRaises(
            errors.KmsError,
            lambda: self.zuul.decrypt(
                encrypted_private_key=TEST_ENCRYPTED_PRIVATE_KEY))

    def test_decrypt_secret_with_missing_kms_key(self):
        self.assertRaises(
            errors.InputError,
            lambda: self.zuul.decrypt('FOO'))

    @mock.patch("boto3.client")
    def test_decrypt_secret_with_kms(self, mock_client):
        secret = 'DDD'
        self._encrypt_helper(TEST_PUBLIC_KEY, 'SECRET_NAME_DDD', secret)
        mock_client.return_value = mock.MagicMock()

        self.zuul = zuul_alpha.Zuul(
            kms_key_id=KMS_KEY_ID,
            data_dir=DATA_DIR,
            env=ENV,
            ciphertext_ext=EXT,
            rsa_key_size=RSA_KEY_SIZE)

        self.zuul.kms.decrypt.return_value = {
            'Plaintext': TEST_PLAINTEXT_PRIVATE_KEY}
        decrypted_result = self.zuul.decrypt(
            'SECRET_NAME_DDD',
            encrypted_private_key=TEST_ENCRYPTED_PRIVATE_KEY)

        mock_client.assert_called_with('kms', region_name='us-east-1')

        self.assertEqual(decrypted_result, secret)

    @mock.patch("boto3.client")
    def test_decrypt_large_secret_with_kms(self, mock_client):
        self.zuul.encrypt('SECRET_NAME_DDD', LARGE_SECRET, TEST_PUBLIC_KEY)
        mock_client.return_value = mock.MagicMock()

        self.zuul = zuul_alpha.Zuul(
            kms_key_id=KMS_KEY_ID,
            data_dir=DATA_DIR,
            env=ENV,
            ciphertext_ext=EXT,
            rsa_key_size=RSA_KEY_SIZE)

        self.zuul.kms.decrypt.return_value = {
            'Plaintext': TEST_PLAINTEXT_PRIVATE_KEY}
        decrypted_result = self.zuul.decrypt(
            'SECRET_NAME_DDD',
            encrypted_private_key=TEST_ENCRYPTED_PRIVATE_KEY)

        mock_client.assert_called_with('kms', region_name='us-east-1')

        self.assertEqual(decrypted_result, LARGE_SECRET)

    @mock.patch("boto3.client")
    def test_decrypt_explicit_all_with_kms(self, mock_client):
        secret_one = 'one'
        secret_two = 'two'
        self._encrypt_helper(TEST_PUBLIC_KEY, 'SECRET_NAME_1', secret_one)
        self._encrypt_helper(TEST_PUBLIC_KEY, 'SECRET_NAME_2', secret_two)
        mock_client.return_value = mock.MagicMock()

        self.zuul = zuul_alpha.Zuul(
            kms_key_id=KMS_KEY_ID,
            data_dir=DATA_DIR,
            env=ENV,
            ciphertext_ext=EXT,
            rsa_key_size=RSA_KEY_SIZE)

        self.zuul.kms.decrypt.return_value = {
            'Plaintext': TEST_PLAINTEXT_PRIVATE_KEY}
        decrypted_result = self.zuul.decrypt(
            encrypted_private_key=TEST_ENCRYPTED_PRIVATE_KEY)

        mock_client.assert_called_with('kms', region_name='us-east-1')

        self.assertEqual(decrypted_result['SECRET_NAME_1'], secret_one)
        self.assertEqual(decrypted_result['SECRET_NAME_2'], secret_two)

    @mock.patch("boto3.client")
    def test_decrypt_all_with_kms(self, mock_client):
        secret_one = 'one'
        secret_two = 'two'
        self._encrypt_helper(TEST_PUBLIC_KEY, 'SECRET_NAME_1', secret_one)
        self._encrypt_helper(TEST_PUBLIC_KEY, 'SECRET_NAME_2', secret_two)
        mock_client.return_value = mock.MagicMock()

        self.zuul = zuul_alpha.Zuul(
            kms_key_id=KMS_KEY_ID,
            data_dir=DATA_DIR,
            env=ENV,
            ciphertext_ext=EXT,
            rsa_key_size=RSA_KEY_SIZE)

        self.zuul.kms.decrypt.return_value = {
            'Plaintext': TEST_PLAINTEXT_PRIVATE_KEY}
        decrypted_result = self.zuul.decrypt(
            plaintext_private_key=TEST_PLAINTEXT_PRIVATE_KEY)

        mock_client.assert_called_with('kms', region_name='us-east-1')

        self.assertEqual(decrypted_result['SECRET_NAME_1'], secret_one)
        self.assertEqual(decrypted_result['SECRET_NAME_2'], secret_two)

    def tearDown(self):
        shutil.rmtree(DATA_DIR)


class TestEncrypt(unittest.TestCase):

    def _decrypt_helper(self, private_key, secret_name):
        secret_file = os.path.join(
            DATA_DIR, 'secrets', ENV, secret_name + EXT)
        decryptor = PKCS1_OAEP.new(RSA.import_key(private_key))

        with open(secret_file) as f:
            plaintext_secret = decryptor.decrypt(b64decode(f.read()))

        return plaintext_secret

    def _encrypt_helper(self, public_key, secret_name, secret):
        secret_file = os.path.join(
            DATA_DIR, 'secrets', ENV, secret_name + EXT)

        encryptor = PKCS1_OAEP.new(RSA.import_key(public_key))
        encrypted_secret = encryptor.encrypt(secret.encode('utf-8'))

        with open(secret_file, 'w') as f:
            f.write(b64encode(encrypted_secret))

        return secret_file

    def setUp(self):
        self.zuul = zuul_alpha.Zuul(
            kms_key_id=KMS_KEY_ID,
            data_dir=DATA_DIR,
            env=ENV,
            ciphertext_ext=EXT,
            rsa_key_size=RSA_KEY_SIZE)

    def test_encrypt_with_missing_public_key(self):
        self.assertRaises(
            errors.InputError,
            lambda: self.zuul.encrypt('FOO', 'BAR'))

    def test_encrypt_with_malformed_public_key(self):
        self.assertRaises(
            errors.EncryptorError,
            lambda: self.zuul.encrypt('FOO', 'BAR', 'SOME_BAD_KEY'))

    def test_encrypt_with_zero_length_secret_name(self):
        secret_name = ''
        secret = 'AAA'
        self.assertRaises(
            errors.InputError,
            lambda: self.zuul.encrypt(
                secret_name, secret, public_key=TEST_PUBLIC_KEY))

    def test_encrypt_with_non_ascii_secret_name(self):
        secret_name = u'试'
        secret = 'AAA'
        self.assertRaises(
            errors.InputError,
            lambda: self.zuul.encrypt(
                secret_name, secret, public_key=TEST_PUBLIC_KEY))

    def test_encrypt_on_new_secret(self):
        secret_name = 'NEW_SECRET'
        secret = 'AAA'
        self.zuul.encrypt(secret_name, secret, public_key=TEST_PUBLIC_KEY)

        decrypted_result = self._decrypt_helper(
            TEST_PLAINTEXT_PRIVATE_KEY, secret_name)

        self.assertEquals(decrypted_result, secret)

    def test_encrypt_on_existing_secret(self):
        secret_name = 'EXISTING_SECRET'
        secret = 'AAA'
        new_secret = 'BBB'
        self._encrypt_helper(TEST_PUBLIC_KEY, secret_name, secret)

        self.zuul.encrypt(
            secret_name, new_secret, public_key=TEST_PUBLIC_KEY)

        decrypted_result = self._decrypt_helper(
            TEST_PLAINTEXT_PRIVATE_KEY, secret_name)

        self.assertEquals(decrypted_result, new_secret)

    def tearDown(self):
        shutil.rmtree(DATA_DIR)


if __name__ == '__main__':
    unittest.main()
