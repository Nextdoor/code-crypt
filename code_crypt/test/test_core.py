# coding: utf8

import mock
import os
import shutil
import tempfile
import unittest

from code_crypt import core as code_crypt
from code_crypt import errors

APP_ROOT = tempfile.mkdtemp()
DATA_DIR = u'code_crypt_data'
ENV = u'test'
EXT = u'.bin'
KMS_KEY_ID = u'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

TEST_VALID_JSON = u"""{
  "SECRET_NAME_A": "AAA",
  "SECRET_NAME_B": "BBB"
}"""

TEST_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoarMXPlutxvhuBLeCAhX
rYcmjMbQlxzJCiF8dPcTeTBrNxK8ZZCwwgB++zCqLnoiK3+SPqhp09berzNtZVAi
UGPoE65qBwL/zwjbiXfA/QiUN8rercJHWSbT5uNLWQrNJOabC/OASPvjM2VUjGl/
1DquzjPjHxqo2hSSRfbygovm4DHutDQVkuJ5nPIwBtZZ3t/RJW4wbfyCtXJFcOdE
L/UYdbRbgCLEbQ9K1pD0yQ4PRMeuWl8BqwDJSip+wTU0kBRlHEdnMeMLPx4C/4rg
TOj1XyNOXMyhzYHs99BmZRxsE5jAa2eUKVEltxZnEp9K/IqewXbT4RCfICZE8WPM
bwIDAQAB
-----END PUBLIC KEY-----"""

TEST_PLAINTEXT_PRIVATE_KEY = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAoarMXPlutxvhuBLeCAhXrYcmjMbQlxzJCiF8dPcTeTBrNxK8
ZZCwwgB++zCqLnoiK3+SPqhp09berzNtZVAiUGPoE65qBwL/zwjbiXfA/QiUN8re
rcJHWSbT5uNLWQrNJOabC/OASPvjM2VUjGl/1DquzjPjHxqo2hSSRfbygovm4DHu
tDQVkuJ5nPIwBtZZ3t/RJW4wbfyCtXJFcOdEL/UYdbRbgCLEbQ9K1pD0yQ4PRMeu
Wl8BqwDJSip+wTU0kBRlHEdnMeMLPx4C/4rgTOj1XyNOXMyhzYHs99BmZRxsE5jA
a2eUKVEltxZnEp9K/IqewXbT4RCfICZE8WPMbwIDAQABAoIBAFB/MvK4YCBcia+V
9Wgaf02wFcnS1NnpQ1EAC3BR9ihJq5jog1YvDVQL2y5HtPUfaxQtmSwJv2fzfT3P
ZZEkrXFJzay/E5waKjV0O5vfPQDA3MxK/0WVjuEdLDWyxzm23x6YlGsG+8Fbam2U
7txbS4LpFVEnFNfP9nNf+tVLeMT3CX54e2D1+rXG1egnw2uH0uzbui12l1kE+G+l
MojHLbTXSrYBZf5yPvdJiEWP9iX/J4HIWO9LBk9hdYLLGkzbNwLTQrXHZgWN2NWP
0PTU35AhX0yWLH/dEFwCEowiue+eGx3Qq9VwrHAaqbkE8xk961HbjNqjVvyptMm5
BCGVXkECgYEA0JH2zFehVF9/dYQrJ/uW166m/CmO+oSue5iilq0ESPufhcKo7zPo
x2gR+jcsB25DhVra/HLKcFQUcUVPk6M+V4CKc5LW08Zf3SxUSXejYhR9LZXaPJ2J
pV2cMUJxmNtCxRxtj/urbBEF24JphLe85KRSUYHUucSqrFtvz2ilQgsCgYEAxm5Z
TrjSDRyHo6RP8l2gjGGwFZ4qG95p0brcV9uYv1y2eo7MsaY5IUhz/5sf7J4XcJ0r
byFaB/AflKzMITeG/nbzRmGB7kIfd1nT508/oxWU5Jv9/9AhyLbMM3gzQyIbV0qs
VlvN90LaToHhkhk6mvCMaTDyG95Cij7MkVEQYa0CgYEA0BvUlbAaWYWwOCHYrdxr
dmneVF1jPLSHJOv3z0Bzth7b3SuORJ8W9WDyDyhd1kw/MyCkwKAJPmumuh7eeAG6
grTPcOJjWIvnu1gwAd5ON98ZyBJt322Rml79KmmRz2N4DBWBfNkxAnM51P0bLEHp
SHptaMaS64lAgxn5Roqz2mECgYEAiClymQVUBfE81jrLLUm4AHyMItlslcESJfuu
dY9XioCpKwJQTdr9OuyHxK8CwhBdj0YaZuCg8e+BDDlivaxnsreXCgWg7ghrpS97
rC8CQPtvN0wfiGmetSdSikMCEiAWWNkB1ySZ+gDi4ppXWjR7tZQ5FXmjuSHT0R90
qobQ0eUCgYEAoMhv5SsaFyk53pjXuqllX4tOiq2FAC8iUfnmGoXOAgOMb/Y0DxZo
39Ok73YeQSa3Aaa4ibfPJv+/keTEVuvkMIhCxOhOI6YT992B1VQQbeovlf6YwPNC
RnzPabvLpiSymUdlOMiTOBG1IEioY48rYt/JRzwywcZJ24dm3FE5/cM=
-----END RSA PRIVATE KEY-----"""

TEST_ENCRYPTED_PRIVATE_KEY = u"""AQICAHhiG23RsuSTqwlDgwSBWuBR8vtuEXp93gSa1U3HT2
B6gwFXBr/FJsoxfaluFn9dEQaXAAAG9zCCBvMGCSqGSIb3DQEHBqCCBuQwggbgAgEAMIIG2QYJKoZI
hvcNAQcBMB4GCWCGSAFlAwQBLjARBAwRxVHAc1aReGMBLLUCARCAggaqcBmtFSHgQYH8xRJCnkcNyc
5HAtYG0jz+yA/DUKyWNaaPzqdx2+sFYVttHEjv/P5i01DwYuzn5AT7dSi73cTvXn0znShV+GsGC7WQ
ZfEwziGS6Liyod4Gyn5flS/Ttgypc+2kmDOyOAABXr+3/Kmo6zE1FJkXOsYF6UuN9wGUFLtm7Ygerk
Hd0asVHKEfv398etOgwwxrzqe0mJXH5EZpn1g5x6DPgLvrTApednt+wtcpT+HgV8onFhAj5BQyZ9h6
i0P15Y49S1VrpMFfS9t3DdpWgFgt/Dyf3Cc7eiXZYca4o9eC7Mf+HALDM2wxpICOOrkACq6YYPFgL3
7ocUVjEs35xijz+UsG5abrVqn
v6XtpJYXpOhZstmfwQAK8VpCFH6gjnSxeZNmG6sNYb16Qdfs1frMq1nXlYxPKfe+yzjooMPGfP3Kv5
ManSSO1MP9tWBIRJoBzRFn1zQhUrpqvQ+rYux4PGZwAloxsiGDfOMbJGUZSpT+WguPTNGGH2srvLo1
fNvCMD/sC3HqqeKBdFzAvzsNJkUTVo0IZ8fmmrRf62SoNd+QFw2nqLeZS9MocIhp1qa/yah9zj9Pep
1epK3/pNdq7I0PZ9X8WFoDIm+71nUXmgQoLa5Dcmej5d2ugbi2Ope/RRj5lXGprl+L087LzBCpHbZh
0nKdVdwF2xiKmtQZWjcSsGAiB8aRXrOieH7fLfQfsJ+aASzCyViOK8cajypFFZQbgGi11zMqCTEiK4
CI4iqyfjYrL71W1bbHXuTB07JsMjlcyU/aefbm59gDOKi0kNg45qzz7zC5NWoAaoFWF79QU81LCgnN
n9ziIwpEv5P8YkOuziUyikpHGGo7vt67I7Rguz/tr0FHI8K9JoZBx/MsJ4N/PqT1OaE0VEEL3TbMRa
zAYouivOVSnqdvNFzntrMoMLnCqRhVnCP9NEihhkCIaQUO50LVm+N0zaP76eWrPVVlsHVKR8GjuhQ7
lS8FyFPkQT1NBdKzO69ISKQ5MZ2l0MEeyLHKj1BzLrgkYW2ms/ZIUj+yXU7Y6M392oXM1YGfyWregF
2zKL/gbRXqQg3Uk9DtmOsGv5PoLxpG6Us2YfHgUeDqr5qsgnMqzGj0EaFalE43rD1HbRCCWSSq0P+x
9XlJPCKei1PPDGsGkXwiBDiJuexK8ji/K5z5nmgQeE/GTIhFka/2EiUnNLJ1vOCWcH7Xq9ka6nV6EN
0EEpvxZ7Ch7F0mYXW1D79zLTcvzPjMtvIH2O7gXFQL13wlRnTt5wKT63eEscSZjXGa6ajEnPQcXuCz
Xr1LSsCuxzYp2UXMJppilxMmI07Erw28ybJa3I5QTCHjHXAYPGFjwm2nh6bAI/TRLQwamgSsdXBhw2
XJ+TWSj9Rsn7VCtavjW3u6KKFBINjSA+P7udJq93y5YDMD8mvOmsql0l8V6HyhxLKK4HYOOXz/Fz84
IZoifgvZLmgRRW0oofBZ1zCs0ERxtwypMq4kIGwErr8YGJ/fykWu15YIR/kYb/9ObyXrw80fJtGB5b
hv1T5KHSV7TJiQAqQplepsHkjTQNC6/yzGjhxWsRSGcNXLxYHH6Mnhzdzxl24FjLUCi6Q4Nhp0HfW+
QT178iwrc5arogEYWZI0oDFGHIwfLhUNjrzB6Udu0xN6mHLoshyZuqrAYjGmVZVkOmjZprLghuGprk
oKU5RzKMI6GwkBO6py7w6OkRrSqMeO3qpz6U/rbnhtSATBKaVicGpIUbM5efdbKZ8bIkct3t/WHjNr
35j7kLuLk2jBESIGCfd/lberJaoJfn8gprlxmsc/ppADbT/mAr03NygPKAuuNZVZaiHYhgTi0uHbGp
573L9RPQqrJBs1NPZTVOiXVp1+iX0zoqvDg3hUOFZSTTVXVFhZVJ3jLI1XY3CagrnX6n542xjfUrE4
6/PxDAbwc8D+jmRv5H/snLrBXTbRPTGR7XY61UGLDy850dFwqYMkf5bPu3rzicopu5fE2VBOEOLGCo
g/okmP7DNeqCvHHBV84aoNzQfap94iChtHB9s3vhGnSelQSb5bC9KV8cZE3q9FTc/NkeWwbF2TlMUi
+hdl5RAs67eEJ8TpckK5xds5nN4XwFYh+hm/5Z9KqpWx4u3mR+LTk0W1zhfd9GBc+Zt9O9Lfb8p45g
CMJ0pdKGEMy/44aY1Y2cq7AXC5SPH+ie+iAzs/keOvBbjbniJK4Uf+PMQJq0KMjzLyw0KXYS6RzinW
n91rMuBMWam1FHtcPdLeXFw1NX68NtUfiB48keI1tBgo="""

# Sample RSA Private Key
LARGE_SECRET = u"""-----BEGIN RSA PRIVATE KEY-----
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
        self.cc_obj = code_crypt.CodeCrypt(
            kms_key_id=KMS_KEY_ID,
            app_root=APP_ROOT,
            env=ENV,
            ciphertext_ext=EXT)

        self.expected_public_key_file = os.path.join(
            APP_ROOT, DATA_DIR, 'keys', ENV, 'public_key.asc')

        self.expected_private_key_file = os.path.join(
            APP_ROOT, DATA_DIR, 'keys', ENV, 'encrypted_private_key.pem')

    def test_generate_key_pair_with_missing_private_key(self):
        with open(self.expected_public_key_file, 'wb') as f:
            f.write(b'')

        self.assertRaises(
            errors.CodeCryptError,
            lambda: self.cc_obj.generate_key_pair())

    def test_generate_key_pair_with_missing_public_key_only(self):
        with open(self.expected_private_key_file, 'wb') as f:
            f.write(b'')

        self.assertRaises(
            errors.CodeCryptError,
            lambda: self.cc_obj.generate_key_pair())

    # TODO: mock and test for write out of keys instead of exiting
    @mock.patch("boto3.client")
    def test_generate_key_pair_with_no_existing_keys(
            self, mock_client):
        mock_client.return_value = mock.MagicMock()

        self.cc_obj = code_crypt.CodeCrypt(
            kms_key_id=KMS_KEY_ID,
            app_root=APP_ROOT,
            env=ENV,
            ciphertext_ext=EXT)

        self.cc_obj.kms.encrypt.return_value = {
                'CiphertextBlob': TEST_PLAINTEXT_PRIVATE_KEY}

        self.cc_obj.generate_key_pair()

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
        shutil.rmtree(APP_ROOT)


class TestImportSecrets(unittest.TestCase):

    def setUp(self):
        self.cc_obj = code_crypt.CodeCrypt(
            kms_key_id=KMS_KEY_ID,
            app_root=APP_ROOT,
            env=ENV,
            ciphertext_ext=EXT)

    def test_import_secrets_with_invalid_secrets_json(self):
        self.assertRaises(
            errors.InputError,
            lambda: self.cc_obj.import_secrets(
                '{foo=bar}', TEST_PUBLIC_KEY))

    def test_import_secrets_with_valid_data(self):
        self.cc_obj.import_secrets(TEST_VALID_JSON, TEST_PUBLIC_KEY)

        decrypted_result = self.cc_obj.decrypt(
            'SECRET_NAME_A', plaintext_private_key=TEST_PLAINTEXT_PRIVATE_KEY)
        self.assertEqual(decrypted_result, 'AAA')

        decrypted_result = self.cc_obj.decrypt(
            'SECRET_NAME_B', plaintext_private_key=TEST_PLAINTEXT_PRIVATE_KEY)
        self.assertEqual(decrypted_result, 'BBB')

    def tearDown(self):
        shutil.rmtree(APP_ROOT)


class TestDecrypt(unittest.TestCase):

    def setUp(self):
        self.cc_obj = code_crypt.CodeCrypt(
            kms_key_id=KMS_KEY_ID,
            app_root=APP_ROOT,
            env=ENV,
            ciphertext_ext=EXT)

    def test_decrypt_with_missing_private_key_file(self):
        self.assertRaises(errors.InputError, lambda: self.cc_obj.decrypt('FOO'))

    def test_decrypt_with_malformed_private_key(self):
        self.assertRaises(
            errors.DecryptorError,
            lambda: self.cc_obj.decrypt('FOO', 'bar'))

    def test_decrypt_with_missing_secret(self):
        decrypted_result = self.cc_obj.decrypt(
            'FOO', plaintext_private_key=TEST_PLAINTEXT_PRIVATE_KEY)
        self.assertIsNone(decrypted_result)

    def test_decrypt_secret_with_plaintext_private_key(self):
        self.cc_obj.encrypt('SECRET_NAME_CCC', 'CCC', TEST_PUBLIC_KEY)

        decrypted_result = self.cc_obj.decrypt(
            'SECRET_NAME_CCC',
            plaintext_private_key=TEST_PLAINTEXT_PRIVATE_KEY)
        self.assertEqual(decrypted_result, 'CCC')

    def test_decrypt_secret_with_invalid_kms_context(self):
        self.assertRaises(
            errors.KmsError,
            lambda: self.cc_obj.decrypt(
                encrypted_private_key=TEST_ENCRYPTED_PRIVATE_KEY))

    def test_decrypt_secret_with_missing_kms_key(self):
        self.assertRaises(
            errors.InputError,
            lambda: self.cc_obj.decrypt('FOO'))

    def test_decrypt_all_with_no_secrets(self):
        decrypted_result = self.cc_obj.decrypt(plaintext_private_key=TEST_PLAINTEXT_PRIVATE_KEY)
        self.assertEquals(decrypted_result, {})

    @mock.patch("boto3.client")
    def test_decrypt_secret_with_kms(self, mock_client):
        secret = 'DDD'
        self.cc_obj.encrypt('SECRET_NAME_DDD', secret, TEST_PUBLIC_KEY)
        mock_client.return_value = mock.MagicMock()

        self.cc_obj = code_crypt.CodeCrypt(
            kms_key_id=KMS_KEY_ID,
            app_root=APP_ROOT,
            env=ENV,
            ciphertext_ext=EXT)

        self.cc_obj.kms.decrypt.return_value = {
            'Plaintext': TEST_PLAINTEXT_PRIVATE_KEY}
        decrypted_result = self.cc_obj.decrypt(
            'SECRET_NAME_DDD',
            encrypted_private_key=TEST_ENCRYPTED_PRIVATE_KEY)

        mock_client.assert_called_with('kms', region_name='us-east-1')

        self.assertEqual(decrypted_result, secret)

    @mock.patch("boto3.client")
    def test_decrypt_large_secret_with_kms(self, mock_client):
        self.cc_obj.encrypt('SECRET_NAME_DDD', LARGE_SECRET, TEST_PUBLIC_KEY)
        mock_client.return_value = mock.MagicMock()

        self.cc_obj = code_crypt.CodeCrypt(
            kms_key_id=KMS_KEY_ID,
            app_root=APP_ROOT,
            env=ENV,
            ciphertext_ext=EXT)

        self.cc_obj.kms.decrypt.return_value = {
            'Plaintext': TEST_PLAINTEXT_PRIVATE_KEY}
        decrypted_result = self.cc_obj.decrypt(
            'SECRET_NAME_DDD',
            encrypted_private_key=TEST_ENCRYPTED_PRIVATE_KEY)

        mock_client.assert_called_with('kms', region_name='us-east-1')

        self.assertEqual(decrypted_result, LARGE_SECRET)

    @mock.patch("boto3.client")
    def test_decrypt_explicit_all_with_kms(self, mock_client):
        secret_one = 'one'
        secret_two = 'two'
        self.cc_obj.encrypt(
            'SECRET_NAME_1', secret_one, public_key=TEST_PUBLIC_KEY)
        self.cc_obj.encrypt(
            'SECRET_NAME_2', secret_two, public_key=TEST_PUBLIC_KEY)
        mock_client.return_value = mock.MagicMock()

        self.cc_obj = code_crypt.CodeCrypt(
            kms_key_id=KMS_KEY_ID,
            app_root=APP_ROOT,
            env=ENV,
            ciphertext_ext=EXT)

        self.cc_obj.kms.decrypt.return_value = {
            'Plaintext': TEST_PLAINTEXT_PRIVATE_KEY}
        decrypted_result = self.cc_obj.decrypt(
            encrypted_private_key=TEST_ENCRYPTED_PRIVATE_KEY)

        mock_client.assert_called_with('kms', region_name='us-east-1')

        self.assertEqual(decrypted_result['SECRET_NAME_1'], secret_one)
        self.assertEqual(decrypted_result['SECRET_NAME_2'], secret_two)

    @mock.patch("boto3.client")
    def test_decrypt_all_with_kms(self, mock_client):
        secret_one = 'one'
        secret_two = 'two'
        self.cc_obj.encrypt(
            'SECRET_NAME_1', secret_one, public_key=TEST_PUBLIC_KEY)
        self.cc_obj.encrypt(
            'SECRET_NAME_2', secret_two, public_key=TEST_PUBLIC_KEY)
        mock_client.return_value = mock.MagicMock()

        self.cc_obj = code_crypt.CodeCrypt(
            kms_key_id=KMS_KEY_ID,
            app_root=APP_ROOT,
            env=ENV,
            ciphertext_ext=EXT)

        self.cc_obj.kms.decrypt.return_value = {
            'Plaintext': TEST_PLAINTEXT_PRIVATE_KEY}
        decrypted_result = self.cc_obj.decrypt(
            plaintext_private_key=TEST_PLAINTEXT_PRIVATE_KEY)

        mock_client.assert_called_with('kms', region_name='us-east-1')

        self.assertEqual(decrypted_result['SECRET_NAME_1'], secret_one)
        self.assertEqual(decrypted_result['SECRET_NAME_2'], secret_two)

    def tearDown(self):
        shutil.rmtree(APP_ROOT)


class TestEncrypt(unittest.TestCase):

    def setUp(self):
        self.cc_obj = code_crypt.CodeCrypt(
            kms_key_id=KMS_KEY_ID,
            app_root=APP_ROOT,
            env=ENV,
            ciphertext_ext=EXT)

    def test_encrypt_with_missing_public_key(self):
        self.assertRaises(
            errors.InputError,
            lambda: self.cc_obj.encrypt('FOO', 'BAR'))

    def test_encrypt_with_malformed_public_key(self):
        self.assertRaises(
            errors.EncryptorError,
            lambda: self.cc_obj.encrypt('FOO', 'BAR', 'SOME_BAD_KEY'))

    def test_encrypt_with_zero_length_secret_name(self):
        secret_name = ''
        secret = 'AAA'
        self.assertRaises(
            errors.InputError,
            lambda: self.cc_obj.encrypt(
                secret_name, secret, public_key=TEST_PUBLIC_KEY))

    def test_encrypt_with_non_ascii_secret_name(self):
        secret_name = u'试'
        secret = 'AAA'
        self.assertRaises(
            errors.InputError,
            lambda: self.cc_obj.encrypt(
                secret_name, secret, public_key=TEST_PUBLIC_KEY))

    def test_encrypt_on_new_secret(self):
        secret_name = 'NEW_SECRET'
        secret = 'AAA'
        self.cc_obj.encrypt(secret_name, secret, public_key=TEST_PUBLIC_KEY)

        decrypted_result = self.cc_obj.decrypt(
            secret_name, plaintext_private_key=TEST_PLAINTEXT_PRIVATE_KEY)

        self.assertEquals(decrypted_result, secret)

    def test_encrypt_on_existing_secret(self):
        secret_name = 'EXISTING_SECRET'
        secret = 'AAA'
        new_secret = 'BBB'
        self.cc_obj.encrypt(secret_name, secret, public_key=TEST_PUBLIC_KEY)

        self.cc_obj.encrypt(secret_name, new_secret, public_key=TEST_PUBLIC_KEY)

        decrypted_result = self.cc_obj.decrypt(
            secret_name, plaintext_private_key=TEST_PLAINTEXT_PRIVATE_KEY)

        self.assertEquals(decrypted_result, new_secret)

    def tearDown(self):
        shutil.rmtree(APP_ROOT)


if __name__ == '__main__':
    unittest.main()
