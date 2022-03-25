import unittest

from code_crypt import cli

KMS_KEY_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class CliTest(unittest.TestCase):
    """This is a simple sanity check that argparser is setup properly"""

    def test_get_config_init(self):

        argv = ["cli.py", "--kms-key-id", KMS_KEY_ID, "--init"]
        config = cli.get_config(argv)
        self.assertTrue(config.init)
        self.assertEqual(config.kms_key_id, KMS_KEY_ID)

    def test_get_config_encrypt(self):
        encrypt_param = "TEST=value"

        argv = ["cli.py", "--encrypt", "TEST=value"]
        config = cli.get_config(argv)
        self.assertEqual(config.encrypt, encrypt_param)
