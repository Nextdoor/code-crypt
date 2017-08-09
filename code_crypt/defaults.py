import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


AWS_REGION = u'us-east-1'
APP_ROOT = os.getenv(u'APP_ROOT', os.getcwd())
DATA_DIR = u'code_crypt/data'
DEFAULT_ENV = u'development'
ENV_TAGS = [DEFAULT_ENV, u'staging', u'production']
ENV_MAP = {u'dev': u'development', u'stag': u'staging', u'prod': u'production'}
RSA_KEY_SIZE = 2048
CIPHERTEXT_EXT = u'.bin'

RSA_PADDING = padding.OAEP(
  mgf=padding.MGF1(algorithm=hashes.SHA1()),
  algorithm=hashes.SHA1(),
  label=None)
