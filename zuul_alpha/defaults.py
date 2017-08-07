import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

AWS_REGION = 'us-east-1'
APP_ROOT = os.getenv('APP_ROOT', os.getcwd())
DATA_DIR = 'zuul_data'
DEFAULT_ENV = 'development'
ENV_TAGS = [DEFAULT_ENV, 'staging', 'production']
RSA_KEY_SIZE = 2048
CIPHERTEXT_EXT = '.bin'

RSA_PADDING = padding.OAEP(
  mgf=padding.MGF1(algorithm=hashes.SHA1()),
  algorithm=hashes.SHA1(),
  label=None)
