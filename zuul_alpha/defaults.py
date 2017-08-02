import os

AWS_REGION = 'us-east-1'
APP_ROOT = os.getenv('APP_ROOT', os.getcwd())
DEFAULT_ENV = 'development'
ENV_TAGS = [DEFAULT_ENV, 'staging', 'production']
RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 128
CIPHERTEXT_EXT = '.enc'
ZUUL_DATA_DIR = os.path.join(APP_ROOT, 'zuul_data')
