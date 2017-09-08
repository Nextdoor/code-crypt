[![CircleCI](https://circleci.com/gh/Nextdoor/code-crypt.svg)](https://circleci.com/gh/Nextdoor/code-crypt)

# Code Crypt

Code Crypt provides a simple Python library and command line interface to 
manage your application secrets within a project repository. Master keys are
managed externally by the AWS Key Management Service (KMS), which perform 
envelope encryption on a RSA private key used for decrypts on individual
secrets within a particular environment context. Encrypted secrets are kept 
as binary files within the project folder using hybrid RSA-AES cryptopgraphy.

It supports Python 2.6 or newer and all Python 3 versions.

## Features

- Self-serve for project contributors
- Scalable for a large amount of secrets (1 KMS API call to decrypt all secrets)
- CRUD operations on a per-secret basis
- Environment contexts (development, staging, production)

## Initialize Project

We have a project `my_project` that we'd like to initialize with 3 different 
environment contexts (`development`, `staging` and `production`) with their own 
KMS master keys.

    $ APP_ROOT=/Users/bob/my_project code-crypt --env development --init --kms-key-id aaaaaaaa-bbbb-cccc-dddd-123456111111
    $ APP_ROOT=/Users/bob/my_project code-crypt --env staging --init --kms-key-id eeeeeeee-ffff-gggg-hhhh-123456222222
    $ APP_ROOT=/Users/bob/my_project code-crypt --env production --init --kms-key-id iiiiiiii-jjjj-kkkk-llll-123456333333
    
This will initialize the project folder with a data directory of the following 
structure:

    $ pwd
    /Users/bob/my_project
    $ tree
    .
    └── code_crypt
        └── data
            ├── keys
            │   ├── development
            │   │   ├── encrypted_private_key.pem
            │   │   └── public_key.asc
            │   ├── production
            │   │   ├── encrypted_private_key.pem
            │   │   └── public_key.asc
            │   └── staging
            │       ├── encrypted_private_key.pem
            │       └── public_key.asc
            └── secrets
                ├── development
                ├── production
                └── staging
    
(Note: `--env` defaults to `development` and won't be explicitly used in this 
guide going forward.)

## Encrypt Secrets

Single secrets can be encrypted with `--encrypt` option.

    $ APP_ROOT=/Users/bob/my_project code-crypt --encrypt SOME_SECRET='a1b2c3'
    
In this case an encrypted binary file would be created at 
`code_crypt/data/secrets/development/SOME_SECRET.bin`.
    
## Decrypt Secrets (CLI)

Single secrets can be decrypted with `--decrypt` option which returns a 
plaintext value.

    $ APP_ROOT=/Users/bob/my_project code-crypt --decrypt SOME_SECRET
    a1b2c3
    
Multiple secrets can be decrypted with the `--decrypt-all` option which returns 
a JSON string
of key-value pairs.

    $ APP_ROOT=/Users/bob/my_project code-crypt --decrypt-all
    {
      "SOME_SECRET": "a1b2c3"
    }

## Decrypt Secrets (Application)

Prerequisite: Grant your application run-time authentication to its environment's respective 
KMS master key.

Create a Code Crypt object and run the `decrypt()` function.

    from code_crypt import core as code_crypt

    CC = code_crypt.CodeCrypt(app_root=MY_APP_ROOT, env=MY_ENV)
    CC_SECRETS = CC.decrypt()
    
The resulting `CC_SECRETS` object is a dict of decrypted secret key-value pairs.


# Developer Setup

If you are interested in working on the codebase, setting up your development
environment is quick and easy.

    $ virtualenv .venv
    $ source .venv/bin/activate
    $ pip install -r requirements.txt
