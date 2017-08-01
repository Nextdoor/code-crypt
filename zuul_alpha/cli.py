#!/usr/bin/env python

import argparse
import json
import logging
import sys

from zuul_alpha import core as zuul_alpha
from zuul_alpha import defaults
from zuul_alpha import errors
from zuul_alpha.metadata import __version__


def get_config(argv):
    parser = argparse.ArgumentParser(
        prog=argv[0],
        description='Zuul Alpha')

    parser.add_argument(
        "--kms-key-id",
        help="the KMS key id of the master key.")
    parser.add_argument(
        "--env",
        help="the environment context for secrets from %s "
        "Defaults to '%s'" % (str(defaults.ENV_TAGS), defaults.DEFAULT_ENV),
        default=defaults.DEFAULT_ENV)

    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument(
        "--init",
        help="initializes the repo with an asymmetric RSA key pair "
        "('%s' is the default env)" % defaults.DEFAULT_ENV,
        action="store_true")
    action_group.add_argument(
        "--decrypt",
        help="decrypt and print a single secret")
    action_group.add_argument(
        "--decrypt-all",
        help="decrypt and print all secrets",
        action="store_true")
    action_group.add_argument(
        "--import-secrets",
        help="imports and encrypts secrets from a json file")
    action_group.add_argument(
        "--encrypt",
        help="encrypts single secret (usage: KEY=value)")
    action_group.add_argument(
        "-v",
        "--version",
        help="prints version",
        action="store_true")

    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        "--verbose",
        help="increase output verbosity",
        action="store_true")
    log_group.add_argument(
        "--debug",
        help="enable full debug mode",
        action="store_true")
    log_group.add_argument(
        "--quiet",
        help="enable quiet mode, no logs will be outputted",
        action="store_true")

    args = parser.parse_args(args=argv[1:])
    return args


def main():
    config = get_config(sys.argv)
    if config.debug:
        logging.basicConfig(level=logging.DEBUG)
    elif config.verbose:
        logging.basicConfig(level=logging.INFO)
    elif config.quiet:
        logging.disable(sys.maxint)

    if config.version:
            print("Zuul Alpha - " + str(__version__))
            return

    if config.env not in defaults.ENV_TAGS:
        print("Error: env must be set to one of the following: %s" % (
            str(defaults.ENV_TAGS)))
        exit(1)
    env = config.env

    zuul = zuul_alpha.Zuul(kms_key_id=config.kms_key_id, env=env)

    try:
        if config.init:
            zuul.generate_key_pair()
            return
        if config.decrypt:
            secret = zuul.decrypt(config.decrypt)
            if secret:
                print(secret)
                return
            return
        if config.decrypt_all:
            secrets = zuul.decrypt()
            print(json.dumps(secrets, indent=2))
            return
        if config.import_secrets:
            secrets_file = config.import_secrets
            try:
                with open(secrets_file, 'r') as f:
                    secrets_json = f.read()
            except IOError as e:
                raise errors.InputError("secrets file '%s' does not exist" % (
                    secrets_file))
            zuul.import_secrets(secrets_json)
            return
        if config.encrypt:
            keyval = config.encrypt.split('=')
            zuul.encrypt(keyval[0], keyval[1])
            return

    except errors.ZuulError as e:
        print(e.message)
        exit(1)

if __name__ == '__main__':
    main()