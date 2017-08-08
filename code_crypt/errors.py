
class CodeCryptError(Exception):
    '''Base Exception for Code Crypt'''
    def __init__(self, message=""):
        if message is not "":
            self.message = "%s: %s" % (self.__class__.__name__, message)
        else:
            self.message = self.__class__.__name__


class EncryptorError(CodeCryptError):
    '''Error creating RSA encryptor'''
    pass


class DecryptorError(CodeCryptError):
    '''Error creating RSA decryptor'''
    pass


class InputError(CodeCryptError):
    '''Error with inputs into the CodeCrypt object'''
    pass


class KmsError(CodeCryptError):
    '''Error with using an AWS KMS operation'''
    pass
