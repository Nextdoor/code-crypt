
class ZuulError(Exception):
    '''Base Exception for Zuul Alpha'''
    def __init__(self, message=""):
        if message is not "":
            self.message = "%s: %s" % (self.__class__.__name__, message)
        else:
            self.message = self.__class__.__name__


class EncryptorError(ZuulError):
    '''Error creating RSA encryptor'''
    pass


class DecryptorError(ZuulError):
    '''Error creating RSA decryptor'''
    pass


class InputError(ZuulError):
    '''Error with inputs into the Zuul object'''
    pass


class KmsError(ZuulError):
    '''Error with using an AWS KMS operation'''
    pass
