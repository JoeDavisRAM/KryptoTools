"""
Crypto-Tools Exceptions

Custom exceptions for the crypto-tools package.
"""

class CryptoError(Exception):
    """Base class for all crypto-tools exceptions"""
    pass

class EncryptionError(CryptoError):
    """Error during encryption operations"""
    pass

class DecryptionError(CryptoError):
    """Error during decryption operations"""
    pass

class HashError(CryptoError):
    """Error during hashing operations"""
    pass

class KeyError(CryptoError):
    """Error related to cryptographic keys"""
    pass

class RandomError(CryptoError):
    """Error during random number generation"""
    pass

class InvalidTokenError(CryptoError):
    """Error when validating tokens"""
    pass