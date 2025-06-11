"""
Crypto-Tools Package

A comprehensive collection of cryptographic utilities for Python.
"""

__version__ = "0.1.0"

from crypto_tools.exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    HashError,
    InvalidTokenError,
    KeyError,
    RandomError,
)

from crypto_tools.communication import secure_channel
from crypto_tools.encryption import (aes, ecc, rsa)
from crypto_tools.hashing import (bcrypt, sha)
from crypto_tools.passwords import generator
from crypto_tools.random import secure_random
from crypto_tools.tokens import(jwt_utils, oauth)

__all__ = [
    '__version__',
    'CryptoError',
    'DecryptionError',
    'EncryptionError',
    'HashError',
    'InvalidTokenError',
    'KeyError',
    'RandomError',
]