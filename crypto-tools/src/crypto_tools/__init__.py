"""
Crypto-Tools Package

A comprehensive collection of cryptographic utilities for Python.

Subpackages:
- encryption: Symmetric and asymmetric encryption algorithms
- hashing: Cryptographic hash functions
- random: Secure random number generation
- passwords: Password generation and verification
- communication: Secure communication protocols
- tokens: Token generation and validation
"""

__version__ = "0.1.0"

from .exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    HashError,
    InvalidTokenError,
    KeyError,
    RandomError,
)

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