"""
Crypto-Tools Package

A comprehensive collection of cryptographic utilities for Python.
"""

__version__ = "0.1.0"

from .exceptions import (  # Используем относительный импорт
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