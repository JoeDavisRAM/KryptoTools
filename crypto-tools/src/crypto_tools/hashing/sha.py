"""
SHA Hash Functions

Provides SHA-256 and SHA-512 cryptographic hash functions.

Example:
    >>> hash_value = sha256("data to hash")
    >>> hash_value = sha512("data to hash", salt="random_salt")
"""

import hashlib
from ..exceptions import HashError

def sha256(data, salt=None):
    """
    Generate SHA-256 hash of input data.
    
    Args:
        data (str/bytes): Data to hash
        salt (str/bytes, optional): Optional salt to prepend to data
        
    Returns:
        str: Hexadecimal string representation of the hash
    """
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if salt is not None:
            if isinstance(salt, str):
                salt = salt.encode('utf-8')
            data = salt + data
            
        return hashlib.sha256(data).hexdigest()
        
    except Exception as e:
        raise HashError(f"SHA-256 hashing failed: {str(e)}")

def sha512(data, salt=None):
    """
    Generate SHA-512 hash of input data.
    
    Args:
        data (str/bytes): Data to hash
        salt (str/bytes, optional): Optional salt to prepend to data
        
    Returns:
        str: Hexadecimal string representation of the hash
    """
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if salt is not None:
            if isinstance(salt, str):
                salt = salt.encode('utf-8')
            data = salt + data
            
        return hashlib.sha512(data).hexdigest()
        
    except Exception as e:
        raise HashError(f"SHA-512 hashing failed: {str(e)}")