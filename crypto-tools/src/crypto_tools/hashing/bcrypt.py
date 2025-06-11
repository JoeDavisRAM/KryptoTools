"""
Bcrypt Password Hashing

Provides secure password hashing and verification using bcrypt.

Example:
    >>> hashed = bcrypt_hash("my_password")
    >>> verified = bcrypt_verify("my_password", hashed)
"""

import bcrypt
from ..exceptions import HashError

def bcrypt_hash(password, rounds=12):
    """
    Hash a password using bcrypt.
    
    Args:
        password (str): Password to hash
        rounds (int): Work factor (4-31, default 12)
        
    Returns:
        str: Hashed password
    """
    try:
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(password, salt).decode('utf-8')
        
    except Exception as e:
        raise HashError(f"Bcrypt hashing failed: {str(e)}")

def bcrypt_verify(password, hashed_password):
    """
    Verify a password against a bcrypt hash.
    
    Args:
        password (str): Password to verify
        hashed_password (str): Bcrypt hash to compare against
        
    Returns:
        bool: True if password matches hash
    """
    try:
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')
            
        return bcrypt.checkpw(password, hashed_password)
        
    except Exception as e:
        raise HashError(f"Bcrypt verification failed: {str(e)}")