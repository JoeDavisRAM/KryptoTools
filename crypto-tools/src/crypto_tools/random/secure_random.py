"""
Secure Random Generator

Provides cryptographically secure random number generation.

Example:
    >>> random_bytes = secure_random_bytes(32)
"""

import os
from exceptions import RandomError

def secure_random_bytes(length):
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length (int): Number of bytes to generate
        
    Returns:
        bytes: Random bytes
    """
    try:
        return os.urandom(length)
    except Exception as e:
        raise RandomError(f"Secure random generation failed: {str(e)}")