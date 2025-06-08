"""
Password Generator

Generate secure random passwords with customizable complexity.

Example:
    >>> password = generate_password(length=16, use_special_chars=True)
"""

import string
from ..random.secure_random import secure_random_bytes
from ..exceptions import RandomError

def generate_password(length=12, use_special_chars=True):
    """
    Generate a secure random password.
    
    Args:
        length (int): Length of password (default 12)
        use_special_chars (bool): Include special characters (default True)
        
    Returns:
        str: Generated password
    """
    try:
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
            
        chars = string.ascii_letters + string.digits
        if use_special_chars:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
        # Ensure we have at least one of each character type
        password = [
            secure_random_bytes(1)[0] % len(string.ascii_lowercase),
            secure_random_bytes(1)[0] % len(string.ascii_uppercase),
            secure_random_bytes(1)[0] % len(string.digits),
        ]
        
        if use_special_chars:
            password.append(
                secure_random_bytes(1)[0] % len("!@#$%^&*()_+-=[]{}|;:,.<>?")
            )
            
        # Fill the rest with random characters
        remaining = length - len(password)
        password.extend(
            secure_random_bytes(1)[0] % len(chars)
            for _ in range(remaining)
        )
        
        # Shuffle the characters
        password_bytes = bytes(password)
        shuffled = bytearray(password_bytes)
        
        for i in range(len(shuffled)):
            j = secure_random_bytes(1)[0] % len(shuffled)
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
            
        # Convert to characters
        password_chars = []
        for byte in shuffled:
            password_chars.append(chars[byte % len(chars)])
            
        return ''.join(password_chars)
        
    except Exception as e:
        raise RandomError(f"Password generation failed: {str(e)}")