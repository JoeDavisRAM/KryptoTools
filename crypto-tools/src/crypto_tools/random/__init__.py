"""
Random Module

Provides secure random number generation.

Available functions:
- secure_random_bytes: Generate cryptographically secure random bytes
"""

from .secure_random import secure_random_bytes

__all__ = ['secure_random_bytes']