"""
Passwords Module

Provides password generation and verification utilities.

Available functions:
- generate_password: Generate secure random passwords
"""

from .generator import generate_password

__all__ = ['generate_password']