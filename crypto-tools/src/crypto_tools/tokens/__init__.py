"""
Tokens Module

Provides token generation and validation.

Available modules:
- jwt: JSON Web Token implementation
- oauth: OAuth utilities
"""

from .tokens import generate_oauth_token

__all__ = ['generate_oauth_token']
