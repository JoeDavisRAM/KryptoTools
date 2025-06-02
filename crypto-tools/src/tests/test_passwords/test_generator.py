"""
Password Generator Tests
"""

import pytest
import string
from crypto_tools.passwords.generator import generate_password

class TestPasswordGenerator:
    def test_default_length(self):
        password = generate_password()
        assert len(password) == 12

    def test_custom_length(self):
        password = generate_password(length=16)
        assert len(password) == 16

    def test_character_types(self):
        password = generate_password(use_special_chars=True)
        
        # Check for at least one lowercase, uppercase, digit, and special char
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        assert has_lower
        assert has_upper
        assert has_digit
        assert has_special

    def test_no_special_chars(self):
        password = generate_password(use_special_chars=False)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        assert not has_special

    def test_minimum_length(self):
        with pytest.raises(ValueError):
            generate_password(length=7)