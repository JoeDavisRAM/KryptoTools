"""
Bcrypt Hashing Tests
"""

import pytest
from crypto_tools.hashing.bcrypt import bcrypt_hash, bcrypt_verify

class TestBcrypt:
    def test_hash_verify(self):
        password = "secure_password123"
        hashed = bcrypt_hash(password)
        assert bcrypt_verify(password, hashed)

    def test_wrong_password(self):
        password = "secure_password123"
        wrong_password = "wrong_password"
        hashed = bcrypt_hash(password)
        assert not bcrypt_verify(wrong_password, hashed)

    def test_different_hashes(self):
        password = "secure_password123"
        hash1 = bcrypt_hash(password)
        hash2 = bcrypt_hash(password)
        assert hash1 != hash2  # Different salts should produce different hashes
        assert bcrypt_verify(password, hash1)
        assert bcrypt_verify(password, hash2)

    def test_work_factor(self):
        password = "secure_password123"
        fast_hash = bcrypt_hash(password, rounds=4)
        slow_hash = bcrypt_hash(password, rounds=12)
        assert bcrypt_verify(password, fast_hash)
        assert bcrypt_verify(password, slow_hash)