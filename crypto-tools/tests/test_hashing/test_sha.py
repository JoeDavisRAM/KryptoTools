"""
SHA Hashing Tests
"""

from crypto_tools.hashing import sha256, sha512

class TestSHA:
    def test_sha256_consistency(self):
        data = "test data"
        hash1 = sha256(data)
        hash2 = sha256(data)
        assert hash1 == hash2
        assert len(hash1) == 64  # 256 bits = 64 hex chars

    def test_sha256_with_salt(self):
        data = "test data"
        salt = "random salt"
        hash1 = sha256(data, salt)
        hash2 = sha256(data, salt)
        hash3 = sha256(data)
        assert hash1 == hash2
        assert hash1 != hash3

    def test_sha512_consistency(self):
        data = "test data"
        hash1 = sha512(data)
        hash2 = sha512(data)
        assert hash1 == hash2
        assert len(hash1) == 128  # 512 bits = 128 hex chars

    def test_sha512_with_salt(self):
        data = "test data"
        salt = "random salt"
        hash1 = sha512(data, salt)
        hash2 = sha512(data, salt)
        hash3 = sha512(data)
        assert hash1 == hash2
        assert hash1 != hash3