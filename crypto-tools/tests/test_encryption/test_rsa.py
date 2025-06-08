"""
RSA Encryption Tests
"""

import pytest
from src.crypto_tools.encryption.rsa import RSA

class TestRSA:
    def test_key_generation(self):
        rsa = RSA()
        private_key, public_key = rsa.generate_key_pair()
        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)
        assert b"PRIVATE KEY" in private_key
        assert b"PUBLIC KEY" in public_key

    def test_encryption_decryption(self):
        rsa = RSA()
        private_key, public_key = rsa.generate_key_pair()
        plaintext = "Secret message"
        encrypted = rsa.encrypt(plaintext, public_key)
        decrypted = rsa.decrypt(encrypted, private_key)
        assert decrypted == plaintext

    def test_different_keys(self):
        rsa = RSA()
        priv1, pub1 = rsa.generate_key_pair()
        priv2, pub2 = rsa.generate_key_pair()
        plaintext = "Secret message"
        encrypted = rsa.encrypt(plaintext, pub1)
        
        with pytest.raises(Exception):
            rsa.decrypt(encrypted, priv2)

    def test_message_too_long(self):
        rsa = RSA()
        _, public_key = rsa.generate_key_pair(key_size=512)
        long_message = "a" * 500  # Too long for 512-bit RSA
        
        with pytest.raises(Exception):
            rsa.encrypt(long_message, public_key)