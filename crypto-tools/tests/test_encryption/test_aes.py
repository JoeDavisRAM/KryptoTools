"""
AES Encryption Tests
"""

import pytest
from crypto_tools.encryption.aes import AES

class TestAES:
    def test_encryption_decryption(self):
        cipher = AES(key="test_key_1234567890123456")
        plaintext = "Secret message"
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext

    def test_different_keys(self):
        cipher1 = AES(key="key1_123456789012345678")
        cipher2 = AES(key="key2_123456789012345678")
        plaintext = "Secret message"
        encrypted = cipher1.encrypt(plaintext)
        
        with pytest.raises(Exception):
            cipher2.decrypt(encrypted)

    def test_non_string_input(self):
        cipher = AES(key="test_key_1234567890123456")
        plaintext = b"Binary data \x00\x01\x02"
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted.encode('utf-8') == plaintext
