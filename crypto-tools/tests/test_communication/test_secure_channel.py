"""
Secure Channel Tests
"""

import pytest
from crypto_tools.communication.secure_channel import SecureChannel
class TestSecureChannel:
    def test_message_encryption(self):
        channel1 = SecureChannel()
        channel2 = SecureChannel()
        
        # Generate key pairs
        priv1, pub1 = channel1.rsa.generate_key_pair()
        priv2, pub2 = channel2.rsa.generate_key_pair()
        
        # Encrypt message from 1 to 2
        message = "Secret message"
        encrypted = channel1.encrypt_message(message, pub2)
        decrypted = channel2.decrypt_message(encrypted, priv2)
        
        assert decrypted == message

    def test_wrong_recipient(self):
        channel1 = SecureChannel()
        channel2 = SecureChannel()
        channel3 = SecureChannel()
        
        # Generate key pairs
        priv1, pub1 = channel1.rsa.generate_key_pair()
        priv2, pub2 = channel2.rsa.generate_key_pair()
        priv3, _ = channel3.rsa.generate_key_pair()
        
        # Encrypt message from 1 to 2
        message = "Secret message"
        encrypted = channel1.encrypt_message(message, pub2)
        
        # Try to decrypt with wrong private key
        with pytest.raises(Exception):
            channel3.decrypt_message(encrypted, priv3)

    def test_message_tampering(self):
        channel1 = SecureChannel()
        channel2 = SecureChannel()
        
        # Generate key pairs
        priv1, pub1 = channel1.rsa.generate_key_pair()
        priv2, pub2 = channel2.rsa.generate_key_pair()
        
        # Encrypt message from 1 to 2
        message = "Secret message"
        encrypted = channel1.encrypt_message(message, pub2)
        
        # Tamper with the message
        tampered = encrypted[:-10] + b'1234567890'
        
        with pytest.raises(Exception):
            channel2.decrypt_message(tampered, priv2)
