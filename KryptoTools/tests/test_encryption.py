import unittest
from my_crypto_package.keys import KeyManager
from my_crypto_package.encryption import EncryptionManager
from cryptography.hazmat.primitives import hashes 
import os

class TestEncryption(unittest.TestCase):
       def test_rsa_encryption(self):
           private_key, public_key = KeyManager.generate_rsa_keypair()
           message = b'Test message'
           ciphertext = EncryptionManager.encrypt_rsa(public_key, message)
           decrypted_message = EncryptionManager.decrypt_rsa(private_key, ciphertext)
           self.assertEqual(message, decrypted_message)

       def test_aes_encryption(self):
           key = os.urandom(32)
           plaintext = b'Test message for AES'
           ciphertext = EncryptionManager.encrypt_aes(key, plaintext)
           decrypted_message = EncryptionManager.decrypt_aes(key, ciphertext)
           self.assertEqual(plaintext, decrypted_message)

if __name__ == '__main__':
       unittest.main()