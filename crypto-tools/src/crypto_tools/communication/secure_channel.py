"""
Secure Communication Channel

Provides an encrypted communication channel using AES and RSA.

Example:
    >>> channel = SecureChannel()
    >>> encrypted = channel.encrypt_message("Hello", peer_public_key)
    >>> decrypted = channel.decrypt_message(encrypted, private_key)
"""

from ..encryption.aes import AES
from ..encryption.rsa import RSA
from ..random.secure_random import secure_random_bytes
from exceptions import CryptoError

class SecureChannel:
    """
    Secure communication channel using hybrid encryption:
    - RSA for key exchange
    - AES for message encryption
    
    Provides end-to-end encrypted messaging.
    """
    
    def __init__(self):
        self.rsa = RSA()

    def encrypt_message(self, message, peer_public_key):
        """
        Encrypt a message for secure transmission.
        
        Args:
            message (str): Message to encrypt
            peer_public_key (bytes): Recipient's RSA public key (PEM)
            
        Returns:
            bytes: Encrypted message (AES key encrypted with RSA + AES encrypted message)
        """
        try:
            # Generate a random AES key
            aes_key = secure_random_bytes(32)
            
            # Encrypt the message with AES
            aes = AES(key=aes_key)
            encrypted_message = aes.encrypt(message)
            
            # Encrypt the AES key with RSA
            encrypted_key = self.rsa.encrypt(aes_key, peer_public_key)
            
            # Combine the encrypted key and message
            return encrypted_key + b'|||' + encrypted_message
            
        except Exception as e:
            raise CryptoError(f"Message encryption failed: {str(e)}")

    def decrypt_message(self, encrypted_data, private_key):
        """
        Decrypt a received message.
        
        Args:
            encrypted_data (bytes): Encrypted data from encrypt_message
            private_key (bytes): Your RSA private key (PEM)
            
        Returns:
            str: Decrypted message
        """
        try:
            # Split the encrypted key and message
            encrypted_key, encrypted_message = encrypted_data.split(b'|||', 1)
            
            # Decrypt the AES key with RSA
            aes_key = self.rsa.decrypt(encrypted_key, private_key)
            
            # Decrypt the message with AES
            aes = AES(key=aes_key)
            return aes.decrypt(encrypted_message)
            
        except Exception as e:
            raise CryptoError(f"Message decryption failed: {str(e)}")