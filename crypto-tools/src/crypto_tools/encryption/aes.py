"""
AES (Advanced Encryption Standard) Implementation

Provides symmetric encryption using AES algorithm with CBC mode and PKCS7 padding.

Example:
    >>> cipher = AES(key="my_secret_key")
    >>> encrypted = cipher.encrypt("Sensitive data")
    >>> decrypted = cipher.decrypt(encrypted)
"""

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from exceptions import EncryptionError, DecryptionError

class AES:
    """
    AES encryption/decryption using CBC mode with PKCS7 padding.
    
    Args:
        key (str/bytes): Encryption key (16, 24, or 32 bytes for AES-128, AES-192, AES-256)
        iv (bytes, optional): Initialization vector (16 bytes). Randomly generated if None.
    """
    
    def __init__(self, key, iv=None):
        try:
            if isinstance(key, str):
                key = key.encode('utf-8')
            
            if len(key) not in (16, 24, 32):
                raise ValueError("Key must be 16, 24, or 32 bytes long")
            
            self.key = key
            self.iv = iv if iv is not None else self._generate_iv()
            self.backend = default_backend()
            
        except Exception as e:
            raise EncryptionError(f"AES initialization failed: {str(e)}")

    def _generate_iv(self):
        """Generate a random initialization vector"""
        from random.secure_random import secure_random_bytes
        return secure_random_bytes(16)

    def encrypt(self, plaintext):
        """
        Encrypt plaintext using AES-CBC with PKCS7 padding.
        
        Args:
            plaintext (str/bytes): Data to encrypt
            
        Returns:
            bytes: Encrypted data (IV + ciphertext) as base64 encoded bytes
        """
        try:
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
                
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(self.iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Return IV + ciphertext as base64
            return base64.b64encode(self.iv + ciphertext)
            
        except Exception as e:
            raise EncryptionError(f"AES encryption failed: {str(e)}")

    def decrypt(self, ciphertext):
        """
        Decrypt AES-CBC encrypted data with PKCS7 padding.
        
        Args:
            ciphertext (bytes): Encrypted data (base64 encoded IV + ciphertext)
            
        Returns:
            str: Decrypted plaintext as UTF-8 string
        """
        try:
            # Decode base64 and split IV from ciphertext
            decoded = base64.b64decode(ciphertext)
            iv = decoded[:16]
            actual_ciphertext = decoded[16:]
            
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise DecryptionError(f"AES decryption failed: {str(e)}")