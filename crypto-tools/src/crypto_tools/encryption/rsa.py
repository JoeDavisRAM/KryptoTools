"""
RSA Implementation

Provides asymmetric encryption using RSA algorithm with OAEP padding.

Example:
    >>> rsa = RSA()
    >>> private_key, public_key = rsa.generate_key_pair()
    >>> encrypted = rsa.encrypt("Sensitive data", public_key)
    >>> decrypted = rsa.decrypt(encrypted, private_key)
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from exceptions import EncryptionError, DecryptionError, KeyError

class RSA:
    """
    RSA encryption/decryption with OAEP padding and SHA-256.
    
    Provides methods for key generation, encryption, and decryption.
    """
    
    def generate_key_pair(self, key_size=2048):
        """
        Generate RSA key pair.
        
        Args:
            key_size (int): Key size in bits (2048 or 4096 recommended)
            
        Returns:
            tuple: (private_key, public_key) as PEM-encoded bytes
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            public_key = private_key.public_key()
            
            # Serialize keys to PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return private_pem, public_pem
            
        except Exception as e:
            raise KeyError(f"RSA key generation failed: {str(e)}")

    def encrypt(self, plaintext, public_key):
        """
        Encrypt data with RSA public key using OAEP padding.
        
        Args:
            plaintext (str/bytes): Data to encrypt
            public_key (bytes): PEM-encoded public key
            
        Returns:
            bytes: Encrypted data as bytes
        """
        try:
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
                
            # Load public key
            pub_key = serialization.load_pem_public_key(
                public_key,
                backend=default_backend()
            )
            
            ciphertext = pub_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return ciphertext
            
        except Exception as e:
            raise EncryptionError(f"RSA encryption failed: {str(e)}")

    def decrypt(self, ciphertext, private_key):
        """
        Decrypt data with RSA private key using OAEP padding.
        
        Args:
            ciphertext (bytes): Data to decrypt
            private_key (bytes): PEM-encoded private key
            
        Returns:
            str: Decrypted plaintext as UTF-8 string
        """
        try:
            # Load private key
            priv_key = serialization.load_pem_private_key(
                private_key,
                password=None,
                backend=default_backend()
            )
            
            plaintext = priv_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise DecryptionError(f"RSA decryption failed: {str(e)}")