"""
ECC (Elliptic Curve Cryptography) Implementation

Provides ECDSA for digital signatures and ECDH for key exchange.

Example:
    >>> ecc = ECC()
    >>> private_key, public_key = ecc.generate_key_pair()
    >>> signature = ecc.sign("Message", private_key)
    >>> verified = ecc.verify("Message", signature, public_key)
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from exceptions import KeyError, CryptoError

class ECC:
    """
    Elliptic Curve Cryptography operations using SECP384R1 curve.
    
    Provides:
    - Key generation
    - ECDSA signatures
    - ECDH key exchange
    """
    
    def __init__(self, curve=ec.SECP384R1()):
        self.curve = curve
        self.backend = default_backend()

    def generate_key_pair(self):
        """
        Generate ECC key pair.
        
        Returns:
            tuple: (private_key, public_key) as PEM-encoded bytes
        """
        try:
            private_key = ec.generate_private_key(
                self.curve,
                self.backend
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
            raise KeyError(f"ECC key generation failed: {str(e)}")

    def sign(self, message, private_key):
        """
        Sign a message using ECDSA.
        
        Args:
            message (str/bytes): Message to sign
            private_key (bytes): PEM-encoded private key
            
        Returns:
            bytes: Signature
        """
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
                
            priv_key = serialization.load_pem_private_key(
                private_key,
                password=None,
                backend=self.backend
            )
            
            signature = priv_key.sign(
                message,
                ec.ECDSA(hashes.SHA256())
            )
            
            return signature
            
        except Exception as e:
            raise CryptoError(f"ECDSA signing failed: {str(e)}")

    def verify(self, message, signature, public_key):
        """
        Verify an ECDSA signature.
        
        Args:
            message (str/bytes): Original message
            signature (bytes): Signature to verify
            public_key (bytes): PEM-encoded public key
            
        Returns:
            bool: True if signature is valid
        """
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
                
            pub_key = serialization.load_pem_public_key(
                public_key,
                backend=self.backend
            )
            
            pub_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            
            return True
            
        except InvalidSignature:
            return False
        except Exception as e:
            raise CryptoError(f"ECDSA verification failed: {str(e)}")

    def derive_shared_key(self, private_key, peer_public_key):
        """
        Derive shared secret using ECDH.
        
        Args:
            private_key (bytes): Your PEM-encoded private key
            peer_public_key (bytes): Peer's PEM-encoded public key
            
        Returns:
            bytes: Shared secret key
        """
        try:
            priv_key = serialization.load_pem_private_key(
                private_key,
                password=None,
                backend=self.backend
            )
            
            peer_pub_key = serialization.load_pem_public_key(
                peer_public_key,
                backend=self.backend
            )
            
            shared_key = priv_key.exchange(ec.ECDH(), peer_pub_key)
            
            # Derive a secure key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'crypto-tools-ecdh',
                backend=self.backend
            ).derive(shared_key)
            
            return derived_key
            
        except Exception as e:
            raise CryptoError(f"ECDH key derivation failed: {str(e)}")