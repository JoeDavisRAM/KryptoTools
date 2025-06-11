"""
ECC Encryption Tests
"""

import pytest
from crypto_tools.encryption.ecc import ECC

class TestECC:
    def test_key_generation(self):
        ecc = ECC()
        private_key, public_key = ecc.generate_key_pair()
        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)
        assert b"PRIVATE KEY" in private_key
        assert b"PUBLIC KEY" in public_key

    def test_signature_verification(self):
        ecc = ECC()
        private_key, public_key = ecc.generate_key_pair()
        message = "Important message"
        signature = ecc.sign(message, private_key)
        assert ecc.verify(message, signature, public_key)

    def test_invalid_signature(self):
        ecc = ECC()
        private_key, public_key = ecc.generate_key_pair()
        message = "Important message"
        signature = ecc.sign(message, private_key)
        assert not ecc.verify("Tampered message", signature, public_key)

    def test_shared_key(self):
        ecc = ECC()
        priv1, pub1 = ecc.generate_key_pair()
        priv2, pub2 = ecc.generate_key_pair()
        
        shared1 = ecc.derive_shared_key(priv1, pub2)
        shared2 = ecc.derive_shared_key(priv2, pub1)
        
        assert shared1 == shared2
        assert len(shared1) == 32  # Should be 256-bit key