"""
Secure Random Tests
"""

import pytest
from crypto_tools.random.secure_random import secure_random_bytes

class TestSecureRandom:
    def test_length(self):
        data = secure_random_bytes(32)
        assert len(data) == 32

    def test_randomness(self):
        # This is a probabilistic test that might very rarely fail
        data1 = secure_random_bytes(32)
        data2 = secure_random_bytes(32)
        assert data1 != data2

    def test_zero_length(self):
        data = secure_random_bytes(0)
        assert len(data) == 0

    def test_large_length(self):
        data = secure_random_bytes(1024)
        assert len(data) == 1024