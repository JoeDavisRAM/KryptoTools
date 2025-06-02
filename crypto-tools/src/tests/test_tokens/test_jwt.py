"""
JWT Token Tests
"""

import time
import pytest
from crypto_tools.tokens.jwt import create_jwt, verify_jwt

class TestJWT:
    def test_token_creation_verification(self):
        payload = {"user_id": 123, "role": "admin"}
        secret = "my_secret_key"
        token = create_jwt(payload, secret)
        verified = verify_jwt(token, secret)
        
        assert verified["user_id"] == 123
        assert verified["role"] == "admin"

    def test_expired_token(self):
        payload = {"user_id": 123}
        secret = "my_secret_key"
        token = create_jwt(payload, secret, expires_in=1)  # 1 second expiration
        
        time.sleep(2)  # Wait for token to expire
        
        with pytest.raises(Exception):
            verify_jwt(token, secret)

    def test_invalid_signature(self):
        payload = {"user_id": 123}
        token = create_jwt(payload, "correct_key")
        
        with pytest.raises(Exception):
            verify_jwt(token, "wrong_key")

    def test_tampered_token(self):
        payload = {"user_id": 123}
        secret = "my_secret_key"
        token = create_jwt(payload, secret)
        
        # Tamper with the token
        parts = token.split('.')
        tampered = f"{parts[0]}.{parts[1]}.tampered_signature"
        
        with pytest.raises(Exception):
            verify_jwt(tampered, secret)