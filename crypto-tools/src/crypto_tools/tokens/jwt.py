"""
JWT (JSON Web Token) Implementation

Provides JWT creation and verification.

Example:
    >>> token = create_jwt({"user_id": 123}, "secret_key")
    >>> payload = verify_jwt(token, "secret_key")
"""

import json
import base64
import hmac
import hashlib
import time
from exceptions import InvalidTokenError

def create_jwt(payload, secret_key, algorithm='HS256', expires_in=None):
    """
    Create a JSON Web Token (JWT).
    
    Args:
        payload (dict): Data to include in the token
        secret_key (str): Secret key for signing
        algorithm (str): Hashing algorithm (default HS256)
        expires_in (int, optional): Token lifetime in seconds
        
    Returns:
        str: JWT token
    """
    try:
        # Add expiration if specified
        if expires_in is not None:
            payload['exp'] = int(time.time()) + expires_in
            
        # Create header
        header = {
            "alg": algorithm,
            "typ": "JWT"
        }
        
        # Encode header and payload
        encoded_header = base64.urlsafe_b64encode(
            json.dumps(header).encode('utf-8')
        ).decode('utf-8').rstrip('=')
        
        encoded_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode('utf-8')
        ).decode('utf-8').rstrip('=')
        
        # Create signature
        message = f"{encoded_header}.{encoded_payload}"
        
        if algorithm == 'HS256':
            signature = hmac.new(
                secret_key.encode('utf-8'),
                message.encode('utf-8'),
                hashlib.sha256
            ).digest()
        else:
            raise ValueError("Unsupported algorithm")
            
        encoded_signature = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
        
        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"
        
    except Exception as e:
        raise InvalidTokenError(f"JWT creation failed: {str(e)}")

def verify_jwt(token, secret_key):
    """
    Verify a JWT token and return its payload.
    
    Args:
        token (str): JWT token to verify
        secret_key (str): Secret key used for signing
        
    Returns:
        dict: Decoded payload
        
    Raises:
        InvalidTokenError: If token is invalid or expired
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise InvalidTokenError("Invalid token format")
            
        encoded_header, encoded_payload, encoded_signature = parts
        
        # Reconstruct message for signature verification
        message = f"{encoded_header}.{encoded_payload}"
        
        # Decode signature
        signature = base64.urlsafe_b64decode(encoded_signature + '=' * (4 - len(encoded_signature) % 4))
        
        # Verify signature
        expected_signature = hmac.new(
            secret_key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        if not hmac.compare_digest(signature, expected_signature):
            raise InvalidTokenError("Invalid signature")
            
        # Decode payload
        payload_json = base64.urlsafe_b64decode(
            encoded_payload + '=' * (4 - len(encoded_payload) % 4)
        ).decode('utf-8')
        
        payload = json.loads(payload_json)
        
        # Check expiration
        if 'exp' in payload and payload['exp'] < time.time():
            raise InvalidTokenError("Token has expired")
            
        return payload
        
    except Exception as e:
        raise InvalidTokenError(f"JWT verification failed: {str(e)}")