"""
Token Demo

Demonstrates JWT token creation and verification.
"""

import time
from crypto_tools.tokens import create_jwt, verify_jwt

def main():
    print("=== JWT Token Demo ===")
    
    # Create a token
    secret = "my_super_secret_key"
    payload = {
        "user_id": 12345,
        "username": "johndoe",
        "role": "admin"
    }
    
    print("\nCreating JWT token...")
    token = create_jwt(payload, secret, expires_in=30)  # Expires in 30 seconds
    print(f"Token: {token}")
    
    # Verify the token
    print("\nVerifying token...")
    verified = verify_jwt(token, secret)
    print(f"Verified payload: {verified}")
    
    # Try with wrong secret
    print("\nTrying with wrong secret...")
    try:
        verify_jwt(token, "wrong_secret")
    except Exception as e:
        print(f"Error: {e}")
    
    # Wait for token to expire
    print("\nWaiting for token to expire...")
    time.sleep(35)
    
    try:
        verify_jwt(token, secret)
    except Exception as e:
        print(f"Error (expired token): {e}")

if __name__ == "__main__":
    main()