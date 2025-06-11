from crypto_tools.tokens import create_jwt_token
from datetime import timedelta

def main():
    user_data = {
        "user_id": 123,
        "username": "john_doe",
        "role": "admin"
    }
    
    token_custom = create_jwt_token(user_data, expires_delta=timedelta(hours=1))
    print("\nТокен (1 hour):", token_custom)

if __name__ == "__main__":
    main()