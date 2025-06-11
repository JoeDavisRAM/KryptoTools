from crypto_tools.tokens import generate_oauth_token

# Генерация OAuth-токена
oauth_token = generate_oauth_token(
    token_length=40,
    expires_in=7200,  # 2 часа
    prefix="myapp_"
)

print("OAuth Token:")
print(f"Access Token: {oauth_token['access_token']}")
print(f"Expires At: {oauth_token['expires_at']}")
print(f"Token Type: {oauth_token['token_type']}")