"""
OAuth Utilities

Provides OAuth 2.0 client implementation.

Example:
    >>> oauth = OAuthClient(client_id, client_secret, redirect_uri)
    >>> auth_url = oauth.get_authorization_url()
    >>> token = oauth.get_access_token(authorization_code)
"""

import secrets
import string
from datetime import datetime, timedelta

def generate_oauth_token(
    token_length: int = 32,
    expires_in: int = 3600,
    prefix: str = "oauth_"
) -> dict:
    """
    Генерирует случайный OAuth-токен.
    
    Args:
        token_length (int): Длина токена (по умолчанию 32 символа).
        expires_in (int): Время жизни токена в секундах (по умолчанию 1 час).
        prefix (str): Префикс токена (по умолчанию "oauth_").
    
    Returns:
        dict: Словарь с токеном и его метаданными.
            {
                "access_token": str,
                "token_type": "Bearer",
                "expires_in": int,
                "expires_at": str (ISO-формат времени)
            }
    """
    # Генерация случайной строки
    alphabet = string.ascii_letters + string.digits
    token = prefix + ''.join(secrets.choice(alphabet) for _ in range(token_length))
    
    # Расчет времени истечения
    expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
    
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "expires_at": expires_at.isoformat()
    }