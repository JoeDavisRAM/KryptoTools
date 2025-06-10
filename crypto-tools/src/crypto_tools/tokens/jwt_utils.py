import base64
import hmac
import hashlib
import json
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

def base64url_encode(data: bytes) -> str:
    """Кодирует данные в формат Base64URL (без padding '=')."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def create_jwt_token(data: dict, expires_delta: timedelta = None) -> str:
    """Создает JWT вручную (без PyJWT)."""
    # 1. Подготовка данных (добавляем срок действия)
    payload = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload.update({"exp": int(expire.timestamp())})

    # 2. Кодируем заголовок (header) и payload
    header = {"alg": ALGORITHM, "typ": "JWT"}
    header_encoded = base64url_encode(json.dumps(header).encode('utf-8'))
    payload_encoded = base64url_encode(json.dumps(payload).encode('utf-8'))

    # 3. Создаем подпись (signature)
    message = f"{header_encoded}.{payload_encoded}".encode('utf-8')
    signature = hmac.new(
        SECRET_KEY.encode('utf-8'),
        message,
        hashlib.sha256
    ).digest()
    signature_encoded = base64url_encode(signature)

    # 4. Собираем итоговый токен
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"