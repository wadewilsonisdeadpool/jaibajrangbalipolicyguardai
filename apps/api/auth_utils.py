from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

import os

import apps.api.settings  # noqa: F401  (loads .env before JWT_SECRET is read)

SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-change-me")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60 * 24  # 24h


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain_password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), password_hash.encode())


def create_access_token(user_id: int, email: str, role: str, token_version: int = 0) -> str:
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "ver": token_version,  # bumping the user's token_version revokes every existing session
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
