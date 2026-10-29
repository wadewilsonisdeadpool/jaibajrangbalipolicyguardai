from datetime import datetime

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.api import trust
from apps.api.auth_utils import create_access_token, decode_access_token, hash_password, verify_password
from apps.api.database import get_db
from apps.api.models import User

router = APIRouter(prefix="/api/auth")
bearer_scheme = HTTPBearer(auto_error=False)

VALID_ROLES = {"admin", "analyst", "approver", "viewer"}


class SignupRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


def user_payload(user: User) -> dict:
    v = trust.view(user)
    until = trust.locked_until(user)
    return {"id": user.id, "email": user.email, "role": user.role, "is_active": user.is_active,
            "trust": v.as_dict(), "flagged": bool(user.flagged),
            "suspended_until": until.isoformat() if until else None,
            "suspension_reason": user.suspension_reason if until else None}


def _suspension_error(user: User) -> HTTPException | None:
    until = trust.locked_until(user)
    if until:
        mins = max(1, int((until - datetime.utcnow()).total_seconds() // 60))
        return HTTPException(status_code=403, detail=f"Account suspended for ~{mins} more minute(s). Reason: {user.suspension_reason or 'security review'}")
    return None


def _token(user: User) -> dict:
    return {"access_token": create_access_token(user.id, user.email, user.role, user.token_version or 0),
            "token_type": "bearer", "user": user_payload(user)}


@router.post("/signup")
def signup(request: SignupRequest, db: Session = Depends(get_db)):
    email = request.email.strip().lower()
    if len(request.password) < 8:
        raise HTTPException(status_code=400, detail="A password of at least 8 characters is required.")
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email already registered.")
    user_count = db.scalar(select(func.count()).select_from(User)) or 0
    user = User(email=email, password_hash=hash_password(request.password),
                role="admin" if user_count == 0 else "viewer")
    db.add(user)
    db.commit()
    db.refresh(user)
    return _token(user)


@router.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == request.email.strip().lower()))
    if user is None or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled by an administrator.")
    err = _suspension_error(user)
    if err:
        raise err
    return _token(user)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    try:
        payload = decode_access_token(credentials.credentials)
        user_id = int(payload["sub"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token.")

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or disabled.")
    if int(payload.get("ver", 0)) != (user.token_version or 0):
        raise HTTPException(status_code=401, detail="Session revoked. Please log in again.")
    err = _suspension_error(user)
    if err:
        raise err
    return user


def require_role(*allowed_roles: str):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {', '.join(allowed_roles)}")
        return user
    return checker


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return user_payload(user)
