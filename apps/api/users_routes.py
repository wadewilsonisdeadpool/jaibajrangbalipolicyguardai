from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api import trust
from apps.api.auth_routes import VALID_ROLES, require_role, user_payload
from apps.api.database import get_db
from apps.api.models import TrustEvent, User

router = APIRouter(prefix="/api/users")


class UserUpdateRequest(BaseModel):
    role: str | None = None
    is_active: bool | None = None


class SuspendRequest(BaseModel):
    minutes: int = 60
    reason: str = "Suspended by administrator"


def _get(db: Session, user_id: int, admin: User, allow_self: bool = False) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id and not allow_self:
        raise HTTPException(status_code=400, detail="You cannot do this to your own admin account.")
    return user


def _audit(db: Session, user: User, admin: User, text: str) -> None:
    v = trust.view(user)
    db.add(TrustEvent(entity_type="user", entity_id=user.id, pos_delta=0, neg_delta=0,
                      reason=f"{text} (by {admin.email})", source="admin", mean_after=v.mean, lower_after=v.lower))


@router.get("")
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_role("admin"))):
    rows = db.scalars(select(User).order_by(User.id)).all()
    return [{**user_payload(u), "created_at": u.created_at} for u in rows]


@router.patch("/{user_id}")
def update_user(user_id: int, request: UserUpdateRequest, db: Session = Depends(get_db),
                admin: User = Depends(require_role("admin"))):
    user = _get(db, user_id, admin)
    if request.role is not None:
        if request.role not in VALID_ROLES:
            raise HTTPException(status_code=400, detail=f"Role must be one of {sorted(VALID_ROLES)}")
        user.role = request.role
        _audit(db, user, admin, f"Role changed to {request.role}")
    if request.is_active is not None:
        user.is_active = request.is_active
        if not request.is_active:
            user.token_version = (user.token_version or 0) + 1  # kick out immediately
        _audit(db, user, admin, "Account disabled" if not request.is_active else "Account re-enabled")
    db.commit()
    return user_payload(user)


@router.post("/{user_id}/suspend")
def suspend(user_id: int, body: SuspendRequest, db: Session = Depends(get_db), admin: User = Depends(require_role("admin"))):
    user = _get(db, user_id, admin)
    minutes = max(1, min(60 * 24 * 30, body.minutes))
    user.suspended_until = datetime.utcnow() + timedelta(minutes=minutes)
    user.suspension_reason = body.reason[:250]
    user.token_version = (user.token_version or 0) + 1
    _audit(db, user, admin, f"Suspended for {minutes} min: {body.reason}")
    db.commit()
    return user_payload(user)


@router.post("/{user_id}/unsuspend")
def unsuspend(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_role("admin"))):
    user = _get(db, user_id, admin)
    user.suspended_until = None
    user.suspension_reason = None
    _audit(db, user, admin, "Suspension lifted")
    db.commit()
    return user_payload(user)


@router.post("/{user_id}/revoke-sessions")
def revoke_sessions(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_role("admin"))):
    user = _get(db, user_id, admin, allow_self=True)
    user.token_version = (user.token_version or 0) + 1
    _audit(db, user, admin, "All sessions revoked")
    db.commit()
    return user_payload(user)


@router.post("/{user_id}/reset-trust")
def reset_trust(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_role("admin"))):
    user = _get(db, user_id, admin, allow_self=True)
    user.trust_pos = user.trust_neg = 0.0
    user.trust_score = 0.8
    user.trust_updated_at = datetime.utcnow()
    user.flagged = False
    _audit(db, user, admin, "Trust reset to baseline and flag cleared")
    db.commit()
    return user_payload(user)
