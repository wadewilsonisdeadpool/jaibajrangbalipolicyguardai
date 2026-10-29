from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.auth_routes import get_current_user
from apps.api.database import get_db
from apps.api.models import TrustEvent, User
from apps.api.trust_model import NEG_HALF_LIFE_DAYS, POS_HALF_LIFE_DAYS, PRIORS, TIERS

router = APIRouter(prefix="/api/trust")


@router.get("/model")
def trust_model_info(user: User = Depends(get_current_user)):
    return {"priors": PRIORS, "positive_half_life_days": POS_HALF_LIFE_DAYS,
            "negative_half_life_days": NEG_HALF_LIFE_DAYS, "tiers": TIERS}


@router.get("/{entity_type}/{entity_id}")
def trust_history(entity_type: str, entity_id: int, limit: int = 100,
                  db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if entity_type not in {"agent", "user"}:
        raise HTTPException(status_code=400, detail="entity_type must be agent or user")
    if entity_type == "user" and user.role != "admin" and user.id != entity_id:
        raise HTTPException(status_code=403, detail="You can only view your own trust history.")
    rows = db.scalars(select(TrustEvent).where(TrustEvent.entity_type == entity_type, TrustEvent.entity_id == entity_id)
                      .order_by(TrustEvent.id.desc()).limit(min(limit, 500))).all()
    return [{"id": e.id, "pos_delta": e.pos_delta, "neg_delta": e.neg_delta, "reason": e.reason, "source": e.source,
             "mean_after": e.mean_after, "lower_after": e.lower_after, "created_at": e.created_at} for e in reversed(rows)]
