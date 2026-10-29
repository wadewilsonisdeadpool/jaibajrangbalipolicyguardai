"""Persistence layer for the trust model: applies evidence to agents/users,
records an explainable TrustEvent for every change, and enforces automatic
quarantine / suspension."""
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.api.models import Agent, TrustEvent, User
from apps.api.trust_model import (
    BURST_COUNT,
    BURST_LOCK_MIN,
    BURST_WINDOW_MIN,
    CRITICAL_FLOOR,
    CRITICAL_LOCK_MIN,
    TrustView,
    compute,
    decayed,
)


def _kind(entity) -> str:
    return "agent" if isinstance(entity, Agent) else "user"


def view(entity, now: datetime | None = None) -> TrustView:
    now = now or datetime.utcnow()
    pos, neg = decayed(entity.trust_pos or 0.0, entity.trust_neg or 0.0, entity.trust_updated_at, now)
    return compute(_kind(entity), pos, neg)


def locked_until(entity) -> datetime | None:
    value = entity.quarantined_until if isinstance(entity, Agent) else entity.suspended_until
    return value if value and value > datetime.utcnow() else None


def apply_evidence(session: Session, entity, pos: float, neg: float, reason: str, source: str) -> TrustView:
    if entity is None or (pos == 0 and neg == 0):
        return view(entity) if entity is not None else None
    now = datetime.utcnow()
    kind = _kind(entity)
    cur_pos, cur_neg = decayed(entity.trust_pos or 0.0, entity.trust_neg or 0.0, entity.trust_updated_at, now)
    entity.trust_pos = cur_pos + pos
    entity.trust_neg = cur_neg + neg
    entity.trust_updated_at = now
    result = compute(kind, entity.trust_pos, entity.trust_neg)
    entity.trust_score = round(result.mean, 4)

    session.add(TrustEvent(
        entity_type=kind, entity_id=entity.id, pos_delta=pos, neg_delta=neg,
        reason=reason, source=source, mean_after=result.mean, lower_after=result.lower,
    ))
    session.flush()

    if neg > 0:
        _escalate(session, entity, kind, result, now)
    return result


def _escalate(session: Session, entity, kind: str, result: TrustView, now: datetime) -> None:
    window_start = now - timedelta(minutes=BURST_WINDOW_MIN[kind])
    recent_negatives = session.scalar(
        select(func.count()).select_from(TrustEvent).where(
            TrustEvent.entity_type == kind,
            TrustEvent.entity_id == entity.id,
            TrustEvent.neg_delta > 0,
            TrustEvent.created_at >= window_start,
        )
    ) or 0

    lock_minutes, why = 0, ""
    if result.lower < CRITICAL_FLOOR:
        lock_minutes, why = CRITICAL_LOCK_MIN, "trust fell below critical floor"
    elif recent_negatives >= BURST_COUNT:
        lock_minutes, why = BURST_LOCK_MIN[kind], f"{recent_negatives} violations within {BURST_WINDOW_MIN[kind]} min"
    if not lock_minutes:
        return

    until = now + timedelta(minutes=lock_minutes)
    if kind == "agent":
        if not entity.quarantined_until or entity.quarantined_until < until:
            entity.quarantined_until = until
    else:
        if not entity.suspended_until or entity.suspended_until < until:
            entity.suspended_until = until
            entity.suspension_reason = f"Automatic: {why}"
            entity.flagged = True
    session.add(TrustEvent(
        entity_type=kind, entity_id=entity.id, pos_delta=0, neg_delta=0,
        reason=f"Automatic {'quarantine' if kind == 'agent' else 'suspension'} for {lock_minutes} min: {why}",
        source="escalation", mean_after=result.mean, lower_after=result.lower,
    ))
    if kind == "user" and result.tier in {"probation", "restricted"}:
        entity.flagged = True


def mark_flag_if_needed(entity: User, result: TrustView | None) -> None:
    if result is not None and result.tier in {"probation", "restricted"}:
        entity.flagged = True
