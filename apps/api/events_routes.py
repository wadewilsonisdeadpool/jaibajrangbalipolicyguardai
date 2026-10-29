from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.auth_routes import get_current_user
from apps.api.database import get_db
from apps.api.models import Agent, AgentRun, SecurityEvent, User

router = APIRouter()


def _event_payload(e: SecurityEvent, agent_names: dict[int, str]) -> dict[str, Any]:
    return {
        "id": e.id,
        "run_id": e.run_id,
        "agent_id": e.agent_id,
        "agent_name": agent_names.get(e.agent_id, f"agent-{e.agent_id}"),
        "tool_name": e.tool_name,
        "action": e.action,
        "arguments": e.arguments,
        "decision": e.decision,
        "risk_score": e.risk_score,
        "rule": e.rule,
        "reasons": e.reasons or [],
        "factors": e.factors or {},
        "trust_before": e.trust_before,
        "tainted": e.tainted,
        "user_id": e.user_id,
        "conversation_id": e.conversation_id,
        "destination": e.destination,
        "content_findings": e.content_findings or [],
        "request_risk": e.request_risk,
        "created_at": e.created_at,
    }


def _agent_names(db: Session) -> dict[int, str]:
    return {a.id: a.name for a in db.scalars(select(Agent)).all()}


@router.get("/api/events")
def list_events(
    decision: str | None = None,
    agent_id: int | None = None,
    tool_name: str | None = None,
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    stmt = select(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(limit)
    if user.role != "admin":
        stmt = stmt.where(SecurityEvent.user_id == user.id)
    if decision:
        stmt = stmt.where(SecurityEvent.decision == decision.upper())
    if agent_id:
        stmt = stmt.where(SecurityEvent.agent_id == agent_id)
    if tool_name:
        stmt = stmt.where(SecurityEvent.tool_name == tool_name)
    names = _agent_names(db)
    return [_event_payload(e, names) for e in db.scalars(stmt).all()]


def _run_payload(run: AgentRun, db: Session, names: dict[int, str]) -> dict[str, Any]:
    events = db.scalars(
        select(SecurityEvent).where(SecurityEvent.run_id == run.id).order_by(SecurityEvent.id)
    ).all()
    return {
        "id": run.id,
        "agent_id": run.agent_id,
        "agent_name": names.get(run.agent_id, f"agent-{run.agent_id}"),
        "user_email": run.user_email,
        "prompt": run.prompt,
        "status": run.status,
        "final_output": run.final_output,
        "steps": run.steps,
        "created_at": run.created_at,
        "events": [_event_payload(e, names) for e in events],
    }


@router.get("/api/runs")
def list_runs(
    limit: int = Query(20, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    names = _agent_names(db)
    stmt = select(AgentRun).order_by(AgentRun.created_at.desc()).limit(limit)
    if user.role != "admin":
        stmt = stmt.where(AgentRun.user_email == user.email)
    runs = db.scalars(stmt).all()
    return [_run_payload(r, db, names) for r in runs]


@router.get("/api/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    run = db.get(AgentRun, run_id)
    if run is None or (user.role != "admin" and run.user_email != user.email):
        raise HTTPException(status_code=404, detail="Run not found")
    return _run_payload(run, db, _agent_names(db))
