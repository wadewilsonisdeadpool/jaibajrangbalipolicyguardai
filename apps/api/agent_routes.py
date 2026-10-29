import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.api import trust
from apps.api.auth_routes import get_current_user, require_role
from apps.api.chat_service import agent_profile, runtime
from apps.api.context import ExecutionContext
from apps.api.database import get_db
from apps.api.models import Agent, AgentRun, SecurityEvent, TrustEvent, User

router = APIRouter()


class AgentChatRequest(BaseModel):
    agent_id: int
    message: str


class AgentUpdateRequest(BaseModel):
    is_active: bool | None = None
    reset_trust: bool = False
    release_quarantine: bool = False


def _counts(db: Session) -> dict[int, dict[str, int]]:
    rows = db.execute(select(SecurityEvent.agent_id, SecurityEvent.decision, func.count())
                      .group_by(SecurityEvent.agent_id, SecurityEvent.decision)).all()
    out: dict[int, dict[str, int]] = {}
    for agent_id, decision, n in rows:
        out.setdefault(agent_id, {"ALLOW": 0, "REVIEW": 0, "DENY": 0})[decision] = n
    return out


def _payload(agent: Agent, counts: dict[str, int] | None = None) -> dict[str, Any]:
    until = trust.locked_until(agent)
    return {"id": agent.id, "name": agent.name, "role": agent.role, "description": agent.description,
            "allowed_tools": agent.allowed_tools or [], "trust_score": agent.trust_score,
            "trust": trust.view(agent).as_dict(), "is_active": agent.is_active,
            "quarantined_until": until.isoformat() if until else None,
            "decisions": counts or {"ALLOW": 0, "REVIEW": 0, "DENY": 0}}


@router.get("/api/agents")
def list_agents(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    counts = _counts(db)
    return [_payload(a, counts.get(a.id)) for a in db.scalars(select(Agent).order_by(Agent.id)).all()]


@router.patch("/api/agents/{agent_id}")
def update_agent(agent_id: int, request: AgentUpdateRequest, db: Session = Depends(get_db),
                 admin: User = Depends(require_role("admin"))):
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    notes = []
    if request.is_active is not None:
        agent.is_active = request.is_active
        notes.append("activated" if request.is_active else "deactivated")
    if request.reset_trust:
        agent.trust_pos = agent.trust_neg = 0.0
        agent.trust_score = 0.8
        agent.trust_updated_at = datetime.utcnow()
        notes.append("trust reset to baseline")
    if request.release_quarantine:
        agent.quarantined_until = None
        notes.append("quarantine released")
    if notes:
        v = trust.view(agent)
        db.add(TrustEvent(entity_type="agent", entity_id=agent.id, pos_delta=0, neg_delta=0,
                          reason=f"Admin: {', '.join(notes)} (by {admin.email})", source="admin",
                          mean_after=v.mean, lower_after=v.lower))
    db.commit()
    return _payload(agent, _counts(db).get(agent.id))


@router.post("/api/agent/chat")
def agent_chat(request: AgentChatRequest, db: Session = Depends(get_db),
               current_user: User = Depends(require_role("admin", "analyst"))) -> dict[str, Any]:
    """Direct console: run a specific agent without routing (for experiments)."""
    agent = db.get(Agent, request.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if not agent.is_active or trust.locked_until(agent):
        raise HTTPException(status_code=403, detail="Agent is deactivated or quarantined.")
    ctx = ExecutionContext(run_id=uuid.uuid4().hex, user_id=current_user.id, user_email=current_user.email)
    before = trust.view(agent).as_dict()
    db.add(AgentRun(id=ctx.run_id, agent_id=agent.id, user_email=current_user.email, prompt=request.message))
    db.commit()
    result = runtime.run(agent_profile(agent), request.message, ctx)
    run = db.get(AgentRun, ctx.run_id)
    run.status, run.final_output, run.steps = result["type"], result.get("content"), result.get("steps", 0)
    db.commit()
    db.refresh(agent)
    after = trust.view(agent).as_dict()
    result.update({"agent_id": agent.id, "agent_name": agent.name, "trust_before": before["lower"],
                   "trust_after": after["lower"], "trust_view": after})
    return result
