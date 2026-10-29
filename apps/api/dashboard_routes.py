from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.api.auth_routes import get_current_user
from apps.api.database import engine
from apps.api.models import Agent, ApprovalRequest, SecurityEvent, Tool, User


router = APIRouter(prefix="/api/dashboard")


@router.get("")
def get_dashboard(user: User = Depends(get_current_user)):
    with Session(engine) as session:
        total_agents = session.scalar(
            select(func.count()).select_from(Agent)
        ) or 0

        active_agents = session.scalar(
            select(func.count()).select_from(Agent).where(
                Agent.is_active.is_(True)
            )
        ) or 0

        total_tools = session.scalar(
            select(func.count()).select_from(Tool)
        ) or 0

        total_events = session.scalar(
            select(func.count()).select_from(SecurityEvent)
        ) or 0

        allowed_events = session.scalar(
            select(func.count()).select_from(SecurityEvent).where(
                SecurityEvent.decision == "ALLOW"
            )
        ) or 0

        review_events = session.scalar(
            select(func.count()).select_from(SecurityEvent).where(
                SecurityEvent.decision == "REVIEW"
            )
        ) or 0

        denied_events = session.scalar(
            select(func.count()).select_from(SecurityEvent).where(
                SecurityEvent.decision == "DENY"
            )
        ) or 0

        pending_approvals = session.scalar(
            select(func.count()).select_from(ApprovalRequest).where(
                ApprovalRequest.status == "PENDING"
            )
        ) or 0

        blocked_rate = (
            denied_events / total_events
            if total_events > 0
            else 0.0
        )

        average_risk = session.scalar(
            select(func.avg(SecurityEvent.risk_score))
        )

        now = datetime.utcnow()
        flagged_users = session.scalar(select(func.count()).select_from(User).where(User.flagged.is_(True))) or 0
        suspended_users = session.scalar(select(func.count()).select_from(User).where(User.suspended_until > now)) or 0
        quarantined_agents = session.scalar(select(func.count()).select_from(Agent).where(Agent.quarantined_until > now)) or 0

        return {
            "users": {"flagged": flagged_users, "suspended": suspended_users},
            "quarantined_agents": quarantined_agents,
            "agents": {
                "total": total_agents,
                "active": active_agents,
            },
            "tools": {
                "total": total_tools,
            },
            "events": {
                "total": total_events,
                "allowed": allowed_events,
                "review": review_events,
                "denied": denied_events,
            },
            "approvals": {
                "pending": pending_approvals,
            },
            "security": {
                "average_risk": round(float(average_risk or 0), 4),
                "blocked_rate": round(blocked_rate, 4),
            },
        }