from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.api.auth_routes import get_current_user
from apps.api.database import get_db
from apps.api.models import SecurityEvent, User
from apps.api.settings import email_mode
from apps.api.web_domains import ALLOWED_DOMAINS, BLOCKED_DOMAINS
from apps.api.tool_registry import list_tools

router = APIRouter()


@router.get("/api/tools")
def get_tools(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = db.execute(
        select(SecurityEvent.tool_name, SecurityEvent.decision, func.count())
        .group_by(SecurityEvent.tool_name, SecurityEvent.decision)
    ).all()
    usage: dict[str, dict[str, int]] = {}
    for tool, decision, n in rows:
        usage.setdefault(tool, {"ALLOW": 0, "REVIEW": 0, "DENY": 0})[decision] = n

    return {
        "tools": [
            {**t, "usage": usage.get(t["name"], {"ALLOW": 0, "REVIEW": 0, "DENY": 0})}
            for t in list_tools()
        ],
        "web_allowlist": ALLOWED_DOMAINS,
        "web_blocklist": BLOCKED_DOMAINS,
        "email_mode": email_mode(),
    }
