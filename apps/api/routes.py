import uuid

from fastapi import APIRouter, Depends

from apps.api.auth_routes import require_role
from apps.api.context import ExecutionContext
from apps.api.models import User
from apps.api.tool_broker import ToolBroker, ToolRequest

router = APIRouter(prefix="/api")


@router.post("/tool-request")
def tool_request(request: ToolRequest, user: User = Depends(require_role("admin", "analyst"))):
    """Direct broker access (no LLM). Used for scripted experiments / Attack Lab."""
    ctx = ExecutionContext(run_id=uuid.uuid4().hex, user_id=user.id, user_email=user.email,
                           tainted=request.context_tainted, taint_sources=["experiment"] if request.context_tainted else [])
    return ToolBroker().request_tool(request.agent_id, request.tool_name, request.arguments, ctx)
