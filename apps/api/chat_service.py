"""Conversation orchestration: scan request -> route to agent -> run agent
through PolicyGuard -> (optional handoffs) -> store messages -> trust.

Handoffs reuse the SAME security context: taint and data sensitivity carry
over, so bouncing a task between agents can never launder data."""
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api import trust
from apps.api.agent_router import route
from apps.api.content_inspector import inspect_request, inspect_uploaded_text
from apps.api.context import ExecutionContext
from apps.api.documents import read_text
from apps.api.models import Agent, AgentRun, ApprovalRequest, ChatMessage, Conversation, User
from apps.api.qwen_agent import QwenAgent
from apps.api.trust_model import USER_TASK_COMPLETED, user_evidence_for_request
from apps.api.workspace import UPLOADS_DIR, WorkspaceError, relative, safe_path

runtime = QwenAgent()
HISTORY_MESSAGES = 12
MAX_HANDOFFS = 3


def agent_profile(agent: Agent, roster: list[Agent] | None = None) -> dict[str, Any]:
    profile = {"id": agent.id, "name": agent.name, "role": agent.role, "description": agent.description,
               "allowed_tools": agent.allowed_tools or [],
               "is_active": agent.is_active and not trust.locked_until(agent)}
    if roster is not None:
        profile["roster"] = [{"name": a.name, "allowed_tools": [t for t in (a.allowed_tools or []) if t != "handoff_to_agent"]}
                             for a in roster if a.id != agent.id and a.is_active and not trust.locked_until(a)]
    return profile


def scan_upload(path) -> dict[str, Any]:
    try:
        text, _ = read_text(path)
    except Exception as exc:  # noqa: BLE001
        return {"score": 0.0, "findings": [{"severity": "low", "finding": f"Could not scan: {exc.__class__.__name__}"}]}
    return inspect_uploaded_text(text)


def resolve_attachments(conversation: Conversation, paths: list[str]) -> list[dict[str, Any]]:
    out = []
    for p in paths[:10]:
        path = safe_path(p)
        if not path.is_relative_to((UPLOADS_DIR / conversation.id).resolve()) or not path.is_file():
            raise WorkspaceError(f"Attachment not found in this chat: {p}")
        out.append({"name": path.name, "path": relative(path), "size": path.stat().st_size, "scan": scan_upload(path)})
    return out


def _history(db: Session, conversation_id: str) -> list[dict[str, str]]:
    rows = db.scalars(select(ChatMessage).where(ChatMessage.conversation_id == conversation_id)
                      .order_by(ChatMessage.id.desc()).limit(HISTORY_MESSAGES)).all()
    return [{"role": m.role, "content": m.content} for m in reversed(rows) if m.role in {"user", "assistant"} and m.content]


def _uploads(db: Session, conversation_id: str) -> list[str]:
    msgs = db.scalars(select(ChatMessage).where(ChatMessage.conversation_id == conversation_id)).all()
    return [a["path"] for m in msgs for a in (m.attachments or [])]


def _assistant(db: Session, conversation: Conversation, content: str, agent: Agent | None, meta: dict[str, Any]) -> ChatMessage:
    msg = ChatMessage(conversation_id=conversation.id, role="assistant", content=content,
                      agent_id=agent.id if agent else None, run_id=meta.get("run_id"), meta=meta)
    db.add(msg)
    conversation.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(msg)
    return msg


def _run_agent(db: Session, user: User, conversation: Conversation, agent: Agent, prompt: str,
               ctx: ExecutionContext, routing: dict[str, Any] | None) -> ChatMessage:
    db.add(AgentRun(id=ctx.run_id, agent_id=agent.id, user_email=user.email, prompt=prompt[:4000]))
    db.commit()
    agent_before = trust.view(agent).as_dict()
    roster = db.scalars(select(Agent).order_by(Agent.id)).all()

    result = runtime.run(agent_profile(agent, roster), prompt, ctx,
                         history=_history(db, conversation.id), attachments=_uploads(db, conversation.id))

    run = db.get(AgentRun, ctx.run_id)
    run.status, run.final_output, run.steps = result["type"], result.get("content"), result.get("steps", 0)
    conversation.data_level = max(conversation.data_level or 0, ctx.data_level)  # sticky for the whole chat
    db.commit()
    db.refresh(agent)
    db.refresh(user)

    denied = any(t["decision"] == "DENY" for t in result["trace"])
    if result["type"] == "final" and not denied:
        trust.apply_evidence(db, user, USER_TASK_COMPLETED[0], USER_TASK_COMPLETED[1], USER_TASK_COMPLETED[2], "task")
        db.commit()

    meta = {
        "type": result["type"], "run_id": ctx.run_id, "agent_name": agent.name, "routing": routing,
        "trace": result["trace"], "files_created": result.get("files_created", []),
        "approval_id": result.get("approval_id"), "pending_tool": result.get("pending_tool"),
        "handoff_to": result.get("handoff_to"), "data_level": ctx.data_level,
        "trust": {"agent_before": agent_before, "agent_after": trust.view(agent).as_dict(),
                  "user_after": trust.view(user).as_dict()},
    }
    return _assistant(db, conversation, result.get("content") or "", agent, meta)


def _run_chain(db: Session, user: User, conversation: Conversation, agent: Agent, prompt: str,
               ctx: ExecutionContext, routing: dict[str, Any], original_request: str) -> list[ChatMessage]:
    replies: list[ChatMessage] = []
    visited: list[str] = []
    for hop in range(MAX_HANDOFFS + 1):
        msg = _run_agent(db, user, conversation, agent, prompt, ctx, routing)
        replies.append(msg)
        visited.append(agent.name)
        meta = msg.meta or {}
        if meta.get("type") != "handoff":
            break
        target_name = str(meta.get("handoff_to") or "").strip().lower()
        target = next((a for a in db.scalars(select(Agent)).all()
                       if a.name.lower() == target_name and a.id != agent.id), None)
        if target is None or not target.is_active or trust.locked_until(target) or hop == MAX_HANDOFFS:
            why = "that agent is unavailable" if hop < MAX_HANDOFFS else "the handoff limit was reached"
            replies.append(_assistant(db, conversation, f"I couldn't hand this off because {why}.", None, {"type": "error"}))
            break
        files = [f["path"] for r in replies for f in (r.meta or {}).get("files_created", [])]
        instructions = next((t.get("arguments", {}).get("instructions") for t in reversed(meta.get("trace", []))
                             if t.get("tool") == "handoff_to_agent"), "") or ""
        prompt = (f"[Handoff from {agent.name}] Original user request: {original_request}\n"
                  f"Done so far: {msg.content}\n"
                  f"Files created so far: {', '.join(files) or 'none'}\n"
                  f"Your part: {instructions}")
        # Same user, same chat, SAME taint and data sensitivity -> no laundering via handoff.
        ctx = ExecutionContext(run_id=uuid.uuid4().hex, user_id=ctx.user_id, user_email=ctx.user_email,
                               conversation_id=ctx.conversation_id, tainted=ctx.tainted,
                               taint_sources=list(ctx.taint_sources), request_risk=ctx.request_risk,
                               data_level=ctx.data_level, data_sources=list(ctx.data_sources))
        routing = {"method": "handoff", "reason": f"Delegated by {agent.name}"}
        agent = target
    return replies


def handle_message(db: Session, user: User, conversation: Conversation, content: str,
                   attachment_paths: list[str]) -> tuple[ChatMessage, list[ChatMessage]]:
    attachments = resolve_attachments(conversation, attachment_paths)
    request_scan = inspect_request(content)

    user_msg = ChatMessage(conversation_id=conversation.id, role="user", content=content,
                           attachments=attachments, meta={"request_scan": request_scan})
    db.add(user_msg)
    if conversation.title == "New chat":
        conversation.title = (content.strip() or (attachments[0]["name"] if attachments else "New chat"))[:60]

    _, neg, why = user_evidence_for_request(request_scan["score"])
    if neg:
        findings = "; ".join(f["finding"] for f in request_scan["findings"])
        trust.mark_flag_if_needed(user, trust.apply_evidence(db, user, 0, neg, f"{why}: {findings}", "request"))
    db.commit()
    db.refresh(user_msg)

    if trust.locked_until(user):
        return user_msg, [_assistant(db, conversation,
            "Your account has been temporarily suspended by PolicyGuard after repeated high-risk requests. "
            "An administrator can review and lift the suspension.", None, {"type": "suspended"})]

    agents = db.scalars(select(Agent).order_by(Agent.id)).all()
    decision = route(content, [a["path"] for a in attachments], [agent_profile(a) for a in agents])
    agent = db.get(Agent, decision["agent"]["id"])

    prompt = content
    if attachments:
        prompt += "\n\n[Attached files: " + ", ".join(a["path"] for a in attachments) + "]"
    ctx = ExecutionContext(run_id=uuid.uuid4().hex, user_id=user.id, user_email=user.email,
                           conversation_id=conversation.id, request_risk=request_scan["score"],
                           data_level=conversation.data_level or 0)
    routing = {"method": decision["method"], "reason": decision["reason"]}
    return user_msg, _run_chain(db, user, conversation, agent, prompt, ctx, routing, content)


def handle_resume(db: Session, user: User, conversation: Conversation, approval_id: int) -> list[ChatMessage]:
    approval = db.get(ApprovalRequest, approval_id)
    if approval is None or (approval.context or {}).get("conversation_id") != conversation.id:
        raise ValueError("Approval not found in this conversation.")
    if approval.status == "PENDING":
        raise ValueError("Still waiting for a reviewer.")
    existing = db.scalars(select(ChatMessage).where(ChatMessage.conversation_id == conversation.id)).all()
    if any((m.meta or {}).get("resumed_approval_id") == approval_id for m in existing):
        raise ValueError("This approval was already continued.")

    agent = db.get(Agent, approval.agent_id)
    old = ExecutionContext.from_json(approval.context)
    ctx = ExecutionContext(run_id=uuid.uuid4().hex, user_id=user.id, user_email=user.email,
                           conversation_id=conversation.id, tainted=old.tainted, taint_sources=old.taint_sources,
                           request_risk=old.request_risk,
                           data_level=max(old.data_level, conversation.data_level or 0), data_sources=old.data_sources)
    if approval.status == "APPROVED":
        note = (f"[PolicyGuard] Your requested action `{approval.tool_name}` was APPROVED by {approval.decided_by} "
                f"and has already been executed. Result: {str(approval.execution_result)[:3000]}\n"
                "Continue the user's task using this result. Do not repeat that action.")
    else:
        note = (f"[PolicyGuard] Your requested action `{approval.tool_name}` was REJECTED by {approval.decided_by}. "
                "Do not retry it. Tell the user briefly what could not be done and offer a safe alternative.")
    original = next((m.content for m in reversed(existing) if m.role == "user"), "")
    replies = _run_chain(db, user, conversation, agent, note, ctx,
                         {"method": "resume", "reason": "Continuing after review"}, original)
    first = replies[0]
    first.meta = {**(first.meta or {}), "resumed_approval_id": approval_id,
                  "approved_files": (approval.execution_result or {}).get("files", [])}
    db.commit()
    return replies
