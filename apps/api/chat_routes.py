import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api import chat_service
from apps.api.auth_routes import get_current_user
from apps.api.database import get_db
from apps.api.models import ChatMessage, Conversation, User
from apps.api.settings import MAX_UPLOAD_MB
from apps.api.workspace import OUTPUTS_DIR, READABLE_EXTENSIONS, UPLOADS_DIR, WorkspaceError, relative, safe_path, unique_path

router = APIRouter()


class NewConversation(BaseModel):
    title: str | None = None


class SendMessage(BaseModel):
    content: str = ""
    attachments: list[str] = Field(default_factory=list)


class ResumeRequest(BaseModel):
    approval_id: int


def _conv(db: Session, conversation_id: str, user: User, writable: bool = True) -> Conversation:
    """Only the owner can open a chat; admin is the sole exception.
    Deleted chats are gone for the owner; admin can still read them (audit)."""
    conv = db.get(Conversation, conversation_id)
    is_owner = conv is not None and conv.user_id == user.id
    if conv is None or not (is_owner or user.role == "admin"):
        raise HTTPException(status_code=404, detail="Conversation not found")
    if conv.deleted_at and (user.role != "admin" or writable):
        raise HTTPException(status_code=404, detail="Conversation not found")
    if writable and not is_owner:
        raise HTTPException(status_code=403, detail="Only the owner can post in this chat.")
    return conv


def _msg(m: ChatMessage) -> dict[str, Any]:
    return {"id": m.id, "role": m.role, "content": m.content, "agent_id": m.agent_id, "run_id": m.run_id,
            "attachments": m.attachments or [], "meta": m.meta or {}, "created_at": m.created_at}


@router.get("/api/chat/conversations")
def list_conversations(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = db.scalars(select(Conversation).where(Conversation.user_id == user.id, Conversation.deleted_at.is_(None))
                      .order_by(Conversation.updated_at.desc()).limit(100)).all()
    return [{"id": c.id, "title": c.title, "updated_at": c.updated_at} for c in rows]


@router.post("/api/chat/conversations")
def create_conversation(body: NewConversation, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    conv = Conversation(id=uuid.uuid4().hex, user_id=user.id, title=(body.title or "New chat")[:200])
    db.add(conv)
    db.commit()
    return {"id": conv.id, "title": conv.title, "updated_at": conv.updated_at}


@router.get("/api/chat/conversations/{conversation_id}")
def get_conversation(conversation_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    conv = _conv(db, conversation_id, user, writable=False)
    msgs = db.scalars(select(ChatMessage).where(ChatMessage.conversation_id == conv.id).order_by(ChatMessage.id)).all()
    return {"id": conv.id, "title": conv.title, "messages": [_msg(m) for m in msgs]}


@router.delete("/api/chat/conversations/{conversation_id}")
def delete_conversation(conversation_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Soft delete: the chat and its files disappear for the user, but every
    message, agent run, security event, approval and trust event is kept."""
    conv = db.get(Conversation, conversation_id)
    if conv is None or conv.deleted_at or not (conv.user_id == user.id or user.role == "admin"):
        raise HTTPException(status_code=404, detail="Conversation not found")
    conv.deleted_at = datetime.utcnow()
    db.commit()
    return {"id": conv.id, "deleted": True}


@router.post("/api/chat/conversations/{conversation_id}/upload")
async def upload(conversation_id: str, files: list[UploadFile] = File(...),
                 db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    conv = _conv(db, conversation_id, user)
    saved = []
    limit = MAX_UPLOAD_MB * 1024 * 1024
    for f in files[:5]:
        name = f.filename or "file"
        ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
        if ext not in READABLE_EXTENSIONS:
            raise HTTPException(status_code=400, detail=f"{name}: unsupported type. Allowed: {', '.join(sorted(READABLE_EXTENSIONS))}")
        data = await f.read(limit + 1)
        if len(data) > limit:
            raise HTTPException(status_code=400, detail=f"{name} exceeds {MAX_UPLOAD_MB} MB")
        target = unique_path(UPLOADS_DIR / conv.id, name)
        target.write_bytes(data)
        saved.append({"name": target.name, "path": relative(target), "size": len(data),
                      "scan": chat_service.scan_upload(target)})
    return saved


@router.post("/api/chat/conversations/{conversation_id}/messages")
def send_message(conversation_id: str, body: SendMessage, db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    conv = _conv(db, conversation_id, user)
    if not body.content.strip() and not body.attachments:
        raise HTTPException(status_code=400, detail="Message is empty.")
    try:
        user_msg, replies = chat_service.handle_message(db, user, conv, body.content.strip(), body.attachments)
    except (WorkspaceError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"user_message": _msg(user_msg), "replies": [_msg(r) for r in replies], "reply": _msg(replies[-1])}


@router.post("/api/chat/conversations/{conversation_id}/resume")
def resume(conversation_id: str, body: ResumeRequest, db: Session = Depends(get_db),
           user: User = Depends(get_current_user)):
    conv = _conv(db, conversation_id, user)
    try:
        replies = chat_service.handle_resume(db, user, conv, body.approval_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"replies": [_msg(r) for r in replies], "reply": _msg(replies[-1])}


# ---------------- generated files ----------------
# A file folder belongs to exactly one user: a chat folder to the chat's owner,
# a console-<id> folder to that user. Admin is the only exception.

def _owned_folders(db: Session, user: User) -> dict[str, str]:
    if user.role == "admin":
        folders = {c.id: c.title + (" (deleted)" if c.deleted_at else "") for c in db.scalars(select(Conversation)).all()}
        for u in db.scalars(select(User)).all():
            folders[f"console-{u.id}"] = f"Agent Console ({u.email})"
        return folders
    folders = {c.id: c.title for c in db.scalars(select(Conversation).where(
        Conversation.user_id == user.id, Conversation.deleted_at.is_(None))).all()}
    folders[f"console-{user.id}"] = "Agent Console"
    return folders


def _list_folder(base, kind: str, folders: dict[str, str]) -> list[dict[str, Any]]:
    out = []
    if base.exists():
        for folder in base.iterdir():
            if folder.is_dir() and folder.name in folders:
                for f in sorted(folder.iterdir()):
                    if f.is_file():
                        out.append({"name": f.name, "path": relative(f), "size": f.stat().st_size, "kind": kind,
                                    "modified": f.stat().st_mtime, "conversation_id": folder.name,
                                    "conversation_title": folders[folder.name]})
    return out


@router.get("/api/files")
def list_files(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    folders = _owned_folders(db, user)
    files = _list_folder(OUTPUTS_DIR, "generated", folders) + _list_folder(UPLOADS_DIR, "uploaded", folders)
    return sorted(files, key=lambda x: x["modified"], reverse=True)


@router.get("/api/files/download")
def download(path: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    try:
        target = safe_path(path)
    except WorkspaceError:
        raise HTTPException(status_code=404, detail="File not found")
    rel = relative(target).split("/")
    allowed = len(rel) == 3 and rel[0] in {"outputs", "uploads"} and rel[1] in _owned_folders(db, user)
    if not allowed or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")  # same answer whether it exists or not
    return FileResponse(target, filename=target.name)
