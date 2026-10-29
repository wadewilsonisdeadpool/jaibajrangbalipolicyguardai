"""Everything the security layer knows about *where* a tool call comes from."""
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ExecutionContext:
    run_id: str
    user_id: int | None = None
    user_email: str | None = None
    conversation_id: str | None = None
    tainted: bool = False
    taint_sources: list[str] = field(default_factory=list)
    request_risk: float = 0.0
    data_level: int = 0                     # 0 public/none, 1 internal, 2 confidential
    data_sources: list[str] = field(default_factory=list)
    files_created: list[dict[str, Any]] = field(default_factory=list)

    @property
    def workspace_key(self) -> str:
        """Folder for this conversation's uploads/outputs. Console runs get a
        per-user folder, so files always belong to exactly one user."""
        if self.conversation_id:
            return self.conversation_id
        if self.user_id:
            return f"console-{self.user_id}"
        return f"run-{self.run_id[:12]}"

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("files_created", None)
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any] | None) -> "ExecutionContext":
        data = dict(data or {})
        data.setdefault("run_id", "approval")
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in allowed})
