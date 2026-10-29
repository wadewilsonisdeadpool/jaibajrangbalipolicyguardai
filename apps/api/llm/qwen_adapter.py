from typing import Any

import requests

from apps.api.llm.base import LLMAdapter
from apps.api.settings import OLLAMA_MODEL, OLLAMA_THINK, OLLAMA_URL


class QwenAdapter(LLMAdapter):
    def __init__(self, model: str | None = None, base_url: str | None = None) -> None:
        self.model = model or OLLAMA_MODEL
        self.base_url = (base_url or OLLAMA_URL).rstrip("/")

    def generate(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
                 json_mode: bool = False, timeout: int = 240) -> dict[str, Any]:
        payload: dict[str, Any] = {"model": self.model, "messages": messages, "stream": False}
        if tools:
            payload["tools"] = tools
        if json_mode:
            payload["format"] = "json"
        if OLLAMA_THINK in {"true", "false"}:
            payload["think"] = OLLAMA_THINK == "true"
        response = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        return {"model": data.get("model", self.model), "message": data.get("message", {}), "done": data.get("done", False)}
