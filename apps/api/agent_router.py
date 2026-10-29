"""Picks the most suitable agent for a user request.

hybrid (default): fast keyword scoring; if there is no clear winner, ask
the LLM to choose (JSON mode); if that fails, fall back to the best keyword
match. Routing is advisory for capability only: the chosen agent still
cannot exceed its own allowlist."""
import json
import re
from typing import Any

from apps.api.llm.qwen_adapter import QwenAdapter
from apps.api.settings import ROUTER_MODE

KEYWORDS: dict[str, list[str]] = {
    "Qwen Research Agent": [
        "summar", "read", "document", "report", "pdf", "docx", "word file", "article", "web", "website",
        "page", "wikipedia", "news", "research", "explain", "weather", "forecast", "temperature", "rain",
        "notes", "key points", "bullet", "translate", "rewrite", "extract", "spreadsheet", "excel", "xlsx",
    ],
    "Data Analyst Agent": [
        "database", "sql", "query", "table", "customer", "order", "ticket", "revenue", "sales", "record",
        "row", "count", "how many", "average", "total", "analytics", "report on customers", "insert",
        "update ticket", "close ticket", "csv", "data",
    ],
    "Operations Agent": [
        "email", "e-mail", "mail", "send", "notify", "gmail", "message to", "shell", "command", "server",
        "restart", "deploy", "terminal", "run ",
    ],
}
ATTACHMENT_HINTS = {".pdf": "Qwen Research Agent", ".docx": "Qwen Research Agent", ".txt": "Qwen Research Agent",
                    ".md": "Qwen Research Agent", ".xlsx": "Qwen Research Agent", ".csv": "Data Analyst Agent"}


def _keyword_scores(text: str, attachments: list[str], agents: list[dict[str, Any]]) -> dict[str, float]:
    lower = text.lower()
    scores = {a["name"]: 0.0 for a in agents}
    for name, words in KEYWORDS.items():
        if name in scores:
            scores[name] = float(sum(1 for w in words if w in lower))
    for path in attachments:
        for ext, name in ATTACHMENT_HINTS.items():
            if path.lower().endswith(ext) and name in scores:
                scores[name] += 1.5
    return scores


def _llm_choice(text: str, agents: list[dict[str, Any]]) -> tuple[str | None, str]:
    roster = "\n".join(f"- {a['name']}: {a['role']}. {a.get('description') or ''} Tools: {', '.join(a['allowed_tools'])}" for a in agents)
    prompt = [
        {"role": "system", "content": "You route user requests to the single best agent. Reply ONLY with JSON: {\"agent\": \"<exact name>\", \"reason\": \"<short>\"}"},
        {"role": "user", "content": f"Agents:\n{roster}\n\nRequest: {text[:1500]}"},
    ]
    try:
        raw = QwenAdapter().generate(prompt, json_mode=True, timeout=60)["message"].get("content", "")
        raw = re.sub(r"(?s)<think>.*?</think>", "", raw)
        data = json.loads(raw[raw.find("{"): raw.rfind("}") + 1])
        names = {a["name"] for a in agents}
        if data.get("agent") in names:
            return data["agent"], str(data.get("reason", ""))[:200]
    except Exception:  # noqa: BLE001
        pass
    return None, ""


def route(text: str, attachments: list[str], agents: list[dict[str, Any]]) -> dict[str, Any]:
    active = [a for a in agents if a["is_active"]]
    if not active:
        raise ValueError("No active agents available.")
    scores = _keyword_scores(text, attachments, active)
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    best, best_score = ranked[0]
    margin = best_score - (ranked[1][1] if len(ranked) > 1 else 0)

    if ROUTER_MODE != "llm" and best_score >= 1 and (margin >= 1 or ROUTER_MODE == "keyword"):
        chosen, method, reason = best, "keyword", f"Matched {int(best_score)} task signal(s) for this agent."
    else:
        chosen, reason = (None, "") if ROUTER_MODE == "keyword" else _llm_choice(text, active)
        method = "llm"
        if chosen is None:
            chosen, method = (best if best_score > 0 else active[0]["name"]), "fallback"
            reason = "Best available match."
    agent = next(a for a in active if a["name"] == chosen)
    return {"agent": agent, "method": method, "reason": reason, "scores": scores}
