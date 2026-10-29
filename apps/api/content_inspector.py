"""Payload inspection: what is the agent actually trying to write/send/run?

Two entry points:
  inspect_arguments(tool, action, args) -> scans outgoing tool payloads
  inspect_request(text)                 -> scans the *user's* message for intent
Findings have a severity; 'critical' forces a DENY in the policy engine.
"""
import re
from typing import Any

SEVERITY_SCORE = {"low": 0.2, "medium": 0.45, "high": 0.75, "critical": 1.0}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_PAYLOAD_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("critical", "Spreadsheet DDE / command execution payload",
     re.compile(r"(?i)^\s*[=+\-@].*\b(cmd|powershell|mshta|rundll32|msexcel)\s*\|")),
    ("critical", "DDEAUTO field", re.compile(r"(?i)\bddeauto\b")),
    ("critical", "Private key material", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("critical", "Cloud/API secret key", re.compile(r"\b(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_\-]{30,})\b")),
    ("critical", "Destructive shell command",
     re.compile(r"(?i)(\brm\s+-rf\b|\bmkfs\b|\bformat\s+[a-z]:|\bdel\s+/[fsq]|:\(\)\s*\{\s*:\|:&\s*\};:|\bshutdown\s+(-h|/s))")),
    ("high", "Spreadsheet formula calling external resources",
     re.compile(r"(?i)^\s*=\s*(hyperlink|webservice|importxml|importdata|importhtml|importrange|filterxml)\s*\(")),
    ("high", "Script / HTML injection", re.compile(r"(?i)(<script\b|javascript:|onerror\s*=|onload\s*=)")),
    ("high", "Prompt-injection text in outgoing content",
     re.compile(r"(?i)(ignore (all |any |your )?(previous|prior) instructions|disregard (the )?system prompt)")),
    ("high", "Password or credential assignment", re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*\S{4,}")),
    ("medium", "Spreadsheet formula", re.compile(r"^\s*=\s*[A-Za-z]+\s*\(")),
    ("medium", "Mass-destructive SQL keyword", re.compile(r"(?i)\b(drop|truncate)\s+table\b")),
]

_REQUEST_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("high", "Asks to override instructions or safety",
     re.compile(r"(?i)(ignore (all |any |your )?(previous|prior|safety) (instructions|rules)|bypass (the )?(security|policy|guard|filter)|disable (the )?(security|policy|guard))")),
    ("high", "Data exfiltration intent",
     re.compile(r"(?i)(exfiltrat|leak|dump|steal|smuggle|siphon)\w*\b.{0,40}\b(data|database|customers?|users?|emails?|records|credentials|passwords)")),
    ("high", "Credential harvesting",
     re.compile(r"(?i)\b(give|show|send|get|extract|reveal)\b.{0,30}\b(passwords?|password hashes|credentials|api keys?|secrets?|private keys?|\.env)\b")),
    ("high", "Destructive system command", re.compile(r"(?i)(rm\s+-rf|/etc/passwd|/etc/shadow|format\s+c:|del\s+/[fsq])")),
    ("medium", "Bulk export of personal data to an outside party",
     re.compile(r"(?i)(\b(all|every|full list of|entire)\b.{0,30}\b(customers?|users?|emails?|contacts)\b.{0,60}\b(send|email|upload|post|share)\b|\b(send|email|upload|post|share|forward)\b.{0,40}\b(all|every|full list|entire)\b.{0,30}\b(customers?|users?|emails?|contacts)\b)")),
    ("medium", "Deletion of records", re.compile(r"(?i)\b(delete|drop|wipe|truncate|erase)\b.{0,30}\b(all|every|table|database|records)\b")),
    ("low", "Asks to hide activity from others",
     re.compile(r"(?i)(don'?t|do not|never) (tell|mention|log|record|inform)")),
]


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)
    elif value is not None:
        yield str(value)


def _score(findings: list[dict[str, str]]) -> float:
    if not findings:
        return 0.0
    scores = sorted((SEVERITY_SCORE[f["severity"]] for f in findings), reverse=True)
    # strongest finding dominates; extra findings add a little
    return round(min(1.0, scores[0] + 0.1 * (len(scores) - 1)), 3)


def inspect_arguments(tool_name: str, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(sev: str, finding: str):
        if finding not in seen:
            seen.add(finding)
            findings.append({"severity": sev, "finding": finding})

    texts = list(_strings(arguments))
    for text in texts:
        for line in text.splitlines() or [text]:
            for sev, name, pattern in _PAYLOAD_PATTERNS:
                if pattern.search(line):
                    add(sev, name)

    # Bulk personal data leaving via write/send actions.
    if action in {"send", "create", "write"}:
        emails = {e.lower() for t in texts for e in EMAIL_RE.findall(t)}
        recipients = arguments.get("to") if tool_name == "email_sender" else None
        if isinstance(recipients, str):
            emails -= {r.strip().lower() for r in recipients.split(",")}
        elif isinstance(recipients, list):
            emails -= {str(r).strip().lower() for r in recipients}
        if len(emails) >= 5:
            add("high", f"Bulk personal data: {len(emails)} email addresses in payload")
        elif len(emails) >= 2:
            add("low", f"Contains {len(emails)} email addresses")

    if tool_name == "database_writer":
        op = str(arguments.get("operation", "insert")).lower()
        if op == "delete":
            add("medium", "Deletes database records")
        if op in {"update", "delete"} and not arguments.get("id"):
            add("high", f"{op.upper()} without a specific row id")

    if tool_name == "web_fetch":
        url = str(arguments.get("url", ""))
        query = url.split("?", 1)[1] if "?" in url else ""
        if len(query) > 150 or EMAIL_RE.search(query):
            add("high", "URL query string may carry exfiltrated data")

    return {"score": _score(findings), "findings": findings,
            "critical": any(f["severity"] == "critical" for f in findings)}


def inspect_request(text: str) -> dict[str, Any]:
    findings = [
        {"severity": sev, "finding": name}
        for sev, name, pattern in _REQUEST_PATTERNS
        if pattern.search(text or "")
    ]
    return {"score": _score(findings), "findings": findings}


def inspect_uploaded_text(text: str) -> dict[str, Any]:
    """Scan an uploaded document for embedded instructions aimed at the AI."""
    findings = []
    if re.search(r"(?i)(ignore (all |any |your )?(previous|prior) instructions|note to (the )?ai|ai assistant processing this|do not (tell|mention) (this|the user))", text or ""):
        findings.append({"severity": "high", "finding": "Embedded instructions addressed to the AI (possible prompt injection)"})
    if len(EMAIL_RE.findall(text or "")) >= 5:
        findings.append({"severity": "low", "finding": "Contains many email addresses (personal data)"})
    return {"score": _score(findings), "findings": findings}
