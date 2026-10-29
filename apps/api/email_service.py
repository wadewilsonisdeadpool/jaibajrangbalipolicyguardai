"""Real email delivery through Gmail SMTP (App Password), with a local
outbox log of every message. Falls back to outbox-only when Gmail is not
configured, and says so honestly in the result."""
import json
import mimetypes
import re
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from apps.api import settings
from apps.api.workspace import OUTBOX_DIR

ADDRESS_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
MAX_RECIPIENTS = 5
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024


def _sent_last_hour() -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    count = 0
    for f in OUTBOX_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if data.get("mode") == "gmail" and datetime.fromisoformat(data["sent_at"]) >= cutoff:
                count += 1
        except Exception:  # noqa: BLE001
            continue
    return count


def send(to: list[str], subject: str, body: str, attachments: list[Path], sender_label: str) -> dict[str, Any]:
    recipients = [r.strip() for r in to if r.strip()]
    if not recipients or len(recipients) > MAX_RECIPIENTS:
        raise ValueError(f"Provide 1-{MAX_RECIPIENTS} recipients.")
    bad = [r for r in recipients if not ADDRESS_RE.match(r)]
    if bad:
        raise ValueError(f"Invalid address(es): {', '.join(bad)}")
    if sum(p.stat().st_size for p in attachments) > MAX_ATTACHMENT_BYTES:
        raise ValueError("Attachments exceed 10 MB.")

    mode = settings.email_mode()
    if mode == "gmail" and _sent_last_hour() >= settings.EMAIL_MAX_PER_HOUR:
        raise ValueError(f"Hourly email limit ({settings.EMAIL_MAX_PER_HOUR}) reached.")

    msg = EmailMessage()
    msg["From"] = settings.GMAIL_ADDRESS or "policyguard@localhost"
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject[:200]
    msg.set_content(f"{body}\n\n--\nSent by a PolicyGuard-AI agent on behalf of {sender_label}.")
    for path in attachments:
        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        msg.add_attachment(path.read_bytes(), maintype=maintype, subtype=subtype, filename=path.name)

    if mode == "gmail":
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ssl.create_default_context(), timeout=20) as smtp:
            smtp.login(settings.GMAIL_ADDRESS, settings.GMAIL_APP_PASSWORD)
            smtp.send_message(msg)

    now = datetime.now(timezone.utc)
    OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
    (OUTBOX_DIR / f"{now.strftime('%Y%m%dT%H%M%S%f')}.json").write_text(json.dumps({
        "mode": mode, "sent_at": now.isoformat(), "to": recipients, "subject": subject, "body": body,
        "attachments": [p.name for p in attachments], "on_behalf_of": sender_label,
    }, indent=2), encoding="utf-8")

    return {"mode": mode, "to": recipients, "attachments": [p.name for p in attachments],
            "note": "Delivered via Gmail." if mode == "gmail" else "Gmail not configured: saved to local outbox only."}
