"""All runtime configuration in one place, loaded from apps/api/.env."""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql+psycopg://policyguard:policyguard_dev@localhost:5432/policyguard"
)

# Least-privilege Postgres roles used ONLY by the agent database tools.
AGENT_DB_READER_PASSWORD = os.getenv("AGENT_DB_READER_PASSWORD", "agent_reader_dev")
AGENT_DB_WRITER_PASSWORD = os.getenv("AGENT_DB_WRITER_PASSWORD", "agent_writer_dev")

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.5:9b")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_THINK = os.getenv("OLLAMA_THINK", "").strip().lower()  # "", "true" or "false"
ROUTER_MODE = os.getenv("ROUTER_MODE", "hybrid")  # hybrid | keyword | llm

# Gmail (real delivery). Needs a Google App Password, not your normal password.
GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS", "").strip()
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "").replace(" ", "").strip()
EMAIL_MAX_PER_HOUR = int(os.getenv("EMAIL_MAX_PER_HOUR", "10"))
EMAIL_TRUSTED_DOMAINS = {
    d.strip().lower() for d in os.getenv("EMAIL_TRUSTED_DOMAINS", "").split(",") if d.strip()
}

MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "10"))

OPENWEATHER_API_KEY = os.getenv("OPENWEATHER_API_KEY", "").strip()


def email_mode() -> str:
    return "gmail" if GMAIL_ADDRESS and GMAIL_APP_PASSWORD else "outbox"
