"""One-time, idempotent migration to schema v2. Safe to run repeatedly.

create_all() only creates *missing tables*; it never adds columns to
existing ones. This adds the new columns in place so no data is lost.

Run from the repo root:  python -m apps.api.migrate_v2
"""
from sqlalchemy import text

from apps.api.database import engine
from apps.api.models import Base

ALTERS = [
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS description VARCHAR(500)",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS allowed_tools JSON",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS run_id VARCHAR(64)",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS arguments JSON",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS rule VARCHAR(50)",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS reasons JSON",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS factors JSON",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS trust_before DOUBLE PRECISION",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS tainted BOOLEAN",
    "CREATE INDEX IF NOT EXISTS ix_security_events_run_id ON security_events (run_id)",
    "ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS run_id VARCHAR(64)",
    "ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS reasons JSON",
    "ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS decided_by VARCHAR(255)",
    "ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS decided_at TIMESTAMP",
]


def migrate() -> None:
    Base.metadata.create_all(bind=engine)  # creates agent_runs (and anything else missing)
    with engine.begin() as conn:
        for statement in ALTERS:
            conn.execute(text(statement))


if __name__ == "__main__":
    migrate()
    print("PolicyGuard schema migrated to v2.")
