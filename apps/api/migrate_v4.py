"""Schema v4: soft-deletable chats and per-chat data sensitivity. Idempotent.

Run from the repo root:  python -m apps.api.migrate_v4
"""
from sqlalchemy import text

from apps.api.database import engine
from apps.api.models import Base

ALTERS = [
    "ALTER TABLE conversations ADD COLUMN IF NOT EXISTS data_level INTEGER DEFAULT 0",
    "ALTER TABLE conversations ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP",
]


def migrate() -> None:
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        for statement in ALTERS:
            conn.execute(text(statement))


if __name__ == "__main__":
    migrate()
    print("PolicyGuard schema migrated to v4 (chat delete + data sensitivity).")
