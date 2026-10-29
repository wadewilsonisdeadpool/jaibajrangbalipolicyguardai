"""Schema v3 migration: trust v3 columns, chat tables, and the business
database with least-privilege roles for the agent DB tools. Idempotent.

Run from the repo root:  python -m apps.api.migrate_v3
"""
from sqlalchemy import text

from apps.api.database import engine
from apps.api.migrate_v2 import ALTERS as V2_ALTERS
from apps.api.models import Base
from apps.api.settings import AGENT_DB_READER_PASSWORD, AGENT_DB_WRITER_PASSWORD

V3_ALTERS = [
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS trust_pos DOUBLE PRECISION DEFAULT 0",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS trust_neg DOUBLE PRECISION DEFAULT 0",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS trust_updated_at TIMESTAMP",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS quarantined_until TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS trust_score DOUBLE PRECISION DEFAULT 0.8",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS trust_pos DOUBLE PRECISION DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS trust_neg DOUBLE PRECISION DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS trust_updated_at TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS flagged BOOLEAN DEFAULT FALSE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_until TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS suspension_reason VARCHAR(255)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER DEFAULT 0",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS user_id INTEGER",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS conversation_id VARCHAR(64)",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS destination VARCHAR(30)",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS content_findings JSON",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS request_risk DOUBLE PRECISION",
    "ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS context JSON",
    # Trust v3 replaces the old EWMA number: start everyone from the prior.
    "UPDATE agents SET trust_pos = 0, trust_neg = 0, trust_score = 0.8 WHERE trust_updated_at IS NULL",
    "UPDATE users SET trust_pos = 0, trust_neg = 0, trust_score = 0.8, token_version = COALESCE(token_version, 0) WHERE trust_updated_at IS NULL",
]

BUSINESS_SCHEMA = [
    "CREATE SCHEMA IF NOT EXISTS biz",
    """CREATE TABLE IF NOT EXISTS biz.customers (
        id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, company TEXT,
        plan TEXT, region TEXT, created_at TIMESTAMP DEFAULT now())""",
    """CREATE TABLE IF NOT EXISTS biz.orders (
        id SERIAL PRIMARY KEY, customer_id INTEGER REFERENCES biz.customers(id),
        product TEXT NOT NULL, amount NUMERIC(10,2) NOT NULL, status TEXT DEFAULT 'paid',
        created_at TIMESTAMP DEFAULT now())""",
    """CREATE TABLE IF NOT EXISTS biz.tickets (
        id SERIAL PRIMARY KEY, customer_id INTEGER REFERENCES biz.customers(id),
        subject TEXT NOT NULL, status TEXT DEFAULT 'open', priority TEXT DEFAULT 'medium',
        created_at TIMESTAMP DEFAULT now())""",
    """CREATE TABLE IF NOT EXISTS biz.notes (
        id SERIAL PRIMARY KEY, author TEXT, content TEXT NOT NULL, created_at TIMESTAMP DEFAULT now())""",
]

SEED_SQL = [
    """INSERT INTO biz.customers (name, email, company, plan, region) VALUES
        ('Asha Verma','asha@example.com','Verma Textiles','enterprise','APAC'),
        ('Liam Carter','liam@example.com','Carter Logistics','pro','EMEA'),
        ('Mei Tanaka','mei@example.com','Tanaka Design','free','APAC'),
        ('Diego Ruiz','diego@example.com','Ruiz Foods','pro','AMER'),
        ('Sara Okafor','sara@example.com','Okafor Health','enterprise','EMEA'),
        ('Rohan Iyer','rohan@example.com','Iyer Fintech','pro','APAC'),
        ('Emma Schultz','emma@example.com','Schultz Automotive','enterprise','EMEA'),
        ('Kenji Mori','kenji@example.com','Mori Robotics','pro','APAC'),
        ('Priya Nair','priya@example.com','Nair Pharma','enterprise','APAC'),
        ('Noah Williams','noah@example.com','Williams Retail','free','AMER')""",
    """INSERT INTO biz.orders (customer_id, product, amount, status) VALUES
        (1,'Enterprise licence',12000,'paid'),(2,'Pro licence',2400,'paid'),(4,'Pro licence',2400,'refunded'),
        (5,'Enterprise licence',12000,'paid'),(6,'Pro licence',2400,'paid'),(7,'Enterprise licence',12000,'pending'),
        (8,'Pro licence',2400,'paid'),(9,'Enterprise licence',12000,'paid'),(1,'Support add-on',1800,'paid'),
        (5,'Support add-on',1800,'pending')""",
    """INSERT INTO biz.tickets (customer_id, subject, status, priority) VALUES
        (1,'SSO login failing','open','high'),(2,'Invoice mismatch','open','medium'),
        (4,'API rate limit question','closed','low'),(5,'Data export request','open','high'),
        (7,'Onboarding for new team','open','medium'),(9,'Audit log retention','closed','low')""",
]


def _role_sql(name: str, password: str) -> str:
    pw = password.replace("'", "''")
    return (
        f"DO $body$ BEGIN "
        f"IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{name}') THEN "
        f"CREATE ROLE {name} LOGIN PASSWORD '{pw}'; "
        f"ELSE ALTER ROLE {name} LOGIN PASSWORD '{pw}'; END IF; END $body$"
    )


GRANTS = [
    "GRANT USAGE ON SCHEMA biz TO agent_reader, agent_writer",
    "GRANT SELECT ON ALL TABLES IN SCHEMA biz TO agent_reader, agent_writer",
    "GRANT INSERT, UPDATE ON biz.tickets, biz.notes, biz.orders TO agent_writer",
    "GRANT DELETE ON biz.tickets, biz.notes TO agent_writer",
    "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA biz TO agent_writer",
    # The agent roles get NOTHING on PolicyGuard's own tables (users, events, ...).
    "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM agent_reader, agent_writer",
]


def migrate() -> None:
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        for statement in V2_ALTERS + V3_ALTERS + BUSINESS_SCHEMA:
            conn.execute(text(statement))
        if conn.execute(text("SELECT COUNT(*) FROM biz.customers")).scalar() == 0:
            for statement in SEED_SQL:
                conn.execute(text(statement))
        conn.execute(text(_role_sql("agent_reader", AGENT_DB_READER_PASSWORD)))
        conn.execute(text(_role_sql("agent_writer", AGENT_DB_WRITER_PASSWORD)))
        for statement in GRANTS:
            conn.execute(text(statement))


if __name__ == "__main__":
    migrate()
    print("PolicyGuard schema migrated to v3 (trust v3, chat, business DB + least-privilege roles).")
