import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Load the .env file located at: apps/api/.env
ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(ENV_PATH)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://policyguard:policyguard_dev@localhost:5432/policyguard",
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    """FastAPI dependency: yields a session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()