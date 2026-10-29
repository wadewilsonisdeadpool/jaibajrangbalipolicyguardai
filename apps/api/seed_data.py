"""Seeds agents + tool catalog and prepares the workspace. Safe to re-run:
existing agents keep their trust history, but role/allowlist are synced.

Run from the repo root:  python -m apps.api.seed_data
"""
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.database import engine
from apps.api.models import Agent, Tool
from apps.api.tool_registry import TOOLS
from apps.api.workspace import ensure_workspace

AGENT_PROFILES = [
    {
        "name": "Qwen Research Agent",
        "role": "Research & Documents Assistant",
        "description": "Reads documents and web pages, checks the weather, and produces summaries, reports and edited copies of files.",
        "allowed_tools": ["file_reader", "create_document", "modify_file_copy", "web_fetch", "weather_lookup", "handoff_to_agent"],
    },
    {
        "name": "Data Analyst Agent",
        "role": "Business Data Analyst",
        "description": "Answers questions from the business database, records tickets and notes, and exports results as files.",
        "allowed_tools": ["database_query", "database_writer", "file_reader", "create_document", "modify_file_copy", "handoff_to_agent"],
    },
    {
        "name": "Operations Agent",
        "role": "Operations & Communications Assistant",
        "description": "Sends emails (with files created in the chat) and handles operational requests.",
        "allowed_tools": ["email_sender", "file_reader", "create_document", "admin_shell", "handoff_to_agent"],
    },
]


def seed_database() -> None:
    ensure_workspace()
    with Session(engine) as session:
        for profile in AGENT_PROFILES:
            agent = session.scalar(select(Agent).where(Agent.name == profile["name"]))
            if agent is None:
                session.add(Agent(trust_score=0.8, trust_pos=0.0, trust_neg=0.0, is_active=True, **profile))
            else:
                agent.role, agent.description, agent.allowed_tools = profile["role"], profile["description"], profile["allowed_tools"]

        for tool in session.scalars(select(Tool)).all():
            tool.is_active = tool.name in TOOLS
        for name, definition in TOOLS.items():
            tool = session.scalar(select(Tool).where(Tool.name == name))
            if tool is None:
                session.add(Tool(name=name, description=definition["description"][:500],
                                 sensitivity=definition["sensitivity"], is_active=True))
            else:
                tool.description, tool.sensitivity = definition["description"][:500], definition["sensitivity"]
        session.commit()


if __name__ == "__main__":
    seed_database()
    print(f"PolicyGuard seeded: {len(AGENT_PROFILES)} agents, {len(TOOLS)} tools, workspace ready.")
