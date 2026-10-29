"""The agents' business database (schema `biz`), accessed ONLY through two
least-privilege Postgres roles:

  agent_reader : SELECT on biz.*, read-only transaction, 5s timeout
  agent_writer : INSERT/UPDATE on tickets, notes, orders; DELETE on tickets, notes

So even if every other check failed, the database itself refuses to let an
agent read PolicyGuard's own tables (users, password hashes) or drop tables.
"""
import re
from decimal import Decimal
from datetime import date, datetime
from typing import Any

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url

from apps.api.settings import AGENT_DB_READER_PASSWORD, AGENT_DB_WRITER_PASSWORD, DATABASE_URL

WRITABLE = {"insert": {"tickets", "notes", "orders"}, "update": {"tickets", "notes", "orders"},
            "delete": {"tickets", "notes"}}
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAX_ROWS = 100


def _conninfo(user: str, password: str) -> str:
    url = make_url(DATABASE_URL).set(drivername="postgresql", username=user, password=password)
    return url.render_as_string(hide_password=False)


def _jsonable(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def query(statement: str) -> dict[str, Any]:
    stmt = statement.strip().rstrip(";").strip()
    if not re.match(r"(?is)^(select|with)\b", stmt) or ";" in stmt:
        raise ValueError("Only a single SELECT (or WITH ... SELECT) statement is allowed.")
    with psycopg.connect(_conninfo("agent_reader", AGENT_DB_READER_PASSWORD), connect_timeout=5) as conn:
        conn.read_only = True
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SET search_path TO biz")
            cur.execute(stmt)
            columns = [c.name for c in cur.description] if cur.description else []
            rows = cur.fetchmany(MAX_ROWS)
    return {"columns": columns, "rows": [[_jsonable(v) for v in r] for r in rows], "row_count": len(rows),
            "truncated": len(rows) == MAX_ROWS}


def write(table: str, operation: str, row_id: int | None, values: dict[str, Any]) -> dict[str, Any]:
    operation = (operation or "insert").lower()
    if operation not in WRITABLE:
        raise ValueError("operation must be insert, update or delete")
    if table not in WRITABLE[operation]:
        raise ValueError(f"'{operation}' is not permitted on table '{table}'. Allowed: {sorted(WRITABLE[operation])}")
    for column in values:
        if not IDENT_RE.match(column) or column == "id":
            raise ValueError(f"Invalid column '{column}'")
    target = sql.Identifier("biz", table)

    with psycopg.connect(_conninfo("agent_writer", AGENT_DB_WRITER_PASSWORD), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            if operation == "insert":
                if not values:
                    raise ValueError("insert needs values")
                q = sql.SQL("INSERT INTO {} ({}) VALUES ({}) RETURNING id").format(
                    target, sql.SQL(", ").join(map(sql.Identifier, values)),
                    sql.SQL(", ").join(sql.Placeholder() * len(values)))
                cur.execute(q, list(values.values()))
                return {"operation": "insert", "table": table, "id": cur.fetchone()[0]}
            if row_id is None:
                raise ValueError(f"{operation} requires a row id")
            if operation == "update":
                if not values:
                    raise ValueError("update needs values")
                q = sql.SQL("UPDATE {} SET {} WHERE id = %s").format(
                    target, sql.SQL(", ").join(sql.SQL("{} = %s").format(sql.Identifier(c)) for c in values))
                cur.execute(q, [*values.values(), row_id])
            else:
                cur.execute(sql.SQL("DELETE FROM {} WHERE id = %s").format(target), [row_id])
            if cur.rowcount == 0:
                raise ValueError(f"No row with id {row_id} in {table}")
            return {"operation": operation, "table": table, "id": row_id, "rows_affected": cur.rowcount}
