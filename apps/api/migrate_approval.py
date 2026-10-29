from sqlalchemy import text

from apps.api.database import engine


with engine.begin() as connection:
    connection.execute(
        text(
            """
            ALTER TABLE approval_requests
            ADD COLUMN IF NOT EXISTS arguments JSONB;
            """
        )
    )

    connection.execute(
        text(
            """
            UPDATE approval_requests
            SET arguments = '{"table": "users"}'::jsonb
            WHERE id = 1 AND arguments IS NULL;
            """
        )
    )

    connection.execute(
        text(
            """
            ALTER TABLE approval_requests
            ALTER COLUMN arguments SET NOT NULL;
            """
        )
    )

print("approval_requests migration completed")