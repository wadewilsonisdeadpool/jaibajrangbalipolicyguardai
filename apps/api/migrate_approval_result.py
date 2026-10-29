from sqlalchemy import text

from apps.api.database import engine


with engine.begin() as connection:
    connection.execute(
        text(
            """
            ALTER TABLE approval_requests
            ADD COLUMN IF NOT EXISTS execution_result JSONB;
            """
        )
    )

print("approval_requests execution_result migration completed")