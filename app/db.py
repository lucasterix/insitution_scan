from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()

engine = create_async_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


async def init_db() -> None:
    from app import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Ad-hoc migrations for columns added after the initial table
        # creation. ADD COLUMN IF NOT EXISTS is Postgres 9.6+.
        for ddl in (
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS ownership_confirmed BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS deep_scan BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS rate_limit_test BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS context JSON",
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS read_at TIMESTAMPTZ",
            "CREATE INDEX IF NOT EXISTS ix_messages_read_at ON messages (read_at)",
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS bot_action VARCHAR(16)",
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS bot_processed_at TIMESTAMPTZ",
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS bot_confidence REAL",
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS bot_reasoning TEXT",
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS bot_draft_text TEXT",
            "CREATE INDEX IF NOT EXISTS ix_messages_bot_action ON messages (bot_action)",
            # scan_episodes table is created by create_all above; the unique
            # index is declared in the model. Nothing extra needed here.
        ):
            await conn.execute(text(ddl))

        # User table columns are created by Base.metadata.create_all already.
        # No migrations needed yet.
