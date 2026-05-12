from collections.abc import AsyncGenerator
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.core.logging import logger

settings = get_settings()
engine = create_async_engine(settings.database_url, pool_pre_ping=True, future=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def run_migrations() -> None:
    migration_path = Path(__file__).resolve().parents[2] / "migrations" / "001_init.sql"
    if not migration_path.exists():
        logger.warning("migration_file_missing", path=str(migration_path))
        return
    sql = migration_path.read_text(encoding="utf-8")
    async with engine.begin() as connection:
        for statement in sql.split(";"):
            cleaned = statement.strip()
            if cleaned:
                await connection.exec_driver_sql(cleaned)
    logger.info("database_migrations_applied", path=str(migration_path))
