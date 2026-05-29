from __future__ import annotations

from platform.database.models import Base

from sqlalchemy.ext.asyncio import AsyncEngine


async def migrate(engine: AsyncEngine) -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
