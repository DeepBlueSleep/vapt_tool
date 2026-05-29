from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine


@dataclass(frozen=True)
class DatabaseSettings:
    url: str = "sqlite+aiosqlite:///./platform.db"
    echo: bool = False


def create_session_factory(settings: DatabaseSettings | None = None) -> async_sessionmaker[AsyncSession]:
    settings = settings or DatabaseSettings()
    engine: AsyncEngine = create_async_engine(settings.url, echo=settings.echo, future=True)
    return async_sessionmaker(engine, expire_on_commit=False)
