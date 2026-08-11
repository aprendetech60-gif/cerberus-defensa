"""
CERBERUS V4 - Base de datos
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

Base = declarative_base()

def normalize_async_database_url(url: str) -> str:
    """Normaliza la URL para usar asyncpg."""
    url = url.strip()
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql+psycopg2://"):
        url = url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url

database_url = settings.CERBERUS_DATABASE_URL

if database_url.startswith("sqlite"):
    engine = create_async_engine(
        database_url,
        echo=settings.CERBERUS_DEBUG,
        connect_args={"check_same_thread": False},
    )
else:
    engine = create_async_engine(
        normalize_async_database_url(database_url),
        echo=settings.CERBERUS_DEBUG,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=10,
    )

AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def check_database_health() -> bool:
    """Verifica que la base de datos esté disponible."""
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("SELECT 1"))
            return result.scalar() == 1
    except Exception:
        return False