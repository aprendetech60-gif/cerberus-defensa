"""
CERBERUS V4 - Base de datos
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import settings


# ============================================================
# BASE SQLALCHEMY
# ============================================================

Base = declarative_base()


# ============================================================
# NORMALIZADOR DE URL PARA ASYNC DRIVER
# ============================================================

def normalize_async_database_url(url: str) -> str:
    """
    Normaliza la URL de base de datos para usar asyncpg con SQLAlchemy async.
    """
    url = url.strip()
    
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql+psycopg2://"):
        url = url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    
    return url


# ============================================================
# ENGINE
# ============================================================

database_url = settings.CERBERUS_DATABASE_URL

if database_url.startswith("sqlite"):
    engine = create_async_engine(
        database_url,
        echo=settings.CERBERUS_DEBUG,
        connect_args={"check_same_thread": False},
    )
else:
    async_database_url = normalize_async_database_url(database_url)
    
    engine = create_async_engine(
        async_database_url,
        echo=settings.CERBERUS_DEBUG,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=10,
    )


# ============================================================
# SESSION FACTORY
# ============================================================

AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ============================================================
# DATABASE DEPENDENCY
# ============================================================

async def get_db():
    """Obtiene una sesión de base de datos."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


# ============================================================
# DATABASE HEALTH
# ============================================================

async def check_database_health() -> bool:
    """
    Comprueba que la base de datos esté disponible.
    """
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("SELECT 1"))
            return result.scalar() == 1
    except Exception:
        return False