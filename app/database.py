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
# ENGINE
# ============================================================

database_url = settings.CERBERUS_DATABASE_URL

if database_url.startswith("sqlite"):
    engine = create_async_engine(
        database_url,
        echo=settings.CERBERUS_DEBUG,
        connect_args={
            "check_same_thread": False
        },
    )

else:
    engine = create_async_engine(
        database_url,
        echo=settings.CERBERUS_DEBUG,
        pool_pre_ping=True,
        pool_size=5,
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
# DATABASE HEALTH - ✅ CORREGIDO CON LOGGING
# ============================================================

async def check_database_health() -> bool:
    """
    Comprueba que la base de datos esté disponible.
    Compatible con SQLAlchemy 2.x.
    """
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("SELECT 1"))
            val = result.scalar()
            print(f"✅ DB Health Check: SELECT 1 = {val}")
            return val == 1
    except Exception as e:
        print(f"❌ DB Health Check ERROR: {e}")
        return False