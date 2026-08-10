"""
CERBERUS V4 - Base de datos
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

# ============================================
# BASE PARA MODELOS SQLAlchemy
# ============================================

Base = declarative_base()

# ============================================
# ENGINE
# ============================================

if settings.CERBERUS_DATABASE_URL.startswith("sqlite"):
    engine = create_async_engine(
        settings.CERBERUS_DATABASE_URL,
        echo=settings.CERBERUS_DEBUG,
        connect_args={"check_same_thread": False}
    )
else:
    engine = create_async_engine(
        settings.CERBERUS_DATABASE_URL,
        echo=settings.CERBERUS_DEBUG,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
    )

AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# ============================================
# DEPENDENCIAS
# ============================================

async def get_db():
    """Obtener sesión de base de datos (dependencia FastAPI)"""
    async with AsyncSessionLocal() as session:
        yield session

async def check_database_health() -> bool:
    """Verifica la salud de la base de datos"""
    try:
        async with AsyncSessionLocal() as session:
            await session.execute("SELECT 1")
            return True
    except Exception as e:
        return False