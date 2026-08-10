"""
CERBERUS V4 - Configuración
"""

import os
from typing import List

class Settings:
    # Entorno
    CERBERUS_ENV = os.getenv("CERBERUS_ENV", "production")
    CERBERUS_DEBUG = os.getenv("CERBERUS_DEBUG", "false").lower() == "true"
    
    # Seguridad
    CERBERUS_DRY_RUN = os.getenv("CERBERUS_DRY_RUN", "false").lower() == "true"
    CERBERUS_FAIL_CLOSED = os.getenv("CERBERUS_FAIL_CLOSED", "true").lower() == "true"
    
    # Rate Limiting
    CERBERUS_RATE_LIMIT_ENABLED = os.getenv("CERBERUS_RATE_LIMIT_ENABLED", "true").lower() == "true"
    CERBERUS_RATE_LIMIT_REQUESTS = int(os.getenv("CERBERUS_RATE_LIMIT_REQUESTS", "100"))
    CERBERUS_RATE_LIMIT_WINDOW = int(os.getenv("CERBERUS_RATE_LIMIT_WINDOW", "60"))
    
    # Base de datos
    CERBERUS_DATABASE_URL = os.getenv("CERBERUS_DATABASE_URL", "sqlite+aiosqlite:///./cerberus.db")
    
    # API Keys
    CERBERUS_API_KEYS = [k.strip() for k in os.getenv("CERBERUS_API_KEYS", "").split(",") if k.strip()]
    CERBERUS_API_KEY_ROTATION_INTERVAL = int(os.getenv("CERBERUS_API_KEY_ROTATION_INTERVAL", "90"))
    
    # CORS - Seguro (sin wildcards en producción)
    CERBERUS_ALLOWED_ORIGINS = [o.strip() for o in os.getenv("CERBERUS_ALLOWED_ORIGINS", "").split(",") if o.strip()]
    CERBERUS_ALLOWED_METHODS = os.getenv("CERBERUS_ALLOWED_METHODS", "POST").split(",")
    CERBERUS_ALLOWED_HEADERS = os.getenv("CERBERUS_ALLOWED_HEADERS", "X-API-Key,Content-Type").split(",")
    
    # API
    CERBERUS_API_HOST = os.getenv("CERBERUS_API_HOST", "0.0.0.0")
    CERBERUS_API_PORT = int(os.getenv("CERBERUS_API_PORT", "8000"))
    CERBERUS_API_WORKERS = int(os.getenv("CERBERUS_API_WORKERS", "1"))
    
    # Enforcement
    CERBERUS_BLOCK_DEFAULT_DURATION = int(os.getenv("CERBERUS_BLOCK_DEFAULT_DURATION", "30"))
    
    # Redis (opcional)
    CERBERUS_REDIS_URL = os.getenv("CERBERUS_REDIS_URL", "")

settings = Settings()