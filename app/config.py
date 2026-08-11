"""
CERBERUS V4 - Configuración
"""

import os
from typing import List, Optional

class Settings:
    # ============================================
    # ENTORNO
    # ============================================
    CERBERUS_ENV = os.getenv("CERBERUS_ENV", "production")
    CERBERUS_DEBUG = os.getenv("CERBERUS_DEBUG", "false").lower() == "true"
    
    # ============================================
    # SEGURIDAD
    # ============================================
    CERBERUS_DRY_RUN = os.getenv("CERBERUS_DRY_RUN", "false").lower() == "true"
    CERBERUS_FAIL_CLOSED = os.getenv("CERBERUS_FAIL_CLOSED", "true").lower() == "true"
    
    # ============================================
    # PROXIES CONFIABLES
    # ============================================
    CERBERUS_TRUST_PROXY_HEADERS = os.getenv("CERBERUS_TRUST_PROXY_HEADERS", "false").lower() == "true"
    CERBERUS_TRUSTED_PROXIES = [p.strip() for p in os.getenv("CERBERUS_TRUSTED_PROXIES", "").split(",") if p.strip()]
    
    # ============================================
    # RATE LIMITING
    # ============================================
    CERBERUS_RATE_LIMIT_ENABLED = os.getenv("CERBERUS_RATE_LIMIT_ENABLED", "true").lower() == "true"
    CERBERUS_RATE_LIMIT_REQUESTS = int(os.getenv("CERBERUS_RATE_LIMIT_REQUESTS", "100"))
    CERBERUS_RATE_LIMIT_WINDOW = int(os.getenv("CERBERUS_RATE_LIMIT_WINDOW", "60"))
    
    # ============================================
    # BASE DE DATOS
    # ============================================
    CERBERUS_DATABASE_URL = (
        os.getenv("CERBERUS_DATABASE_URL") or
        os.getenv("DATABASE_URL") or
        "sqlite+aiosqlite:///./cerberus.db"
    )
    
    # ============================================
    # API KEYS
    # ============================================
    CERBERUS_API_KEY = os.getenv("CERBERUS_API_KEY", "")
    CERBERUS_API_KEYS = [k.strip() for k in os.getenv("CERBERUS_API_KEYS", "").split(",") if k.strip()]
    CERBERUS_API_KEY_HEADER = os.getenv("CERBERUS_API_KEY_HEADER", "X-API-Key")
    CERBERUS_API_KEY_ROTATION_INTERVAL = int(os.getenv("CERBERUS_API_KEY_ROTATION_INTERVAL", "90"))
    
    # ============================================
    # CORS
    # ============================================
    CERBERUS_ALLOWED_ORIGINS = [o.strip() for o in os.getenv("CERBERUS_ALLOWED_ORIGINS", "").split(",") if o.strip()]
    CERBERUS_ALLOWED_METHODS = os.getenv("CERBERUS_ALLOWED_METHODS", "GET,POST,PUT,DELETE,OPTIONS").split(",")
    CERBERUS_ALLOWED_HEADERS = os.getenv("CERBERUS_ALLOWED_HEADERS", "Content-Type,Authorization,X-API-Key,X-Request-ID").split(",")
    
    # ============================================
    # API
    # ============================================
    CERBERUS_API_HOST = os.getenv("CERBERUS_API_HOST", "0.0.0.0")
    CERBERUS_API_PORT = int(os.getenv("CERBERUS_API_PORT", "8000"))
    CERBERUS_API_WORKERS = int(os.getenv("CERBERUS_API_WORKERS", "4"))
    
    # ============================================
    # ENFORCEMENT
    # ============================================
    CERBERUS_BLOCK_DEFAULT_DURATION = int(os.getenv("CERBERUS_BLOCK_DEFAULT_DURATION", "30"))
    CERBERUS_RATE_LIMIT_BLOCK_DURATION = int(os.getenv("CERBERUS_RATE_LIMIT_BLOCK_DURATION", "300"))
    
    # ============================================
    # REDIS
    # ============================================
    CERBERUS_REDIS_URL = os.getenv("CERBERUS_REDIS_URL", "")
    CERBERUS_REDIS_PASSWORD = os.getenv("CERBERUS_REDIS_PASSWORD", "")
    CERBERUS_REDIS_DB = int(os.getenv("CERBERUS_REDIS_DB", "0"))
    
    # ============================================
    # CLAVES CRIPTOGRÁFICAS
    # ============================================
    CERBERUS_PRIVATE_KEY_B64 = os.getenv("CERBERUS_PRIVATE_KEY_B64", "")
    CERBERUS_PUBLIC_KEY_B64 = os.getenv("CERBERUS_PUBLIC_KEY_B64", "")
    
    # ============================================
    # LOGGING
    # ============================================
    CERBERUS_LOG_LEVEL = os.getenv("CERBERUS_LOG_LEVEL", "INFO")

settings = Settings()