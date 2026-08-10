"""
Configuración completa de CERBERUS
"""

from pydantic_settings import BaseSettings
from pydantic import Field, validator
from typing import Optional, List
import os

class Settings(BaseSettings):
    """Configuración completa de CERBERUS"""
    
    # ==========================================
    # ENTORNO
    # ==========================================
    CERBERUS_ENV: str = Field("development", env="CERBERUS_ENV")
    CERBERUS_LOG_LEVEL: str = Field("INFO", env="CERBERUS_LOG_LEVEL")
    CERBERUS_DEBUG: bool = Field(False, env="CERBERUS_DEBUG")
    
    # ==========================================
    # BASE DE DATOS
    # ==========================================
    CERBERUS_DATABASE_URL: str = Field(
        "postgresql+psycopg://cerberus:cerberus@localhost:5432/cerberus",
        env="CERBERUS_DATABASE_URL"
    )
    CERBERUS_DATABASE_POOL_SIZE: int = Field(10, env="CERBERUS_DATABASE_POOL_SIZE")
    CERBERUS_DATABASE_MAX_OVERFLOW: int = Field(20, env="CERBERUS_DATABASE_MAX_OVERFLOW")
    
    # ==========================================
    # REDIS
    # ==========================================
    CERBERUS_REDIS_URL: str = Field(
        "redis://localhost:6379/0",
        env="CERBERUS_REDIS_URL"
    )
    CERBERUS_REDIS_PASSWORD: Optional[str] = Field(None, env="CERBERUS_REDIS_PASSWORD")
    CERBERUS_REDIS_SSL: bool = Field(False, env="CERBERUS_REDIS_SSL")
    
    # ==========================================
    # CRIPTOGRAFÍA
    # ==========================================
    CERBERUS_PRIVATE_KEY_B64: str = Field(..., env="CERBERUS_PRIVATE_KEY_B64")
    CERBERUS_PUBLIC_KEY_B64: str = Field(..., env="CERBERUS_PUBLIC_KEY_B64")
    CERBERUS_KEY_ROTATION_DAYS: int = Field(90, env="CERBERUS_KEY_ROTATION_DAYS")
    
    # ==========================================
    # SEGURIDAD
    # ==========================================
    CERBERUS_APPROVAL_TTL_SECONDS: int = Field(300, env="CERBERUS_APPROVAL_TTL_SECONDS")
    CERBERUS_RATE_LIMIT_ENABLED: bool = Field(True, env="CERBERUS_RATE_LIMIT_ENABLED")
    CERBERUS_FAIL_CLOSED: bool = Field(True, env="CERBERUS_FAIL_CLOSED")
    CERBERUS_DRY_RUN: bool = Field(True, env="CERBERUS_DRY_RUN")
    CERBERUS_MAX_BLOCKS_PER_MINUTE: int = Field(100, env="CERBERUS_MAX_BLOCKS_PER_MINUTE")
    CERBERUS_MAX_ISOLATIONS_PER_HOUR: int = Field(10, env="CERBERUS_MAX_ISOLATIONS_PER_HOUR")
    
    # ==========================================
    # AUDITORÍA
    # ==========================================
    CERBERUS_AUDIT_RETENTION_DAYS: int = Field(365, env="CERBERUS_AUDIT_RETENTION_DAYS")
    CERBERUS_AUDIT_WORM_STORAGE: str = Field("local", env="CERBERUS_AUDIT_WORM_STORAGE")
    CERBERUS_AUDIT_WORM_BUCKET: str = Field("cerberus-audit-logs", env="CERBERUS_AUDIT_WORM_BUCKET")
    
    # ==========================================
    # DISTRIBUCIÓN
    # ==========================================
    CERBERUS_KAFKA_BOOTSTRAP_SERVERS: str = Field(
        "kafka:9092",
        env="CERBERUS_KAFKA_BOOTSTRAP_SERVERS"
    )
    CERBERUS_KAFKA_TOPIC: str = Field(
        "cerberus-policies",
        env="CERBERUS_KAFKA_TOPIC"
    )
    CERBERUS_ETCD_ENDPOINTS: str = Field(
        "etcd:2379",
        env="CERBERUS_ETCD_ENDPOINTS"
    )
    
    # ==========================================
    # MONITOREO
    # ==========================================
    CERBERUS_METRICS_ENABLED: bool = Field(True, env="CERBERUS_METRICS_ENABLED")
    CERBERUS_METRICS_PORT: int = Field(9090, env="CERBERUS_METRICS_PORT")
    CERBERUS_ALERT_WEBHOOK_URL: Optional[str] = Field(None, env="CERBERUS_ALERT_WEBHOOK_URL")
    
    # ==========================================
    # API
    # ==========================================
    CERBERUS_API_HOST: str = Field("0.0.0.0", env="CERBERUS_API_HOST")
    CERBERUS_API_PORT: int = Field(8000, env="CERBERUS_API_PORT")
    CERBERUS_API_WORKERS: int = Field(4, env="CERBERUS_API_WORKERS")
    
    @validator("CERBERUS_LOG_LEVEL")
    def validar_log_level(cls, v):
        niveles = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v not in niveles:
            raise ValueError(f"Log level debe ser: {niveles}")
        return v
    
    @property
    def is_production(self) -> bool:
        return self.CERBERUS_ENV == "production"
    
    @property
    def is_development(self) -> bool:
        return self.CERBERUS_ENV == "development"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True

# Instancia global
settings = Settings()