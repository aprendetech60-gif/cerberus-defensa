"""
Modelos de base de datos para CERBERUS
"""

from sqlalchemy import (
    Column, Integer, String, DateTime, Float, Boolean,
    Text, JSON, Index, UniqueConstraint, BigInteger,
    ForeignKey
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime, timezone
import uuid

Base = declarative_base()

# ============================================
# AUDITORÍA - HASH CHAIN
# ============================================

class AuditRecord(Base):
    """Registro de auditoría con hash chain"""
    __tablename__ = "audit_records"
    
    id = Column(Integer, primary_key=True)
    event_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    source = Column(String(100), nullable=False)
    event_type = Column(String(100), nullable=False)
    payload = Column(JSON, nullable=False)
    
    # Hash chain
    previous_hash = Column(String(64))
    hash = Column(String(64), nullable=False)
    signature = Column(String(128), nullable=False)
    
    # Metadatos
    ip = Column(String(45))
    user_id = Column(String(100))
    execution_id = Column(String(36))
    
    __table_args__ = (
        Index('idx_audit_timestamp', timestamp.desc()),
        Index('idx_audit_event_type', event_type),
        Index('idx_audit_execution', execution_id),
        Index('idx_audit_user', user_id),
        UniqueConstraint('event_id'),
    )

# ============================================
# APROBACIONES HUMANAS
# ============================================

class ApprovalRequest(Base):
    """Solicitud de aprobación humana"""
    __tablename__ = "approval_requests"
    
    id = Column(Integer, primary_key=True)
    approval_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    execution_id = Column(String(36), nullable=False)
    action = Column(String(50), nullable=False)
    context = Column(JSON, nullable=False)
    policy_version = Column(Integer, nullable=False)
    
    status = Column(String(20), nullable=False, default="PENDING")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    approved_by = Column(String(100))
    approved_at = Column(DateTime(timezone=True))
    denial_reason = Column(Text)
    
    __table_args__ = (
        Index('idx_approval_execution', execution_id),
        Index('idx_approval_status', status),
        Index('idx_approval_created', created_at.desc()),
        UniqueConstraint('approval_id'),
    )

# ============================================
# EJECUCIÓN - IDEMPOTENCIA
# ============================================

class ExecutionRecord(Base):
    """Registro de ejecución para idempotencia"""
    __tablename__ = "execution_records"
    
    id = Column(Integer, primary_key=True)
    execution_id = Column(String(36), unique=True, nullable=False)
    action = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False)
    context = Column(JSON, nullable=False)
    result = Column(JSON)
    error = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    __table_args__ = (
        Index('idx_execution_status', status),
        Index('idx_execution_created', created_at.desc()),
        UniqueConstraint('execution_id'),
    )

# ============================================
# POLÍTICAS DE SEGURIDAD
# ============================================

class SafetyPolicy(Base):
    """Política de seguridad firmada"""
    __tablename__ = "safety_policies"
    
    id = Column(Integer, primary_key=True)
    policy_id = Column(String(36), nullable=False)
    version = Column(Integer, nullable=False)
    policy = Column(JSON, nullable=False)
    hash = Column(String(64), nullable=False)
    signature = Column(String(128), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
    signer = Column(String(100), nullable=False)
    
    __table_args__ = (
        Index('idx_policy_id_version', policy_id, version.desc()),
        Index('idx_policy_expires', expires_at),
        UniqueConstraint('policy_id', 'version', name='uq_policy_version'),
    )

# ============================================
# IPS BLOQUEADAS
# ============================================

class BlockedIP(Base):
    """IPs bloqueadas por CERBERUS"""
    __tablename__ = "blocked_ips"
    
    id = Column(Integer, primary_key=True)
    ip = Column(String(45), unique=True, nullable=False)
    reason = Column(String(255))
    blocked_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
    blocked_by = Column(String(100))
    attempts = Column(Integer, default=0)
    
    __table_args__ = (
        Index('idx_blocked_expires', expires_at),
        UniqueConstraint('ip'),
    )

# ============================================
# MÉTRICAS
# ============================================

class SecurityMetric(Base):
    """Métricas de seguridad"""
    __tablename__ = "security_metrics"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    metric_type = Column(String(50), nullable=False)
    value = Column(Float, nullable=False)
    labels = Column(JSON)
    
    __table_args__ = (
        Index('idx_metric_timestamp', timestamp.desc()),
        Index('idx_metric_type', metric_type),
    )

# ============================================
# RATE LIMITS
# ============================================

class RateLimitRecord(Base):
    """Registro de rate limiting"""
    __tablename__ = "rate_limit_records"
    
    id = Column(Integer, primary_key=True)
    key = Column(String(255), nullable=False)
    action = Column(String(50), nullable=False)
    count = Column(Integer, default=0)
    window_start = Column(DateTime(timezone=True), nullable=False)
    window_end = Column(DateTime(timezone=True), nullable=False)
    
    __table_args__ = (
        Index('idx_ratelimit_key_action', key, action),
        Index('idx_ratelimit_window', window_start, window_end),
    )