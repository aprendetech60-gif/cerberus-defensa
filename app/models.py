"""
CERBERUS V4 - Modelos de datos
"""

from pydantic import BaseModel, Field, validator
from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, Index, Float
from sqlalchemy.sql import func
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

# ✅ IMPORTAR EL BASE CENTRAL desde database.py
from app.database import Base

# ============================================
# ENUMS
# ============================================

class DecisionStatus(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    CHALLENGE = "CHALLENGE"
    THROTTLE = "THROTTLE"

class RiskLevel(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# ============================================
# MODELOS SQLALCHEMY
# ============================================

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True)
    execution_id = Column(String(36), nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    event_type = Column(String(50), nullable=False)
    payload = Column(JSON, nullable=False)
    ip = Column(String(45))
    path = Column(String(255))
    method = Column(String(10))
    user_id = Column(String(100))
    risk_score = Column(Float)  # ✅ CORREGIDO: String → Float
    risk_level = Column(String(20))
    action = Column(String(20))
    
    __table_args__ = (
        Index('idx_audit_timestamp', timestamp.desc()),
        Index('idx_audit_event_type', event_type),
        Index('idx_audit_execution', execution_id),
        Index('idx_audit_ip', ip),
        Index('idx_audit_user', user_id),
    )

class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    
    id = Column(Integer, primary_key=True)
    ip = Column(String(45), unique=True, nullable=False)
    reason = Column(Text)
    blocked_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    
    __table_args__ = (
        Index('idx_blocked_expires', expires_at),
        Index('idx_blocked_ip', ip),
    )

class RateLimit(Base):
    __tablename__ = "rate_limits"
    
    id = Column(Integer, primary_key=True)
    key = Column(String(255), nullable=False)
    window_start = Column(DateTime(timezone=True), nullable=False)
    window_end = Column(DateTime(timezone=True), nullable=False)
    
    __table_args__ = (
        Index('idx_ratelimit_key', key),
        Index('idx_ratelimit_window', window_start, window_end),
    )

# ============================================
# MODELOS PYDANTIC - CONTRATO FUERTE
# ============================================

class ClientSignals(BaseModel):
    user_agent: Optional[str] = None
    screen: Optional[str] = None
    language: Optional[str] = None
    timezone: Optional[str] = None
    mouse_movements: Optional[int] = 0
    clicks: Optional[int] = 0
    key_presses: Optional[int] = 0
    scroll_depth: Optional[float] = 0
    time_on_page: Optional[int] = 0

class DecisionRequest(BaseModel):
    path: str = Field(..., max_length=255)
    method: str = Field(..., pattern="^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)$")
    user_id: Optional[str] = Field(None, max_length=100)
    body: Optional[Dict[str, Any]] = None
    client_signals: Optional[ClientSignals] = None
    
    @validator('path')
    def validar_path(cls, v):
        if not v or not v.startswith('/'):
            raise ValueError('Path debe comenzar con /')
        if len(v) > 255:
            raise ValueError('Path demasiado largo')
        if '../' in v or '..\\' in v:
            raise ValueError('Path traversal no permitido')
        return v

class DecisionResponse(BaseModel):
    status: DecisionStatus
    execution_id: str
    reason: Optional[str] = None
    message: str
    timestamp: str
    ip: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

class SecurityContext(BaseModel):
    execution_id: str
    timestamp: datetime
    ip: str
    path: str
    method: str
    user_id: str
    api_key: str
    dry_run: bool
    fail_closed: bool
    client_signals: Dict[str, Any] = {}
    body: Dict[str, Any] = {}
    
    class Config:
        arbitrary_types_allowed = True

class DetectionResult(BaseModel):
    evidences: List[Dict[str, Any]] = Field(default_factory=list)
    sql_risk: float = 0.0
    path_risk: float = 0.0
    total_risk: float = 0.0
    is_suspicious: bool = False
    
    @property
    def threats(self) -> List[str]:
        """Compatibilidad con versión anterior"""
        return [e.get('type', 'unknown') for e in self.evidences if e.get('type')]

class RiskResult(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    level: str = "NONE"
    confidence: float = Field(ge=0.0, le=1.0)
    factors: Dict[str, float] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    
    @validator('level')
    def validar_nivel(cls, v, values):
        if 'score' in values:
            score = values['score']
            if score < 0.2:
                return "NONE"
            elif score < 0.4:
                return "LOW"
            elif score < 0.6:
                return "MEDIUM"
            elif score < 0.8:
                return "HIGH"
            else:
                return "CRITICAL"
        return v

class PolicyResult(BaseModel):
    action: str
    reason: str
    risk_score: float = 0.0
    risk_level: str = "NONE"
    dry_run: bool = False
    evidencias: List[str] = Field(default_factory=list)
    policy_rules: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    requires_manual_review: bool = False
    severity: str = "LOW"
    
    @validator('action')
    def validar_action(cls, v):
        allowed = ["ALLOW", "DENY", "CHALLENGE", "THROTTLE"]
        if v.upper() not in allowed:
            raise ValueError(f"Action must be one of {allowed}")
        return v.upper()