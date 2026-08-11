"""
CERBERUS V4 - Auditoría
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from app.models import AuditLog

class AuditLogger:
    """Registra eventos de seguridad para auditoría."""

    async def log_event(
        self,
        db: AsyncSession,
        execution_id: str,
        event_type: str,
        payload: Dict,
        ip: Optional[str] = None,
        path: Optional[str] = None,
        method: Optional[str] = None,
        user_id: Optional[str] = None,
        risk_score: Optional[float] = None,
        risk_level: Optional[str] = None,
        action: Optional[str] = None
    ):
        """Registra un evento en el log de auditoría."""
        log_entry = AuditLog(
            execution_id=execution_id,
            event_type=event_type,
            payload=payload,
            ip=ip,
            path=path,
            method=method,
            user_id=user_id,
            risk_score=risk_score,
            risk_level=risk_level,
            action=action
        )
        db.add(log_entry)
        await db.commit()
        return log_entry

    async def get_events(
        self,
        db: AsyncSession,
        limit: int = 50,
        event_type: Optional[str] = None,
        ip: Optional[str] = None
    ) -> List[Dict]:
        """Obtiene eventos de auditoría con filtros."""
        query = select(AuditLog).order_by(desc(AuditLog.id))
        if event_type:
            query = query.where(AuditLog.event_type == event_type)
        if ip:
            query = query.where(AuditLog.ip == ip)
        query = query.limit(limit)
        result = await db.execute(query)
        records = result.scalars().all()
        return [{
            "id": r.id,
            "execution_id": r.execution_id,
            "timestamp": r.timestamp.isoformat(),
            "event_type": r.event_type,
            "payload": r.payload,
            "ip": r.ip,
            "path": r.path,
            "method": r.method,
            "user_id": r.user_id,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "action": r.action
        } for r in records]

    async def get_stats(self, db: AsyncSession) -> Dict:
        """Obtiene estadísticas de auditoría."""
        total_result = await db.execute(select(func.count(AuditLog.id)))
        total = total_result.scalar() or 0
        
        type_result = await db.execute(
            select(AuditLog.event_type, func.count(AuditLog.id))
            .group_by(AuditLog.event_type)
        )
        by_type = {row[0]: row[1] for row in type_result.all()}
        
        return {
            "total_events": total,
            "by_type": by_type
        }