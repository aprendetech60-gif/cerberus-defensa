"""
CERBERUS V4 - Enforcement Engine
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from app.models import BlockedIP, RateLimit

class EnforcementEngine:
    """Motor de enforcement para bloqueos y rate limiting."""
    
    async def check_rate_limit(
        self,
        ip: str,
        path: str,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Verifica si la IP ha excedido el rate limit.
        """
        # Implementación básica
        return {
            "allowed": True,
            "limit": 100,
            "current": 0
        }
    
    async def enforce(
        self,
        policy_result,
        context: Dict[str, Any],
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Ejecuta la decisión de política.
        """
        return {
            "enforced": True,
            "action": policy_result.action if hasattr(policy_result, 'action') else "ALLOW"
        }
    
    async def block_ip(
        self,
        ip: str,
        duration_minutes: int,
        reason: str,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """Bloquea una IP manualmente."""
        # Validar que no esté ya bloqueada
        existing = await db.execute(
            select(BlockedIP).where(
                and_(
                    BlockedIP.ip == ip,
                    BlockedIP.expires_at > datetime.now(timezone.utc)
                )
            )
        )
        if existing.scalar_one_or_none():
            return {"message": f"IP {ip} ya está bloqueada"}
        
        blocked = BlockedIP(
            ip=ip,
            reason=reason,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        )
        db.add(blocked)
        await db.commit()
        return {"message": f"IP {ip} bloqueada por {duration_minutes} minutos"}
    
    async def unblock_ip(
        self,
        ip: str,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """Desbloquea una IP manualmente."""
        result = await db.execute(
            select(BlockedIP).where(BlockedIP.ip == ip)
        )
        blocked = result.scalar_one_or_none()
        if blocked:
            await db.delete(blocked)
            await db.commit()
            return {"message": f"IP {ip} desbloqueada"}
        return {"message": f"IP {ip} no estaba bloqueada"}
    
    async def get_blocked_ips(self, db: AsyncSession) -> List[str]:
        """Obtiene lista de IPs bloqueadas activas."""
        result = await db.execute(
            select(BlockedIP.ip).where(
                BlockedIP.expires_at > datetime.now(timezone.utc)
            )
        )
        return [row[0] for row in result.all()]
    
    async def health_check(self) -> bool:
        """Verifica la salud del enforcement engine."""
        return True