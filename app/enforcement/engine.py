"""
CERBERUS V4 - Motor de Enforcement
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.config import settings
from app.models import BlockedIP, RateLimit

class EnforcementEngine:
    """
    Ejecuta las acciones: bloqueo, throttling, challenge
    """
    
    def __init__(self):
        self.block_duration = settings.CERBERUS_BLOCK_DEFAULT_DURATION
        
    async def check_rate_limit(self, ip: str, path: str, db: AsyncSession) -> Dict:
        """
        Verifica si la IP excede el rate limit
        """
        if not settings.CERBERUS_RATE_LIMIT_ENABLED:
            return {"allowed": True}
        
        window = settings.CERBERUS_RATE_LIMIT_WINDOW
        max_requests = settings.CERBERUS_RATE_LIMIT_REQUESTS
        
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=window)
        
        key = f"{ip}:{path}"
        result = await db.execute(
            select(RateLimit).where(
                RateLimit.key == key,
                RateLimit.window_start >= window_start
            )
        )
        count = len(result.scalars().all())
        
        if count >= max_requests:
            return {
                "allowed": False,
                "limit": max_requests,
                "current": count,
                "window": window
            }
        
        new_record = RateLimit(
            key=key,
            window_start=now,
            window_end=now + timedelta(seconds=window)
        )
        db.add(new_record)
        await db.commit()
        
        return {
            "allowed": True,
            "limit": max_requests,
            "current": count + 1,
            "window": window
        }
    
    async def block_ip(self, ip: str, duration_minutes: int, reason: str, db: AsyncSession) -> Dict:
        """
        Bloquea una IP temporalmente
        """
        result = await db.execute(
            select(BlockedIP).where(BlockedIP.ip == ip)
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            existing.expires_at = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
            existing.reason = reason
            await db.commit()
            return {
                "status": "updated",
                "ip": ip,
                "expires_at": existing.expires_at.isoformat()
            }
        
        blocked = BlockedIP(
            ip=ip,
            reason=reason,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        )
        db.add(blocked)
        await db.commit()
        
        return {
            "status": "blocked",
            "ip": ip,
            "duration_minutes": duration_minutes,
            "reason": reason,
            "expires_at": blocked.expires_at.isoformat()
        }
    
    async def unblock_ip(self, ip: str, db: AsyncSession) -> Dict:
        """
        Desbloquea una IP
        """
        await db.execute(delete(BlockedIP).where(BlockedIP.ip == ip))
        await db.commit()
        return {"status": "unblocked", "ip": ip}
    
    async def get_blocked_ips(self, db: AsyncSession) -> List[Dict]:
        """
        Obtiene todas las IPs bloqueadas
        """
        result = await db.execute(
            select(BlockedIP).where(BlockedIP.expires_at > datetime.now(timezone.utc))
        )
        records = result.scalars().all()
        
        return [
            {
                "ip": r.ip,
                "reason": r.reason,
                "blocked_at": r.blocked_at.isoformat(),
                "expires_at": r.expires_at.isoformat()
            }
            for r in records
        ]
    
    async def enforce(self, policy_result: Dict, context, db: AsyncSession) -> Dict:
        """
        Ejecuta la acción determinada por policy
        """
        action = policy_result.get("action", "ALLOW")
        ip = context.ip if hasattr(context, 'ip') else "0.0.0.0"
        
        enforcement_result = {
            "action": action,
            "applied": True,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if action == "DENY":
            if not settings.CERBERUS_DRY_RUN:
                block_result = await self.block_ip(
                    ip=ip,
                    duration_minutes=self.block_duration,
                    reason=policy_result.get("reason", "Ataque detectado"),
                    db=db
                )
                enforcement_result["block"] = block_result
            else:
                enforcement_result["block"] = {
                    "status": "simulated",
                    "ip": ip,
                    "reason": "DRY_RUN"
                }
        
        elif action == "THROTTLE":
            enforcement_result["throttle"] = {
                "wait_seconds": 30,
                "message": "Demasiadas peticiones"
            }
        
        elif action == "CHALLENGE":
            enforcement_result["challenge"] = {
                "type": "captcha",
                "message": "Verificación adicional requerida"
            }
        
        return enforcement_result