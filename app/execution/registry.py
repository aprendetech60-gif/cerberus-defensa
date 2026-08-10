"""
Registro de ejecuciones para idempotencia
"""

from typing import Dict, Optional
from datetime import datetime, timezone
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import ExecutionRecord

class ExecutionRegistry:
    """
    Registro de ejecuciones para prevenir duplicados.
    Usa base de datos para persistencia distribuida.
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self._cache = {}
        self._cache_ttl = 60  # segundos
    
    async def reserve(self, execution_id: str, action: str, context: Dict) -> bool:
        """
        Reserva un execution_id.
        Retorna True si es nuevo, False si ya existe.
        """
        # Verificar caché primero
        if execution_id in self._cache:
            return False
        
        # Verificar en base de datos
        result = await self.session.execute(
            select(ExecutionRecord).where(
                ExecutionRecord.execution_id == execution_id
            )
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            self._cache[execution_id] = existing.status
            return False
        
        # Crear nuevo registro
        record = ExecutionRecord(
            execution_id=execution_id,
            action=action,
            status="RESERVED",
            context=context,
            created_at=datetime.now(timezone.utc),
        )
        
        self.session.add(record)
        await self.session.commit()
        
        self._cache[execution_id] = "RESERVED"
        return True
    
    async def start(self, execution_id: str) -> bool:
        """Marca ejecución como iniciada"""
        if execution_id not in self._cache:
            return False
        
        result = await self.session.execute(
            select(ExecutionRecord).where(
                ExecutionRecord.execution_id == execution_id
            )
        )
        record = result.scalar_one_or_none()
        
        if not record or record.status != "RESERVED":
            return False
        
        record.status = "STARTED"
        record.started_at = datetime.now(timezone.utc)
        await self.session.commit()
        
        self._cache[execution_id] = "STARTED"
        return True
    
    async def complete(self, execution_id: str, result: Dict) -> bool:
        """Marca ejecución como completada"""
        result = await self.session.execute(
            select(ExecutionRecord).where(
                ExecutionRecord.execution_id == execution_id
            )
        )
        record = result.scalar_one_or_none()
        
        if not record:
            return False
        
        record.status = "COMPLETED"
        record.completed_at = datetime.now(timezone.utc)
        record.result = result
        await self.session.commit()
        
        self._cache[execution_id] = "COMPLETED"
        return True
    
    async def fail(self, execution_id: str, error: str) -> bool:
        """Marca ejecución como fallida"""
        result = await self.session.execute(
            select(ExecutionRecord).where(
                ExecutionRecord.execution_id == execution_id
            )
        )
        record = result.scalar_one_or_none()
        
        if not record:
            return False
        
        record.status = "FAILED"
        record.completed_at = datetime.now(timezone.utc)
        record.error = error
        await self.session.commit()
        
        self._cache[execution_id] = "FAILED"
        return True
    
    async def get_status(self, execution_id: str) -> Optional[str]:
        """Obtiene estado de una ejecución"""
        if execution_id in self._cache:
            return self._cache[execution_id]
        
        result = await self.session.execute(
            select(ExecutionRecord).where(
                ExecutionRecord.execution_id == execution_id
            )
        )
        record = result.scalar_one_or_none()
        
        if not record:
            return None
        
        self._cache[execution_id] = record.status
        return record.status
    
    async def is_completed(self, execution_id: str) -> bool:
        """Verifica si una ejecución ya está completada"""
        status = await self.get_status(execution_id)
        return status in ("COMPLETED", "FAILED")
    
    async def cleanup(self, max_age_hours: int = 24):
        """Limpia registros antiguos"""
        # En producción: eliminar registros más antiguos que max_age_hours
        pass