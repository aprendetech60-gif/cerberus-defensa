"""
Cadena de auditoría inmutable con hash chain
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, text
from sqlalchemy.sql import expression

# ✅ CORREGIDO: Importar AuditLog como AuditRecord
from app.models import AuditLog as AuditRecord
from app.security.crypto import (
    canonical_json, hash_canonical, sign_hash, verify_signature,
    load_private_key, load_public_key, verify_hash
)
from app.config import settings

class AuditChain:
    """
    Cadena de auditoría inmutable.
    Cada registro contiene: hash = SHA256(event + previous_hash)
    
    ARQUITECTURA:
    ┌─────────────────────────────────────────────────────────────┐
    │                      AUDIT CHAIN                           │
    ├─────────────────────────────────────────────────────────────┤
    │  Evento 1:  hash1 = SHA256(event1 + null)                 │
    │  Evento 2:  hash2 = SHA256(event2 + hash1)                │
    │  Evento 3:  hash3 = SHA256(event3 + hash2)                │
    │  Evento N:  hashN = SHA256(eventN + hashN-1)              │
    └─────────────────────────────────────────────────────────────┘
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.private_key = load_private_key(settings.CERBERUS_PRIVATE_KEY_B64) if settings.CERBERUS_PRIVATE_KEY_B64 else None
        self.public_key = load_public_key(settings.CERBERUS_PUBLIC_KEY_B64) if settings.CERBERUS_PUBLIC_KEY_B64 else None
        self._previous_hash = None
        self._last_event_id = None
        
    def canonicalize_event(self, event: Dict) -> Dict:
        """Representación canónica del evento (orden determinista)"""
        return {
            "event_id": event.get("event_id", str(uuid.uuid4())),
            "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "source": event.get("source", "CERBERUS"),
            "event_type": event.get("event_type"),
            "payload": event.get("payload", {}),
        }
    
    def calculate_hash(self, event: Dict, previous_hash: Optional[str]) -> str:
        """Hash = SHA256(event + previous_hash)"""
        data = {
            "event": event,
            "previous_hash": previous_hash,
        }
        return hash_canonical(data)
    
    async def _get_last_hash(self) -> Optional[str]:
        """Obtiene el último hash de la BD"""
        if self._previous_hash is not None:
            return self._previous_hash
        
        result = await self.session.execute(
            select(AuditRecord).order_by(desc(AuditRecord.id)).limit(1)
        )
        last = result.scalar_one_or_none()
        
        if last:
            self._previous_hash = last.hash
            self._last_event_id = last.event_id
        
        return self._previous_hash
    
    async def append(self, event: Dict) -> str:
        """
        Añade evento a la cadena.
        Siempre firmado y encadenado.
        
        FLUJO:
        1. Obtener último hash
        2. Canonicalizar evento
        3. Calcular hash (incluye previous_hash)
        4. Firmar hash
        5. Guardar en BD
        6. Actualizar estado local
        """
        # 1. Obtener último hash
        previous_hash = await self._get_last_hash()
        
        # 2. Canonicalizar evento
        canonical = self.canonicalize_event(event)
        event_id = canonical["event_id"]
        
        # 3. Calcular hash (incluye previous_hash)
        record_hash = self.calculate_hash(canonical, previous_hash)
        
        # 4. Firmar (si hay clave privada)
        signature = None
        if self.private_key:
            signature = sign_hash(self.private_key, record_hash)
        else:
            # Modo sin firma (desarrollo) - solo hash
            signature = f"NO_SIG_{record_hash[:16]}"
        
        # 5. Crear registro
        record = {
            "event_id": event_id,
            "timestamp": canonical["timestamp"],
            "source": canonical["source"],
            "event_type": canonical["event_type"],
            "payload": canonical["payload"],
            "previous_hash": previous_hash,
            "hash": record_hash,
            "signature": signature,
        }
        
        # 6. Guardar en BD
        db_record = AuditRecord(
            execution_id=event.get("execution_id", str(uuid.uuid4())),
            event_type=record["event_type"],
            payload=record["payload"],
            ip=event.get("ip"),
            user_id=event.get("user_id"),
            # Campos específicos de AuditChain
            event_id=record["event_id"],
            timestamp=datetime.fromisoformat(record["timestamp"]),
            source=record["source"],
            previous_hash=record["previous_hash"],
            hash=record["hash"],
            signature=record["signature"],
        )
        
        self.session.add(db_record)
        await self.session.commit()
        
        # 7. Actualizar estado local
        self._previous_hash = record_hash
        self._last_event_id = event_id
        
        return event_id
    
    async def verify_chain(self, limit: int = None) -> Dict:
        """
        Verifica toda la cadena: hash + enlace + firma
        
        RETURNS:
        {
            "valid": True/False,
            "total_records": N,
            "last_hash": "hash",
            "last_event_id": "id",
            "error": "mensaje" (si hay error)
        }
        """
        query = select(AuditRecord).order_by(AuditRecord.id)
        if limit:
            query = query.limit(limit)
        
        result = await self.session.execute(query)
        records = result.scalars().all()
        
        if not records:
            return {
                "valid": True,
                "total_records": 0,
                "last_hash": None,
                "last_event_id": None,
                "message": "Cadena vacía"
            }
        
        previous_hash = None
        
        for idx, record in enumerate(records):
            # 1. Reconstruir evento canonico
            event = {
                "event_id": record.event_id,
                "timestamp": record.timestamp.isoformat(),
                "source": record.source,
                "event_type": record.event_type,
                "payload": record.payload,
            }
            
            # 2. Recalcular hash
            calculated = self.calculate_hash(event, previous_hash)
            
            # 3. Verificar hash
            if not verify_hash(calculated, record.hash):
                return {
                    "valid": False,
                    "index": idx,
                    "event_id": record.event_id,
                    "reason": "HASH_MISMATCH",
                    "expected": calculated,
                    "got": record.hash,
                }
            
            # 4. Verificar enlace de cadena
            if record.previous_hash != previous_hash:
                return {
                    "valid": False,
                    "index": idx,
                    "event_id": record.event_id,
                    "reason": "CHAIN_BREAK",
                    "expected": previous_hash,
                    "got": record.previous_hash,
                }
            
            # 5. Verificar firma (si existe y hay clave pública)
            if self.public_key and record.signature and not record.signature.startswith("NO_SIG_"):
                if not verify_signature(
                    self.public_key,
                    record.signature,
                    record.hash
                ):
                    return {
                        "valid": False,
                        "index": idx,
                        "event_id": record.event_id,
                        "reason": "INVALID_SIGNATURE",
                    }
            
            previous_hash = record.hash
        
        return {
            "valid": True,
            "total_records": len(records),
            "last_hash": previous_hash,
            "last_event_id": records[-1].event_id if records else None,
            "message": "Cadena verificada correctamente"
        }
    
    async def get_stats(self) -> Dict:
        """
        Obtiene estadísticas de la cadena
        
        RETURNS:
        {
            "total_records": N,
            "last_hash": "hash",
            "last_event_id": "id",
            "last_timestamp": "iso_timestamp"
        }
        """
        # Total de registros
        total_result = await self.session.execute(
            select(func.count()).select_from(AuditRecord)
        )
        total = total_result.scalar() or 0
        
        # Obtener último registro
        result = await self.session.execute(
            select(AuditRecord).order_by(desc(AuditRecord.id)).limit(1)
        )
        last = result.scalar_one_or_none()
        
        return {
            "total_records": total,
            "last_hash": last.hash if last else None,
            "last_event_id": last.event_id if last else None,
            "last_timestamp": last.timestamp.isoformat() if last else None,
        }