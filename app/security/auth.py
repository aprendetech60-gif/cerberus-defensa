"""
CERBERUS V4 - Autenticación
"""

import hmac
import hashlib
import ipaddress
from fastapi import HTTPException, Request, status, Depends
from fastapi.security import APIKeyHeader
from typing import Optional
from app.config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def validar_api_key(
    api_key: Optional[str] = Depends(api_key_header)
) -> str:
    """
    Valida la API Key usando comparación segura.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key requerida"
        )
    
    # Verificar CERBERUS_API_KEY
    if settings.CERBERUS_API_KEY and hmac.compare_digest(
        api_key.strip(), 
        settings.CERBERUS_API_KEY.strip()
    ):
        return api_key
    
    # Verificar CERBERUS_API_KEYS
    for valid_key in settings.CERBERUS_API_KEYS:
        if valid_key and hmac.compare_digest(api_key.strip(), valid_key.strip()):
            return api_key
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="API Key inválida"
    )

def hash_identifier(identifier: str) -> str:
    """Genera un hash no reversible de un identificador."""
    return hashlib.sha256(identifier.encode()).hexdigest()[:16]