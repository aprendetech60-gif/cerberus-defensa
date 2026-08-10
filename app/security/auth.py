"""
CERBERUS V4 - Autenticación
"""

import hmac
import hashlib
from fastapi import HTTPException, Request, Header, status, Depends
from fastapi.security import APIKeyHeader
from typing import Optional
from app.config import settings

# Header para API Key
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def validar_api_key(
    api_key: Optional[str] = Depends(api_key_header)
) -> str:
    """
    Valida la API Key usando comparación segura (hmac.compare_digest)
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key requerida"
        )
    
    # ✅ USAR CERBERUS_API_KEY (la que está en Render)
    expected_key = settings.CERBERUS_API_KEY
    
    if not expected_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API Key no configurada en el servidor"
        )
    
    # Comparación segura
    if hmac.compare_digest(api_key.strip(), expected_key.strip()):
        return api_key
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="API Key inválida"
    )

def get_real_ip(request: Request) -> str:
    """
    Obtiene la IP real del cliente desde request.state (middleware)
    """
    return getattr(request.state, 'real_ip', '0.0.0.0')

async def extract_real_ip_middleware(request: Request, call_next):
    """
    Middleware que extrae la IP real y la guarda en request.state
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        request.state.real_ip = forwarded.split(",")[0].strip()
    else:
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            request.state.real_ip = real_ip.strip()
        else:
            request.state.real_ip = request.client.host if request.client else "0.0.0.0"
    
    return await call_next(request)

def hash_identifier(identifier: str) -> str:
    """Genera un hash no reversible de un identificador"""
    return hashlib.sha256(identifier.encode()).hexdigest()[:16]