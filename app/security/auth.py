"""
CERBERUS V4 - Autenticación
"""

import hmac
import hashlib
import ipaddress
from fastapi import HTTPException, Request, Header, status, Depends
from fastapi.security import APIKeyHeader
from typing import Optional
from app.config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def is_trusted_proxy(client_ip: str) -> bool:
    """Verifica si la IP del cliente inmediato es un proxy confiable."""
    if not settings.CERBERUS_TRUST_PROXY_HEADERS:
        return False
    
    try:
        ip_obj = ipaddress.ip_address(client_ip)
        for trusted in settings.CERBERUS_TRUSTED_PROXIES:
            try:
                if '/' in trusted:
                    network = ipaddress.ip_network(trusted, strict=False)
                    if ip_obj in network:
                        return True
                else:
                    if client_ip == trusted:
                        return True
            except ValueError:
                continue
    except ValueError:
        return False
    
    return False

def resolve_real_ip(request: Request) -> str:
    """
    Resuelve la IP real del cliente, verificando proxies confiables.
    
    Flujo:
    1. Si el cliente inmediato es proxy confiable → aceptar X-Forwarded-For
    2. Si no → usar la IP directa de conexión
    """
    # IP del cliente inmediato (el que se conectó a Render)
    client_ip = request.client.host if request.client else "0.0.0.0"
    
    # Si no confiamos en headers o el cliente no es proxy confiable → usar IP directa
    if not settings.CERBERUS_TRUST_PROXY_HEADERS or not is_trusted_proxy(client_ip):
        return client_ip
    
    # Si es proxy confiable, extraer la IP real de X-Forwarded-For
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Tomar la primera IP (la del cliente original)
        ips = [ip.strip() for ip in forwarded.split(",")]
        return ips[0] if ips else client_ip
    
    # Si no hay X-Forwarded-For, usar la IP directa
    return client_ip

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
    
    # Verificar CERBERUS_API_KEY (única)
    if settings.CERBERUS_API_KEY and hmac.compare_digest(
        api_key.strip(), 
        settings.CERBERUS_API_KEY.strip()
    ):
        return api_key
    
    # Verificar CERBERUS_API_KEYS (múltiples)
    for valid_key in settings.CERBERUS_API_KEYS:
        if valid_key and hmac.compare_digest(api_key.strip(), valid_key.strip()):
            return api_key
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="API Key inválida"
    )

async def get_real_ip(request: Request) -> str:
    """Dependencia FastAPI para obtener IP real."""
    return resolve_real_ip(request)

def hash_identifier(identifier: str) -> str:
    """Genera un hash no reversible de un identificador"""
    return hashlib.sha256(identifier.encode()).hexdigest()[:16]