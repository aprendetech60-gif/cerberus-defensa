"""
CERBERUS V3.5 - API Principal (Versión Render)
Simplificada para desplegar en Render sin dependencias complejas
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional
import os

# ============================================
# CONFIGURACIÓN SIMPLIFICADA
# ============================================

class Settings:
    """Configuración simplificada para Render"""
    CERBERUS_ENV = os.getenv("CERBERUS_ENV", "production")
    CERBERUS_DEBUG = os.getenv("CERBERUS_DEBUG", "false").lower() == "true"
    CERBERUS_DRY_RUN = os.getenv("CERBERUS_DRY_RUN", "true").lower() == "true"
    CERBERUS_FAIL_CLOSED = os.getenv("CERBERUS_FAIL_CLOSED", "true").lower() == "true"
    CERBERUS_RATE_LIMIT_ENABLED = os.getenv("CERBERUS_RATE_LIMIT_ENABLED", "true").lower() == "true"
    CERBERUS_AUDIT_RETENTION_DAYS = int(os.getenv("CERBERUS_AUDIT_RETENTION_DAYS", "365"))
    CERBERUS_APPROVAL_TTL_SECONDS = int(os.getenv("CERBERUS_APPROVAL_TTL_SECONDS", "300"))
    CERBERUS_API_HOST = os.getenv("CERBERUS_API_HOST", "0.0.0.0")
    CERBERUS_API_PORT = int(os.getenv("CERBERUS_API_PORT", "8000"))
    CERBERUS_API_WORKERS = int(os.getenv("CERBERUS_API_WORKERS", "1"))

settings = Settings()

# ============================================
# DATOS EN MEMORIA (en lugar de base de datos)
# ============================================

class Memoria:
    """Almacenamiento en memoria para Render"""
    ips_bloqueadas = set()
    logs = []
    aprobaciones = {}
    ejecuciones = {}

memoria = Memoria()

# ============================================
# FUNCIONES DE SEGURIDAD
# ============================================

def detectar_ataque(peticion: Dict) -> Dict:
    """Analiza si una petición es un ataque"""
    ip = peticion.get("ip", "desconocida")
    path = peticion.get("path", "/")
    user_id = peticion.get("user_id", "anonimo")
    body = peticion.get("body", {})
    
    riesgo = 0.0
    
    # 1. IP bloqueada
    if ip in memoria.ips_bloqueadas:
        return {
            "ataque": True,
            "razon": "IP_BLOQUEADA",
            "riesgo": 1.0,
            "accion": "BLOQUEAR"
        }
    
    # 2. Rutas peligrosas
    rutas_peligrosas = ["/admin", "/administrator", "/root", "/config", "/.env", "/.git"]
    for ruta in rutas_peligrosas:
        if ruta in path.lower():
            riesgo += 0.3
    
    # 3. Inyección SQL
    palabras_sql = ["SELECT", "DROP", "INSERT", "UPDATE", "DELETE", "UNION"]
    body_str = str(body).upper()
    for palabra in palabras_sql:
        if palabra in body_str:
            riesgo += 0.2
    
    # 4. Admin sin autenticación
    if user_id == "admin" and not peticion.get("auth_token"):
        riesgo += 0.4
    
    # Decidir
    if riesgo >= 0.7:
        return {"ataque": True, "razon": "RIESGO_ALTO", "riesgo": riesgo, "accion": "BLOQUEAR"}
    elif riesgo >= 0.4:
        return {"ataque": True, "razon": "RIESGO_MEDIO", "riesgo": riesgo, "accion": "ALERTAR"}
    else:
        return {"ataque": False, "razon": "SEGURO", "riesgo": riesgo, "accion": "PERMITIR"}

# ============================================
# CREAR APP
# ============================================

app = FastAPI(
    title="CERBERUS V3.5",
    description="Sistema de Defensa Autónoma para Web y Backend",
    version="3.5.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# ENDPOINTS PRINCIPALES
# ============================================

@app.get("/")
async def root():
    """Estado de CERBERUS"""
    return {
        "name": "CERBERUS",
        "version": "3.5.0",
        "status": "active",
        "environment": settings.CERBERUS_ENV,
        "features": {
            "rate_limiting": settings.CERBERUS_RATE_LIMIT_ENABLED,
            "fail_closed": settings.CERBERUS_FAIL_CLOSED,
            "dry_run": settings.CERBERUS_DRY_RUN,
        }
    }

@app.get("/health")
async def health():
    """Health check para Render"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ips_bloqueadas": len(memoria.ips_bloqueadas),
        "total_logs": len(memoria.logs)
    }

# ============================================
# ENDPOINT PRINCIPAL: DECISIÓN
# ============================================

@app.post("/v1/decide")
async def decide(request: Dict):
    """
    Toma una decisión de seguridad basada en la solicitud.
    Tu web en Firebase llama a este endpoint.
    """
    # Extraer datos
    execution_id = str(uuid.uuid4())
    ip = request.get("ip", "desconocida")
    path = request.get("path", "/")
    user_id = request.get("user_id", "anonimo")
    risk_score = float(request.get("risk_score", 0.0))
    confidence = float(request.get("confidence", 0.0))
    
    # Analizar
    resultado = detectar_ataque(request)
    
    # Guardar log
    log = {
        "execution_id": execution_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "path": path,
        "user_id": user_id,
        "riesgo": resultado["riesgo"],
        "accion": resultado["accion"],
        "razon": resultado["razon"]
    }
    memoria.logs.append(log)
    
    # Mantener solo últimos 1000 logs
    if len(memoria.logs) > 1000:
        memoria.logs = memoria.logs[-1000:]
    
    # Ejecutar acción
    if resultado["accion"] == "BLOQUEAR":
        memoria.ips_bloqueadas.add(ip)
        return {
            "status": "DENIED",
            "execution_id": execution_id,
            "reason": resultado["razon"],
            "message": "🚫 Acceso bloqueado por CERBERUS",
            "ip": ip,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    elif resultado["accion"] == "ALERTAR":
        return {
            "status": "ALERT",
            "execution_id": execution_id,
            "reason": resultado["razon"],
            "message": "⚠️ Comportamiento sospechoso detectado",
            "ip": ip,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    else:
        return {
            "status": "ALLOWED",
            "execution_id": execution_id,
            "message": "✅ Petición segura",
            "ip": ip,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

# ============================================
# ENDPOINTS DE SEGURIDAD
# ============================================

@app.get("/safety/estado")
async def safety_estado():
    """Estado de seguridad"""
    return {
        "estado": "activo",
        "ips_bloqueadas": len(memoria.ips_bloqueadas),
        "total_peticiones": len(memoria.logs)
    }

@app.get("/safety/ips-bloqueadas")
async def safety_ips():
    """Listar IPs bloqueadas"""
    return {
        "total": len(memoria.ips_bloqueadas),
        "ips": list(memoria.ips_bloqueadas)
    }

@app.post("/safety/bloquear/{ip}")
async def safety_bloquear(ip: str, razon: str = "Bloqueo manual"):
    """Bloquear IP manualmente"""
    memoria.ips_bloqueadas.add(ip)
    return {
        "mensaje": f"IP {ip} bloqueada",
        "razon": razon
    }

@app.post("/safety/desbloquear/{ip}")
async def safety_desbloquear(ip: str):
    """Desbloquear IP manualmente"""
    if ip in memoria.ips_bloqueadas:
        memoria.ips_bloqueadas.remove(ip)
        return {"mensaje": f"IP {ip} desbloqueada"}
    return {"mensaje": f"IP {ip} no estaba bloqueada"}

# ============================================
# ENDPOINTS DE AUDITORÍA
# ============================================

@app.get("/auditoria/eventos")
async def auditoria_eventos(limit: int = 50):
    """Ver logs recientes"""
    logs = memoria.logs[-limit:] if memoria.logs else []
    return {
        "total": len(memoria.logs),
        "eventos": logs
    }

@app.get("/auditoria/estadisticas")
async def auditoria_stats():
    """Estadísticas de auditoría"""
    total = len(memoria.logs)
    bloqueados = len([l for l in memoria.logs if l.get("accion") == "BLOQUEAR"])
    permitidos = len([l for l in memoria.logs if l.get("accion") == "PERMITIR"])
    
    return {
        "total_eventos": total,
        "bloqueados": bloqueados,
        "permitidos": permitidos,
        "ips_bloqueadas": len(memoria.ips_bloqueadas)
    }

# ============================================
# ENDPOINT DE APROBACIÓN (simplificado)
# ============================================

@app.post("/v1/approve/{approval_id}")
async def approve_action(approval_id: str, request: Dict):
    """Aprueba una acción (simplificado)"""
    return {
        "status": "APPROVED",
        "approval_id": approval_id,
        "approved_by": request.get("approved_by", "unknown"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.post("/v1/deny/{approval_id}")
async def deny_action(approval_id: str, request: Dict):
    """Deniega una acción (simplificado)"""
    return {
        "status": "DENIED",
        "approval_id": approval_id,
        "reason": request.get("reason", "No reason provided"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# ============================================
# INICIAR
# ============================================

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("🛡️ CERBERUS V3.5 - SISTEMA DE DEFENSA")
    print("=" * 60)
    print(f"📡 Entorno: {settings.CERBERUS_ENV}")
    print(f"🔒 Dry Run: {settings.CERBERUS_DRY_RUN}")
    print("=" * 60)
    print("✅ CERBERUS LISTO PARA PROTEGER")
    print("=" * 60)
    
    uvicorn.run(
        "app.main:app",
        host=settings.CERBERUS_API_HOST,
        port=settings.CERBERUS_API_PORT,
        reload=settings.CERBERUS_DEBUG,
    )