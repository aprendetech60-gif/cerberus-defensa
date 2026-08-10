"""
CERBERUS V4 - SISTEMA DE DEFENSA AUTÓNOMO
Versión Endurecida para Producción en Render

ARQUITECTURA:
Authentication → Validation → Rate Limit → Detection → Risk → Policy → Enforcement → Audit

CARACTERÍSTICAS:
✅ API Key con rotación
✅ IP real de conexión (con proxies confiables)
✅ Rate limiting con Redis/PostgreSQL
✅ Detección SQL mejorada
✅ Risk Engine con correlación
✅ Policy Engine (ALLOW/CHALLENGE/THROTTLE/DENY)
✅ Enforcement con bloqueos temporales
✅ Auditoría persistente
✅ Health checks
✅ Métricas
✅ Fail-closed real
✅ CORS seguro (sin wildcards en producción)
✅ Manejo robusto de errores
"""

from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uuid
import os
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, List, Any
import logging

# ============================================
# CONFIGURACIÓN DE LOGGING
# ============================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("cerberus")

# ============================================
# IMPORTACIONES MODULARES
# ============================================

from app.config import settings
from app.models import (
    DecisionRequest, DecisionResponse,
    ClientSignals, DetectionResult, RiskResult,
    PolicyResult, SecurityContext, DecisionStatus
)
from app.database import get_db, engine, Base, check_database_health
from app.security.auth import validar_api_key, get_real_ip, extract_real_ip_middleware
from app.detection.engine import DetectionEngine
from app.risk.engine import RiskEngine
from app.policy.engine import PolicyEngine
from app.enforcement.engine import EnforcementEngine
from app.audit.logger import AuditLogger

# ============================================
# LIFECYCLE
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Inicialización y limpieza de CERBERUS"""
    
    try:
        # Crear tablas en base de datos
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        print("=" * 60)
        print("🛡️ CERBERUS V4 - SISTEMA DE DEFENSA ENDURECIDO")
        print("=" * 60)
        print(f"📡 Entorno: {settings.CERBERUS_ENV}")
        print(f"🔒 Dry Run: {settings.CERBERUS_DRY_RUN}")
        print(f"🔒 Fail Closed: {settings.CERBERUS_FAIL_CLOSED}")
        print(f"🗄️  Persistencia: PostgreSQL")
        print(f"⚡ Rate Limiting: {settings.CERBERUS_RATE_LIMIT_ENABLED}")
        print(f"🔄 API Key Rotation: {settings.CERBERUS_API_KEY_ROTATION_INTERVAL} días")
        print(f"🌐 CORS Origins: {len(settings.CERBERUS_ALLOWED_ORIGINS)} dominios configurados")
        print("=" * 60)
        print("✅ CERBERUS LISTO PARA PROTEGER")
        print("=" * 60)
        
    except Exception as e:
        logger.error(f"❌ Error en inicialización: {e}")
        raise
    
    yield
    
    # Limpieza
    try:
        await engine.dispose()
        print("🛑 CERBERUS V4 Detenido")
    except Exception as e:
        logger.error(f"❌ Error en limpieza: {e}")

# ============================================
# CREAR APP
# ============================================

app = FastAPI(
    title="CERBERUS V4",
    description="Sistema de Defensa Autónomo - Versión Endurecida",
    version="4.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.CERBERUS_DEBUG else None,
    redoc_url="/redoc" if settings.CERBERUS_DEBUG else None,
)

# ============================================
# CORS SEGURO (SIN WILDCARDS EN PRODUCCIÓN)
# ============================================

# Validación crítica: No permitir wildcards en producción
if settings.CERBERUS_ENV == "production":
    if "*" in settings.CERBERUS_ALLOWED_ORIGINS:
        raise ValueError("❌ Wildcard CORS origin not allowed in production!")
    if not settings.CERBERUS_ALLOWED_ORIGINS:
        raise ValueError("❌ At least one CORS origin must be configured in production!")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CERBERUS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=settings.CERBERUS_ALLOWED_METHODS,
    allow_headers=settings.CERBERUS_ALLOWED_HEADERS,
    expose_headers=["X-Execution-ID", "X-Risk-Score"],
)

# ============================================
# MIDDLEWARE: IP REAL (usando request.state)
# ============================================

@app.middleware("http")
async def extract_real_ip(request: Request, call_next):
    """Extrae la IP real de la conexión y la almacena en request.state"""
    await extract_real_ip_middleware(request, call_next)
    return await call_next(request)

# ============================================
# INSTANCIAS DE MOTORES
# ============================================

detection_engine = DetectionEngine()
risk_engine = RiskEngine()
policy_engine = PolicyEngine()
enforcement_engine = EnforcementEngine()
audit_logger = AuditLogger()

# ============================================
# ENDPOINTS PÚBLICOS
# ============================================

@app.get("/")
async def root():
    """Estado de CERBERUS"""
    return {
        "name": "CERBERUS",
        "version": "4.0.0",
        "status": "active",
        "environment": settings.CERBERUS_ENV,
        "features": {
            "rate_limiting": settings.CERBERUS_RATE_LIMIT_ENABLED,
            "fail_closed": settings.CERBERUS_FAIL_CLOSED,
            "dry_run": settings.CERBERUS_DRY_RUN,
            "persistence": "postgresql",
            "api_key_rotation": settings.CERBERUS_API_KEY_ROTATION_INTERVAL,
        }
    }

@app.get("/health")
async def health(db=Depends(get_db)):
    """Health check para Render - VERIFICA DEPENDENCIAS CRÍTICAS"""
    
    components = {
        "api": "healthy",
        "database": "unknown",
        "rate_limiting": "unknown" if not settings.CERBERUS_RATE_LIMIT_ENABLED else "healthy",
        "audit": "unknown"
    }
    
    # Verificar base de datos
    try:
        db_healthy = await check_database_health()
        components["database"] = "healthy" if db_healthy else "degraded"
    except Exception as e:
        logger.error(f"Health check DB error: {e}")
        components["database"] = "unhealthy"
    
    # Verificar auditoría (escritura de prueba)
    try:
        test_execution_id = str(uuid.uuid4())
        await audit_logger.log_event(
            db=db,
            execution_id=test_execution_id,
            event_type="HEALTH_CHECK",
            payload={"status": "test"},
            ip="127.0.0.1",
            path="/health",
            method="GET"
        )
        components["audit"] = "healthy"
    except Exception as e:
        logger.error(f"Health check audit error: {e}")
        components["audit"] = "degraded"
    
    # Determinar estado general
    critical_components = ["database", "audit"]
    unhealthy = [c for c in critical_components if components.get(c) == "unhealthy"]
    degraded = [c for c in critical_components if components.get(c) == "degraded"]
    
    if unhealthy:
        status = "unhealthy"
    elif degraded:
        status = "degraded"
    else:
        status = "healthy"
    
    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "4.0.0",
        "components": components,
        "details": {
            "fail_closed": settings.CERBERUS_FAIL_CLOSED,
            "dry_run": settings.CERBERUS_DRY_RUN,
        }
    }

# ============================================
# ENDPOINT PRINCIPAL: DECISIÓN
# ============================================

@app.post("/v1/decide", response_model=DecisionResponse)
async def decide(
    request: DecisionRequest,
    api_key: str = Depends(validar_api_key),
    real_ip: str = Depends(get_real_ip),  # ✅ Reutiliza request.state.real_ip
    db=Depends(get_db)
):
    """
    Toma una decisión de seguridad basada en la solicitud.
    
    FLUJO:
      1. ✅ Autenticación (API Key)
      2. ✅ IP Real (no confiable del cliente)
      3. ✅ Rate Limiting (por IP)
      4. ✅ Normalización
      5. ✅ Detección
      6. ✅ Risk Engine
      7. ✅ Policy Engine
      8. ✅ Enforcement
      9. ✅ Auditoría
    """
    execution_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc)
    
    # ============================================
    # 1. PREPARAR CONTEXTO
    # ============================================
    
    context = SecurityContext(
        execution_id=execution_id,
        timestamp=timestamp,
        ip=real_ip,
        path=request.path,
        method=request.method,
        user_id=request.user_id or "anonimo",
        api_key=api_key,
        dry_run=settings.CERBERUS_DRY_RUN,
        fail_closed=settings.CERBERUS_FAIL_CLOSED,
        client_signals=request.client_signals.model_dump() if request.client_signals else {},
        body=request.body or {}
    )
    
    try:
        # ============================================
        # 2. RATE LIMITING
        # ============================================
        
        if settings.CERBERUS_RATE_LIMIT_ENABLED:
            rate_limit_result = await enforcement_engine.check_rate_limit(
                ip=real_ip,
                path=request.path,
                db=db
            )
            
            if not rate_limit_result["allowed"]:
                # Auditoría con manejo de errores
                await _safe_audit_log(
                    db=db,
                    execution_id=execution_id,
                    event_type="RATE_LIMIT_EXCEEDED",
                    payload={
                        "ip": real_ip,
                        "path": request.path,
                        "limit": rate_limit_result["limit"],
                        "current": rate_limit_result["current"]
                    }
                )
                
                return DecisionResponse(
                    status=DecisionStatus.THROTTLE,
                    execution_id=execution_id,
                    reason="RATE_LIMIT_EXCEEDED",
                    message="⏳ Demasiadas peticiones, espera unos segundos",
                    timestamp=timestamp.isoformat()
                )
        
        # ============================================
        # 3. DETECCIÓN
        # ============================================
        
        detection_result = detection_engine.analyze(context)
        
        # ============================================
        # 4. RISK ENGINE
        # ============================================
        
        risk_result = risk_engine.calculate(
            detection_result=detection_result,
            context=context
        )
        
        # ============================================
        # 5. POLICY ENGINE
        # ============================================
        
        policy_result = policy_engine.evaluate(
            risk_result=risk_result,
            context=context
        )
        
        # ============================================
        # 6. ENFORCEMENT
        # ============================================
        
        enforcement_result = await enforcement_engine.enforce(
            policy_result=policy_result,
            context=context,
            db=db
        )
        
        # ============================================
        # 7. AUDITORÍA (con manejo de errores)
        # ============================================
        
        await _safe_audit_log(
            db=db,
            execution_id=execution_id,
            event_type=f"DECISION_{policy_result.action}",
            payload={
                "ip": real_ip,
                "path": request.path,
                "method": request.method,
                "user_id": request.user_id,
                "risk_score": risk_result.score,
                "risk_level": risk_result.level,
                "action": policy_result.action,
                "reason": policy_result.reason,
                "evidencias": [e.get("type") for e in detection_result.evidences[:5]],
                "enforcement": enforcement_result
            },
            ip=real_ip,
            path=request.path,
            method=request.method,
            user_id=request.user_id,
            risk_score=risk_result.score,
            risk_level=risk_result.level,
            action=policy_result.action
        )
        
        # ============================================
        # 8. RESPONDER
        # ============================================
        
        if policy_result.action == "DENY":
            return DecisionResponse(
                status=DecisionStatus.DENIED,
                execution_id=execution_id,
                reason=policy_result.reason,
                message="🚫 Acceso bloqueado por CERBERUS",
                timestamp=timestamp.isoformat()
            )
        
        elif policy_result.action == "CHALLENGE":
            return DecisionResponse(
                status=DecisionStatus.CHALLENGE,
                execution_id=execution_id,
                reason=policy_result.reason,
                message="🔒 Se requiere verificación adicional",
                timestamp=timestamp.isoformat()
            )
        
        elif policy_result.action == "THROTTLE":
            return DecisionResponse(
                status=DecisionStatus.THROTTLE,
                execution_id=execution_id,
                reason=policy_result.reason,
                message="⏳ Demasiadas peticiones",
                timestamp=timestamp.isoformat()
            )
        
        else:  # ALLOW
            return DecisionResponse(
                status=DecisionStatus.ALLOWED,
                execution_id=execution_id,
                message="✅ Petición segura",
                timestamp=timestamp.isoformat()
            )
            
    except Exception as e:
        # ============================================
        # FAIL-CLOSED: Si algo falla, DENY
        # ============================================
        
        logger.error(f"❌ Error en decisión {execution_id}: {e}", exc_info=True)
        
        # Auditoría de error con protección contra fallos secundarios
        try:
            await _safe_audit_log(
                db=db,
                execution_id=execution_id,
                event_type="DECISION_ERROR",
                payload={
                    "ip": real_ip,
                    "path": request.path,
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "fail_closed": settings.CERBERUS_FAIL_CLOSED
                },
                ip=real_ip,
                path=request.path,
                method=request.method
            )
        except Exception as audit_error:
            logger.error(f"❌ Error en auditoría de fallo: {audit_error}")
        
        if settings.CERBERUS_FAIL_CLOSED:
            return DecisionResponse(
                status=DecisionStatus.DENIED,
                execution_id=execution_id,
                reason="INTERNAL_ERROR",
                message="⚠️ Error de seguridad, intente más tarde",
                timestamp=timestamp.isoformat()
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Sistema de seguridad no disponible"
            )

# ============================================
# FUNCIÓN AUXILIAR: AUDITORÍA SEGURA
# ============================================

async def _safe_audit_log(db, execution_id: str, event_type: str, payload: dict, **kwargs):
    """
    Auditoría con manejo de errores para evitar fallos secundarios
    """
    try:
        await audit_logger.log_event(
            db=db,
            execution_id=execution_id,
            event_type=event_type,
            payload=payload,
            **kwargs
        )
    except Exception as e:
        logger.error(f"❌ Error en auditoría {execution_id}: {e}")

# ============================================
# ENDPOINTS DE ADMINISTRACIÓN
# ============================================

@app.get("/v1/admin/status")
async def admin_status(
    api_key: str = Depends(validar_api_key),
    db=Depends(get_db)
):
    """Estado del sistema (requiere API Key)"""
    
    # Obtener estadísticas de auditoría
    try:
        stats = await audit_logger.get_stats(db)
    except Exception as e:
        logger.error(f"Error obteniendo stats: {e}")
        stats = {"error": str(e)}
    
    return {
        "status": "active",
        "version": "4.0.0",
        "environment": settings.CERBERUS_ENV,
        "features": {
            "rate_limiting": settings.CERBERUS_RATE_LIMIT_ENABLED,
            "fail_closed": settings.CERBERUS_FAIL_CLOSED,
            "dry_run": settings.CERBERUS_DRY_RUN,
            "api_key_rotation": settings.CERBERUS_API_KEY_ROTATION_INTERVAL,
        },
        "stats": stats,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/v1/admin/blocked-ips")
async def admin_blocked_ips(
    api_key: str = Depends(validar_api_key),
    db=Depends(get_db)
):
    """Listar IPs bloqueadas (requiere API Key)"""
    try:
        blocked = await enforcement_engine.get_blocked_ips(db)
        return {
            "total": len(blocked),
            "ips": blocked,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Error obteniendo IPs bloqueadas: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error obteniendo IPs bloqueadas"
        )

@app.post("/v1/admin/block/{ip}")
async def admin_block_ip(
    ip: str,
    duration_minutes: int = 30,
    reason: str = "Bloqueo manual",
    api_key: str = Depends(validar_api_key),
    db=Depends(get_db)
):
    """Bloquear IP manualmente (requiere API Key)"""
    try:
        result = await enforcement_engine.block_ip(
            ip=ip,
            duration_minutes=duration_minutes,
            reason=reason,
            db=db
        )
        return result
    except Exception as e:
        logger.error(f"Error bloqueando IP {ip}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error bloqueando IP: {str(e)}"
        )

@app.post("/v1/admin/unblock/{ip}")
async def admin_unblock_ip(
    ip: str,
    api_key: str = Depends(validar_api_key),
    db=Depends(get_db)
):
    """Desbloquear IP manualmente (requiere API Key)"""
    try:
        result = await enforcement_engine.unblock_ip(ip, db)
        return result
    except Exception as e:
        logger.error(f"Error desbloqueando IP {ip}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error desbloqueando IP: {str(e)}"
        )

@app.get("/v1/admin/audit")
async def admin_audit(
    limit: int = 50,
    event_type: Optional[str] = None,
    api_key: str = Depends(validar_api_key),
    db=Depends(get_db)
):
    """Ver logs de auditoría (requiere API Key)"""
    try:
        if limit > 1000:
            limit = 1000
        
        logs = await audit_logger.get_events(
            db=db,
            limit=limit,
            event_type=event_type
        )
        return {
            "total": len(logs),
            "events": logs,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Error obteniendo auditoría: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error obteniendo logs de auditoría"
        )

# ============================================
# MANEJADORES DE ERRORES
# ============================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Manejo de errores HTTP con auditoría"""
    
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "🚫 No autorizado",
                "message": exc.detail,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Manejo de errores generales con fail-closed"""
    
    logger.error(f"❌ Error no manejado: {exc}", exc_info=True)
    
    if settings.CERBERUS_FAIL_CLOSED:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "⚠️ Servicio no disponible",
                "message": "Error interno de seguridad",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
    else:
        # En modo no fail-closed, devolver error detallado
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Error interno del servidor",
                "message": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

# ============================================
# MIDDLEWARE: LOGGING DE PETICIONES
# ============================================

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Logging de peticiones para auditoría"""
    
    # Obtener IP real
    real_ip = getattr(request.state, 'real_ip', 'unknown')
    
    # Log de petición
    logger.info(f"📥 {request.method} {request.url.path} desde {real_ip}")
    
    start_time = datetime.now(timezone.utc)
    
    try:
        response = await call_next(request)
        
        # Calcular duración
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        # Log de respuesta
        logger.info(f"📤 {request.method} {request.url.path} → {response.status_code} ({duration:.3f}s)")
        
        return response
        
    except Exception as e:
        logger.error(f"❌ Error en {request.method} {request.url.path}: {e}")
        raise

# ============================================
# INICIAR
# ============================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.CERBERUS_API_HOST,
        port=settings.CERBERUS_API_PORT,
        reload=settings.CERBERUS_DEBUG,
        workers=settings.CERBERUS_API_WORKERS,
        log_level="info" if not settings.CERBERUS_DEBUG else "debug",
    )