"""
CERBERUS V4 - SISTEMA DE DEFENSA AUTÓNOMO
Versión Endurecida para Producción en Render

ARQUITECTURA:
Authentication → Validation → Rate Limit → Detection → Risk → Policy → Enforcement → Audit
"""

from fastapi import FastAPI, Request, HTTPException, Depends, status, Response
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
from app.security.auth import validar_api_key, resolve_real_ip
from app.detection.engine import DetectionEngine
from app.risk.engine import RiskEngine
from app.policy.engine import PolicyEngine
from app.enforcement.engine import EnforcementEngine
from app.audit.logger import AuditLogger

# ============================================
# FUNCIONES DE NORMALIZACIÓN - CONTRATO FUERTE
# ============================================

def _normalize_policy_result(policy_result: Any) -> PolicyResult:
    """
    Normaliza y valida el resultado del Policy Engine.

    Contrato:
        PolicyResult -> se devuelve directamente.
        dict         -> se valida mediante Pydantic.
        cualquier otro tipo -> error explícito.
    """
    if isinstance(policy_result, PolicyResult):
        return policy_result

    if isinstance(policy_result, dict):
        try:
            return PolicyResult.model_validate(policy_result)
        except Exception as exc:
            raise ValueError(
                f"Policy Engine devolvió un resultado inválido: {exc}"
            ) from exc

    raise TypeError(
        "Policy Engine devolvió un tipo no soportado: "
        f"{type(policy_result).__name__}"
    )


def _get_policy_action(policy_result: PolicyResult) -> str:
    """
    Obtiene la acción de política como string canónico.
    """
    action = policy_result.action

    if hasattr(action, "value"):
        action = action.value

    action = str(action).upper().strip()

    allowed_actions = {
        "ALLOW",
        "CHALLENGE",
        "THROTTLE",
        "DENY",
    }

    if action not in allowed_actions:
        raise ValueError(
            f"Acción de política inválida: {action}"
        )

    return action


def _resolve_real_ip(request: Request) -> str:
    """Resuelve la IP real usando la política de proxies confiables."""
    return resolve_real_ip(request)

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
        logger.info("✅ Tablas de base de datos creadas/verificadas")
        
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
# MIDDLEWARE: IP REAL
# ============================================

@app.middleware("http")
async def extract_real_ip(request: Request, call_next):
    """Extrae la IP real de la conexión usando política de proxies confiables."""
    request.state.real_ip = _resolve_real_ip(request)
    response = await call_next(request)
    return response

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

@app.head("/")
async def root_head():
    """HEAD para / - evita 405"""
    return Response(status_code=200)

@app.get("/health")
async def health():
    """
    Health check operacional.

    NO escribe auditoría.
    NO ejecuta lógica de seguridad.
    NO modifica estado.
    """
    components = {
        "api": "healthy",
        "database": "unknown",
        "rate_limiting": "disabled",
        "audit": "available",
    }

    # --------------------------------------------
    # DATABASE
    # --------------------------------------------

    try:
        db_healthy = await check_database_health()
        components["database"] = "healthy" if db_healthy else "unhealthy"
    except Exception as exc:
        logger.error(f"Health check DB error: {exc}")
        components["database"] = "unhealthy"

    # --------------------------------------------
    # RATE LIMITING
    # --------------------------------------------

    if settings.CERBERUS_RATE_LIMIT_ENABLED:
        components["rate_limiting"] = "healthy"

    # --------------------------------------------
    # ESTADO GENERAL
    # --------------------------------------------

    critical = [components["api"], components["database"]]
    overall_status = "healthy" if "unhealthy" not in critical else "unhealthy"

    return {
        "status": overall_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "4.0.0",
        "components": components,
        "details": {
            "fail_closed": settings.CERBERUS_FAIL_CLOSED,
            "dry_run": settings.CERBERUS_DRY_RUN,
        },
    }

# ============================================
# ENDPOINT PRINCIPAL: DECISIÓN
# ============================================

@app.post("/v1/decide", response_model=DecisionResponse)
async def decide(
    request_data: DecisionRequest,
    request: Request,
    api_key: str = Depends(validar_api_key),
    db=Depends(get_db)
):
    """
    Toma una decisión de seguridad basada en la solicitud.
    
    FLUJO:
      1. ✅ Autenticación (API Key)
      2. ✅ IP Real (con proxies confiables)
      3. ✅ Rate Limiting
      4. ✅ Detección
      5. ✅ Risk Engine
      6. ✅ Policy Engine
      7. ✅ Enforcement
      8. ✅ Auditoría
    """
    execution_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc)

    # IP real resuelta por el middleware
    real_ip = getattr(request.state, "real_ip", "unknown")

    # ============================================
    # 1. PREPARAR CONTEXTO
    # ============================================
    
    context = SecurityContext(
        execution_id=execution_id,
        timestamp=timestamp,
        ip=real_ip,
        path=request_data.path,
        method=request_data.method,
        user_id=request_data.user_id or "anonimo",
        api_key=api_key,
        dry_run=settings.CERBERUS_DRY_RUN,
        fail_closed=settings.CERBERUS_FAIL_CLOSED,
        client_signals=request_data.client_signals.model_dump() if request_data.client_signals else {},
        body=request_data.body or {}
    )
    
    try:
        # ============================================
        # 2. RATE LIMITING
        # ============================================
        
        if settings.CERBERUS_RATE_LIMIT_ENABLED:
            rate_limit_result = await enforcement_engine.check_rate_limit(
                ip=real_ip,
                path=request_data.path,
                db=db
            )
            
            if not rate_limit_result["allowed"]:
                await _safe_audit_log(
                    db=db,
                    execution_id=execution_id,
                    event_type="RATE_LIMIT_EXCEEDED",
                    payload={
                        "ip": real_ip,
                        "path": request_data.path,
                        "limit": rate_limit_result["limit"],
                        "current": rate_limit_result["current"]
                    },
                    ip=real_ip,
                    path=request_data.path,
                    method=request_data.method
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
        
        raw_policy_result = policy_engine.evaluate(
            risk_result=risk_result,
            context=context
        )
        
        # ✅ Normalizar y validar resultado del Policy Engine
        policy_result = _normalize_policy_result(raw_policy_result)
        
        # ✅ Obtener acción canónica
        action = _get_policy_action(policy_result)
        
        # ============================================
        # 6. ENFORCEMENT
        # ============================================
        
        enforcement_result = await enforcement_engine.enforce(
            policy_result=policy_result,
            context=context,
            db=db
        )
        
        # ============================================
        # 7. AUDITORÍA - Evento de seguridad crítico
        # ============================================
        
        await _audit_security_event(
            db=db,
            execution_id=execution_id,
            event_type=f"DECISION_{action}",
            payload={
                "ip": real_ip,
                "path": request_data.path,
                "method": request_data.method,
                "user_id": request_data.user_id,
                "risk_score": risk_result.score,
                "risk_level": risk_result.level,
                "action": action,
                "reason": policy_result.reason,
                "evidencias": [
                    e.get("type")
                    for e in detection_result.evidences[:5]
                ],
                "enforcement": enforcement_result
            },
            ip=real_ip,
            path=request_data.path,
            method=request_data.method,
            user_id=request_data.user_id,
            risk_score=risk_result.score,
            risk_level=risk_result.level,
            action=action
        )
        
        # ============================================
        # 8. RESPONDER
        # ============================================
        
        if action == "DENY":
            return DecisionResponse(
                status=DecisionStatus.DENIED,
                execution_id=execution_id,
                reason=policy_result.reason,
                message="🚫 Acceso bloqueado por CERBERUS",
                timestamp=timestamp.isoformat()
            )
        
        elif action == "CHALLENGE":
            return DecisionResponse(
                status=DecisionStatus.CHALLENGE,
                execution_id=execution_id,
                reason=policy_result.reason,
                message="🔒 Se requiere verificación adicional",
                timestamp=timestamp.isoformat()
            )
        
        elif action == "THROTTLE":
            return DecisionResponse(
                status=DecisionStatus.THROTTLE,
                execution_id=execution_id,
                reason=policy_result.reason,
                message="⏳ Demasiadas peticiones",
                timestamp=timestamp.isoformat()
            )
        
        elif action == "ALLOW":
            return DecisionResponse(
                status=DecisionStatus.ALLOWED,
                execution_id=execution_id,
                message="✅ Petición segura",
                timestamp=timestamp.isoformat()
            )
        
        else:
            raise RuntimeError(f"Acción no contemplada: {action}")
            
    except Exception as exc:
        # ============================================
        # FAIL-CLOSED: Si el motor falla, 503
        # ============================================
        
        logger.error(f"❌ Error en decisión {execution_id}: {exc}", exc_info=True)
        
        # Auditoría del error
        try:
            await _safe_audit_log(
                db=db,
                execution_id=execution_id,
                event_type="DECISION_ERROR",
                payload={
                    "ip": real_ip,
                    "path": request_data.path,
                    "error_type": type(exc).__name__,
                    "fail_closed": settings.CERBERUS_FAIL_CLOSED
                },
                ip=real_ip,
                path=request_data.path,
                method=request_data.method
            )
        except Exception as audit_error:
            logger.error(f"❌ Error auditando fallo: {audit_error}")
        
        if settings.CERBERUS_FAIL_CLOSED:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "status": "DENIED",
                    "execution_id": execution_id,
                    "reason": "SECURITY_ENGINE_ERROR",
                    "message": "⚠️ CERBERUS no pudo completar la evaluación",
                    "timestamp": timestamp.isoformat()
                }
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error interno del motor de seguridad"
            )

# ============================================
# FUNCIONES AUXILIARES DE AUDITORÍA
# ============================================

async def _audit_security_event(db, execution_id: str, event_type: str, payload: dict, **kwargs):
    """
    Auditoría para eventos de seguridad críticos.
    Si falla, propaga el error.
    """
    await audit_logger.log_event(
        db=db,
        execution_id=execution_id,
        event_type=event_type,
        payload=payload,
        **kwargs
    )

async def _safe_audit_log(db, execution_id: str, event_type: str, payload: dict, **kwargs):
    """
    Auditoría con manejo de errores para eventos no críticos.
    """
    try:
        await audit_logger.log_event(
            db=db,
            execution_id=execution_id,
            event_type=event_type,
            payload=payload,
            **kwargs
        )
    except Exception as exc:
        logger.error(f"❌ Error en auditoría {execution_id}: {exc}", exc_info=True)

# ============================================
# ENDPOINTS DE ADMINISTRACIÓN
# ============================================

@app.get("/v1/admin/status")
async def admin_status(
    api_key: str = Depends(validar_api_key),
    db=Depends(get_db)
):
    """Estado del sistema (requiere API Key)"""
    
    try:
        stats = await audit_logger.get_stats(db)
    except Exception as e:
        logger.error(f"Error obteniendo stats: {e}")
        stats = {"error": "Error obteniendo estadísticas"}
    
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
        if duration_minutes < 1 or duration_minutes > 10080:
            raise ValueError("duration_minutes debe estar entre 1 y 10080 (7 días)")
        
        result = await enforcement_engine.block_ip(
            ip=ip,
            duration_minutes=duration_minutes,
            reason=reason,
            db=db
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Error bloqueando IP {ip}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno al bloquear IP"
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
        logger.error(f"Error desbloqueando IP {ip}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno al desbloquear IP"
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
        if limit < 1 or limit > 1000:
            raise ValueError("limit debe estar entre 1 y 1000")
        
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
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Error obteniendo auditoría: {e}", exc_info=True)
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
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Error interno del servidor",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

# ============================================
# MIDDLEWARE: LOGGING DE PETICIONES
# ============================================

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Logging de peticiones para auditoría"""
    
    real_ip = getattr(request.state, 'real_ip', 'unknown')
    logger.info(f"📥 {request.method} {request.url.path} desde {real_ip}")
    
    start_time = datetime.now(timezone.utc)
    
    try:
        response = await call_next(request)
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
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