"""
CERBERUS V4 - Policy Engine
"""

from typing import Dict, Any
from app.models import RiskResult, PolicyResult, SecurityContext

class PolicyEngine:
    """Motor de políticas de seguridad."""
    
    def evaluate(
        self,
        risk_result: RiskResult,
        context: SecurityContext
    ) -> PolicyResult:
        """Evalúa el riesgo y decide la acción."""
        score = risk_result.score
        
        # Decisión basada en el score
        if score >= 0.8:
            return PolicyResult(
                action="DENY",
                reason="RIESGO_CRITICO - Acción bloqueada",
                risk_score=score,
                risk_level=risk_result.level,
                dry_run=context.dry_run,
                evidencias=["ALTA_SEVERIDAD"]
            )
        elif score >= 0.6:
            return PolicyResult(
                action="CHALLENGE",
                reason="RIESGO_ALTO - Se requiere verificación",
                risk_score=score,
                risk_level=risk_result.level,
                dry_run=context.dry_run,
                evidencias=["MEDIA_SEVERIDAD"]
            )
        elif score >= 0.4:
            return PolicyResult(
                action="THROTTLE",
                reason="RIESGO_MEDIO - Aplicar rate limiting",
                risk_score=score,
                risk_level=risk_result.level,
                dry_run=context.dry_run,
                evidencias=["BAJA_SEVERIDAD"]
            )
        else:
            return PolicyResult(
                action="ALLOW",
                reason="RIESGO_BAJO - Petición segura",
                risk_score=score,
                risk_level=risk_result.level,
                dry_run=context.dry_run,
                evidencias=["SEGURO"]
            )