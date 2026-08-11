"""
CERBERUS V4 - Policy Engine
"""

from typing import Dict, Any
from app.models import RiskResult, PolicyResult

class PolicyEngine:
    """Motor de políticas de seguridad."""
    
    def evaluate(
        self,
        risk_result: RiskResult,
        context: Dict[str, Any]
    ) -> PolicyResult:
        """Evalúa el riesgo y decide la acción."""
        score = risk_result.score
        
        if score >= 0.8:
            return PolicyResult(
                action="DENY",
                reason="RIESGO_CRITICO",
                risk_score=score,
                risk_level=risk_result.level,
                dry_run=context.get("dry_run", False)
            )
        elif score >= 0.6:
            return PolicyResult(
                action="CHALLENGE",
                reason="RIESGO_ALTO",
                risk_score=score,
                risk_level=risk_result.level,
                dry_run=context.get("dry_run", False)
            )
        elif score >= 0.4:
            return PolicyResult(
                action="THROTTLE",
                reason="RIESGO_MEDIO",
                risk_score=score,
                risk_level=risk_result.level,
                dry_run=context.get("dry_run", False)
            )
        else:
            return PolicyResult(
                action="ALLOW",
                reason="RIESGO_BAJO",
                risk_score=score,
                risk_level=risk_result.level,
                dry_run=context.get("dry_run", False)
            )