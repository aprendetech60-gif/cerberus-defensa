"""
CERBERUS V4 - Motor de Políticas
"""

from typing import Dict, Any
from app.config import settings

class PolicyEngine:
    """
    Evalúa el riesgo y decide la acción
    """
    
    def __init__(self):
        self.thresholds = {
            "DENY": 0.7,
            "CHALLENGE": 0.5,
            "THROTTLE": 0.3,
            "ALLOW": 0.0,
        }
        
        self.risk_actions = {
            "CRITICAL": "DENY",
            "HIGH": "CHALLENGE",
            "MEDIUM": "THROTTLE",
            "LOW": "ALLOW",
            "MINIMAL": "ALLOW",
        }
    
    def evaluate(self, risk_result: Dict, context) -> Dict:
        """
        Evalúa el riesgo y retorna una acción
        """
        risk_score = risk_result.get("score", 0.0)
        risk_level = risk_result.get("level", "MINIMAL")
        
        # Si está en DRY_RUN, siempre permitir (solo simular)
        if settings.CERBERUS_DRY_RUN:
            return {
                "action": "ALLOW",
                "reason": "DRY_RUN",
                "risk_score": risk_score,
                "risk_level": risk_level,
                "dry_run": True,
                "evidencias": risk_result.get("evidencias", [])
            }
        
        # Acción por nivel de riesgo
        action = self.risk_actions.get(risk_level, "ALLOW")
        
        # Override por umbrales
        if risk_score >= self.thresholds["DENY"]:
            action = "DENY"
        elif risk_score >= self.thresholds["CHALLENGE"]:
            action = "CHALLENGE"
        elif risk_score >= self.thresholds["THROTTLE"]:
            action = "THROTTLE"
        else:
            action = "ALLOW"
        
        # Razón de la decisión
        if action == "DENY":
            reason = f"RIESGO_CRITICO ({risk_score:.2f})"
        elif action == "CHALLENGE":
            reason = f"RIESGO_ALTO ({risk_score:.2f})"
        elif action == "THROTTLE":
            reason = f"RIESGO_MEDIO ({risk_score:.2f})"
        else:
            reason = "RIESGO_BAJO"
        
        return {
            "action": action,
            "reason": reason,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "dry_run": settings.CERBERUS_DRY_RUN,
            "evidencias": risk_result.get("evidencias", [])
        }