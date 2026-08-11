"""
CERBERUS V4 - Risk Engine
"""

from typing import Dict, Any
from app.models import DetectionResult, RiskResult

class RiskEngine:
    """Motor de cálculo de riesgo."""
    
    def calculate(
        self,
        detection_result: DetectionResult,
        context: Dict[str, Any]
    ) -> RiskResult:
        """Calcula el riesgo basado en detecciones."""
        score = detection_result.total_risk
        
        # Factores adicionales
        factors = {
            "sql_risk": detection_result.sql_risk,
            "path_risk": detection_result.path_risk,
            "is_suspicious": 1.0 if detection_result.is_suspicious else 0.0
        }
        
        # Nivel de riesgo
        if score < 0.2:
            level = "NONE"
        elif score < 0.4:
            level = "LOW"
        elif score < 0.6:
            level = "MEDIUM"
        elif score < 0.8:
            level = "HIGH"
        else:
            level = "CRITICAL"
        
        return RiskResult(
            score=score,
            level=level,
            confidence=0.9,
            factors=factors
        )