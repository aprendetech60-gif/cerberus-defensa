"""
CERBERUS V4 - Motor de Riesgo
"""

from typing import Dict, Any

class RiskEngine:
    """
    Calcula el riesgo basado en detecciones y contexto
    """
    
    def __init__(self):
        self.weight_sql = 0.35
        self.weight_path = 0.25
        self.weight_bot = 0.20
        self.weight_auth = 0.20
    
    def calculate(self, detection_result: Dict, context) -> Dict:
        """
        Calcula el riesgo total y nivel
        """
        # Riesgo base de detección
        base_risk = detection_result.get("total_risk", 0.0)
        
        # Factores de riesgo
        factors = {
            "sql_injection": detection_result.get("sql_risk", 0.0) * self.weight_sql,
            "path_abuse": detection_result.get("path_risk", 0.0) * self.weight_path,
            "bot_signals": 0.0,
            "auth_risk": 0.0,
        }
        
        # Riesgo por señales de bot
        evidencias = detection_result.get("evidences", [])
        if len(evidencias) > 0:
            # Aumentar riesgo por cantidad de evidencias
            bot_score = min(0.1 * len(evidencias), 0.4)
            # Añadir confianza de las evidencias
            confidence_sum = sum(e.get("confidence", 0.0) for e in evidencias)
            if confidence_sum > 1.0:
                bot_score += min((confidence_sum - 1.0) * 0.1, 0.2)
            factors["bot_signals"] = min(bot_score, 0.4)
        
        # Riesgo por autenticación
        if hasattr(context, 'user_id') and context.user_id == "admin":
            if not context.client_signals.get("auth_token"):
                factors["auth_risk"] = 0.4
        
        # Riesgo total
        total_risk = sum(factors.values())
        total_risk = min(total_risk, 1.0)
        
        # Determinar nivel
        if total_risk >= 0.7:
            level = "CRITICAL"
        elif total_risk >= 0.5:
            level = "HIGH"
        elif total_risk >= 0.3:
            level = "MEDIUM"
        elif total_risk >= 0.1:
            level = "LOW"
        else:
            level = "MINIMAL"
        
        # Confianza (basada en cantidad de señales)
        signal_count = len(evidencias)
        confidence = min(0.5 + (signal_count * 0.1), 0.95)
        
        return {
            "score": total_risk,
            "level": level,
            "confidence": confidence,
            "factors": factors,
            "evidencias": [e.get("type", "unknown") for e in evidencias]
        }