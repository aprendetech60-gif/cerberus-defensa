"""
CERBERUS V4 - Detection Engine
"""

import re
from typing import Dict, Any, List
from app.models import DetectionResult, SecurityContext

class DetectionEngine:
    """Motor de detección de amenazas."""
    
    def __init__(self):
        self.sql_patterns = [
            re.compile(r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|--)", re.IGNORECASE),
        ]
    
    def analyze(self, context: SecurityContext) -> DetectionResult:
        """Analiza el contexto en busca de amenazas."""
        # Convertir SecurityContext a dict
        context_dict = context.model_dump()
        
        evidences = []
        sql_risk = 0.0
        path_risk = 0.0
        
        # Analizar body
        body = context_dict.get("body", {})
        body_str = str(body)
        
        for pattern in self.sql_patterns:
            if pattern.search(body_str):
                evidences.append({
                    "type": "sql_injection",
                    "pattern": pattern.pattern,
                    "value": body_str[:200]
                })
                sql_risk = 0.8
                break
        
        # Analizar path
        path = context_dict.get("path", "")
        if "/admin" in path or "/system" in path:
            path_risk = 0.5
            evidences.append({
                "type": "sensitive_path",
                "path": path
            })
        
        total_risk = max(sql_risk, path_risk)
        is_suspicious = total_risk > 0.5
        
        return DetectionResult(
            evidences=evidences,
            sql_risk=sql_risk,
            path_risk=path_risk,
            total_risk=total_risk,
            is_suspicious=is_suspicious
        )