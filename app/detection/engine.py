"""
CERBERUS V4 - Detection Engine
"""

import re
from typing import Dict, Any, List
from app.models import DetectionResult

class DetectionEngine:
    """Motor de detección de amenazas."""
    
    def __init__(self):
        self.sql_patterns = [
            re.compile(r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|--|;)", re.IGNORECASE),
        ]
    
    def analyze(self, context: Dict[str, Any]) -> DetectionResult:
        """Analiza el contexto en busca de amenazas."""
        evidences = []
        sql_risk = 0.0
        
        body = context.get("body", {})
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
        
        return DetectionResult(
            evidences=evidences,
            sql_risk=sql_risk,
            path_risk=0.0,
            total_risk=sql_risk,
            is_suspicious=sql_risk > 0.5
        )