"""
CERBERUS V4 - Motor de Detección
"""

import re
from typing import Dict, List, Any

class DetectionEngine:
    """
    Motor de detección de amenazas
    """
    
    def __init__(self):
        self.sql_patterns = [
            (r'SELECT\s+.*?\s+FROM', 0.3),
            (r'DROP\s+TABLE', 0.4),
            (r'INSERT\s+INTO', 0.3),
            (r'UPDATE\s+.*?\s+SET', 0.3),
            (r'DELETE\s+FROM', 0.3),
            (r'UNION\s+SELECT', 0.4),
            (r'OR\s+1\s*=\s*1', 0.4),
            (r'OR\s+1=1', 0.3),
            (r'--', 0.2),
            (r'/\*', 0.2),
            (r'\bWAITFOR\b', 0.3),
            (r'\bBENCHMARK\b', 0.3),
            (r'\bSLEEP\b', 0.3),
            (r'\bEXEC\b', 0.3),
            (r'\bEXECUTE\b', 0.3),
            (r'\bXP_CMDSHELL\b', 0.5),
        ]
        
        self.path_patterns = [
            (r'/admin', 0.3),
            (r'/administrator', 0.3),
            (r'/root', 0.3),
            (r'/config', 0.3),
            (r'/\.env', 0.4),
            (r'/\.git', 0.4),
            (r'/wp-admin', 0.3),
            (r'/phpmyadmin', 0.3),
            (r'/\.\./', 0.4),
            (r'/\.\.%2f', 0.4),
        ]
    
    def normalize_text(self, text: str) -> str:
        """Normaliza texto para detección"""
        if not text:
            return ""
        text = text.upper()
        text = re.sub(r'--.*?$', '', text, flags=re.MULTILINE)
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
        return text
    
    def detect_sql_injection(self, body: Dict) -> float:
        """Detecta SQL Injection en el body"""
        body_str = str(body)
        body_norm = self.normalize_text(body_str)
        
        riesgo = 0.0
        for pattern, score in self.sql_patterns:
            if re.search(pattern, body_norm, re.IGNORECASE):
                riesgo += score
        
        return min(riesgo, 1.0)
    
    def detect_path_abuse(self, path: str) -> float:
        """Detecta abuso en la ruta"""
        path_lower = path.lower()
        riesgo = 0.0
        
        for pattern, score in self.path_patterns:
            if re.search(pattern, path_lower, re.IGNORECASE):
                riesgo += score
        
        return min(riesgo, 1.0)
    
    def detect_bot_signals(self, context) -> List[Dict]:
        """Detecta señales de bot/automation"""
        evidencias = []
        client_signals = context.client_signals if hasattr(context, 'client_signals') else {}
        
        if client_signals.get("user_agent"):
            user_agent = client_signals["user_agent"].lower()
            bot_patterns = ['bot', 'crawler', 'spider', 'scrape', 'curl', 'wget', 'python', 'java']
            for pattern in bot_patterns:
                if pattern in user_agent:
                    evidencias.append({
                        "type": "user_agent_bot",
                        "details": {"pattern": pattern},
                        "confidence": 0.6
                    })
                    break
        
        if client_signals.get("mouse_movements", 0) < 1 and \
           client_signals.get("clicks", 0) < 1 and \
           client_signals.get("key_presses", 0) < 1:
            if client_signals.get("time_on_page", 0) < 2000:
                evidencias.append({
                    "type": "sin_interaccion_humana",
                    "details": {"time_on_page": client_signals.get("time_on_page", 0)},
                    "confidence": 0.4
                })
        
        if client_signals.get("time_on_page", 0) < 500:
            evidencias.append({
                "type": "tiempo_en_pagina_muy_corto",
                "details": {"time_on_page": client_signals.get("time_on_page", 0)},
                "confidence": 0.3
            })
        
        return evidencias
    
    def analyze(self, context) -> Dict:
        """
        Analiza el contexto y retorna evidencias de detección
        """
        path = context.path if hasattr(context, 'path') else "/"
        body = context.body if hasattr(context, 'body') else {}
        
        sql_risk = self.detect_sql_injection(body)
        path_risk = self.detect_path_abuse(path)
        bot_evidencias = self.detect_bot_signals(context)
        
        evidencias = bot_evidencias.copy()
        
        if sql_risk > 0.3:
            evidencias.append({
                "type": "sql_injection_detectada",
                "details": {"risk": sql_risk},
                "confidence": min(0.5 + sql_risk, 0.9)
            })
        
        if path_risk > 0.3:
            evidencias.append({
                "type": "path_abuse_detectado",
                "details": {"risk": path_risk},
                "confidence": min(0.5 + path_risk, 0.9)
            })
        
        if hasattr(context, 'user_id') and context.user_id == "admin" and not context.client_signals.get("auth_token"):
            evidencias.append({
                "type": "admin_sin_autenticacion",
                "details": {"user_id": "admin"},
                "confidence": 0.7
            })
        
        total_risk = sql_risk + path_risk
        if len(evidencias) > 2:
            total_risk += 0.1 * len(evidencias)
        total_risk = min(total_risk, 1.0)
        
        return {
            "evidences": evidencias,
            "sql_risk": sql_risk,
            "path_risk": path_risk,
            "total_risk": total_risk,
            "is_suspicious": len(evidencias) > 0 or total_risk > 0.3
        }