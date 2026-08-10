"""
Safety Gate - Última barrera antes de ejecutar acciones
"""

from typing import Dict, Optional, List
from enum import Enum
from datetime import datetime, timezone

class SafetyMode(Enum):
    ACTIVE = "ACTIVE"
    SAFE = "SAFE"
    KILL_SWITCH = "KILL_SWITCH"
    MAINTENANCE = "MAINTENANCE"
    UNKNOWN = "UNKNOWN"

class ActionType(Enum):
    ALERT = "ALERT"
    RATE_LIMIT = "RATE_LIMIT"
    BLOCK = "BLOCK"
    ISOLATE = "ISOLATE"
    REVOKE = "REVOKE"
    RECOVER = "RECOVER"

# Política de seguridad por defecto
DEFAULT_SAFETY_POLICY = {
    "version": 1,
    "mode": "SAFE",
    "actions": {
        "ALERT": {
            "enabled": True,
            "human_approval": False,
            "reversible": True,
            "max_per_minute": 1000,
            "severity": "LOW",
        },
        "RATE_LIMIT": {
            "enabled": True,
            "human_approval": False,
            "reversible": True,
            "max_per_minute": 100,
            "severity": "MEDIUM",
        },
        "BLOCK": {
            "enabled": True,
            "human_approval": False,
            "reversible": True,
            "max_duration_seconds": 900,
            "max_per_hour": 10,
            "severity": "HIGH",
        },
        "ISOLATE": {
            "enabled": True,
            "human_approval": True,
            "reversible": True,
            "max_per_hour": 5,
            "severity": "HIGH",
        },
        "REVOKE": {
            "enabled": True,
            "human_approval": True,
            "reversible": False,
            "max_per_hour": 3,
            "severity": "CRITICAL",
        },
        "RECOVER": {
            "enabled": True,
            "human_approval": True,
            "reversible": False,
            "max_per_day": 2,
            "severity": "CRITICAL",
        },
    },
    "fail_safe": {
        "allowed_actions": ["ALERT", "RATE_LIMIT"],
        "default_mode": "SAFE",
    },
}

class SafetyGate:
    """
    Última barrera antes de ejecutar acciones.
    Verifica: modo de seguridad, acción habilitada, aprobación humana.
    """
    
    FAIL_SAFE_ACTIONS = {"ALERT", "RATE_LIMIT"}
    
    def __init__(self, policy: Optional[Dict] = None):
        self.policy = policy or DEFAULT_SAFETY_POLICY
        self.actions = self.policy["actions"]
        self.fail_safe = self.policy["fail_safe"]
        self._rate_cache = {}
    
    def evaluate(self, action: str, context: Dict) -> Dict:
        """
        Evalúa si una acción puede ejecutarse.
        Retorna decisión con motivo.
        """
        # 1. Obtener modo de seguridad
        mode = context.get("safety_mode", "UNKNOWN")
        
        # 2. UNKNOWN / KILL_SWITCH / MAINTENANCE = FAIL SAFE
        if mode in {"UNKNOWN", "KILL_SWITCH", "MAINTENANCE"}:
            if action not in self.FAIL_SAFE_ACTIONS:
                return {
                    "allowed": False,
                    "reason": f"FAIL_SAFE_MODE: {mode}",
                    "action": action,
                    "mode": mode,
                    "severity": "CRITICAL",
                }
        
        # 3. Verificar que la acción existe
        action_policy = self.actions.get(action)
        if not action_policy:
            return {
                "allowed": False,
                "reason": "UNKNOWN_ACTION",
                "action": action,
                "severity": "HIGH",
            }
        
        # 4. Verificar que la acción está habilitada
        if not action_policy.get("enabled", False):
            return {
                "allowed": False,
                "reason": "ACTION_DISABLED",
                "action": action,
                "severity": action_policy.get("severity", "MEDIUM"),
            }
        
        # 5. Verificar límites de rate (si aplica)
        rate_result = self._check_rate_limit(action, context)
        if not rate_result["allowed"]:
            return {
                "allowed": False,
                "reason": "RATE_LIMIT_EXCEEDED",
                "action": action,
                "limit": rate_result["limit"],
                "current": rate_result["current"],
                "severity": action_policy.get("severity", "MEDIUM"),
            }
        
        # 6. Verificar si requiere aprobación humana
        if action_policy.get("human_approval", False):
            return {
                "allowed": False,
                "requires_human_approval": True,
                "reason": "HUMAN_APPROVAL_REQUIRED",
                "action": action,
                "severity": action_policy.get("severity", "MEDIUM"),
                "policy": action_policy,
                "ttl_seconds": context.get("approval_ttl", 300),
            }
        
        # 7. Acción permitida automáticamente
        return {
            "allowed": True,
            "requires_human_approval": False,
            "action": action,
            "reversible": action_policy.get("reversible", True),
            "severity": action_policy.get("severity", "MEDIUM"),
            "monitoring_level": "HIGH" if action in {"BLOCK", "ISOLATE"} else "NORMAL",
        }
    
    def _check_rate_limit(self, action: str, context: Dict) -> Dict:
        """Verifica límites de rate para la acción"""
        action_policy = self.actions.get(action, {})
        
        # Verificar límite por minuto
        if "max_per_minute" in action_policy:
            key = f"{action}:{context.get('user_id', 'anonymous')}"
            current = self._rate_cache.get(key, 0)
            limit = action_policy["max_per_minute"]
            
            if current >= limit:
                return {
                    "allowed": False,
                    "limit": limit,
                    "current": current,
                }
        
        return {
            "allowed": True,
            "limit": action_policy.get("max_per_minute", float('inf')),
            "current": 0,
        }
    
    def get_action_severity(self, action: str) -> str:
        """Obtiene severidad de la acción"""
        action_policy = self.actions.get(action, {})
        return action_policy.get("severity", "MEDIUM")
    
    def is_action_reversible(self, action: str) -> bool:
        """Verifica si una acción es reversible"""
        action_policy = self.actions.get(action, {})
        return action_policy.get("reversible", True)
    
    def get_fail_safe_actions(self) -> List[str]:
        """Obtiene acciones permitidas en modo fail-safe"""
        return self.fail_safe.get("allowed_actions", ["ALERT"])