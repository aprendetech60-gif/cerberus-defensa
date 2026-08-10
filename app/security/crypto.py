"""
Criptografía completa para CERBERUS
Ed25519 + SHA-256 + Base64 + Fernet
"""

import json
import hashlib
import hmac
import base64
import os
from typing import Dict, Any, Optional, Union
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# ============================================
# CANONICAL JSON
# ============================================

def canonical_json(data: Any) -> bytes:
    """Representación canónica para hashing y firma"""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

def hash_canonical(data: Any) -> str:
    """Hash SHA-256 de datos canónicos"""
    return hashlib.sha256(canonical_json(data)).hexdigest()

def verify_hash(received: str, calculated: str) -> bool:
    """Comparación segura de hashes (tiempo constante)"""
    return hmac.compare_digest(received, calculated)

# ============================================
# ED25519 - FIRMA Y VERIFICACIÓN
# ============================================

def load_private_key(b64_key: str) -> Ed25519PrivateKey:
    """Carga clave privada desde base64"""
    try:
        raw = base64.b64decode(b64_key)
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as e:
        raise ValueError(f"Error cargando clave privada: {e}")

def load_public_key(b64_key: str) -> Ed25519PublicKey:
    """Carga clave pública desde base64"""
    try:
        raw = base64.b64decode(b64_key)
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as e:
        raise ValueError(f"Error cargando clave pública: {e}")

def private_to_base64(private_key: Ed25519PrivateKey) -> str:
    """Convierte clave privada a base64"""
    raw = private_key.private_bytes(
        Encoding.Raw,
        PrivateFormat.Raw,
        NoEncryption()
    )
    return base64.b64encode(raw).decode('ascii')

def public_to_base64(public_key: Ed25519PublicKey) -> str:
    """Convierte clave pública a base64"""
    raw = public_key.public_bytes(
        Encoding.Raw,
        PublicFormat.Raw
    )
    return base64.b64encode(raw).decode('ascii')

def generate_key_pair() -> tuple:
    """Genera par de llaves Ed25519"""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def sign_hash(private_key: Ed25519PrivateKey, hash_value: str) -> str:
    """Firma un hash con Ed25519, retorna base64"""
    signature = private_key.sign(hash_value.encode("utf-8"))
    return base64.b64encode(signature).decode("ascii")

def verify_signature(
    public_key: Ed25519PublicKey,
    signature_b64: str,
    hash_value: str,
) -> bool:
    """Verifica firma Ed25519 desde base64"""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, hash_value.encode("utf-8"))
        return True
    except Exception:
        return False

# ============================================
# FIRMA DE ESTRUCTURAS
# ============================================

def sign_structure(
    private_key: Ed25519PrivateKey,
    data: Dict,
    exclude_fields: list = None
) -> Dict:
    """
    Firma una estructura de datos.
    Retorna la estructura con hash y firma agregados.
    """
    exclude = exclude_fields or ["hash", "signature"]
    
    to_sign = {
        k: v for k, v in data.items()
        if k not in exclude
    }
    
    data_hash = hash_canonical(to_sign)
    signature = sign_hash(private_key, data_hash)
    
    result = data.copy()
    result["hash"] = data_hash
    result["signature"] = signature
    
    return result

def verify_structure(
    public_key: Ed25519PublicKey,
    data: Dict,
    exclude_fields: list = None
) -> bool:
    """Verifica una estructura firmada."""
    exclude = exclude_fields or ["hash", "signature"]
    
    stored_hash = data.get("hash")
    signature = data.get("signature")
    
    if not stored_hash or not signature:
        return False
    
    to_verify = {
        k: v for k, v in data.items()
        if k not in exclude
    }
    
    calculated_hash = hash_canonical(to_verify)
    
    if not verify_hash(stored_hash, calculated_hash):
        return False
    
    return verify_signature(public_key, signature, stored_hash)

# ============================================
# CLASE PRINCIPAL - CERBERUS CRYPTO
# ============================================

class CerberusCrypto:
    """
    Clase principal de criptografía para Cerberus
    Maneja cifrado simétrico (Fernet) y asimétrico (RSA)
    """
    
    def __init__(self):
        """Inicializar el sistema de criptografía"""
        self.llaves: Dict[str, Any] = {}
        self.fernet_instances: Dict[str, Fernet] = {}
        self._cargar_llaves()
    
    def _cargar_llaves(self):
        """Cargar llaves desde el archivo de configuración"""
        from app.config import settings  # ✅ CORREGIDO: settings en lugar de config
        
        key_path = Path(settings.KEY_FILE) if hasattr(settings, 'KEY_FILE') else Path("app/llaves_cerberus.txt")
        
        if key_path.exists():
            try:
                with open(key_path, 'r') as f:
                    data = json.load(f)
                    for key_id, key_data in data.items():
                        llave = type('Llave', (), {
                            'id': key_id,
                            'llave': key_data.get('llave'),
                            'creada': datetime.fromisoformat(key_data.get('creada')),
                            'activa': key_data.get('activa', True),
                            'tipo': key_data.get('tipo', 'fernet')
                        })()
                        self.llaves[key_id] = llave
                        if llave.activa:
                            self.fernet_instances[key_id] = Fernet(llave.llave.encode())
            except Exception as e:
                print(f"⚠️ Error cargando llaves: {e}")
                self._generar_llave_por_defecto()
        else:
            self._generar_llave_por_defecto()
    
    def _generar_llave_por_defecto(self):
        """Generar llave por defecto si no existe ninguna"""
        key_id = "cerberus_default"
        key = Fernet.generate_key().decode()
        
        llave = type('Llave', (), {
            'id': key_id,
            'llave': key,
            'creada': datetime.now(),
            'activa': True,
            'tipo': 'fernet'
        })()
        
        self.llaves[key_id] = llave
        self.fernet_instances[key_id] = Fernet(key.encode())
        self._guardar_llaves()
        print(f"✅ Llave por defecto generada: {key_id}")
    
    def _guardar_llaves(self):
        """Guardar todas las llaves en el archivo"""
        from app.config import settings  # ✅ CORREGIDO: settings en lugar de config
        
        key_path = Path(settings.KEY_FILE) if hasattr(settings, 'KEY_FILE') else Path("app/llaves_cerberus.txt")
        
        data = {}
        for key_id, llave in self.llaves.items():
            data[key_id] = {
                'llave': llave.llave,
                'creada': llave.creada.isoformat(),
                'activa': llave.activa,
                'tipo': llave.tipo
            }
        
        key_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(key_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def generar_llave(self, key_id: str = None):
        """Generar una nueva llave Fernet"""
        if key_id is None:
            key_id = f"cerberus_key_{len(self.llaves) + 1}"
        
        if key_id in self.llaves:
            key_id = f"{key_id}_{len(self.llaves)}"
        
        key = Fernet.generate_key().decode()
        
        llave = type('Llave', (), {
            'id': key_id,
            'llave': key,
            'creada': datetime.now(),
            'activa': True,
            'tipo': 'fernet'
        })()
        
        self.llaves[key_id] = llave
        self.fernet_instances[key_id] = Fernet(key.encode())
        self._guardar_llaves()
        
        return llave
    
    def cifrar(self, mensaje: str, key_id: str = None):
        """Cifrar un mensaje usando Fernet"""
        if key_id is None:
            for k_id, fernet in self.fernet_instances.items():
                if self.llaves[k_id].activa:
                    key_id = k_id
                    break
        
        if key_id not in self.fernet_instances:
            raise ValueError(f"Llave no encontrada o inactiva: {key_id}")
        
        fernet = self.fernet_instances[key_id]
        mensaje_cifrado = fernet.encrypt(mensaje.encode()).decode()
        
        resultado = type('MensajeCifrado', (), {
            'mensaje': mensaje_cifrado,
            'llave_id': key_id,
            'timestamp': datetime.now(),
            'algoritmo': 'fernet'
        })()
        
        return resultado
    
    def descifrar(self, mensaje_cifrado):
        """Descifrar un mensaje usando Fernet"""
        key_id = mensaje_cifrado.llave_id
        
        if key_id not in self.fernet_instances:
            raise ValueError(f"Llave no encontrada: {key_id}")
        
        fernet = self.fernet_instances[key_id]
        mensaje_descifrado = fernet.decrypt(mensaje_cifrado.mensaje.encode()).decode()
        
        resultado = type('MensajeDescifrado', (), {
            'mensaje_original': mensaje_cifrado.mensaje,
            'mensaje_descifrado': mensaje_descifrado,
            'llave_id': key_id,
            'timestamp': datetime.now()
        })()
        
        return resultado
    
    def cifrar_texto(self, texto: str, key_id: str = None) -> str:
        """Método simplificado para cifrar texto"""
        resultado = self.cifrar(texto, key_id)
        return resultado.mensaje
    
    def descifrar_texto(self, texto_cifrado: str, key_id: str = None) -> str:
        """Método simplificado para descifrar texto"""
        if key_id is None:
            for k_id in self.fernet_instances.keys():
                try:
                    fernet = self.fernet_instances[k_id]
                    return fernet.decrypt(texto_cifrado.encode()).decode()
                except:
                    continue
            raise ValueError("No se pudo descifrar con ninguna llave")
        
        mensaje_cifrado = type('MensajeCifrado', (), {
            'mensaje': texto_cifrado,
            'llave_id': key_id,
            'timestamp': datetime.now(),
            'algoritmo': 'fernet'
        })()
        
        resultado = self.descifrar(mensaje_cifrado)
        return resultado.mensaje_descifrado
    
    def obtener_llaves(self) -> Dict:
        """Obtener todas las llaves"""
        return self.llaves
    
    def obtener_llave(self, key_id: str):
        """Obtener una llave específica"""
        return self.llaves.get(key_id)
    
    def desactivar_llave(self, key_id: str) -> bool:
        """Desactivar una llave"""
        if key_id in self.llaves:
            self.llaves[key_id].activa = False
            if key_id in self.fernet_instances:
                del self.fernet_instances[key_id]
            self._guardar_llaves()
            return True
        return False
    
    def eliminar_llave(self, key_id: str) -> bool:
        """Eliminar una llave (con precaución)"""
        if key_id in self.llaves:
            del self.llaves[key_id]
            if key_id in self.fernet_instances:
                del self.fernet_instances[key_id]
            self._guardar_llaves()
            return True
        return False
    
    def rotar_llave(self, key_id: str):
        """Rotar una llave (generar nueva y desactivar la anterior)"""
        if key_id in self.llaves:
            self.desactivar_llave(key_id)
            new_key_id = f"{key_id}_rotated"
            return self.generar_llave(new_key_id)
        return None

# ============================================
# FUNCIONES DE UTILIDAD
# ============================================

def hash_password(password: str) -> str:
    """Hashear una contraseña usando PBKDF2"""
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return f"{salt.hex()}:{key.decode()}"

def verify_password(password: str, hashed: str) -> bool:
    """Verificar una contraseña contra su hash"""
    try:
        salt_hex, key_str = hashed.split(':')
        salt = bytes.fromhex(salt_hex)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode() == key_str
    except:
        return False

def generar_token_seguro(length: int = 32) -> str:
    """Generar un token seguro aleatorio"""
    return base64.urlsafe_b64encode(os.urandom(length)).decode().rstrip('=')

def cifrar_mensaje_simple(mensaje: str, llave: str) -> str:
    """Cifrar un mensaje con una llave específica"""
    fernet = Fernet(llave.encode())
    return fernet.encrypt(mensaje.encode()).decode()

def descifrar_mensaje_simple(mensaje_cifrado: str, llave: str) -> str:
    """Descifrar un mensaje con una llave específica"""
    fernet = Fernet(llave.encode())
    return fernet.decrypt(mensaje_cifrado.encode()).decode()

# ============================================
# INSTANCIA GLOBAL
# ============================================

crypto = CerberusCrypto()

__all__ = [
    'crypto',
    'CerberusCrypto',
    'load_private_key',
    'load_public_key',
    'private_to_base64',
    'public_to_base64',
    'generate_key_pair',
    'sign_hash',
    'verify_signature',
    'sign_structure',
    'verify_structure',
    'hash_password',
    'verify_password',
    'generar_token_seguro',
    'cifrar_mensaje_simple',
    'descifrar_mensaje_simple',
    'canonical_json',
    'hash_canonical',
    'verify_hash',
]