#!/usr/bin/env python
"""
Generador de llaves Ed25519 para CERBERUS
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
import base64
import os

def generar_llaves():
    """Genera y muestra las llaves de seguridad"""
    
    # Generar llave privada
    llave_privada = Ed25519PrivateKey.generate()
    
    # Obtener llave pública
    llave_publica = llave_privada.public_key()
    
    # Convertir a base64 (texto)
    privada_bytes = llave_privada.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    publica_bytes = llave_publica.public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    
    privada_b64 = base64.b64encode(privada_bytes).decode('ascii')
    publica_b64 = base64.b64encode(publica_bytes).decode('ascii')
    
    # Mostrar en pantalla
    print("=" * 60)
    print("🔑 LLAVES DE CERBERUS - COPIA ESTO")
    print("=" * 60)
    print()
    print("📌 LLAVE PRIVADA (NO LA COMPARTAS):")
    print(privada_b64)
    print()
    print("📌 LLAVE PÚBLICA (Puedes compartirla):")
    print(publica_b64)
    print()
    print("=" * 60)
    print("⚠️  GUARDA ESTAS LLAVES EN UN LUGAR SEGURO")
    print("=" * 60)
    
    # Guardar en archivo
    with open("llaves_cerberus.txt", "w") as f:
        f.write("CERBERUS_PRIVATE_KEY_B64=" + privada_b64 + "\n")
        f.write("CERBERUS_PUBLIC_KEY_B64=" + publica_b64 + "\n")
    
    print()
    print("✅ Las llaves también se guardaron en: llaves_cerberus.txt")

if __name__ == "__main__":
    generar_llaves()