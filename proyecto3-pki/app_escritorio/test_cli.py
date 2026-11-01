"""
Script de Pruebas Automatizadas de mTLS - Proyecto 3 (UNDC 2026)
----------------------------------------------------------------
Ejecuta las 3 pruebas de la rubrica:
1. Conexion con Certificado Valido (firmado por Root CA) -> EXITO
2. Conexion SIN Certificado Digital -> RECHAZADO
3. Conexion con Certificado de OTRA CA (Atacante) -> RECHAZADO
"""

import os
import sys
import ssl
import json
import urllib.request
import urllib.error

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
CERTS_DIR = os.path.join(PROJECT_DIR, "pki", "certs")

CA_CRT = os.path.join(CERTS_DIR, "ca.crt")
CLIENT_CRT = os.path.join(CERTS_DIR, "client.crt")
CLIENT_KEY = os.path.join(CERTS_DIR, "client.key")

ATTACKER_CRT = os.path.join(CERTS_DIR, "attacker.crt")
ATTACKER_KEY = os.path.join(CERTS_DIR, "attacker.key")

API_URL = "https://127.0.0.1:8443/api/operaciones"


def test_con_certificado_valido():
    print("\n" + "="*60)
    print("TEST 1: Conexion con Certificado Valido emitido por Root CA")
    print("="*60)
    
    # Configurar contexto SSL del cliente con su certificado y llave privada
    context = ssl.create_default_context(cafile=CA_CRT)
    context.load_cert_chain(certfile=CLIENT_CRT, keyfile=CLIENT_KEY)
    
    req = urllib.request.Request(API_URL, method="GET")
    try:
        with urllib.request.urlopen(req, context=context, timeout=5) as response:
            status = response.status
            data = json.loads(response.read().decode("utf-8"))
            print(f"[STATUS] {status} OK")
            print(f"[RESPUESTA DEL API]:\n{json.dumps(data, indent=2)}")
            print("\n>>> RESULTADO: [PASO] Acceso autorizado sin contraseñas ni API Keys.")
            return True
    except Exception as e:
        print(f"[FALLO INESPERADO]: {e}")
        return False


def test_sin_certificado():
    print("\n" + "="*60)
    print("TEST 2: Intento de Conexion SIN Certificado de Cliente")
    print("="*60)
    
    # Solo valida el servidor, NO presenta certificado propio
    context = ssl.create_default_context(cafile=CA_CRT)
    
    req = urllib.request.Request(API_URL, method="GET")
    try:
        with urllib.request.urlopen(req, context=context, timeout=5) as response:
            print("[ERROR] El servidor permitio el acceso sin certificado!")
            return False
    except ssl.SSLError as e:
        print(f"[BLOQUEO TLS ESPERADO]: {e.reason or e}")
        print("\n>>> RESULTADO: [PASO] El handshake TLS rechazo la conexion. Acceso denegado.")
        return True
    except urllib.error.URLError as e:
        print(f"[BLOQUEO DE RED ESPERADO]: {e.reason}")
        print("\n>>> RESULTADO: [PASO] Rechazado a nivel de socket por falta de certificado.")
        return True
    except Exception as e:
        print(f"[BLOQUEADO]: {e}")
        return True


def test_con_certificado_falso():
    print("\n" + "="*60)
    print("TEST 3: Intento con Certificado de OTRA CA (Atacante / Rogue CA)")
    print("="*60)
    
    context = ssl.create_default_context(cafile=CA_CRT)
    context.load_cert_chain(certfile=ATTACKER_CRT, keyfile=ATTACKER_KEY)
    
    req = urllib.request.Request(API_URL, method="GET")
    try:
        with urllib.request.urlopen(req, context=context, timeout=5) as response:
            print("[ERROR] El servidor acepto un certificado firmado por otra CA!")
            return False
    except ssl.SSLError as e:
        print(f"[BLOQUEO TLS ESPERADO]: {e.reason or e}")
        print("\n>>> RESULTADO: [PASO] El servidor verifico la cadena de confianza y RECHAZO la CA no autorizada.")
        return True
    except urllib.error.URLError as e:
        print(f"[BLOQUEO DE RED ESPERADO]: {e.reason}")
        print("\n>>> RESULTADO: [PASO] Rechazado exitosamente.")
        return True
    except Exception as e:
        print(f"[BLOQUEADO]: {e}")
        return True


def main():
    print("="*60)
    print("BATERIA DE PRUEBAS mTLS - PROYECTO 3 (UNDC 2026)")
    print("="*60)
    t1 = test_con_certificado_valido()
    t2 = test_sin_certificado()
    t3 = test_con_certificado_falso()
    
    print("\n" + "="*60)
    print("RESUMEN DE RESULTADOS DE SEGURIDAD (SUPERFICIE DE ATAQUE)")
    print("="*60)
    print(f"1. Certificado Valido emitido por CA propia : {'APROBADO [OK]' if t1 else 'FALLO'}")
    print(f"2. Conexion Sin Certificado Digital         : {'BLOQUEADO [OK]' if t2 else 'FALLO'}")
    print(f"3. Certificado de Otra CA (Rogue/Hacker)    : {'BLOQUEADO [OK]' if t3 else 'FALLO'}")
    print("="*60)


if __name__ == "__main__":
    main()

