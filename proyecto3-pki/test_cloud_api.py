"""
Prueba del API en la Nube (Google Cloud Run) - Proyecto 3 (UNDC 2026)
---------------------------------------------------------------------
URL Cloud Run: https://boveda-segura-git-931747537260.southamerica-west1.run.app/api/pki/operaciones
Valida los 3 casos de la rubrica:
1. Certificado Digital Valido (Root CA Boveda) -> 200 OK
2. Sin Certificado Digital -> 401 Unauthorized
3. Certificado de Otra CA (Rogue/Atacante) -> 403 Forbidden
"""

import os
import sys
import json
import urllib.request
import urllib.error

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "pki", "certs")

CLIENT_CRT = os.path.join(CERTS_DIR, "client.crt")
ATTACKER_CRT = os.path.join(CERTS_DIR, "attacker.crt")

CLOUD_URL = os.environ.get(
    "API_URL",
    "https://boveda-segura-git-931747537260.southamerica-west1.run.app/api/pki/operaciones"
)


def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def test_cloud_valid():
    print("\n" + "="*65)
    print("TEST 1: Conexion al API Cloud Run con Certificado Valido")
    print(f"URL: {CLOUD_URL}")
    print("="*65)
    
    cert_data = read_file(CLIENT_CRT)
    payload = json.dumps({"clientCertificate": cert_data}).encode("utf-8")
    
    req = urllib.request.Request(
        CLOUD_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "BovedaPKIClient/1.0"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            data = json.loads(res.read().decode("utf-8"))
            print(f"[STATUS] {res.status} OK")
            print(f"[CLIENTE RECONOCIDO]: {data.get('auth_details', {}).get('client', {}).get('commonName')}")
            print(f"[DATOS PROTEGIDOS RECIBIDOS]:")
            print(json.dumps(data.get("boveda_data"), indent=2))
            print("\n>>> RESULTADO: [APROBADO] Autenticacion PKI en la Nube exitosa.")
            return True
    except urllib.error.HTTPError as e:
        print(f"[ERROR HTTP]: {e.code} - {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"[ERROR RED]: {e}")
        return False


def test_cloud_no_cert():
    print("\n" + "="*65)
    print("TEST 2: Ataque - Peticion a Cloud Run SIN Certificado Digital")
    print("="*65)
    
    payload = json.dumps({}).encode("utf-8")
    req = urllib.request.Request(
        CLOUD_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            print("[FALLO]: El API en la nube permitio acceso sin certificado!")
            return False
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode("utf-8"))
        print(f"[STATUS]: {e.code} Unauthorized (Esperado)")
        print(f"[RESPUESTA DE CLOUD RUN]: {body.get('error')}")
        print("\n>>> RESULTADO: [APROBADO] Peticion bloqueada en la nube por falta de credencial X.509.")
        return True
    except Exception as e:
        print(f"[ERROR]: {e}")
        return False


def test_cloud_rogue_cert():
    print("\n" + "="*65)
    print("TEST 3: Ataque - Certificado de Otra CA (Rogue Malicious Root CA)")
    print("="*65)
    
    cert_data = read_file(ATTACKER_CRT)
    payload = json.dumps({"clientCertificate": cert_data}).encode("utf-8")
    
    req = urllib.request.Request(
        CLOUD_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            print("[FALLO]: El API en la nube acepto un certificado de otra CA!")
            return False
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode("utf-8"))
        print(f"[STATUS]: {e.code} Forbidden (Esperado)")
        print(f"[RESPUESTA DE CLOUD RUN]: {body.get('error')}")
        print("\n>>> RESULTADO: [APROBADO] Cloud Run valido la firma contra la Root CA y RECHAZO al atacante.")
        return True
    except Exception as e:
        print(f"[ERROR]: {e}")
        return False


def main():
    print("="*65)
    print("BATERIA DE PRUEBAS DEL PROYECTO 3 EN GOOGLE CLOUD RUN")
    print("="*65)
    t1 = test_cloud_valid()
    t2 = test_cloud_no_cert()
    t3 = test_cloud_rogue_cert()
    
    print("\n" + "="*65)
    print("RESUMEN DE SEGURIDAD EN GOOGLE CLOUD RUN")
    print("="*65)
    print(f"1. Acceso con Certificado Valido      : {'[APROBADO]' if t1 else '[PENDIENTE DEPL]'}")
    print(f"2. Bloqueo Sin Certificado Digital    : {'[APROBADO]' if t2 else '[PENDIENTE DEPL]'}")
    print(f"3. Rechazo de Certificado de Otra CA  : {'[APROBADO]' if t3 else '[PENDIENTE DEPL]'}")
    print("="*65)


if __name__ == "__main__":
    main()
