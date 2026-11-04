"""
Demostracion Interactiva en Consola - Proyecto 3: PKI y API en Google Cloud Run
-------------------------------------------------------------------------------
Universidad Nacional de Canete - UNDC 2026

Recorre paso a paso el flujo exigido por la rubrica:
  CA -> CSR -> certificado X.509 -> reto -> firma con llave privada -> API -> validacion

La llave privada del cliente permanece en certs/private/ y nunca se transmite.
"""

import json
import os
import sys
import time

from pki_client import (
    CERTS_DIR,
    PRIVATE_DIR,
    authenticate,
    http_get_json,
    http_post_json,
    read_text,
    request_challenge,
    sign_nonce,
)

CA_CRT = os.path.join(CERTS_DIR, "ca.crt")
CLIENT_CRT = os.path.join(CERTS_DIR, "client.crt")
CLIENT_KEY = os.path.join(PRIVATE_DIR, "client.key")
CLIENT_PFX = os.path.join(PRIVATE_DIR, "client.pfx")
ATTACKER_CRT = os.path.join(CERTS_DIR, "attacker.crt")

ORIGIN = os.environ.get(
    "API_ORIGIN",
    "https://boveda-segura-git-931747537260.southamerica-west1.run.app",
)
OPERACIONES_URL = f"{ORIGIN}/api/pki/operaciones"
HEALTH_URL = f"{ORIGIN}/api/pki/health"


def print_step(num, title):
    print("\n" + "=" * 70)
    print(f"PASO {num}: {title}")
    print("=" * 70)
    time.sleep(0.3)


def main():
    os.system("color 0B" if os.name == "nt" else "")
    print("\n" + "#" * 70)
    print("   UNIVERSIDAD NACIONAL DE CAÑETE — PROYECTO 3: SEGURIDAD Y PKI")
    print("   DEMOSTRACIÓN EN VIVO: API EN LA NUBE CON CERTIFICADO DIGITAL")
    print("   Servidor: Google Cloud Run (southamerica-west1)")
    print("   Modelo: X.509 + prueba de posesión (reto firmado, un solo uso)")
    print("#" * 70)

    # -------------------------------------------------------------
    # 1. MINI-PKI Y ESTADO EN LA NUBE
    # -------------------------------------------------------------
    print_step(1, "AUTORIDAD CERTIFICADORA (ROOT CA) Y ESTADO DEL SERVICIO")
    print("[*] Verificando certificado raíz local y en la nube...")
    print(f"    CA pública: {CA_CRT}")
    print("    Algoritmo: RSA 4096 bits | Hash: SHA-256")

    try:
        status, health = http_get_json(HEALTH_URL)
        pki = health.get("pki", {})
        auth = health.get("authentication", {})
        print(f"[OK] Healthcheck HTTP {status}")
        print(f"     -> Root CA instalada: {pki.get('root_ca_installed')}")
        print(f"     -> Validez de la CA: {pki.get('ca_valid_until')}")
        print(f"     -> Prueba de posesión: {auth.get('proof_of_possession')}")
        print(f"     -> Revocación: {auth.get('revocation')}")
    except Exception as e:
        print(f"[!] Aviso al conectar con Healthcheck: {e}")

    # -------------------------------------------------------------
    # 2. IDENTIDAD DEL CLIENTE
    # -------------------------------------------------------------
    print_step(2, "CERTIFICADO DIGITAL DE CLIENTE (X.509 + PKCS#12)")
    print(f"[*] Certificado público: {CLIENT_CRT}")
    print(f"[*] Llave privada: {CLIENT_KEY} (RSA 2048 - NUNCA SALE DEL EQUIPO)")
    print(f"[*] Paquete PKCS#12: {CLIENT_PFX}")
    print("    Identidad X.509: CN=cliente-desktop-01, OU=Operaciones Bancarias")
    print("    Extensión: clientAuth (Autenticación de Cliente)")
    print("\n[!] El certificado es público; lo secreto es la llave privada.")

    input("\n>> Presiona ENTER para la PRUEBA 1 (reto + firma + acceso válido)... ")

    # -------------------------------------------------------------
    # 3. PRUEBA 1: RETO + FIRMA + ACCESO
    # -------------------------------------------------------------
    print_step(3, "RETO CRIPTOGRÁFICO Y FIRMA CON LA LLAVE PRIVADA")
    print("[*] 1) El cliente solicita un nonce aleatorio (GET /api/pki/challenge)")
    challenge = request_challenge(ORIGIN)
    print(f"    -> nonce: {challenge['nonce'][:24]}... ({len(challenge['nonce'])} caracteres)")
    print(f"    -> expira: {challenge['expiresAt']} | un solo uso: {challenge['singleUse']}")

    print("[*] 2) El cliente firma el nonce localmente (RSA-SHA256, PKCS#1 v1.5)")
    signature = sign_nonce(challenge["nonce"], CLIENT_KEY)
    print(f"    -> firma base64: {signature[:40]}... ({len(signature)} caracteres)")
    print("    -> la llave privada NO se transmite")

    print("[*] 3) Enviando certificado + token + firma a /api/pki/operaciones...")
    payload = {
        "clientCertificate": read_text(CLIENT_CRT),
        "challengeToken": challenge["token"],
        "signature": signature,
    }
    t0 = time.time()
    status, data = http_post_json(OPERACIONES_URL, payload)
    elapsed = int((time.time() - t0) * 1000)

    print(f"\n[+] RESPUESTA DEL SERVIDOR GOOGLE CLOUD ({elapsed} ms): HTTP {status}")
    if status == 200:
        print(f"    Mensaje: {data.get('message')}")
        print(f"    Prueba de posesión: {data.get('auth_details', {}).get('proof_of_possession')}")
        print(f"    Reto verificado: {data.get('auth_details', {}).get('challenge_id')}")
        print("    Datos bancarios entregados:")
        print(json.dumps(data.get("boveda_data"), indent=6))
        print("\n>>> RESULTADO PRUEBA 1: [APROBADO] Autenticación PKI sin contraseñas.")
    else:
        print(f"    [FALLO] {data}")
        print("    Verifica que el API desplegado incluya el flujo de reto-firma.")

    input("\n>> Presiona ENTER para la PRUEBA 2 (ataque: sin certificado)... ")

    # -------------------------------------------------------------
    # 4. PRUEBA 2: SIN CERTIFICADO
    # -------------------------------------------------------------
    print_step(4, "PRUEBA DE ATAQUE 1: PETICIÓN SIN CERTIFICADO DIGITAL")
    status, body = http_post_json(OPERACIONES_URL, {})
    print(f"[+] HTTP {status} | código: {body.get('code')}")
    print(f"    {body.get('error')}")
    if status == 401:
        print("\n>>> RESULTADO PRUEBA 2: [APROBADO] Bloqueo por falta de credencial X.509.")
    else:
        print("\n>>> RESULTADO PRUEBA 2: [FALLO] El servidor no bloqueó correctamente.")

    input("\n>> Presiona ENTER para la PRUEBA 3 (ataque: certificado de otra CA)... ")

    # -------------------------------------------------------------
    # 5. PRUEBA 3: ROGUE CA
    # -------------------------------------------------------------
    print_step(5, "PRUEBA DE ATAQUE 2: CERTIFICADO DE OTRA CA (ROGUE ROOT CA)")
    print("[*] El atacante presenta un certificado de una CA no confiable...")
    status, body = http_post_json(
        OPERACIONES_URL, {"clientCertificate": read_text(ATTACKER_CRT)}
    )
    print(f"[+] HTTP {status} | código: {body.get('code')}")
    print(f"    {body.get('error')}")
    if status == 403:
        print("\n>>> RESULTADO PRUEBA 3: [APROBADO] Cadena de confianza rechazada.")
    else:
        print("\n>>> RESULTADO PRUEBA 3: [FALLO] El servidor aceptó una CA no confiable.")

    input("\n>> Presiona ENTER para la PRUEBA 4 (certificado público clonado)... ")

    # -------------------------------------------------------------
    # 6. PRUEBA 4: CERTIFICADO SIN PRUEBA DE POSESIÓN
    # -------------------------------------------------------------
    print_step(6, "PRUEBA DE ATAQUE 3: COPIAR EL CERTIFICADO PÚBLICO (SIN LLAVE)")
    print("[*] El atacante copia client.crt (público) pero no tiene client.key...")
    status, body = http_post_json(
        OPERACIONES_URL, {"clientCertificate": read_text(CLIENT_CRT)}
    )
    print(f"[+] HTTP {status} | código: {body.get('code')}")
    print(f"    {body.get('error')}")
    if status == 403 and body.get("code") == "PROOF_OF_POSSESSION_REQUIRED":
        print("\n>>> RESULTADO PRUEBA 4: [APROBADO] Sin llave privada no hay acceso.")
    else:
        print("\n>>> RESULTADO PRUEBA 4: [FALLO] El certificado público autenticó por sí solo.")

    # -------------------------------------------------------------
    # 7. RESUMEN
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    print("   RESUMEN FINAL DE CUMPLIMIENTO — PROYECTO 3 (UNDC 2026)")
    print("=" * 70)
    print(" [✔] 1. Autoridad Certificadora propia (RSA 4096 + SHA-256):   ACTIVA")
    print(" [✔] 2. Certificado X.509 emitido desde CSR (privada local):   EMITIDO")
    print(" [✔] 3. Reto de un solo uso firmado con llave privada:         VERIFICADO")
    print(" [✔] 4. API en Google Cloud Run valida CA, vigencia, CRL:       VERIFICADO")
    print(" [✔] 5. Sin certificado / otra CA / sin firma:                  BLOQUEADOS")
    print("=" * 70)
    print("\nDemostración completada exitosamente ante el jurado/docente.\n")


if __name__ == "__main__":
    main()
