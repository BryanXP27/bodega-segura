"""
Bateria de pruebas del API en la Nube (Google Cloud Run) - Proyecto 3 (UNDC 2026)
----------------------------------------------------------------------------------
Valida el modelo completo de la rubrica:

1. Certificado valido + firma del reto (posesion de la llave)      -> 200 OK
2. Sin certificado digital                                        -> 401 Unauthorized
3. Certificado de otra CA (Rogue CA)                              -> 403 Forbidden
4. Certificado valido SIN firma del reto                          -> 403 Proof-of-Possession
5. Reutilizacion del mismo reto (anti-replay)                     -> 403 Challenge ya usado
6. Certificado revocado (CRL firmada por la CA)                   -> 403 CERTIFICATE_REVOKED
7. Certificado vencido                                            -> 403 CERTIFICATE_EXPIRED
8. Autenticacion usando PKCS#12 (.pfx)                            -> 200 OK

La llave privada del cliente (certs/private/client.key) nunca se envia.
"""

import os
import sys

from pki_client import (
    CERTS_DIR,
    PRIVATE_DIR,
    authenticate,
    authenticate_pfx,
    http_post_json,
    read_text,
    request_challenge,
    sign_nonce,
)

CLIENT_CRT = os.path.join(CERTS_DIR, "client.crt")
CLIENT_KEY = os.path.join(PRIVATE_DIR, "client.key")
ATTACKER_CRT = os.path.join(CERTS_DIR, "attacker.crt")
ATTACKER_KEY = os.path.join(PRIVATE_DIR, "attacker.key")
REVOKED_CRT = os.path.join(CERTS_DIR, "client-revocado.crt")
REVOKED_KEY = os.path.join(PRIVATE_DIR, "client-revocado.key")
EXPIRED_CRT = os.path.join(CERTS_DIR, "client-vencido.crt")
EXPIRED_KEY = os.path.join(PRIVATE_DIR, "client-vencido.key")
CLIENT_PFX = os.path.join(PRIVATE_DIR, "client.pfx")
PFX_PASSWORD = os.environ.get("PKI_PFX_PASSWORD", "password123")

API_URL = os.environ.get(
    "API_URL",
    "https://boveda-segura-git-931747537260.southamerica-west1.run.app/api/pki/operaciones",
)
ORIGIN = API_URL.split("/api/pki/", 1)[0]


def test_valid_certificate():
    print("\n" + "=" * 70)
    print("TEST 1: Certificado valido + firma del reto (prueba de posesion)")
    print(f"URL: {API_URL}")
    print("=" * 70)

    try:
        status, data, challenge = authenticate(ORIGIN, CLIENT_CRT, CLIENT_KEY)
        if status == 200 and data.get("success"):
            client = data.get("auth_details", {}).get("client", {})
            print(f"[STATUS] {status} OK")
            print(f"[CLIENTE RECONOCIDO] {client.get('commonName')}")
            print(f"[RETO VERIFICADO] id={challenge['token'][:24]}... expira={challenge['expiresAt']}")
            print(f"[PRUEBA DE POSESION] {data['auth_details'].get('proof_of_possession')}")
            print("[DATOS PROTEGIDOS RECIBIDOS]")
            print(data.get("boveda_data"))
            print("\n>>> RESULTADO: [APROBADO] Certificado + llave privada autenticados.")
            return True
        print(f"[FALLO] HTTP {status}: {data}")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def test_no_certificate():
    print("\n" + "=" * 70)
    print("TEST 2: Ataque - peticion SIN certificado digital")
    print("=" * 70)

    status, body = http_post_json(API_URL, {})
    if status == 401 and body.get("code") == "MISSING_CLIENT_CERTIFICATE":
        print(f"[STATUS] {status} Unauthorized (esperado)")
        print(f"[RESPUESTA] {body.get('error')}")
        print("\n>>> RESULTADO: [APROBADO] Bloqueo por falta de credencial X.509.")
        return True
    print(f"[FALLO] HTTP {status}: {body}")
    return False


def test_rogue_ca():
    print("\n" + "=" * 70)
    print("TEST 3: Ataque - certificado de OTRA CA (Rogue Malicious Root CA)")
    print("=" * 70)

    try:
        challenge = request_challenge(ORIGIN)
        # El atacante SI tiene su llave privada; falla la cadena de confianza.
        signature = sign_nonce(challenge["nonce"], ATTACKER_KEY)
        payload = {
            "clientCertificate": read_text(ATTACKER_CRT),
            "challengeToken": challenge["token"],
            "signature": signature,
        }
        status, body = http_post_json(API_URL, payload)
        if status == 403 and body.get("code") in ("INVALID_ISSUER_CA", "MALFORMED_CERTIFICATE"):
            print(f"[STATUS] {status} Forbidden (esperado)")
            print(f"[CODIGO] {body.get('code')}")
            print(f"[RESPUESTA] {body.get('error')}")
            print("\n>>> RESULTADO: [APROBADO] La firma de la CA no es confiable.")
            return True
        print(f"[FALLO] HTTP {status}: {body}")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def test_certificate_without_proof():
    print("\n" + "=" * 70)
    print("TEST 4: Certificado valido SIN firma del reto (replay del PEM publico)")
    print("=" * 70)

    # Este es exactamente el ataque que antes funcionaba: copiar el .crt publico.
    status, body = http_post_json(
        API_URL, {"clientCertificate": read_text(CLIENT_CRT)}
    )
    if status == 403 and body.get("code") == "PROOF_OF_POSSESSION_REQUIRED":
        print(f"[STATUS] {status} Forbidden (esperado)")
        print(f"[CODIGO] {body.get('code')}")
        print(f"[RESPUESTA] {body.get('error')}")
        print("\n>>> RESULTADO: [APROBADO] El certificado publico por si solo NO autentica.")
        return True
    print(f"[FALLO] HTTP {status}: {body}")
    return False


def test_replay_same_challenge():
    print("\n" + "=" * 70)
    print("TEST 5: Reutilizacion del mismo reto firmado (anti-replay)")
    print("=" * 70)

    try:
        challenge = request_challenge(ORIGIN)
        signature = sign_nonce(challenge["nonce"], CLIENT_KEY)
        payload = {
            "clientCertificate": read_text(CLIENT_CRT),
            "challengeToken": challenge["token"],
            "signature": signature,
        }

        first_status, first_body = http_post_json(API_URL, payload)
        second_status, second_body = http_post_json(API_URL, payload)

        if (
            first_status == 200
            and second_status == 403
            and second_body.get("code") == "CHALLENGE_ALREADY_USED"
        ):
            print(f"[PRIMER ENVIO]  {first_status} OK (reto consumido)")
            print(f"[SEGUNDO ENVIO] {second_status} Forbidden [{second_body.get('code')}]")
            print(f"[RESPUESTA] {second_body.get('error')}")
            print("\n>>> RESULTADO: [APROBADO] Cada reto es de un solo uso.")
            return True
        print(f"[FALLO] 1ro={first_status} {first_body} | 2do={second_status} {second_body}")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def test_revoked_certificate():
    print("\n" + "=" * 70)
    print("TEST 6: Certificado revocado (CRL X.509 firmada por la CA)")
    print("=" * 70)

    try:
        status, body, challenge = authenticate(ORIGIN, REVOKED_CRT, REVOKED_KEY)
        if status == 403 and body.get("code") == "CERTIFICATE_REVOKED":
            print(f"[STATUS] {status} Forbidden (esperado)")
            print(f"[CODIGO] {body.get('code')}")
            print(f"[RESPUESTA] {body.get('error')}")
            print(f"[RETO] {challenge['expiresAt']} (firma valida, pero el certificado esta revocado)")
            print("\n>>> RESULTADO: [APROBADO] La CRL real invalida el certificado.")
            return True
        print(f"[FALLO] HTTP {status}: {body}")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def test_expired_certificate():
    print("\n" + "=" * 70)
    print("TEST 7: Certificado vencido (notAfter en el pasado)")
    print("=" * 70)

    try:
        status, body, challenge = authenticate(ORIGIN, EXPIRED_CRT, EXPIRED_KEY)
        if status == 403 and body.get("code") == "CERTIFICATE_EXPIRED":
            print(f"[STATUS] {status} Forbidden (esperado)")
            print(f"[CODIGO] {body.get('code')}")
            print(f"[RESPUESTA] {body.get('error')}")
            print("\n>>> RESULTADO: [APROBADO] Un certificado vencido no autentica.")
            return True
        print(f"[FALLO] HTTP {status}: {body}")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def test_pfx_certificate():
    print("\n" + "=" * 70)
    print("TEST 8: Autenticacion usando PKCS#12 (.pfx)")
    print("=" * 70)

    try:
        status, data, challenge = authenticate_pfx(ORIGIN, CLIENT_PFX, PFX_PASSWORD)
        if status == 200 and data.get("success"):
            client = data.get("auth_details", {}).get("client", {})
            print(f"[STATUS] {status} OK")
            print(f"[ARCHIVO] {os.path.basename(CLIENT_PFX)} (llave + certificado)")
            print(f"[CLIENTE RECONOCIDO] {client.get('commonName')}")
            print(f"[RETO VERIFICADO] {challenge['expiresAt']}")
            print("\n>>> RESULTADO: [APROBADO] El cliente acepta PKCS#12 sin exponer la llave.")
            return True
        print(f"[FALLO] HTTP {status}: {data}")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def main():
    print("=" * 70)
    print("BATERIA DE PRUEBAS DEL PROYECTO 3 EN GOOGLE CLOUD RUN")
    print("Modelo: X.509 + prueba de posesion (challenge-response RSA-SHA256)")
    print("=" * 70)

    results = [
        ("Certificado valido + firma del reto", test_valid_certificate()),
        ("Bloqueo sin certificado digital", test_no_certificate()),
        ("Rechazo de certificado de otra CA", test_rogue_ca()),
        ("Rechazo de certificado sin firma", test_certificate_without_proof()),
        ("Rechazo de reto reutilizado", test_replay_same_challenge()),
        ("Rechazo de certificado revocado (CRL)", test_revoked_certificate()),
        ("Rechazo de certificado vencido", test_expired_certificate()),
        ("Acceso con PKCS#12 (.pfx)", test_pfx_certificate()),
    ]

    print("\n" + "=" * 70)
    print("RESUMEN DE SEGURIDAD EN GOOGLE CLOUD RUN")
    print("=" * 70)
    for i, (name, ok) in enumerate(results, 1):
        print(f"{i}. {name:<44}: {'[APROBADO]' if ok else '[FALLO]'}")
    print("=" * 70)

    return 0 if all(ok for _, ok in results) else 1


if __name__ == "__main__":
    sys.exit(main())
