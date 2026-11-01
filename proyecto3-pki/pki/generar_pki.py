"""
Generador Automatizado de Mini-PKI para Proyecto 3 (UNDC 2026)
--------------------------------------------------------------
Genera:
1. CA Raiz (Root CA: ca.key, ca.crt)
2. Certificado del Servidor API (server.key, server.crt)
3. Certificado del Cliente Autorizado (client.key, client.csr, client.crt, client.pfx)
4. Certificado de Otra CA / Atacante (para pruebas de rechazo mTLS)
"""

import os
import sys
import subprocess
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
OPENSSL_CNF = os.path.join(BASE_DIR, "openssl.cnf")

# Localizar OpenSSL
POSSIBLE_OPENSSL = [
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    "openssl"
]

OPENSSL_BIN = None
for candidate in POSSIBLE_OPENSSL:
    if os.path.isabs(candidate):
        if os.path.exists(candidate):
            OPENSSL_BIN = candidate
            break
    else:
        if shutil.which(candidate):
            OPENSSL_BIN = candidate
            break

if not OPENSSL_BIN:
    print("[ERROR] No se encontro openssl.exe en el sistema.")
    sys.exit(1)

print(f"[OK] Utilizando OpenSSL: {OPENSSL_BIN}")


def run_openssl(args):
    cmd = [OPENSSL_BIN] + args
    res = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[FALLO] {' '.join(cmd)}")
        print(res.stderr)
        raise RuntimeError(f"Error en OpenSSL: {res.stderr}")
    return res.stdout


def main():
    os.makedirs(CERTS_DIR, exist_ok=True)
    pfx_password = "password123"

    print("\n" + "="*60)
    print("PROYECTO 3: CONSTRUCCION DE MINI-PKI Y CERTIFICADOS DIGITALES")
    print("="*60)

    # ---------------------------------------------------------
    # PASO 1: Generar la Autoridad Certificadora Raiz (Root CA)
    # ---------------------------------------------------------
    print("\n[1/4] Creando Autoridad Certificadora (Root CA)...")
    ca_key = os.path.join(CERTS_DIR, "ca.key")
    ca_crt = os.path.join(CERTS_DIR, "ca.crt")

    # Generar llave privada de la CA (RSA 4096 bits)
    run_openssl(["genrsa", "-out", ca_key, "4096"])
    # Generar certificado raiz autofirmado X.509 (valido 10 anos)
    run_openssl([
        "req", "-new", "-x509", "-days", "3650",
        "-key", ca_key,
        "-out", ca_crt,
        "-config", OPENSSL_CNF,
        "-extensions", "v3_ca",
        "-subj", "/C=PE/ST=Lima/L=Canete/O=UNDC - Seguridad Informatica/OU=Root CA/CN=Boveda Segura Root CA/emailAddress=pki@undc.edu.pe"
    ])
    print("  -> Llave privada CA: certs/ca.key (RSA 4096)")
    print("  -> Certificado Raiz: certs/ca.crt (X.509 Autofirmado)")

    # ---------------------------------------------------------
    # PASO 2: Generar Certificado del Servidor API (mTLS)
    # ---------------------------------------------------------
    print("\n[2/4] Creando Certificado para el Servidor API...")
    server_key = os.path.join(CERTS_DIR, "server.key")
    server_csr = os.path.join(CERTS_DIR, "server.csr")
    server_crt = os.path.join(CERTS_DIR, "server.crt")

    run_openssl(["genrsa", "-out", server_key, "2048"])
    run_openssl([
        "req", "-new",
        "-key", server_key,
        "-out", server_csr,
        "-config", OPENSSL_CNF,
        "-subj", "/C=PE/ST=Lima/L=Canete/O=UNDC/OU=API Gateway/CN=localhost/emailAddress=api@undc.edu.pe"
    ])
    run_openssl([
        "x509", "-req", "-days", "825",
        "-in", server_csr,
        "-CA", ca_crt,
        "-CAkey", ca_key,
        "-CAcreateserial",
        "-out", server_crt,
        "-extfile", OPENSSL_CNF,
        "-extensions", "server_cert"
    ])
    print("  -> Llave privada Servidor: certs/server.key")
    print("  -> Certificado Servidor: certs/server.crt (firmado por Root CA)")

    # ---------------------------------------------------------
    # PASO 3: Generar Certificado del Cliente Autorizado
    # ---------------------------------------------------------
    print("\n[3/4] Creando Certificado para el Aplicativo Cliente...")
    client_key = os.path.join(CERTS_DIR, "client.key")
    client_csr = os.path.join(CERTS_DIR, "client.csr")
    client_crt = os.path.join(CERTS_DIR, "client.crt")
    client_pfx = os.path.join(CERTS_DIR, "client.pfx")

    # a) El cliente genera su llave privada en su propio equipo (nunca viaja)
    run_openssl(["genrsa", "-out", client_key, "2048"])

    # b) El cliente genera el CSR (nombre + llave publica, sin la privada)
    run_openssl([
        "req", "-new",
        "-key", client_key,
        "-out", client_csr,
        "-config", OPENSSL_CNF,
        "-subj", "/C=PE/ST=Lima/L=Canete/O=UNDC/OU=Operaciones Bancarias/CN=cliente-desktop-01/emailAddress=operador@boveda.undc.pe"
    ])

    # c) La CA firma el CSR con su llave privada
    run_openssl([
        "x509", "-req", "-days", "365",
        "-in", client_csr,
        "-CA", ca_crt,
        "-CAkey", ca_key,
        "-CAcreateserial",
        "-out", client_crt,
        "-extfile", OPENSSL_CNF,
        "-extensions", "client_cert"
    ])

    # d) Empaquetar llave privada + certificado en formato PKCS#12 (.pfx)
    run_openssl([
        "pkcs12", "-export",
        "-out", client_pfx,
        "-inkey", client_key,
        "-in", client_crt,
        "-certfile", ca_crt,
        "-name", "BovedaClienteCert",
        "-passout", f"pass:{pfx_password}"
    ])
    print("  -> Llave privada Cliente: certs/client.key")
    print("  -> Solicitud de firma: certs/client.csr")
    print("  -> Certificado Cliente: certs/client.crt (firmado por Root CA)")
    print(f"  -> Archivo PKCS#12 (.pfx): certs/client.pfx (Password: {pfx_password})")

    # ---------------------------------------------------------
    # PASO 4: Generar Certificado No Autorizado (de OTRA CA)
    # ---------------------------------------------------------
    print("\n[4/4] Creando Certificado Falso/No Autorizado (para demostracion de ataque)...")
    fake_ca_key = os.path.join(CERTS_DIR, "fake_ca.key")
    fake_ca_crt = os.path.join(CERTS_DIR, "fake_ca.crt")
    fake_client_key = os.path.join(CERTS_DIR, "attacker.key")
    fake_client_csr = os.path.join(CERTS_DIR, "attacker.csr")
    fake_client_crt = os.path.join(CERTS_DIR, "attacker.crt")
    fake_client_pfx = os.path.join(CERTS_DIR, "attacker.pfx")

    run_openssl(["genrsa", "-out", fake_ca_key, "2048"])
    run_openssl([
        "req", "-new", "-x509", "-days", "365",
        "-key", fake_ca_key,
        "-out", fake_ca_crt,
        "-subj", "/C=XX/ST=Unknown/L=Nowhere/O=CA Atacante/CN=Rogue Malicious Root CA"
    ])
    run_openssl(["genrsa", "-out", fake_client_key, "2048"])
    run_openssl([
        "req", "-new",
        "-key", fake_client_key,
        "-out", fake_client_csr,
        "-subj", "/C=XX/ST=Unknown/L=Nowhere/O=Atacante/CN=hacker-client"
    ])
    run_openssl([
        "x509", "-req", "-days", "365",
        "-in", fake_client_csr,
        "-CA", fake_ca_crt,
        "-CAkey", fake_ca_key,
        "-CAcreateserial",
        "-out", fake_client_crt
    ])
    run_openssl([
        "pkcs12", "-export",
        "-out", fake_client_pfx,
        "-inkey", fake_client_key,
        "-in", fake_client_crt,
        "-passout", f"pass:{pfx_password}"
    ])
    print("  -> Certificado Atacante: certs/attacker.crt y certs/attacker.pfx")

    print("\n" + "="*60)
    print("TODO LISTO: Mini-PKI generada exitosamente en proyecto3-pki/pki/certs/")
    print("="*60)


if __name__ == "__main__":
    main()

