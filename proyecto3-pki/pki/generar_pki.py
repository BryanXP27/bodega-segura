"""
Generador Automatizado de Mini-PKI para Proyecto 3 (UNDC 2026)
--------------------------------------------------------------
Genera:
1. CA Raiz (Root CA: certs/private/ca.key + certs/ca.crt)
2. Certificado del Servidor API (certs/private/server.key + certs/server.crt)
3. Certificado del Cliente Autorizado
   (certs/private/client.key + certs/client.csr + certs/client.crt + certs/private/client.pfx)
4. Certificado de Otra CA / Atacante (para pruebas de rechazo)

IMPORTANTE (rotacion de seguridad):
- Toda llave privada se escribe en `certs/private/`, carpeta ignorada por Git.
- En `certs/` solo quedan elementos publicos (certificados, CSR y CA publica).
- Si las llaves antiguas estuvieron publicadas, este script REGENERA la CA y
  todos los certificados, dejando inservibles los comprometidos.
"""

import os
import stat
import sys
import subprocess
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
PRIVATE_DIR = os.path.join(CERTS_DIR, "private")
OPENSSL_CNF = os.path.join(BASE_DIR, "openssl.cnf")

PFX_PASSWORD = os.environ.get("PKI_PFX_PASSWORD", "password123")

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


def harden_private_dir():
    """Restringe permisos de la carpeta de llaves (POSIX). En Windows se apoya en ACL/ignorado por Git."""
    os.makedirs(PRIVATE_DIR, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(PRIVATE_DIR, stat.S_IRWXU)  # 0700
        except OSError:
            pass


def main():
    os.makedirs(CERTS_DIR, exist_ok=True)
    harden_private_dir()

    print("\n" + "=" * 64)
    print("PROYECTO 3: ROTACION DE MINI-PKI Y CERTIFICADOS DIGITALES")
    print("=" * 64)
    print("[SEGURIDAD] Las llaves privadas se guardaran SOLO en certs/private/")
    print("[SEGURIDAD] certs/private/ esta excluida de Git (.gitignore)\n")

    # ---------------------------------------------------------
    # PASO 1: Generar la Autoridad Certificadora Raiz (Root CA)
    # ---------------------------------------------------------
    print("[1/4] Creando Autoridad Certificadora (Root CA)...")
    ca_key = os.path.join(PRIVATE_DIR, "ca.key")
    ca_crt = os.path.join(CERTS_DIR, "ca.crt")

    run_openssl(["genrsa", "-out", ca_key, "4096"])
    run_openssl([
        "req", "-new", "-x509", "-days", "3650",
        "-key", ca_key,
        "-out", ca_crt,
        "-config", OPENSSL_CNF,
        "-extensions", "v3_ca",
        "-sha256",
        "-subj", "/C=PE/ST=Lima/L=Canete/O=UNDC - Seguridad Informatica/OU=Root CA/CN=Boveda Segura Root CA/emailAddress=pki@undc.edu.pe"
    ])
    print("  -> Llave privada CA: certs/private/ca.key (RSA 4096, NO versionar)")
    print("  -> Certificado Raiz: certs/ca.crt (X.509 Autofirmado, publico)")

    # ---------------------------------------------------------
    # PASO 2: Generar Certificado del Servidor API (mTLS)
    # ---------------------------------------------------------
    print("\n[2/4] Creando Certificado para el Servidor API...")
    server_key = os.path.join(PRIVATE_DIR, "server.key")
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
        "-sha256",
        "-out", server_crt,
        "-extfile", OPENSSL_CNF,
        "-extensions", "server_cert"
    ])
    print("  -> Llave privada Servidor: certs/private/server.key (NO versionar)")
    print("  -> Certificado Servidor: certs/server.crt (firmado por Root CA)")

    # ---------------------------------------------------------
    # PASO 3: Generar Certificado del Cliente Autorizado
    # ---------------------------------------------------------
    print("\n[3/4] Creando Certificado para el Aplicativo Cliente...")
    client_key = os.path.join(PRIVATE_DIR, "client.key")
    client_csr = os.path.join(CERTS_DIR, "client.csr")
    client_crt = os.path.join(CERTS_DIR, "client.crt")
    client_pfx = os.path.join(PRIVATE_DIR, "client.pfx")

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
        "-sha256",
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
        "-passout", f"pass:{PFX_PASSWORD}"
    ])
    print("  -> Llave privada Cliente: certs/private/client.key (NO versionar)")
    print("  -> Solicitud de firma: certs/client.csr (publica)")
    print("  -> Certificado Cliente: certs/client.crt (publico)")
    print("  -> Archivo PKCS#12 (.pfx): certs/private/client.pfx (NO versionar)")

    # ---------------------------------------------------------
    # PASO 4: Generar Certificado No Autorizado (de OTRA CA)
    # ---------------------------------------------------------
    print("\n[4/4] Creando Certificado Falso/No Autorizado (demostracion de ataque)...")
    fake_ca_key = os.path.join(PRIVATE_DIR, "fake_ca.key")
    fake_ca_crt = os.path.join(CERTS_DIR, "fake_ca.crt")
    fake_client_key = os.path.join(PRIVATE_DIR, "attacker.key")
    fake_client_csr = os.path.join(CERTS_DIR, "attacker.csr")
    fake_client_crt = os.path.join(CERTS_DIR, "attacker.crt")
    fake_client_pfx = os.path.join(PRIVATE_DIR, "attacker.pfx")

    run_openssl(["genrsa", "-out", fake_ca_key, "2048"])
    run_openssl([
        "req", "-new", "-x509", "-days", "365",
        "-key", fake_ca_key,
        "-out", fake_ca_crt,
        "-sha256",
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
        "-sha256",
        "-out", fake_client_crt
    ])
    run_openssl([
        "pkcs12", "-export",
        "-out", fake_client_pfx,
        "-inkey", fake_client_key,
        "-in", fake_client_crt,
        "-passout", f"pass:{PFX_PASSWORD}"
    ])
    print("  -> Certificado Atacante: certs/attacker.crt (publico, de CA no confiable)")
    print("  -> Llave Atacante: certs/private/attacker.key (NO versionar)")

    print("\n" + "=" * 64)
    print("ROTACION COMPLETA: Mini-PKI regenerada correctamente")
    print("  Publicos : proyecto3-pki/pki/certs/*.crt, *.csr")
    print("  Privados : proyecto3-pki/pki/certs/private/*  (git-ignored)")
    print("=" * 64)
    print("\n[SIGUIENTE PASO] Actualiza BOVEDA_ROOT_CA_CERT/ATTACKER_CERT en")
    print("src/lib/pki/x509-validator.ts con el nuevo contenido de certs/ca.crt")
    print("y certs/attacker.crt, luego redespliega en Cloud Run.\n")


if __name__ == "__main__":
    main()
