"""
Generador Automatizado de Mini-PKI para Proyecto 3 (UNDC 2026)
--------------------------------------------------------------
Genera una PKI completa con base de datos de CA real:

1. Root CA (certs/private/ca.key + certs/ca.crt)
2. Certificado del servidor API (SAN localhost + IP pública opcional)
3. Certificado del cliente autorizado + PKCS#12
4. Certificado de una CA no confiable (demo de ataque)
5. Certificado de cliente REVOCADO + CRL firmada por la CA
6. Certificado de cliente VENCIDO (fechas pasadas)

Salidas para la app Next.js (auto-generadas):
- src/lib/pki/certs.ts  -> CA, cliente, atacante y vencido (PEM públicos)
- src/lib/pki/crl.ts    -> CRL firmada por la CA

Seguridad:
- Toda llave privada se escribe en `certs/private/` (git-ignored).
- En `certs/` solo quedan certificados, CSR y la CRL (material público).
- Ejecutar este script ROTA la CA y todos los certificados.
"""

import os
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
REPO_ROOT = os.path.dirname(PROJECT_DIR)
CERTS_DIR = os.path.join(BASE_DIR, "certs")
PRIVATE_DIR = os.path.join(CERTS_DIR, "private")
ISSUED_DIR = os.path.join(CERTS_DIR, "issued")
SRC_PKI_DIR = os.path.join(REPO_ROOT, "src", "lib", "pki")
OPENSSL_CNF = os.path.join(BASE_DIR, "openssl.cnf")

PFX_PASSWORD = os.environ.get("PKI_PFX_PASSWORD", "password123")
SERVER_PUBLIC_IP = os.environ.get("PKI_SERVER_IP", "").strip()

POSSIBLE_OPENSSL = [
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    "openssl",
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
        print(res.stdout)
        print(res.stderr)
        raise RuntimeError(f"Error en OpenSSL: {res.stderr}")
    return res.stdout


def harden_private_dir():
    os.makedirs(PRIVATE_DIR, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(PRIVATE_DIR, stat.S_IRWXU)  # 0700
        except OSError:
            pass


def reset_ca_database():
    """Reinicia la base de datos de la CA (index.txt, serial, crlnumber)."""
    os.makedirs(ISSUED_DIR, exist_ok=True)
    for name in ("index.txt", "serial", "crlnumber", "index.txt.old", "serial.old", "crlnumber.old"):
        path = os.path.join(BASE_DIR, name)
        if os.path.exists(path):
            os.remove(path)

    # unique_subject=no permite emitir varios certificados con el mismo CN.
    with open(os.path.join(BASE_DIR, "index.txt"), "w", encoding="utf-8") as f:
        f.write("")
    with open(os.path.join(BASE_DIR, "index.txt.attr"), "w", encoding="utf-8") as f:
        f.write("unique_subject = no\n")
    with open(os.path.join(BASE_DIR, "serial"), "w", encoding="utf-8") as f:
        f.write("1000\n")
    with open(os.path.join(BASE_DIR, "crlnumber"), "w", encoding="utf-8") as f:
        f.write("1000\n")

    for entry in os.listdir(ISSUED_DIR):
        os.remove(os.path.join(ISSUED_DIR, entry))


def ca_sign(csr_path, out_path, extensions, days=365, extra_args=None, ext_file=None):
    """Firma un CSR con `openssl ca` (registra el certificado en index.txt)."""
    args = [
        "ca", "-batch", "-config", OPENSSL_CNF,
        "-extensions", extensions,
        "-days", str(days),
        "-in", csr_path,
        "-out", out_path,
        "-notext",
    ]
    if ext_file:
        # Permite inyectar un SAN dinamico (por ejemplo la IP publica de la VM).
        args.extend(["-extfile", ext_file])
    if extra_args:
        args.extend(extra_args)
    run_openssl(args)


def write_server_ext():
    """Extensiones del certificado de servidor, con SAN de la IP publica opcional."""
    san_lines = [
        "DNS.1 = localhost",
        "DNS.2 = 127.0.0.1",
        "IP.1 = 127.0.0.1",
        "IP.2 = 0.0.0.0",
    ]
    if SERVER_PUBLIC_IP:
        san_lines.append(f"IP.3 = {SERVER_PUBLIC_IP}")

    content = "\n".join(
        [
            "[server_cert]",
            "basicConstraints = CA:FALSE",
            "nsCertType = server",
            "nsComment = \"Certificado de Servidor API - Proyecto 3\"",
            "subjectKeyIdentifier = hash",
            "authorityKeyIdentifier = keyid,issuer:always",
            "keyUsage = critical, digitalSignature, keyEncipherment",
            "extendedKeyUsage = serverAuth",
            "subjectAltName = @alt_names",
            "",
            "[alt_names]",
            *san_lines,
            "",
        ]
    )
    path = os.path.join(BASE_DIR, "server_ext.cnf")
    write_text(path, content)
    return path


def write_text(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


def write_ts_assets(ca_pem, client_pem, attacker_pem, revoked_pem, expired_pem, crl_pem):
    """Genera los modulos TypeScript con el material público actualizado."""
    generated_at = datetime.now(timezone.utc).isoformat()

    certs_ts = f"""// AUTO-GENERADO por proyecto3-pki/pki/generar_pki.py — NO EDITAR A MANO.
// Generado: {generated_at}
// Solo contiene material PUBLICO (certificados X.509). Las llaves privadas
// viven en proyecto3-pki/pki/certs/private/ y estan ignoradas por Git.

export const BOVEDA_ROOT_CA_CERT = `{ca_pem.strip()}`;

export const DEMO_CLIENT_CERT = `{client_pem.strip()}`;

export const DEMO_ATTACKER_CERT = `{attacker_pem.strip()}`;

export const DEMO_REVOKED_CERT = `{revoked_pem.strip()}`;

export const DEMO_EXPIRED_CERT = `{expired_pem.strip()}`;
"""
    write_text(os.path.join(SRC_PKI_DIR, "certs.ts"), certs_ts)

    crl_ts = f"""// AUTO-GENERADO por proyecto3-pki/pki/generar_pki.py — NO EDITAR A MANO.
// Generado: {generated_at}

export const BOVEDA_CRL_PEM = `{crl_pem.strip()}`;

export const BOVEDA_CRL_GENERATED_AT = '{generated_at}';
"""
    write_text(os.path.join(SRC_PKI_DIR, "crl.ts"), crl_ts)
    print(f"  -> Constantes actualizadas: {os.path.join(SRC_PKI_DIR, 'certs.ts')}")
    print(f"  -> CRL actualizada: {os.path.join(SRC_PKI_DIR, 'crl.ts')}")


def main():
    os.makedirs(CERTS_DIR, exist_ok=True)
    harden_private_dir()
    reset_ca_database()

    print("\n" + "=" * 66)
    print("PROYECTO 3: PKI COMPLETA CON CRL, REVOCACION Y CERTIFICADO VENCIDO")
    print("=" * 66)
    print("[SEGURIDAD] Llaves privadas -> certs/private/ (git-ignored)")
    if SERVER_PUBLIC_IP:
        print(f"[INFO] SAN del servidor incluira la IP publica: {SERVER_PUBLIC_IP}")

    # ---------------------------------------------------------
    # PASO 1: Root CA
    # ---------------------------------------------------------
    print("\n[1/6] Creando Autoridad Certificadora (Root CA)...")
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
    print("  -> certs/private/ca.key (RSA 4096, NO versionar)")
    print("  -> certs/ca.crt (publico)")

    # ---------------------------------------------------------
    # PASO 2: Certificado del servidor API
    # ---------------------------------------------------------
    print("\n[2/6] Emitiendo certificado del servidor API...")
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
    ca_sign(
        server_csr,
        server_crt,
        "server_cert",
        days=825,
        ext_file=write_server_ext(),
    )
    print("  -> certs/private/server.key (NO versionar)")
    print("  -> certs/server.crt (firmado por la CA)")
    if SERVER_PUBLIC_IP:
        print(f"  -> SAN incluye IP publica {SERVER_PUBLIC_IP}")

    # ---------------------------------------------------------
    # PASO 3: Certificado del cliente autorizado
    # ---------------------------------------------------------
    print("\n[3/6] Emitiendo certificado del cliente autorizado...")
    client_key = os.path.join(PRIVATE_DIR, "client.key")
    client_csr = os.path.join(CERTS_DIR, "client.csr")
    client_crt = os.path.join(CERTS_DIR, "client.crt")
    client_pfx = os.path.join(PRIVATE_DIR, "client.pfx")

    run_openssl(["genrsa", "-out", client_key, "2048"])
    run_openssl([
        "req", "-new",
        "-key", client_key,
        "-out", client_csr,
        "-config", OPENSSL_CNF,
        "-subj", "/C=PE/ST=Lima/L=Canete/O=UNDC/OU=Operaciones Bancarias/CN=cliente-desktop-01/emailAddress=operador@boveda.undc.pe"
    ])
    ca_sign(client_csr, client_crt, "client_cert", days=365)
    run_openssl([
        "pkcs12", "-export",
        "-out", client_pfx,
        "-inkey", client_key,
        "-in", client_crt,
        "-certfile", ca_crt,
        "-name", "BovedaClienteCert",
        "-passout", f"pass:{PFX_PASSWORD}"
    ])
    print("  -> certs/private/client.key + client.pfx (NO versionar)")
    print("  -> certs/client.crt + client.csr (publicos)")

    # ---------------------------------------------------------
    # PASO 4: Certificado de CA no confiable (ataque)
    # ---------------------------------------------------------
    print("\n[4/6] Creando certificado de CA no confiable (demo de ataque)...")
    fake_ca_key = os.path.join(PRIVATE_DIR, "fake_ca.key")
    fake_ca_crt = os.path.join(CERTS_DIR, "fake_ca.crt")
    fake_client_key = os.path.join(PRIVATE_DIR, "attacker.key")
    fake_client_csr = os.path.join(CERTS_DIR, "attacker.csr")
    fake_client_crt = os.path.join(CERTS_DIR, "attacker.crt")

    run_openssl(["genrsa", "-out", fake_ca_key, "2048"])
    run_openssl([
        "req", "-new", "-x509", "-days", "365", "-sha256",
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
        "x509", "-req", "-days", "365", "-sha256",
        "-in", fake_client_csr,
        "-CA", fake_ca_crt,
        "-CAkey", fake_ca_key,
        "-CAcreateserial",
        "-out", fake_client_crt
    ])
    print("  -> certs/attacker.crt (publico, CA no confiable)")
    print("  -> certs/private/attacker.key (NO versionar)")

    # ---------------------------------------------------------
    # PASO 5: Certificado revocado + CRL real
    # ---------------------------------------------------------
    print("\n[5/6] Emitiendo certificado revocado y generando CRL...")
    revoked_key = os.path.join(PRIVATE_DIR, "client-revocado.key")
    revoked_csr = os.path.join(CERTS_DIR, "client-revocado.csr")
    revoked_crt = os.path.join(CERTS_DIR, "client-revocado.crt")

    run_openssl(["genrsa", "-out", revoked_key, "2048"])
    run_openssl([
        "req", "-new",
        "-key", revoked_key,
        "-out", revoked_csr,
        "-config", OPENSSL_CNF,
        "-subj", "/C=PE/ST=Lima/L=Canete/O=UNDC/OU=Operaciones Bancarias/CN=cliente-revocado-01/emailAddress=revocado@boveda.undc.pe"
    ])
    ca_sign(revoked_csr, revoked_crt, "client_cert", days=365)

    run_openssl([
        "ca", "-batch", "-config", OPENSSL_CNF,
        "-revoke", revoked_crt,
        "-crl_reason", "keyCompromise",
    ])

    crl_pem_path = os.path.join(CERTS_DIR, "crl.pem")
    run_openssl(["ca", "-batch", "-config", OPENSSL_CNF, "-gencrl", "-out", crl_pem_path])
    print("  -> certs/client-revocado.crt (publico, en la CRL)")
    print("  -> certs/crl.pem (CRL firmada por la Root CA)")

    # ---------------------------------------------------------
    # PASO 6: Certificado vencido
    # ---------------------------------------------------------
    print("\n[6/6] Emitiendo certificado vencido (fechas pasadas)...")
    expired_key = os.path.join(PRIVATE_DIR, "client-vencido.key")
    expired_csr = os.path.join(CERTS_DIR, "client-vencido.csr")
    expired_crt = os.path.join(CERTS_DIR, "client-vencido.crt")

    run_openssl(["genrsa", "-out", expired_key, "2048"])
    run_openssl([
        "req", "-new",
        "-key", expired_key,
        "-out", expired_csr,
        "-config", OPENSSL_CNF,
        "-subj", "/C=PE/ST=Lima/L=Canete/O=UNDC/OU=Operaciones Bancarias/CN=cliente-vencido-01/emailAddress=vencido@boveda.undc.pe"
    ])
    ca_sign(
        expired_csr, expired_crt, "client_cert", days=365,
        extra_args=["-startdate", "20200101000000Z", "-enddate", "20210101000000Z"],
    )
    print("  -> certs/private/client-vencido.key (NO versionar)")
    print("  -> certs/client-vencido.crt (publico, expirado en 2021)")

    # ---------------------------------------------------------
    # Actualizar constantes TypeScript
    # ---------------------------------------------------------
    print("\n[+] Actualizando constantes publicas de la app Next.js...")
    write_ts_assets(
        ca_pem=open(ca_crt, "r", encoding="utf-8").read(),
        client_pem=open(client_crt, "r", encoding="utf-8").read(),
        attacker_pem=open(fake_client_crt, "r", encoding="utf-8").read(),
        revoked_pem=open(revoked_crt, "r", encoding="utf-8").read(),
        expired_pem=open(expired_crt, "r", encoding="utf-8").read(),
        crl_pem=open(crl_pem_path, "r", encoding="utf-8").read(),
    )

    print("\n" + "=" * 66)
    print("PKI COMPLETA GENERADA")
    print("=" * 66)
    print("  Publicos : certs/*.crt, *.csr, crl.pem")
    print("  Privados : certs/private/* (git-ignored)")
    print("\n[SIGUIENTE PASO] Ejecuta las pruebas locales y luego despliega:")
    print("  python test_cloud_api.py          (usa API_URL del entorno)")
    print("  git add -A && git commit && git push\n")


if __name__ == "__main__":
    main()
