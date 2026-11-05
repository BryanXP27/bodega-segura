"""
Emite un certificado de servidor para la VM de mTLS (Proyecto 3).
----------------------------------------------------------------
Reutiliza la Root CA existente (NO rota la CA ni los certificados de cliente)
y genera un certificado con la IP publica de la VM en el SAN.

Uso:
    set PKI_SERVER_IP=34.176.58.90
    python emitir_cert_servidor.py

Salidas:
    certs/server-vm.crt          (publico)
    certs/server-vm.csr          (publico)
    certs/private/server-vm.key  (privado, git-ignored)
"""

import os
import shutil
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
PRIVATE_DIR = os.path.join(CERTS_DIR, "private")
OPENSSL_CNF = os.path.join(BASE_DIR, "openssl.cnf")

SERVER_IP = os.environ.get("PKI_SERVER_IP", "").strip()
if not SERVER_IP:
    print("[ERROR] Define la IP publica de la VM: set PKI_SERVER_IP=34.x.x.x")
    sys.exit(1)

POSSIBLE_OPENSSL = [
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    "openssl",
]


def find_openssl():
    for candidate in POSSIBLE_OPENSSL:
        if os.path.isabs(candidate):
            if os.path.exists(candidate):
                return candidate
        elif shutil.which(candidate):
            return candidate
    return None


OPENSSL = find_openssl()
if not OPENSSL:
    print("[ERROR] No se encontro openssl.exe.")
    sys.exit(1)


def run(args):
    result = subprocess.run([OPENSSL] + args, cwd=BASE_DIR, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[FALLO] {' '.join(args)}")
        print(result.stdout)
        print(result.stderr)
        raise RuntimeError(result.stderr)
    return result.stdout


def main():
    ca_crt = os.path.join(CERTS_DIR, "ca.crt")
    ca_key = os.path.join(PRIVATE_DIR, "ca.key")
    server_key = os.path.join(PRIVATE_DIR, "server-vm.key")
    server_csr = os.path.join(CERTS_DIR, "server-vm.csr")
    server_crt = os.path.join(CERTS_DIR, "server-vm.crt")
    ext_file = os.path.join(BASE_DIR, "server_vm_ext.cnf")

    for required in (ca_crt, ca_key):
        if not os.path.exists(required):
            print(f"[ERROR] Falta {required}. Ejecuta primero generar_pki.py")
            sys.exit(1)

    print("=" * 66)
    print(f"EMITIENDO CERTIFICADO DE SERVIDOR PARA LA VM ({SERVER_IP})")
    print("=" * 66)

    run(["genrsa", "-out", server_key, "2048"])
    run([
        "req", "-new",
        "-key", server_key,
        "-out", server_csr,
        "-config", OPENSSL_CNF,
        "-subj", f"/C=PE/ST=Lima/L=Canete/O=UNDC/OU=API Gateway/CN={SERVER_IP}/emailAddress=api@undc.edu.pe",
    ])

    with open(ext_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(
            "[server_cert]\n"
            "basicConstraints = CA:FALSE\n"
            "nsCertType = server\n"
            'nsComment = "Certificado de Servidor API VM - Proyecto 3"\n'
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid,issuer:always\n"
            "keyUsage = critical, digitalSignature, keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n"
            "subjectAltName = @alt_names\n"
            "\n"
            "[alt_names]\n"
            "DNS.1 = localhost\n"
            f"IP.1 = {SERVER_IP}\n"
        )

    run([
        "ca", "-batch", "-config", OPENSSL_CNF,
        "-extensions", "server_cert",
        "-extfile", ext_file,
        "-days", "825",
        "-in", server_csr,
        "-out", server_crt,
        "-notext",
    ])

    print("  -> certs/private/server-vm.key (privada, NO versionar)")
    print("  -> certs/server-vm.crt (publica, SAN incluye la IP)")
    print("\n[SIGUIENTE PASO] Copia a la VM:")
    print("  server.py, pki/certs/ca.crt, pki/certs/server-vm.crt, pki/certs/crl.pem")
    print("  y pki/certs/private/server-vm.key (como secreto, permisos 600)\n")


if __name__ == "__main__":
    main()
