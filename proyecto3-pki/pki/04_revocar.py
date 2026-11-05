"""
Revocacion de un certificado y regeneracion de la CRL (Proyecto 3 - UNDC 2026)
-----------------------------------------------------------------------------
Uso:
    python 04_revocar.py --cert certs/client-revocado.crt --reason keyCompromise
    python 04_revocar.py --cert certs/client.crt --reason cessationOfOperation

El script:
1. Marca el certificado como revocado en la base de datos de la CA (index.txt).
2. Genera una nueva CRL firmada por la Root CA (certs/crl.pem).
3. Actualiza src/lib/pki/crl.ts para que la app Next.js use la CRL nueva.

La llave privada de la CA se lee de certs/private/ca.key (git-ignored).
"""

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
REPO_ROOT = os.path.dirname(PROJECT_DIR)
CERTS_DIR = os.path.join(BASE_DIR, "certs")
OPENSSL_CNF = os.path.join(BASE_DIR, "openssl.cnf")
SRC_PKI_DIR = os.path.join(REPO_ROOT, "src", "lib", "pki")

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


def run_openssl(openssl, args, check=True):
    cmd = [openssl] + args
    result = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"[FALLO] {' '.join(cmd)}")
        print(result.stdout)
        print(result.stderr)
        raise RuntimeError(f"OpenSSL fallo: {result.stderr}")
    return result


def update_ts_crl(crl_pem):
    generated_at = datetime.now(timezone.utc).isoformat()
    content = (
        "// AUTO-GENERADO por proyecto3-pki/pki/04_revocar.py — NO EDITAR A MANO.\n"
        f"// Generado: {generated_at}\n\n"
        f"export const BOVEDA_CRL_PEM = `{crl_pem.strip()}`;\n\n"
        f"export const BOVEDA_CRL_GENERATED_AT = '{generated_at}';\n"
    )
    path = os.path.join(SRC_PKI_DIR, "crl.ts")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    print(f"  -> CRL actualizada en la app: {path}")


def main():
    parser = argparse.ArgumentParser(description="Revoca un certificado y regenera la CRL.")
    parser.add_argument("--cert", required=True, help="Ruta del certificado a revocar (PEM).")
    parser.add_argument(
        "--reason",
        default="keyCompromise",
        choices=[
            "unspecified",
            "keyCompromise",
            "CACompromise",
            "affiliationChanged",
            "superseded",
            "cessationOfOperation",
            "certificateHold",
        ],
        help="Motivo de revocacion RFC 5280.",
    )
    args = parser.parse_args()

    openssl = find_openssl()
    if not openssl:
        print("[ERROR] No se encontro openssl.exe en el sistema.")
        sys.exit(1)

    cert_path = args.cert
    if not os.path.isabs(cert_path):
        cert_path = os.path.join(BASE_DIR, cert_path)
    if not os.path.exists(cert_path):
        print(f"[ERROR] No existe el certificado: {cert_path}")
        sys.exit(1)

    print("=" * 66)
    print("REVOCACION DE CERTIFICADO Y REGENERACION DE CRL")
    print("=" * 66)
    print(f"[1/4] Certificado: {cert_path}")
    print(f"[2/4] Motivo: {args.reason}")

    run_openssl(
        openssl,
        [
            "ca", "-batch", "-config", OPENSSL_CNF,
            "-revoke", cert_path,
            "-crl_reason", args.reason,
        ],
    )

    crl_pem_path = os.path.join(CERTS_DIR, "crl.pem")
    print("[3/4] Generando CRL firmada por la Root CA...")
    run_openssl(
        openssl,
        ["ca", "-batch", "-config", OPENSSL_CNF, "-gencrl", "-out", crl_pem_path],
    )

    serial = run_openssl(openssl, ["x509", "-in", cert_path, "-noout", "-serial"]).stdout.strip()
    with open(crl_pem_path, "r", encoding="utf-8") as f:
        crl_pem = f.read()

    print("[4/4] Publicando la CRL en la aplicacion Next.js...")
    update_ts_crl(crl_pem)

    print("\n" + "=" * 66)
    print("REVOCACION COMPLETADA")
    print("=" * 66)
    print(f"  Certificado revocado : {serial}")
    print(f"  CRL publica           : {crl_pem_path}")
    print("  Recuerda redesplegar en Cloud Run:")
    print("    git add src/lib/pki/crl.ts proyecto3-pki/pki/certs/crl.pem")
    print("    git commit -m \"chore(pki): revocar certificado y actualizar CRL\"")
    print("    git push origin master\n")


if __name__ == "__main__":
    main()
