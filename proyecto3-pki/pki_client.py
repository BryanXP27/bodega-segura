"""
Cliente compartido para el flujo de autenticacion PKI con reto-firma.
Proyecto 3 - UNDC 2026

Reglas de seguridad:
- La llave privada NUNCA se envia al servidor.
- El cliente pide un nonce, lo firma localmente (RSA-SHA256 PKCS#1 v1.5)
  y envia: certificado publico + token de reto + firma base64.
"""

import base64
import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "pki", "certs")
PRIVATE_DIR = os.path.join(CERTS_DIR, "private")

OPENSSL_CANDIDATES = [
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    "openssl",
]


def find_openssl():
    for candidate in OPENSSL_CANDIDATES:
        if os.path.isabs(candidate):
            if os.path.exists(candidate):
                return candidate
        elif shutil.which(candidate):
            return candidate
    return None


def read_text(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def origin_from_url(url):
    """Convierte .../api/pki/operaciones en https://host"""
    marker = "/api/pki/"
    if marker in url:
        return url.split(marker, 1)[0]
    return url.rstrip("/")


def http_get_json(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "BovedaPKIClient/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return res.status, json.loads(res.read().decode("utf-8"))


def http_post_json(url, payload, timeout=15):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "BovedaPKIClient/2.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"error": raw}
        return e.code, body


def request_challenge(origin, timeout=15):
    """Solicita un reto de un solo uso. Devuelve el objeto `challenge`."""
    status, body = http_get_json(f"{origin}/api/pki/challenge", timeout=timeout)
    if status != 200 or not body.get("success"):
        raise RuntimeError(f"No se pudo obtener el reto (HTTP {status}): {body}")
    return body["challenge"]


def _sign_with_cryptography(nonce_bytes, key_path):
    """Firma con la libreria `cryptography` si esta instalada."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        return None

    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)

    return key.sign(nonce_bytes, padding.PKCS1v15(), hashes.SHA256())


def _sign_with_openssl(nonce_bytes, key_path):
    openssl = find_openssl()
    if not openssl:
        raise RuntimeError(
            "No se encontro OpenSSL ni la libreria 'cryptography'. "
            "Instala una de las dos para firmar el reto."
        )

    tmpdir = tempfile.mkdtemp(prefix="boveda_pki_")
    nonce_path = os.path.join(tmpdir, "nonce.bin")
    sig_path = os.path.join(tmpdir, "firma.bin")
    try:
        with open(nonce_path, "wb") as f:
            f.write(nonce_bytes)
        subprocess.run(
            [openssl, "dgst", "-sha256", "-sign", key_path, "-out", sig_path, nonce_path],
            check=True,
            capture_output=True,
        )
        with open(sig_path, "rb") as f:
            return f.read()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def sign_nonce(nonce, key_path):
    """Firma el nonce con RSA-SHA256 (PKCS#1 v1.5) y devuelve base64."""
    if not os.path.exists(key_path):
        raise FileNotFoundError(
            f"No se encontro la llave privada: {key_path}\n"
            "Ejecuta primero: python pki/generar_pki.py"
        )

    nonce_bytes = nonce.encode("utf-8")
    signature = _sign_with_cryptography(nonce_bytes, key_path)
    if signature is None:
        signature = _sign_with_openssl(nonce_bytes, key_path)

    return base64.b64encode(signature).decode("ascii")


def authenticate(origin, cert_path, key_path):
    """
    Ejecuta el flujo completo: pide reto, firma el nonce y consume el API.
    Devuelve (status, body, challenge).
    """
    challenge = request_challenge(origin)
    signature = sign_nonce(challenge["nonce"], key_path)
    payload = {
        "clientCertificate": read_text(cert_path),
        "challengeToken": challenge["token"],
        "signature": signature,
    }
    status, body = http_post_json(f"{origin}/api/pki/operaciones", payload)
    return status, body, challenge
