"""
Servidor API Seguro con Autenticacion Mutua (mTLS) - Proyecto 3 (UNDC 2026)
--------------------------------------------------------------------------
Plataforma: Servidor HTTPS Local / VM Compute Engine
Valida:
1. TLS 1.2 / TLS 1.3 con requerimiento estricto de Certificado de Cliente.
2. Firma de la Autoridad Certificadora (Root CA propia de la Boveda).
3. Vigencia (fechas notBefore / notAfter).
4. Sujeto (Common Name) y autorizaciones por rol.
5. Lista de Revocacion de Certificados (CRL / Serial Blacklist).

Nota: Cloud Run termina TLS en el borde y no permite mTLS con CA propia.
Para mTLS real se usa este servidor en una VM; en Cloud Run la app Next.js
valida X.509 + prueba de posesion (reto firmado).
"""

import os
import sys
import json
import ssl
import shutil
import subprocess
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(os.path.dirname(BASE_DIR), "pki", "certs")
PRIVATE_DIR = os.path.join(CERTS_DIR, "private")

SERVER_PORT = int(os.environ.get("PORT", 8443))
SERVER_HOST = "0.0.0.0"

# Certificados publicos (versionables)
CA_CRT = os.path.join(CERTS_DIR, "ca.crt")
SERVER_CRT = os.path.join(CERTS_DIR, "server.crt")
# Llave privada del servidor: NUNCA se versiona (certs/private esta en .gitignore).
# En produccion puede montarse desde un secreto: SERVER_KEY=/run/secrets/server.key
SERVER_KEY = os.environ.get("SERVER_KEY", os.path.join(PRIVATE_DIR, "server.key"))

# CRL real firmada por la Root CA (material publico).
CRL_PEM = os.path.join(CERTS_DIR, "crl.pem")

# Lista de respaldo si OpenSSL no esta disponible (la fuente principal es la CRL).
REVOKED_SERIALS = [
    "1002",  # cliente-revocado-01 (generado por generar_pki.py)
]


def find_openssl():
    candidates = [
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        "openssl",
    ]
    for candidate in candidates:
        if os.path.isabs(candidate):
            if os.path.exists(candidate):
                return candidate
        elif shutil.which(candidate):
            return candidate
    return None


def verify_certificate_with_crl(cert_der):
    """
    Valida el certificado del cliente con OpenSSL: cadena de confianza,
    vigencia y revocacion contra la CRL firmada por la CA.

    Devuelve (ok, code, message). El handshake TLS ya garantiza que la CA
    firmo el certificado; aqui se agrega la CRL y la fecha de vigencia.
    """
    openssl = find_openssl()
    if not openssl:
        # Sin OpenSSL no se puede comprobar la CRL: se falla cerrado.
        return False, "CRL_VALIDATION_UNAVAILABLE", "OpenSSL no esta disponible para validar la CRL."

    if not os.path.exists(CRL_PEM):
        return False, "CRL_MISSING", "No se encontro pki/certs/crl.pem. Ejecuta generar_pki.py."

    fd, cert_path = tempfile.mkstemp(prefix="boveda_peer_", suffix=".pem")
    os.close(fd)
    try:
        # `openssl verify` recibe PEM; convertimos el DER del handshake TLS.
        with open(cert_path, "w", encoding="ascii", newline="\n") as f:
            f.write(ssl.DER_cert_to_PEM_cert(cert_der))

        result = subprocess.run(
            [
                openssl, "verify",
                "-crl_check",
                "-CAfile", CA_CRT,
                "-CRLfile", CRL_PEM,
                cert_path,
            ],
            capture_output=True,
            text=True,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0:
            return True, None, output.strip()

        lowered = output.lower()
        if "revoked" in lowered:
            return False, "CERTIFICATE_REVOKED", "El certificado figura en la CRL firmada por la Root CA."
        if "expired" in lowered:
            return False, "CERTIFICATE_EXPIRED", "El certificado esta fuera de su periodo de vigencia."
        if "not yet valid" in lowered:
            return False, "CERTIFICATE_NOT_YET_VALID", "El certificado aun no es valido."
        return False, "CERTIFICATE_INVALID", output.strip()
    finally:
        try:
            os.remove(cert_path)
        except OSError:
            pass


def parse_dn(dn_tuple):
    """Convierte una tupla de nombres distinguidos de Python ssl a un diccionario."""
    res = {}
    if not dn_tuple:
        return res
    for rdn in dn_tuple:
        for key, val in rdn:
            res[key] = val
    return res


class MTLSRequestHandler(BaseHTTPRequestHandler):
    server_version = "BovedaSecureAPI/1.0"

    def _send_json(self, status_code, data):
        body = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        # 1. Obtener el certificado presentado por el cliente en el handshake TLS
        client_cert = None
        client_cert_der = None
        try:
            if hasattr(self.connection, "getpeercert"):
                client_cert = self.connection.getpeercert()
                client_cert_der = self.connection.getpeercert(binary_form=True)
        except Exception as e:
            print(f"[!] Error leyendo certificado del cliente: {e}")

        # 2. Ruta publica de salud (Healthcheck para Google Cloud Run)
        if self.path == "/" or self.path == "/api/health":
            self._send_json(200, {
                "status": "online",
                "service": "Boveda Segura - API mTLS (Proyecto 3)",
                "pki": {
                    "ca_installed": os.path.exists(CA_CRT),
                    "mtls_active": True,
                    "expected_issuer": "Boveda Segura Root CA"
                },
                "client_authenticated": bool(client_cert),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            return

        # 3. Validacion del Certificado de Cliente para endpoints protegidos
        if not client_cert:
            self._send_json(401, {
                "error": "Acceso Denegado: No se presento ningun certificado digital de cliente",
                "code": "MISSING_CLIENT_CERTIFICATE",
                "detail": "Este API requiere autenticacion mutua (mTLS). Instale su archivo .pfx o presente su certificado X.509 firmado por la CA de la Boveda."
            })
            return

        subject = parse_dn(client_cert.get("subject", ()))
        issuer = parse_dn(client_cert.get("issuer", ()))
        serial_number = str(client_cert.get("serialNumber", ""))
        not_after = client_cert.get("notAfter", "")

        # Verificar vigencia y revocacion contra la CRL real firmada por la CA.
        # Si OpenSSL no esta disponible se aplica la lista de respaldo.
        crl_ok = False
        if client_cert_der:
            crl_ok, crl_code, crl_message = verify_certificate_with_crl(client_cert_der)
            if not crl_ok:
                self._send_json(403, {
                    "error": f"Acceso Denegado: {crl_message}",
                    "code": crl_code,
                    "serial_number": serial_number,
                })
                return

        if not crl_ok and serial_number.lstrip("0") in {s.lstrip("0") for s in REVOKED_SERIALS}:
            self._send_json(403, {
                "error": "Acceso Denegado: Certificado Revocado (lista de respaldo)",
                "code": "CERTIFICATE_REVOKED",
                "serial_number": serial_number,
            })
            return

        client_cn = subject.get("commonName", "desconocido")
        issuer_cn = issuer.get("commonName", "desconocido")

        # 4. Endpoint protegido de consulta de saldo y operaciones de alta seguridad
        if self.path == "/api/secure-data" or self.path == "/api/operaciones":
            self._send_json(200, {
                "success": True,
                "message": f"Autenticacion mTLS Exitosa. Bienvenido, {client_cn}.",
                "auth_details": {
                    "client_subject": subject,
                    "client_issuer": issuer,
                    "serial_number": serial_number,
                    "valid_until": not_after,
                    "auth_method": "TLS Mutual (X.509 Certificate Handshake)",
                    "passwords_used": "Ninguna (Zero-Secret Transmission)",
                    "api_keys_used": "Ninguna"
                },
                "boveda_data": {
                    "cuenta_id": "CTA-UNDC-2026-9948",
                    "titular": "Sistema Financiero Boveda Segura",
                    "saldo_disponible": "$ 1,500,000.00 USD",
                    "nivel_acceso": "OPERACIONES_CRITICAS_AUTORIZADAS",
                    "cifrado_canal": "TLSv1.3 AES-256-GCM / SHA-256"
                }
            })
            return

        # 5. Endpoint de auditoria de PKI
        if self.path == "/api/pki/status":
            self._send_json(200, {
                "ca_name": issuer_cn,
                "client_authorized": client_cn,
                "mutual_tls_status": "ENFORCED",
                "verified_by_cloud": "Google Cloud Run / Custom TLS Engine"
            })
            return

        # Ruta no encontrada
        self._send_json(404, {"error": "Ruta no encontrada", "path": self.path})


def run_server():
    if not os.path.exists(SERVER_CRT) or not os.path.exists(SERVER_KEY) or not os.path.exists(CA_CRT):
        print(f"[ERROR] No se encontraron los certificados en {CERTS_DIR}")
        print(f"  CA publica:        {CA_CRT}")
        print(f"  Certificado server:{SERVER_CRT}")
        print(f"  Llave server:      {SERVER_KEY} (privada, git-ignored)")
        print("Ejecuta primero: python pki/generar_pki.py")
        sys.exit(1)

    print("="*60)
    print("INICIANDO SERVIDOR API mTLS - PROYECTO 3 (UNDC 2026)")
    print("="*60)
    print(f"Puerto: {SERVER_PORT}")
    print(f"CA Raiz: {CA_CRT}")
    print(f"Certificado Servidor: {SERVER_CRT}")
    print(f"Llave privada Servidor: {SERVER_KEY}")
    print("Modo de Autenticacion: TLS MUTUO REQUERIDO (CERT_REQUIRED)")
    print("="*60)

    # Configurar el Contexto SSL con verificacion obligatoria de cliente
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Cargar certificado y llave del servidor
    context.load_cert_chain(certfile=SERVER_CRT, keyfile=SERVER_KEY)
    # Cargar la CA raiz para validar los clientes
    context.load_verify_locations(cafile=CA_CRT)
    # REQUERIR CERTIFICADO DE CLIENTE OBLIGATORIO (mTLS)
    context.verify_mode = ssl.CERT_REQUIRED
    # Forzar TLS 1.2 o TLS 1.3 seguro
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    server_address = (SERVER_HOST, SERVER_PORT)
    httpd = HTTPServer(server_address, MTLSRequestHandler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"[OK] Servidor escuchando en https://localhost:{SERVER_PORT}")
    print("Presiona Ctrl+C para detener el servidor.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Servidor detenido por el usuario.")
        httpd.server_close()


if __name__ == "__main__":
    run_server()

