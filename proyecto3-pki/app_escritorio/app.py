"""
Aplicativo de Escritorio PKI - Proyecto 3 (UNDC 2026)
------------------------------------------------------
Universidad Nacional de Canete - Seguridad de la Informacion
Autenticacion con Certificado Digital X.509, SIN contrasenas ni API Keys.

Dos modos de demostracion:
1. NUBE (Google Cloud Run): certificado X.509 + reto firmado con la llave privada.
2. LOCAL (mTLS real): handshake TLS 1.2/1.3 con certificado de cliente.

La llave privada (certs/private/client.key) nunca sale del equipo.
"""

import os
import sys
import json
import shutil
import ssl
import threading
import urllib.request
import urllib.error
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from pki_client import (  # noqa: E402
    authenticate,
    authenticate_pfx,
    extract_pfx_to_pem,
    http_post_json,
    read_text,
    request_challenge,
    sign_nonce,
)

CERTS_DIR = os.path.join(PROJECT_DIR, "pki", "certs")
PRIVATE_DIR = os.path.join(CERTS_DIR, "private")

DEFAULT_CA = os.path.join(CERTS_DIR, "ca.crt")
DEFAULT_CLIENT_CRT = os.path.join(CERTS_DIR, "client.crt")
DEFAULT_CLIENT_KEY = os.path.join(PRIVATE_DIR, "client.key")
DEFAULT_CLIENT_PFX = os.path.join(PRIVATE_DIR, "client.pfx")

ATTACKER_CRT = os.path.join(CERTS_DIR, "attacker.crt")
ATTACKER_KEY = os.path.join(PRIVATE_DIR, "attacker.key")
REVOKED_CRT = os.path.join(CERTS_DIR, "client-revocado.crt")
EXPIRED_CRT = os.path.join(CERTS_DIR, "client-vencido.crt")

CLOUD_ORIGIN = "https://boveda-segura-git-931747537260.southamerica-west1.run.app"
CLOUD_API_URL = f"{CLOUD_ORIGIN}/api/pki/operaciones"
LOCAL_API_URL = "https://127.0.0.1:8443/api/operaciones"


class BovedaPKIApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bóveda Segura — Cliente PKI (Proyecto 3 UNDC)")
        self.root.geometry("920x860")
        self.root.minsize(860, 740)
        self.root.configure(bg="#071d2a")

        # Variables de estado
        self.mode_var = tk.StringVar(value="cloud")
        self.api_url_var = tk.StringVar(value=CLOUD_API_URL)
        self.ca_path_var = tk.StringVar(value=DEFAULT_CA)
        self.client_crt_var = tk.StringVar(value=DEFAULT_CLIENT_CRT)
        self.client_key_var = tk.StringVar(value=DEFAULT_CLIENT_KEY)
        self.pfx_path_var = tk.StringVar(value=DEFAULT_CLIENT_PFX)
        self.pfx_password_var = tk.StringVar(
            value=os.environ.get("PKI_PFX_PASSWORD", "password123")
        )
        self.status_var = tk.StringVar(value="Listo para autenticación PKI")

        self.setup_ui()
        self.log("🚀 Aplicativo inicializado.")
        self.log("   Modo NUBE: certificado X.509 + reto firmado (RSA-SHA256).")
        self.log("   Llave privada local: certs/private/client.key (NUNCA se transmite).")

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TLabel", background="#071d2a", foreground="#ffffff", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground="#22d3ee")
        style.configure("SubHeader.TLabel", font=("Segoe UI", 10), foreground="#94a3b8")
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
        style.configure("TEntry", fieldbackground="#0f293d", foreground="#ffffff", bordercolor="#1e40af")

        main_frame = tk.Frame(self.root, bg="#071d2a", padx=20, pady=15)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Cabecera
        header_frame = tk.Frame(main_frame, bg="#082331", padx=15, pady=12, highlightbackground="#0e3a53", highlightthickness=1)
        header_frame.pack(fill=tk.X, pady=(0, 15))

        tk.Label(header_frame, text="🔒 BÓVEDA SEGURA — CLIENTE PKI", font=("Segoe UI", 16, "bold"), fg="#22d3ee", bg="#082331").pack(anchor="w")
        tk.Label(
            header_frame,
            text="Certificado X.509 + prueba de posesión · Sin contraseñas ni API Keys",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#082331",
        ).pack(anchor="w", pady=(2, 0))

        # 2. Modo de conexión
        mode_box = tk.LabelFrame(main_frame, text=" Modo de Autenticación ", bg="#082331", fg="#38bdf8", font=("Segoe UI", 10, "bold"), padx=15, pady=8)
        mode_box.pack(fill=tk.X, pady=(0, 10))

        tk.Radiobutton(
            mode_box, text="☁️ Nube (Cloud Run: reto + firma)", variable=self.mode_var, value="cloud",
            bg="#082331", fg="#e2e8f0", selectcolor="#0f293d", activebackground="#082331",
            activeforeground="#22d3ee", command=self.on_mode_change,
        ).pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(
            mode_box, text="🖥️ Local (mTLS real en handshake TLS)", variable=self.mode_var, value="local",
            bg="#082331", fg="#e2e8f0", selectcolor="#0f293d", activebackground="#082331",
            activeforeground="#22d3ee", command=self.on_mode_change,
        ).pack(side=tk.LEFT)

        # 3. Configuración de Certificados
        config_box = tk.LabelFrame(main_frame, text=" Configuración de Certificados Digitales ", bg="#082331", fg="#38bdf8", font=("Segoe UI", 10, "bold"), padx=15, pady=10)
        config_box.pack(fill=tk.X, pady=(0, 12))

        tk.Label(config_box, text="URL del API Seguro:", bg="#082331", fg="#cbd5e1").grid(row=0, column=0, sticky="w", pady=4)
        tk.Entry(config_box, textvariable=self.api_url_var, bg="#0f293d", fg="#ffffff", insertbackground="#38bdf8", width=55, font=("Consolas", 10)).grid(row=0, column=1, sticky="ew", padx=8, pady=4)

        tk.Label(config_box, text="Certificado CA Raíz:", bg="#082331", fg="#cbd5e1").grid(row=1, column=0, sticky="w", pady=4)
        tk.Entry(config_box, textvariable=self.ca_path_var, bg="#0f293d", fg="#a5f3fc", insertbackground="#38bdf8", width=55, font=("Consolas", 9)).grid(row=1, column=1, sticky="ew", padx=8, pady=4)
        tk.Button(config_box, text="Examinar...", bg="#1e293b", fg="#ffffff", command=self.browse_ca, relief=tk.FLAT).grid(row=1, column=2, padx=4)

        tk.Label(config_box, text="Certificado Cliente (.crt):", bg="#082331", fg="#cbd5e1").grid(row=2, column=0, sticky="w", pady=4)
        tk.Entry(config_box, textvariable=self.client_crt_var, bg="#0f293d", fg="#86efac", insertbackground="#38bdf8", width=55, font=("Consolas", 9)).grid(row=2, column=1, sticky="ew", padx=8, pady=4)
        tk.Button(config_box, text="Examinar...", bg="#1e293b", fg="#ffffff", command=self.browse_client_crt, relief=tk.FLAT).grid(row=2, column=2, padx=4)

        tk.Label(config_box, text="Llave Privada (.key):", bg="#082331", fg="#cbd5e1").grid(row=3, column=0, sticky="w", pady=4)
        tk.Entry(config_box, textvariable=self.client_key_var, bg="#0f293d", fg="#fca5a5", insertbackground="#38bdf8", width=55, font=("Consolas", 9)).grid(row=3, column=1, sticky="ew", padx=8, pady=4)
        tk.Button(config_box, text="Examinar...", bg="#1e293b", fg="#ffffff", command=self.browse_client_key, relief=tk.FLAT).grid(row=3, column=2, padx=4)

        tk.Label(config_box, text="Paquete PKCS#12 (.pfx):", bg="#082331", fg="#cbd5e1").grid(row=4, column=0, sticky="w", pady=4)
        tk.Entry(config_box, textvariable=self.pfx_path_var, bg="#0f293d", fg="#fde68a", insertbackground="#38bdf8", width=55, font=("Consolas", 9)).grid(row=4, column=1, sticky="ew", padx=8, pady=4)
        tk.Button(config_box, text="Examinar...", bg="#1e293b", fg="#ffffff", command=self.browse_pfx, relief=tk.FLAT).grid(row=4, column=2, padx=4)

        tk.Label(config_box, text="Password del .pfx:", bg="#082331", fg="#cbd5e1").grid(row=5, column=0, sticky="w", pady=4)
        tk.Entry(config_box, textvariable=self.pfx_password_var, show="*", bg="#0f293d", fg="#fde68a", insertbackground="#38bdf8", width=55, font=("Consolas", 9)).grid(row=5, column=1, sticky="ew", padx=8, pady=4)

        config_box.columnconfigure(1, weight=1)

        # 4. Panel de Acciones y Pruebas (Rúbrica)
        actions_box = tk.LabelFrame(main_frame, text=" Pruebas de Acceso y Superficie de Ataque ", bg="#082331", fg="#38bdf8", font=("Segoe UI", 10, "bold"), padx=15, pady=12)
        actions_box.pack(fill=tk.X, pady=(0, 12))

        tk.Button(actions_box, text="🟢 Certificado Válido + Reto Firmado", bg="#059669", fg="#ffffff", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=10, pady=6, cursor="hand2", command=self.run_valid_auth).grid(row=0, column=0, padx=4, pady=4, sticky="ew")
        tk.Button(actions_box, text="🔴 Ataque: Sin Certificado", bg="#dc2626", fg="#ffffff", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=10, pady=6, cursor="hand2", command=self.run_no_cert_attack).grid(row=0, column=1, padx=4, pady=4, sticky="ew")
        tk.Button(actions_box, text="🟠 Ataque: Otra CA", bg="#d97706", fg="#ffffff", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=10, pady=6, cursor="hand2", command=self.run_rogue_cert_attack).grid(row=0, column=2, padx=4, pady=4, sticky="ew")
        tk.Button(actions_box, text="🟡 Ataque: Certificado sin Llave", bg="#ca8a04", fg="#ffffff", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=10, pady=6, cursor="hand2", command=self.run_no_proof_attack).grid(row=0, column=3, padx=4, pady=4, sticky="ew")

        tk.Button(actions_box, text="🔐 Acceso con PKCS#12 (.pfx)", bg="#0e7490", fg="#ffffff", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=10, pady=6, cursor="hand2", command=self.run_valid_pfx_auth).grid(row=1, column=0, columnspan=2, padx=4, pady=(8, 4), sticky="ew")
        tk.Button(actions_box, text="🧾 Verificar CRL (revocado)", bg="#9f1239", fg="#ffffff", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=10, pady=6, cursor="hand2", command=self.run_revoked_demo).grid(row=1, column=2, columnspan=2, padx=4, pady=(8, 4), sticky="ew")

        for col in range(4):
            actions_box.columnconfigure(col, weight=1)

        # 5. Consola de Logs
        log_frame = tk.LabelFrame(main_frame, text=" Consola de Auditoría y Verificación Criptográfica en Tiempo Real ", bg="#082331", fg="#38bdf8", font=("Segoe UI", 10, "bold"), padx=10, pady=10)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(log_frame, bg="#03131d", fg="#22d3ee", insertbackground="#38bdf8", font=("Consolas", 10), wrap=tk.WORD, borderwidth=0)
        scrollbar = tk.Scrollbar(log_frame, command=self.log_text.yview, bg="#082331")
        self.log_text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        status_bar = tk.Label(self.root, textvariable=self.status_var, bg="#03131d", fg="#94a3b8", font=("Segoe UI", 9), anchor="w", padx=10, pady=4)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def on_mode_change(self):
        if self.mode_var.get() == "cloud":
            self.api_url_var.set(CLOUD_API_URL)
            self.log("ℹ️ Modo NUBE: se solicitará un reto y se firmará con la llave privada.")
        else:
            self.api_url_var.set(LOCAL_API_URL)
            self.log("ℹ️ Modo LOCAL: mTLS real (el certificado se presenta en el handshake TLS).")

    def log(self, text):
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)

    def browse_ca(self):
        f = filedialog.askopenfilename(title="Seleccionar Certificado CA Raíz", filetypes=[("Certificados X.509", "*.crt *.pem")])
        if f:
            self.ca_path_var.set(f)

    def browse_client_crt(self):
        f = filedialog.askopenfilename(title="Seleccionar Certificado de Cliente", filetypes=[("Certificados X.509", "*.crt *.pem")])
        if f:
            self.client_crt_var.set(f)

    def browse_client_key(self):
        f = filedialog.askopenfilename(title="Seleccionar Llave Privada del Cliente", filetypes=[("Llave Privada", "*.key *.pem")])
        if f:
            self.client_key_var.set(f)

    def browse_pfx(self):
        f = filedialog.askopenfilename(title="Seleccionar Paquete PKCS#12", filetypes=[("PKCS#12", "*.pfx *.p12")])
        if f:
            self.pfx_path_var.set(f)

    # ------------------------------------------------------------------
    # PRUEBA 1: ACCESO VÁLIDO
    # ------------------------------------------------------------------
    def run_valid_auth(self):
        threading.Thread(target=self._exec_valid_auth, daemon=True).start()

    def _exec_valid_auth(self):
        if self.mode_var.get() == "cloud":
            self._exec_cloud_auth()
        else:
            self._exec_local_mtls_auth()

    def _exec_cloud_auth(self):
        self.status_var.set("Autenticando en la nube con reto + firma...")
        self.log("\n" + "=" * 70)
        self.log("▶ [INICIO] AUTENTICACIÓN EN CLOUD RUN: CERTIFICADO + PRUEBA DE POSESIÓN")
        self.log("=" * 70)

        ca_file = self.ca_path_var.get()
        crt_file = self.client_crt_var.get()
        key_file = self.client_key_var.get()
        url = self.api_url_var.get()
        origin = url.split("/api/pki/", 1)[0]

        if not os.path.exists(crt_file) or not os.path.exists(key_file):
            self.log("❌ ERROR: No se encontró el certificado o la llave privada del cliente.")
            self.log("   Ejecuta: python pki/generar_pki.py")
            return

        try:
            self.log(f"1. CA de confianza del servidor TLS: {os.path.basename(ca_file)}")
            self.log("2. Solicitando reto de un solo uso (GET /api/pki/challenge)...")
            challenge = request_challenge(origin)
            self.log(f"   -> nonce: {challenge['nonce'][:24]}... | expira: {challenge['expiresAt']}")

            self.log(f"3. Firmando el nonce con la llave privada: {os.path.basename(key_file)}")
            signature = sign_nonce(challenge["nonce"], key_file)
            self.log(f"   -> firma RSA-SHA256: {signature[:36]}... ({len(signature)} chars)")
            self.log("   -> la llave privada NO se transmite")

            self.log(f"4. Enviando certificado + token + firma a {url}")
            payload = {
                "clientCertificate": read_text(crt_file),
                "challengeToken": challenge["token"],
                "signature": signature,
            }
            status, data = http_post_json(url, payload)

            if status == 200:
                client = data.get("auth_details", {}).get("client", {})
                self.log(f"✔ [HTTP {status}] {data.get('message')}")
                self.log(f"✔ [CLIENTE IDENTIFICADO]: {client.get('commonName')}")
                self.log(f"✔ [PRUEBA DE POSESIÓN]: {data.get('auth_details', {}).get('proof_of_possession')}")
                self.log("✔ [DATOS DE LA BÓVEDA OBTENIDOS SIN CONTRASEÑAS]:")
                self.log(json.dumps(data.get("boveda_data", {}), indent=4))
                self.status_var.set("Autenticación PKI en la nube completada con éxito")
                messagebox.showinfo("Éxito PKI", "Autenticación exitosa.\nCertificado + llave privada verificados.")
            else:
                self.log(f"❌ [HTTP {status}] {data.get('code')}: {data.get('error')}")
                self.status_var.set("Acceso denegado por el API")

        except Exception as e:
            self.log(f"❌ [FALLO DE CONEXIÓN]: {e}")
            self.status_var.set("Error en conexión con la nube")

    def _exec_local_mtls_auth(self):
        self.status_var.set("Autenticando con mTLS local...")
        self.log("\n" + "=" * 70)
        self.log("▶ [INICIO] mTLS REAL CONTRA EL SERVIDOR LOCAL (handshake TLS)")
        self.log("=" * 70)

        ca_file = self.ca_path_var.get()
        crt_file = self.client_crt_var.get()
        key_file = self.client_key_var.get()
        url = self.api_url_var.get()

        if not os.path.exists(crt_file) or not os.path.exists(key_file):
            self.log("❌ ERROR: No se encontró el certificado o la llave privada del cliente.")
            return

        try:
            self.log(f"1. Validando servidor contra CA: {os.path.basename(ca_file)}")
            self.log(f"2. Presentando Certificado Digital: {os.path.basename(crt_file)}")
            self.log(f"3. El handshake TLS firma datos únicos con: {os.path.basename(key_file)}")

            context = ssl.create_default_context(cafile=ca_file)
            context.load_cert_chain(certfile=crt_file, keyfile=key_file)

            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, context=context, timeout=8) as response:
                status = response.status
                data = json.loads(response.read().decode("utf-8"))

                self.log(f"✔ [HANDSHAKE mTLS EXITOSO] Status HTTP: {status} OK")
                self.log(f"✔ [CLIENTE IDENTIFICADO]: {data.get('auth_details', {}).get('client_subject', {}).get('commonName', 'OK')}")
                self.log("✔ [DATOS DE LA BÓVEDA OBTENIDOS SIN CONTRASEÑAS]:")
                self.log(json.dumps(data.get("boveda_data", {}), indent=4))
                self.status_var.set("Autenticación mTLS completada con éxito")
                messagebox.showinfo("Éxito mTLS", "Autenticación exitosa.\nCliente identificado por certificado digital.")
        except Exception as e:
            self.log(f"❌ [FALLO DE CONEXIÓN]: {e}")
            self.status_var.set("Error en conexión mTLS local")

    # ------------------------------------------------------------------
    # PRUEBA 1B: ACCESO USANDO PKCS#12 (.pfx)
    # ------------------------------------------------------------------
    def run_valid_pfx_auth(self):
        threading.Thread(target=self._exec_valid_pfx_auth, daemon=True).start()

    def _pfx_password(self):
        password = self.pfx_password_var.get()
        if password:
            return password
        typed = simpledialog.askstring(
            "PKCS#12",
            "Contraseña del archivo .pfx:",
            show="*",
            parent=self.root,
        )
        if typed is None:
            return None
        self.pfx_password_var.set(typed)
        return typed

    def _exec_valid_pfx_auth(self):
        pfx_file = self.pfx_path_var.get()
        password = self._pfx_password()
        if password is None:
            return
        if not os.path.exists(pfx_file):
            self.log(f"❌ ERROR: No se encontró el archivo .pfx: {pfx_file}")
            self.log("   Ejecuta: python pki/generar_pki.py")
            return

        self.status_var.set("Autenticando con PKCS#12...")
        self.log("\n" + "=" * 70)
        self.log("▶ [INICIO] AUTENTICACIÓN CON PKCS#12 (.pfx)")
        self.log("=" * 70)
        self.log(f"1. Paquete PKCS#12: {os.path.basename(pfx_file)}")
        self.log("2. Extrayendo certificado y llave privada a un directorio temporal...")

        if self.mode_var.get() == "cloud":
            url = self.api_url_var.get()
            origin = url.split("/api/pki/", 1)[0]
            try:
                self.log("3. Solicitando reto y firmando el nonce con la llave del .pfx...")
                status, data, challenge = authenticate_pfx(origin, pfx_file, password)

                if status == 200:
                    client = data.get("auth_details", {}).get("client", {})
                    self.log(f"✔ [HTTP {status}] {data.get('message')}")
                    self.log(f"✔ [CLIENTE IDENTIFICADO]: {client.get('commonName')}")
                    self.log(f"✔ [RETO VERIFICADO]: {challenge['expiresAt']}")
                    self.log("✔ [DATOS DE LA BÓVEDA OBTENIDOS SIN CONTRASEÑAS]:")
                    self.log(json.dumps(data.get("boveda_data", {}), indent=4))
                    self.status_var.set("Autenticación PKCS#12 completada")
                    messagebox.showinfo("Éxito PKCS#12", "Autenticación exitosa usando .pfx.")
                else:
                    self.log(f"❌ [HTTP {status}] {data.get('code')}: {data.get('error')}")
                    self.status_var.set("Acceso denegado usando .pfx")
            except Exception as e:
                self.log(f"❌ [FALLO DE CONEXIÓN]: {e}")
                self.status_var.set("Error con el archivo .pfx")
            return

        # Modo local mTLS: se extrae el .pfx a PEM temporales para el handshake TLS.
        ca_file = self.ca_path_var.get()
        url = self.api_url_var.get()
        tmpdir = None
        try:
            cert_path, key_path, tmpdir = extract_pfx_to_pem(pfx_file, password)
            self.log("3. Ejecutando handshake mTLS con el certificado extraído...")
            context = ssl.create_default_context(cafile=ca_file)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, context=context, timeout=8) as response:
                status = response.status
                data = json.loads(response.read().decode("utf-8"))
                self.log(f"✔ [HANDSHAKE mTLS EXITOSO] Status HTTP: {status} OK")
                self.log(f"✔ [CLIENTE IDENTIFICADO]: {data.get('auth_details', {}).get('client_subject', {}).get('commonName', 'OK')}")
                self.log("✔ [DATOS DE LA BÓVEDA OBTENIDOS SIN CONTRASEÑAS]:")
                self.log(json.dumps(data.get("boveda_data", {}), indent=4))
                self.status_var.set("Autenticación mTLS con .pfx completada")
                messagebox.showinfo("Éxito mTLS", "Autenticación exitosa usando .pfx.")
        except Exception as e:
            self.log(f"❌ [FALLO DE CONEXIÓN]: {e}")
            self.status_var.set("Error en mTLS usando .pfx")
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------
    # PRUEBA 1C: CERTIFICADO REVOCADO (CRL REAL)
    # ------------------------------------------------------------------
    def run_revoked_demo(self):
        threading.Thread(target=self._exec_revoked_demo, daemon=True).start()

    def _exec_revoked_demo(self):
        self.status_var.set("Verificando certificado revocado contra la CRL...")
        self.log("\n" + "=" * 70)
        self.log("▶ [CRL] CERTIFICADO REVOCADO POR LA AUTORIDAD CERTIFICADORA")
        self.log("=" * 70)

        if not os.path.exists(REVOKED_CRT):
            self.log("❌ ERROR: No se encontró certs/client-revocado.crt.")
            return

        if self.mode_var.get() == "cloud":
            try:
                self.log("1. Presentando client-revocado.crt (serie incluida en la CRL)...")
                status, data = http_post_json(
                    self.api_url_var.get(),
                    {"clientCertificate": read_text(REVOKED_CRT)},
                )
                self.log(f"🛡️ [HTTP {status}] {data.get('code')}: {data.get('error')}")
                self.log("✔ RESULTADO ESPERADO: la CRL firmada por la CA invalida el certificado.")
                self.status_var.set("Certificado revocado bloqueado")
            except Exception as e:
                self.log(f"❌ [ERROR]: {e}")
            return

        self.log("En modo local, el servidor valida la CRL real antes de autorizar.")
        self.log("Selecciona el modo NUBE para ver el rechazo de forma directa.")

    # ------------------------------------------------------------------
    # PRUEBA 2: SIN CERTIFICADO
    # ------------------------------------------------------------------
    def run_no_cert_attack(self):
        threading.Thread(target=self._exec_no_cert_attack, daemon=True).start()

    def _exec_no_cert_attack(self):
        self.status_var.set("Probando ataque: conexión sin certificado...")
        self.log("\n" + "=" * 70)
        self.log("▶ [PRUEBA DE ATAQUE 1] INTENTO DE ACCESO SIN CERTIFICADO DIGITAL")
        self.log("=" * 70)

        if self.mode_var.get() == "cloud":
            try:
                status, data = http_post_json(self.api_url_var.get(), {})
                self.log(f"🛡️ [HTTP {status}] {data.get('code')}: {data.get('error')}")
                self.log("✔ RESULTADO ESPERADO: rechazo por falta de credencial X.509.")
                self.status_var.set("Ataque bloqueado (401)")
            except Exception as e:
                self.log(f"❌ [ERROR]: {e}")
            return

        ca_file = self.ca_path_var.get()
        url = self.api_url_var.get()

        try:
            context = ssl.create_default_context(cafile=ca_file)
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, context=context, timeout=6):
                self.log("❌ PELIGRO: El servidor permitió el acceso sin certificado!")
        except ssl.SSLError as e:
            self.log(f"🛡️ [BLOQUEADO POR mTLS]: {e.reason or e}")
            self.log("✔ RESULTADO ESPERADO: conexión terminada en el handshake TLS.")
            self.status_var.set("Ataque bloqueado con éxito")
        except urllib.error.URLError as e:
            self.log(f"🛡️ [BLOQUEADO EN SOCKET]: {e.reason}")
            self.status_var.set("Ataque bloqueado con éxito")
        except Exception as e:
            self.log(f"🛡️ [BLOQUEADO]: {e}")

    # ------------------------------------------------------------------
    # PRUEBA 3: CERTIFICADO DE OTRA CA
    # ------------------------------------------------------------------
    def run_rogue_cert_attack(self):
        threading.Thread(target=self._exec_rogue_cert_attack, daemon=True).start()

    def _exec_rogue_cert_attack(self):
        self.status_var.set("Probando ataque: certificado de otra CA...")
        self.log("\n" + "=" * 70)
        self.log("▶ [PRUEBA DE ATAQUE 2] CERTIFICADO DE OTRA CA (ROGUE CA)")
        self.log("=" * 70)

        if not os.path.exists(ATTACKER_CRT):
            self.log("❌ ERROR: No se encontró certs/attacker.crt.")
            return

        if self.mode_var.get() == "cloud":
            try:
                self.log("1. Presentando certificado emitido por 'Rogue Malicious Root CA'...")
                status, data = http_post_json(
                    self.api_url_var.get(), {"clientCertificate": read_text(ATTACKER_CRT)}
                )
                self.log(f"🛡️ [HTTP {status}] {data.get('code')}: {data.get('error')}")
                self.log("✔ RESULTADO ESPERADO: la cadena de confianza no llega a la Root CA propia.")
                self.status_var.set("Ataque bloqueado: CA no confiable")
            except Exception as e:
                self.log(f"❌ [ERROR]: {e}")
            return

        ca_file = self.ca_path_var.get()
        url = self.api_url_var.get()

        if not os.path.exists(ATTACKER_KEY):
            self.log("❌ ERROR: No se encontró certs/private/attacker.key.")
            return

        try:
            self.log("1. Presentando certificado emitido por 'Rogue Malicious Root CA'...")
            context = ssl.create_default_context(cafile=ca_file)
            context.load_cert_chain(certfile=ATTACKER_CRT, keyfile=ATTACKER_KEY)

            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, context=context, timeout=6):
                self.log("❌ PELIGRO: El servidor confió en un certificado de otra CA!")
        except ssl.SSLError as e:
            self.log(f"🛡️ [BLOQUEADO POR LA CA]: {e.reason or e}")
            self.log("✔ RESULTADO ESPERADO: cadena de firma rechazada contra ca.crt.")
            self.status_var.set("Ataque bloqueado: CA no confiable")
        except urllib.error.URLError as e:
            self.log(f"🛡️ [BLOQUEADO EN SOCKET]: {e.reason}")
            self.status_var.set("Ataque bloqueado")
        except Exception as e:
            self.log(f"🛡️ [BLOQUEADO]: {e}")

    # ------------------------------------------------------------------
    # PRUEBA 4: CERTIFICADO SIN LLAVE (REPLAY DEL PEM PÚBLICO)
    # ------------------------------------------------------------------
    def run_no_proof_attack(self):
        threading.Thread(target=self._exec_no_proof_attack, daemon=True).start()

    def _exec_no_proof_attack(self):
        self.status_var.set("Probando ataque: certificado público sin llave privada...")
        self.log("\n" + "=" * 70)
        self.log("▶ [PRUEBA DE ATAQUE 3] COPIAR EL CERTIFICADO PÚBLICO (SIN LLAVE PRIVADA)")
        self.log("=" * 70)

        crt_file = self.client_crt_var.get()
        if not os.path.exists(crt_file):
            self.log("❌ ERROR: No se encontró el certificado del cliente.")
            return

        if self.mode_var.get() == "cloud":
            try:
                self.log("1. El atacante copia client.crt (público) pero NO tiene client.key...")
                status, data = http_post_json(
                    self.api_url_var.get(), {"clientCertificate": read_text(crt_file)}
                )
                self.log(f"🛡️ [HTTP {status}] {data.get('code')}: {data.get('error')}")
                self.log("✔ RESULTADO ESPERADO: sin firma del reto no hay prueba de posesión.")
                self.status_var.set("Ataque bloqueado: falta la llave privada")
            except Exception as e:
                self.log(f"❌ [ERROR]: {e}")
            return

        self.log("En modo LOCAL, presentar solo el certificado sin la llave privada")
        self.log("hace fallar el handshake TLS (no se puede firmar el CertificateVerify).")
        self.log("✔ RESULTADO ESPERADO: conexión rechazada por mTLS.")
        self.status_var.set("Modo local: sin llave no hay handshake")


def main():
    root = tk.Tk()
    BovedaPKIApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
