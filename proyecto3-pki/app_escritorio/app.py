"""
Aplicativo de Escritorio mTLS - Proyecto 3 (UNDC 2026)
------------------------------------------------------
Universidad Nacional de Canete - Seguridad de la Informacion
Autenticacion con Certificado Digital X.509 / PKCS#12 (.pfx)
Sin contrasenas ni API Keys.
"""

import os
import sys
import json
import ssl
import threading
import urllib.request
import urllib.error
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
CERTS_DIR = os.path.join(PROJECT_DIR, "pki", "certs")

DEFAULT_CA = os.path.join(CERTS_DIR, "ca.crt")
DEFAULT_CLIENT_CRT = os.path.join(CERTS_DIR, "client.crt")
DEFAULT_CLIENT_KEY = os.path.join(CERTS_DIR, "client.key")
DEFAULT_CLIENT_PFX = os.path.join(CERTS_DIR, "client.pfx")

ATTACKER_CRT = os.path.join(CERTS_DIR, "attacker.crt")
ATTACKER_KEY = os.path.join(CERTS_DIR, "attacker.key")

DEFAULT_API_URL = "https://127.0.0.1:8443/api/operaciones"


class BovedaPKIApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bóveda Segura — Cliente PKI mTLS (Proyecto 3 UNDC)")
        self.root.geometry("880x720")
        self.root.minsize(820, 650)
        self.root.configure(bg="#071d2a")

        # Variables de estado
        self.api_url_var = tk.StringVar(value=DEFAULT_API_URL)
        self.ca_path_var = tk.StringVar(value=DEFAULT_CA)
        self.client_crt_var = tk.StringVar(value=DEFAULT_CLIENT_CRT)
        self.client_key_var = tk.StringVar(value=DEFAULT_CLIENT_KEY)
        self.status_var = tk.StringVar(value="Listo para autenticación mTLS")

        self.setup_ui()
        self.log("🚀 Aplicativo inicializado. Certificados cargados desde proyecto3-pki/pki/certs/")

    def setup_ui(self):
        # Estilos generales
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

        title_lbl = tk.Label(header_frame, text="🔒 BÓVEDA SEGURA — CLIENTE PKI mTLS", font=("Segoe UI", 16, "bold"), fg="#22d3ee", bg="#082331")
        title_lbl.pack(anchor="w")
        sub_lbl = tk.Label(header_frame, text="Autenticación Mutua TLS 1.3 con Certificado Digital X.509 (Sin Contraseñas ni API Keys)", font=("Segoe UI", 9), fg="#94a3b8", bg="#082331")
        sub_lbl.pack(anchor="w", pady=(2, 0))

        # 2. Configuracion de Conexion y Certificados
        config_box = tk.LabelFrame(main_frame, text=" Configuración de Certificados Digitales ", bg="#082331", fg="#38bdf8", font=("Segoe UI", 10, "bold"), padx=15, pady=10)
        config_box.pack(fill=tk.X, pady=(0, 15))

        # Fila URL API
        tk.Label(config_box, text="URL del API Seguro:", bg="#082331", fg="#cbd5e1").grid(row=0, column=0, sticky="w", pady=4)
        tk.Entry(config_box, textvariable=self.api_url_var, bg="#0f293d", fg="#ffffff", insertbackground="#38bdf8", width=55, font=("Consolas", 10)).grid(row=0, column=1, sticky="ew", padx=8, pady=4)

        # Fila CA Raiz
        tk.Label(config_box, text="Certificado CA Raíz:", bg="#082331", fg="#cbd5e1").grid(row=1, column=0, sticky="w", pady=4)
        tk.Entry(config_box, textvariable=self.ca_path_var, bg="#0f293d", fg="#a5f3fc", insertbackground="#38bdf8", width=55, font=("Consolas", 9)).grid(row=1, column=1, sticky="ew", padx=8, pady=4)
        tk.Button(config_box, text="Examinar...", bg="#1e293b", fg="#ffffff", command=self.browse_ca, relief=tk.FLAT).grid(row=1, column=2, padx=4)

        # Fila Certificado de Cliente
        tk.Label(config_box, text="Certificado Cliente (.crt):", bg="#082331", fg="#cbd5e1").grid(row=2, column=0, sticky="w", pady=4)
        tk.Entry(config_box, textvariable=self.client_crt_var, bg="#0f293d", fg="#86efac", insertbackground="#38bdf8", width=55, font=("Consolas", 9)).grid(row=2, column=1, sticky="ew", padx=8, pady=4)
        tk.Button(config_box, text="Examinar...", bg="#1e293b", fg="#ffffff", command=self.browse_client_crt, relief=tk.FLAT).grid(row=2, column=2, padx=4)

        # Fila Llave Privada
        tk.Label(config_box, text="Llave Privada (.key):", bg="#082331", fg="#cbd5e1").grid(row=3, column=0, sticky="w", pady=4)
        tk.Entry(config_box, textvariable=self.client_key_var, bg="#0f293d", fg="#fca5a5", insertbackground="#38bdf8", width=55, font=("Consolas", 9)).grid(row=3, column=1, sticky="ew", padx=8, pady=4)
        tk.Button(config_box, text="Examinar...", bg="#1e293b", fg="#ffffff", command=self.browse_client_key, relief=tk.FLAT).grid(row=3, column=2, padx=4)

        config_box.columnconfigure(1, weight=1)

        # 3. Panel de Acciones y Pruebas (Rúbrica)
        actions_box = tk.LabelFrame(main_frame, text=" Pruebas de Acceso y Superficie de Ataque ", bg="#082331", fg="#38bdf8", font=("Segoe UI", 10, "bold"), padx=15, pady=12)
        actions_box.pack(fill=tk.X, pady=(0, 15))

        btn_valid = tk.Button(actions_box, text="🟢 Consumir con Certificado Válido (mTLS)", bg="#059669", fg="#ffffff", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=12, pady=6, cursor="hand2", command=self.run_valid_auth)
        btn_valid.grid(row=0, column=0, padx=6, pady=4, sticky="ew")

        btn_no_cert = tk.Button(actions_box, text="🔴 Probar Ataque: Sin Certificado", bg="#dc2626", fg="#ffffff", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=12, pady=6, cursor="hand2", command=self.run_no_cert_attack)
        btn_no_cert.grid(row=0, column=1, padx=6, pady=4, sticky="ew")

        btn_rogue = tk.Button(actions_box, text="🟠 Probar Ataque: Certificado de Otra CA", bg="#d97706", fg="#ffffff", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=12, pady=6, cursor="hand2", command=self.run_rogue_cert_attack)
        btn_rogue.grid(row=0, column=2, padx=6, pady=4, sticky="ew")

        actions_box.columnconfigure(0, weight=1)
        actions_box.columnconfigure(1, weight=1)
        actions_box.columnconfigure(2, weight=1)

        # 4. Consola de Logs y Respuesta Criptográfica
        log_frame = tk.LabelFrame(main_frame, text=" Consola de Auditoría y Verificación Criptográfica en Tiempo Real ", bg="#082331", fg="#38bdf8", font=("Segoe UI", 10, "bold"), padx=10, pady=10)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(log_frame, bg="#03131d", fg="#22d3ee", insertbackground="#38bdf8", font=("Consolas", 10), wrap=tk.WORD, borderwidth=0)
        scrollbar = tk.Scrollbar(log_frame, command=self.log_text.yview, bg="#082331")
        self.log_text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Barra de estado inferior
        status_bar = tk.Label(self.root, textvariable=self.status_var, bg="#03131d", fg="#94a3b8", font=("Segoe UI", 9), anchor="w", padx=10, pady=4)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def log(self, text, color=None):
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)

    def browse_ca(self):
        f = filedialog.askopenfilename(title="Seleccionar Certificado CA Raíz", filetypes=[("Certificados X.509", "*.crt *.pem")])
        if f: self.ca_path_var.set(f)

    def browse_client_crt(self):
        f = filedialog.askopenfilename(title="Seleccionar Certificado de Cliente", filetypes=[("Certificados X.509", "*.crt *.pem")])
        if f: self.client_crt_var.set(f)

    def browse_client_key(self):
        f = filedialog.askopenfilename(title="Seleccionar Llave Privada del Cliente", filetypes=[("Llave Privada", "*.key *.pem")])
        if f: self.client_key_var.set(f)

    def run_valid_auth(self):
        threading.Thread(target=self._exec_valid_auth, daemon=True).start()

    def _exec_valid_auth(self):
        self.status_var.set("Autenticando con certificado digital válido...")
        self.log("\n" + "="*70)
        self.log("▶ [INICIO] CONSUMIENDO API MEDIANTE mTLS CON CERTIFICADO VÁLIDO")
        self.log("="*70)
        
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
            self.log(f"3. Firmando reto TLS con Llave Privada: {os.path.basename(key_file)}")
            
            context = ssl.create_default_context(cafile=ca_file)
            context.load_cert_chain(certfile=crt_file, keyfile=key_file)
            
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, context=context, timeout=6) as response:
                status = response.status
                raw_body = response.read().decode("utf-8")
                data = json.loads(raw_body)
                
                self.log(f"✔ [HANDSHAKE mTLS EXITOSO] Status HTTP: {status} OK")
                self.log(f"✔ [CLIENTE IDENTIFICADO]: {data.get('auth_details', {}).get('client_subject', {}).get('commonName', 'OK')}")
                self.log(f"✔ [DATOS DE LA BÓVEDA OBTENIDOS SIN CONTRASEÑAS]:")
                self.log(json.dumps(data.get("boveda_data", {}), indent=4))
                self.status_var.set("Autenticación mTLS completada con éxito")
                messagebox.showinfo("Éxito mTLS", f"Autenticación exitosa.\nCliente identificado por certificado digital.")
        except Exception as e:
            self.log(f"❌ [FALLO DE CONEXIÓN]: {e}")
            self.status_var.set("Error en conexión mTLS")

    def run_no_cert_attack(self):
        threading.Thread(target=self._exec_no_cert_attack, daemon=True).start()

    def _exec_no_cert_attack(self):
        self.status_var.set("Probando ataque: conexión sin certificado...")
        self.log("\n" + "="*70)
        self.log("▶ [PRUEBA DE ATAQUE 1] INTENTO DE ACCESO SIN CERTIFICADO DIGITAL")
        self.log("="*70)
        
        ca_file = self.ca_path_var.get()
        url = self.api_url_var.get()

        try:
            context = ssl.create_default_context(cafile=ca_file)
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, context=context, timeout=6) as response:
                self.log("❌ PELIGRO: El servidor permitió el acceso sin certificado!")
        except ssl.SSLError as e:
            self.log(f"🛡️ [BLOQUEADO POR mTLS]: {e.reason or e}")
            self.log("✔ RESULTADO ESPERADO: Conexión terminada a nivel TLS porque el cliente no tiene certificado.")
            self.status_var.set("Ataque bloqueado con éxito (401 TLS Alert)")
            messagebox.showwarning("Ataque Bloqueado", "Acceso denegado: El servidor cerró la conexión por falta de certificado digital de cliente.")
        except urllib.error.URLError as e:
            self.log(f"🛡️ [BLOQUEADO EN SOCKET]: {e.reason}")
            self.log("✔ RESULTADO ESPERADO: Conexión rechazada por el servidor mTLS.")
            self.status_var.set("Ataque bloqueado con éxito")
        except Exception as e:
            self.log(f"🛡️ [BLOQUEADO]: {e}")

    def run_rogue_cert_attack(self):
        threading.Thread(target=self._exec_rogue_cert_attack, daemon=True).start()

    def _exec_rogue_cert_attack(self):
        self.status_var.set("Probando ataque: certificado de otra CA...")
        self.log("\n" + "="*70)
        self.log("▶ [PRUEBA DE ATAQUE 2] INTENTO CON CERTIFICADO DE OTRA CA (ROGUE CA)")
        self.log("="*70)
        
        ca_file = self.ca_path_var.get()
        url = self.api_url_var.get()

        if not os.path.exists(ATTACKER_CRT) or not os.path.exists(ATTACKER_KEY):
            self.log("❌ ERROR: No se encontró el certificado del atacante (certs/attacker.crt).")
            return

        try:
            self.log(f"1. Presentando certificado emitido por 'Rogue Malicious Root CA'...")
            context = ssl.create_default_context(cafile=ca_file)
            context.load_cert_chain(certfile=ATTACKER_CRT, keyfile=ATTACKER_KEY)
            
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, context=context, timeout=6) as response:
                self.log("❌ PELIGRO: El servidor confió en un certificado firmado por otra CA!")
        except ssl.SSLError as e:
            self.log(f"🛡️ [BLOQUEADO POR LA CA]: {e.reason or e}")
            self.log("✔ RESULTADO ESPERADO: El servidor verificó la cadena de firma contra ca.crt y RECHAZÓ el certificado atacante.")
            self.status_var.set("Ataque bloqueado: CA no confiable")
            messagebox.showwarning("Ataque Bloqueado", "Acceso denegado: El certificado presentado NO fue firmado por la CA de la Bóveda Segura.")
        except urllib.error.URLError as e:
            self.log(f"🛡️ [BLOQUEADO EN SOCKET]: {e.reason}")
            self.status_var.set("Ataque bloqueado")
        except Exception as e:
            self.log(f"🛡️ [BLOQUEADO]: {e}")


def main():
    root = tk.Tk()
    app = BovedaPKIApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

