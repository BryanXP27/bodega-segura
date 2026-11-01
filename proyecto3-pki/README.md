# Proyecto 3: PKI — API en la Nube con Certificado Digital (mTLS)
> **Universidad Nacional de Cañete — UNDC 2026**  
> Seguridad y Criptografía · Cifrado y Autenticación sin Contraseñas  
> Adaptado para **Google Cloud** y ejecución local lista con un clic.

---

## 📌 ¿Qué resuelve este proyecto?

Este proyecto implementa una **Mini-PKI (Infraestructura de Clave Pública)** y un **API Seguro con Autenticación Mutua (mTLS)**.
El aplicativo de escritorio se identifica ante el servidor **exclusivamente mediante su Certificado Digital X.509**, sin enviar jamás contraseñas ni API Keys por la red.

---

## 📂 Estructura de Archivos

```
proyecto3-pki/
├── pki/                             # Generación y gestión de certificados
│   ├── openssl.cnf                  # Configuración de extensiones X.509 (CA, Server, Client)
│   ├── generar_pki.py               # Script automático que crea la CA, Server, Client y PFX
│   ├── 01_crear_ca.bat              # Script individual para crear la Root CA
│   ├── 02_generar_cliente.bat       # Script individual para emitir certificado de cliente (.pfx)
│   ├── 03_generar_invalido.bat      # Genera certificado atacante (de otra CA)
│   └── certs/                       # Almacén de llaves y certificados generados
│       ├── ca.key / ca.crt          # Root CA propia (RSA 4096)
│       ├── server.key / server.crt  # Certificado del servidor API
│       ├── client.key / client.crt  # Certificado del cliente autorizado
│       ├── client.pfx               # PKCS#12 con password 'password123'
│       └── attacker.crt / attacker.key # Certificado no autorizado (Rogue CA)
│
├── api/                             # Backend API mTLS (Google Cloud Run / Local)
│   ├── server.py                    # Servidor HTTPS nativo con mTLS estricto (ssl.CERT_REQUIRED)
│   ├── iniciar_servidor.bat         # Doble clic para iniciar el API en puerto 8443
│   └── Dockerfile                   # Imagen para despliegue en Google Cloud Run
│
├── app_escritorio/                  # Aplicativo de Escritorio
│   ├── app.py                       # Interfaz gráfica moderna (Tkinter) con consola criptográfica
│   ├── test_cli.py                  # Suite de pruebas automatizada (3 pruebas de seguridad)
│   └── run_app.bat                  # Doble clic para iniciar el aplicativo
│
└── PRESENTACION_P3.md               # Diapositivas y guion de sustentación slide por slide
```

---

## 🚀 Guía Rápida de Ejecución (En Windows con 2 clics)

### Paso 1: Iniciar el Servidor API mTLS
Abre la carpeta `proyecto3-pki\api` y haz doble clic en:
👉 **`iniciar_servidor.bat`**
> Verás en pantalla:
> `[OK] Servidor escuchando en https://localhost:8443`
> `Modo: TLS MUTUO REQUERIDO (CERT_REQUIRED)`

---

### Paso 2: Abrir el Aplicativo de Escritorio
Abre la carpeta `proyecto3-pki\app_escritorio` y haz doble clic en:
👉 **`run_app.bat`**
> Se abrirá la interfaz gráfica con el panel de control mTLS y la consola en tiempo real.

---

### Paso 3: Ejecutar las Pruebas de la Rúbrica

Dentro de la aplicación de escritorio tendrás 3 botones para la demostración ante el profesor:

1. **🟢 Consumir con Certificado Válido (mTLS):**
   - El cliente presenta `client.crt` y firma el reto TLS con `client.key`.
   - El API verifica la firma con `ca.crt`, extrae el Common Name `cliente-desktop-01` y entrega los datos de la bóveda bancaria sin solicitar contraseñas.

2. **🔴 Probar Ataque: Sin Certificado:**
   - El cliente intenta conectarse sin certificado.
   - El servidor corta la conexión en el handshake con la alerta `TLSV13_ALERT_CERTIFICATE_REQUIRED`.

3. **🟠 Probar Ataque: Certificado de Otra CA:**
   - El cliente presenta un certificado firmado por una CA falsa/atacante.
   - El servidor comprueba la cadena de confianza y lo rechaza con `TLSV1_ALERT_UNKNOWN_CA`.

---

## 💻 Pruebas por Consola (Automáticas)

Si prefieres ejecutar la batería de pruebas automatizada por consola:
```powershell
python proyecto3-pki\app_escritorio\test_cli.py
```

Resultado verificado:
```
1. Certificado Valido emitido por CA propia : APROBADO [OK]
2. Conexion Sin Certificado Digital         : BLOQUEADO [OK]
3. Certificado de Otra CA (Rogue/Hacker)    : BLOQUEADO [OK]
```

---

## ☁️ Despliegue en Google Cloud Run

Para desplegar el contenedor en Google Cloud Run con tu cuenta:
```bash
cd proyecto3-pki
gcloud builds submit --tag gcr.io/TU_PROYECTO_GCP/boveda-mtls-api ./api
gcloud run deploy boveda-mtls-api --image gcr.io/TU_PROYECTO_GCP/boveda-mtls-api --platform managed --port 8443
```
*(Para pruebas locales o demostración en clase, el servidor local con `iniciar_servidor.bat` funciona exactamente igual con TLS 1.3).*

---

## 🛡️ Contraseña del archivo PKCS#12 (.pfx)
- Archivo: `pki/certs/client.pfx`
- Contraseña: `password123`
- Se puede instalar en el **Almacén de Certificados de Windows** (Certmgr.msc > Personal > Certificados) haciendo doble clic en el archivo `.pfx`.

