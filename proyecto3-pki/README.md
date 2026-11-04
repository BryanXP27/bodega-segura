# Proyecto 3: PKI — API en la Nube con Certificado Digital

> **Universidad Nacional de Cañete — UNDC 2026**  
> Seguridad y Criptografía · Autenticación sin contraseñas ni API Keys
> Desplegado en **Google Cloud** (sustituto autorizado de Azure).

---

## 📌 ¿Qué resuelve este proyecto?

Implementa una **Mini-PKI** (Autoridad Certificadora propia con OpenSSL RSA 4096 + SHA-256)
y un **API protegido** al que un aplicativo de escritorio se autentica **exclusivamente con
su certificado digital X.509**, sin enviar contraseñas ni API Keys.

La autenticación exige **dos cosas**:

1. **Certificado válido**: firmado por la Root CA propia, dentro de su vigencia y no revocado.
2. **Prueba de posesión**: el cliente firma un **reto (nonce) de un solo uso** con su
   **llave privada** (RSA-SHA256). El certificado es público; la llave privada nunca viaja.

> ⚠️ Presentar solo el certificado (copiar el `.crt` público) **NO concede acceso**.
> Esa era la vulnerabilidad corregida en la rotación de seguridad.

---

## 🔐 Estado de seguridad (rotación 2026-11-04)

- La CA y todos los certificados fueron **regenerados**.
- Las llaves privadas comprometidas quedaron inservibles.
- Toda llave privada vive en `pki/certs/private/` (**ignorada por Git**).
- En el repositorio solo se versionan certificados y CSR **públicos**.

```
pki/certs/
├── ca.crt                 # Root CA pública (RSA 4096)
├── client.crt             # Certificado público del cliente
├── client.csr             # Solicitud de firma (pública)
├── server.crt             # Certificado público del servidor
├── attacker.crt           # Certificado de CA no confiable (demo)
└── private/               # 🔒 GIT-IGNORED — nunca se publica
    ├── ca.key             # Llave privada de la CA
    ├── client.key         # Llave privada del cliente
    ├── client.pfx         # PKCS#12 (llave + certificado)
    ├── server.key         # Llave privada del servidor
    └── attacker.key
```

---

## 📂 Estructura

```
proyecto3-pki/
├── pki/
│   ├── openssl.cnf              # Extensiones X.509 (CA, servidor, cliente)
│   ├── generar_pki.py           # Genera/rota la PKI completa
│   ├── 01_crear_ca.bat
│   ├── 02_generar_cliente.bat
│   ├── 03_generar_invalido.bat
│   └── certs/                   # Públicos + private/ (ignorado)
├── api/
│   ├── server.py                # Servidor HTTPS con mTLS real (ssl.CERT_REQUIRED)
│   ├── iniciar_servidor.bat
│   └── Dockerfile
├── app_escritorio/
│   ├── app.py                   # Cliente Tkinter: modo nube (reto-firma) y local (mTLS)
│   └── run_app.bat
├── pki_client.py                # Firma del nonce (cryptography u OpenSSL CLI)
├── test_cloud_api.py            # Batería de 5 pruebas contra Cloud Run
├── demostrar_pki_cloud.py       # Demostración interactiva paso a paso
├── demostrar_pki_cloud.bat
└── README.md
```

---

## 🚀 Flujo completo (crear CA → emitir certificado → consumir API)

### 1. Generar / rotar la PKI

```powershell
python proyecto3-pki\pki\generar_pki.py
```

Salida:
- `certs/ca.crt` (pública) y `certs/private/ca.key` (privada)
- CSR del cliente → firma de la CA → `certs/client.crt`
- `certs/private/client.pfx` (PKCS#12)
- Certificado de ataque `certs/attacker.crt`

### 2. Autenticarse contra el API en la nube

```powershell
python proyecto3-pki\test_cloud_api.py
```

Flujo interno:

```
GET  /api/pki/challenge
     ← { token, nonce, expiresAt, singleUse: true }

firma local: openssl dgst -sha256 -sign certs/private/client.key -out firma.bin nonce.txt

POST /api/pki/operaciones
     { clientCertificate, challengeToken, signature }
     → 200 OK si certificado + firma son válidos
```

### 3. Aplicativo de escritorio

```powershell
python proyecto3-pki\app_escritorio\app.py
```

- **Modo NUBE:** reto + firma RSA-SHA256 → `200 OK`.
- **Modo LOCAL:** mTLS real contra `api/server.py` en `https://127.0.0.1:8443`.
- Botones de ataque: sin certificado (401), otra CA (403), certificado sin llave (403).

### 4. Demostración para el jurado

```powershell
python proyecto3-pki\demostrar_pki_cloud.py
```

---

## 🧪 Pruebas de la rúbrica

| # | Caso | Resultado esperado |
|---|------|--------------------|
| 1 | Certificado válido + firma del reto | **200 OK** |
| 2 | Sin certificado | **401** `MISSING_CLIENT_CERTIFICATE` |
| 3 | Certificado de otra CA | **403** `INVALID_ISSUER_CA` |
| 4 | Certificado válido **sin** firma | **403** `PROOF_OF_POSSESSION_REQUIRED` |
| 5 | Reutilizar el mismo reto | **403** `CHALLENGE_ALREADY_USED` |
| 6 | Certificado vencido | **403** `CERTIFICATE_EXPIRED` (requiere certificado de prueba) |
| 7 | Certificado revocado | **403** `CERTIFICATE_REVOKED` (vía `PKI_REVOKED_SERIALS`) |

---

## ☁️ Arquitectura de despliegue

### Cloud Run (implementación activa)

Cloud Run **no puede** hacer mTLS a nivel de handshake con una CA propia: termina TLS
en el borde. Por eso la app Next.js implementa la validación equivalente en aplicación:

- `/api/pki/challenge` → emite reto HMAC de un solo uso (TTL 120 s).
- `/api/pki/operaciones` → valida cadena X.509 + vigencia + revocación + firma RSA-SHA256.
- La llave privada del cliente **nunca** llega al servidor.

### VM Compute Engine (mTLS real, fase P1)

Para fidelidad total al enunciado se despliega `api/server.py` (o nginx) en una VM con
IP estática y `ssl.CERT_REQUIRED`. El certificado de servidor debe incluir la IP en el SAN.

---

## 🔒 Variables de entorno relevantes

| Variable | Uso |
|---|---|
| `PKI_CHALLENGE_SECRET` | Secreto HMAC para firmar los retos. **Configurar en producción.** |
| `PKI_REVOKED_SERIALS` | Series revocados separados por coma, p. ej. `A1B2C3,D4E5F6`. |
| `PKI_PFX_PASSWORD` | Contraseña del `.pfx` (por defecto `password123`, solo demo). |
| `SERVER_KEY` | Ruta de la llave privada del servidor en Docker/VM. |
| `API_URL` | URL completa del endpoint para `test_cloud_api.py`. |
| `API_ORIGIN` | Origen del API para `demostrar_pki_cloud.py`. |

---

## 🛡️ Superficie de ataque

- **Llave privada del cliente filtrada** → único punto realmente vulnerable: quien la
  tenga puede firmar retos y suplantar al cliente. Por eso vive fuera de Git.
- **Llave privada de la CA filtrada** → permitiría emitir certificados válidos. También
  fuera de Git; la CA fue rotada tras la exposición.
- **Certificado público filtrado** → sin riesgo por sí solo: no permite firmar retos.
