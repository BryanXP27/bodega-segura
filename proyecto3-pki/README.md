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

1. **Certificado válido**: firmado por la Root CA propia, dentro de su vigencia y **no revocado
   según la CRL X.509 firmada por la CA**.
2. **Prueba de posesión**: el cliente firma un **reto (nonce) de un solo uso** con su
   **llave privada** (RSA-SHA256). El certificado es público; la llave privada nunca viaja.

> ⚠️ Presentar solo el certificado (copiar el `.crt` público) **NO concede acceso**.
> Esa era la vulnerabilidad corregida en la rotación de seguridad.

---

## 🔐 Estado de seguridad (P1 — 2026-11-05)

- La CA y todos los certificados fueron **regenerados**.
- Existe una **CRL real** generada con `openssl ca -gencrl`, firmada por la Root CA.
- Se incluyen certificados de demostración **revocado** (`1002`) y **vencido** (2021).
- El cliente acepta **PKCS#12 (`.pfx`)** además de PEM (`.crt` + `.key`).
- Toda llave privada vive en `pki/certs/private/` (**ignorada por Git**).
- En el repositorio solo se versionan certificados, CSR, la CRL y archivos públicos.

```
pki/certs/
├── ca.crt                 # Root CA pública (RSA 4096)
├── crl.pem                # CRL firmada por la Root CA (pública)
├── client.crt             # Certificado público del cliente
├── client.csr             # Solicitud de firma (pública)
├── client-revocado.crt    # Certificado revocado (serie 0x1002, en la CRL)
├── client-vencido.crt     # Certificado vencido (notAfter 2021-01-01)
├── server.crt             # Certificado público del servidor (localhost)
├── server-vm.crt          # Certificado del servidor VM (SAN IP:34.176.58.90)
├── attacker.crt           # Certificado de CA no confiable (demo)
├── issued/                # Copias emitidas por la BD de la CA (git-ignored)
└── private/               # 🔒 GIT-IGNORED — nunca se publica
    ├── ca.key             # Llave privada de la CA
    ├── client.key         # Llave privada del cliente
    ├── client.pfx         # PKCS#12 (llave + certificado, password123 en demo)
    ├── client-revocado.key
    ├── client-vencido.key
    ├── server.key         # Llave privada del servidor local
    ├── server-vm.key      # Llave privada del servidor VM
    └── attacker.key
```

> La CRL es material **público** y sí se versiona (`crl.pem`). Sin ella el cliente no puede
> comprobar revocaciones.

---

## 📂 Estructura

```
proyecto3-pki/
├── pki/
│   ├── openssl.cnf              # CA, base de datos index.txt, CRL, extensiones
│   ├── generar_pki.py           # Genera/rota la PKI completa + assets TS
│   ├── 04_revocar.py            # Revoca un certificado y regenera la CRL
│   ├── 04_revocar.bat
│   ├── emitir_cert_servidor.py  # Certificado de servidor para la VM (SAN IP)
│   ├── 01_crear_ca.bat
│   ├── 02_generar_cliente.bat
│   ├── 03_generar_invalido.bat
│   └── certs/                   # Públicos + private/ (ignorado)
├── api/
│   ├── server.py                # HTTPS con mTLS real (ssl.CERT_REQUIRED) + CRL
│   ├── boveda-pki.service       # Unidad systemd para la VM
│   ├── iniciar_servidor.bat
│   └── Dockerfile
├── app_escritorio/
│   ├── app.py                   # Cliente Tkinter: nube, local y PKCS#12
│   └── run_app.bat
├── pki_client.py                # Firma del nonce + extracción de .pfx
├── test_cloud_api.py            # Batería de 8 pruebas contra Cloud Run
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
- Certificado revocado `certs/client-revocado.crt` + **CRL firmada** `certs/crl.pem`
- Certificado vencido `certs/client-vencido.crt`
- Assets TypeScript `src/lib/pki/certs.ts` y `src/lib/pki/crl.ts`

La CA mantiene una base de datos real (`index.txt`, `serial`, `crlnumber`) para poder
revocar y regenerar la CRL con `openssl ca`.

### 2. Revocar un certificado (CRL real)

```powershell
cd proyecto3-pki\pki
python 04_revocar.py --cert certs\client.crt --reason cessationOfOperation
```

El script:
1. Marca el certificado como `R` en `index.txt` (`openssl ca -revoke`).
2. Regenera la CRL (`openssl ca -gencrl`) en `certs/crl.pem`.
3. Actualiza `src/lib/pki/crl.ts` para que la app Next.js use la CRL nueva.

Luego se hace commit de `certs/crl.pem` + `src/lib/pki/crl.ts` y se redespliega.
Un certificado revocado se rechaza de inmediato sin cambiar contraseñas.

### 3. Autenticarse contra el API en la nube

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

### 4. Aplicativo de escritorio

```powershell
python proyecto3-pki\app_escritorio\app.py
```

- **Modo NUBE:** reto + firma RSA-SHA256 → `200 OK`.
- **Modo LOCAL:** mTLS real contra `api/server.py` en `https://127.0.0.1:8443`.
- **PKCS#12:** botón que usa directamente `client.pfx` + contraseña.
- **CRL:** botón que presenta `client-revocado.crt` → `403 CERTIFICATE_REVOKED`.
- Botones de ataque: sin certificado (401), otra CA (403), certificado sin llave (403).

### 5. Demostración para el jurado

```powershell
python proyecto3-pki\demostrar_pki_cloud.py
```

---

## 🧪 Pruebas de la rúbrica (8/8 en producción)

| # | Caso | Resultado esperado |
|---|------|--------------------|
| 1 | Certificado válido + firma del reto | **200 OK** |
| 2 | Sin certificado | **401** `MISSING_CLIENT_CERTIFICATE` |
| 3 | Certificado de otra CA | **403** `INVALID_ISSUER_CA` |
| 4 | Certificado válido **sin** firma | **403** `PROOF_OF_POSSESSION_REQUIRED` |
| 5 | Reutilizar el mismo reto | **403** `CHALLENGE_ALREADY_USED` |
| 6 | Certificado **revocado** | **403** `CERTIFICATE_REVOKED` (CRL real) |
| 7 | Certificado **vencido** | **403** `CERTIFICATE_EXPIRED` |
| 8 | Acceso con **PKCS#12 (`.pfx`)** | **200 OK** |

Estado verificado el **2026-11-05** contra
`https://boveda-segura-git-931747537260.southamerica-west1.run.app`: **8/8 APROBADO**.

---

## ☁️ Arquitectura de despliegue

### Cloud Run (implementación activa)

Cloud Run **no puede** hacer mTLS a nivel de handshake con una CA propia: termina TLS
en el borde. Por eso la app Next.js implementa la validación equivalente en aplicación:

- `/api/pki/challenge` → emite reto HMAC de un solo uso (TTL 120 s).
- `/api/pki/operaciones` → valida cadena X.509 + vigencia + **CRL firmada** + firma RSA-SHA256.
- `/api/pki/health` → reporta el estado de la CRL (firma, `thisUpdate`, `nextUpdate`, revocados).
- `/api/pki/demo-certs` → entrega los certificados públicos de demostración.
- La llave privada del cliente **nunca** llega al servidor.

La CRL se decodifica con un parser ASN.1 propio (`src/lib/pki/crl-parser.ts`) y su firma
se verifica con `crypto.verify` usando la llave pública de la Root CA. Si la CRL está
vencida, mal formada o mal firmada, la validación **falla cerrado** (`CRL_*`).

### VM Compute Engine — mTLS real (verificado y desmontado)

mTLS de verdad con `ssl.CERT_REQUIRED`, desplegado y probado en una VM con IP estática.
**La VM, la IP y el firewall se eliminaron el 2026-11-09** para detener el cobro; los
resultados de abajo son la evidencia de la verificación previa.

| Dato | Valor (durante la demostración) |
|---|---|
| URL | `https://34.176.58.90:8443/api/operaciones` |
| Instancia | `boveda-pki-vm` (`e2-micro`, Debian 12, `southamerica-west1-a`) |
| IP estática | `34.176.58.90` (reserva `boveda-pki-vm-ip`) |
| Firewall | `allow-pki-mtls` → tcp:8443 |
| Servicio | `boveda-pki.service` (systemd, `/opt/boveda-pki`) |
| Certificado servidor | `server-vm.crt` con `SAN IP:34.176.58.90` |

Resultados reales del handshake TLS:

| Caso | Resultado |
|---|---|
| Certificado válido | **200 OK** (`CN=cliente-desktop-01`) |
| Acceso con `.pfx` | **200 OK** (`CN=cliente-desktop-01`) |
| Sin certificado | **cortado en TLS** (`certificate required`) |
| Certificado de otra CA | **cortado en TLS** (`unknown ca`) |
| Certificado revocado | **403** `CERTIFICATE_REVOKED` (CRL con `openssl verify -crl_check`) |
| Certificado vencido | **cortado en TLS** (`certificate expired`) |

> ℹ️ La CA, la CRL y los certificados de cliente siguen intactos en el repositorio. Solo
> se apagó la infraestructura de cómputo; Cloud Run continúa operativo.

#### Cómo volver a desplegar la VM (si se necesita otra demo)

```powershell
# 0. Reservar una IP estática nueva y una regla de firewall
gcloud compute addresses create boveda-pki-vm-ip --region southamerica-west1 --project boveda-segura-512214
gcloud compute firewall-rules create allow-pki-mtls --project boveda-segura-512214 --allow tcp:8443 --target-tags boveda-pki --source-ranges 0.0.0.0/0

# 1. Crear la VM con esa IP
gcloud compute instances create boveda-pki-vm --project boveda-segura-512214 --zone southamerica-west1-a --machine-type e2-micro --image-family debian-12 --image-project debian-cloud --boot-disk-size 10GB --address <IP_NUEVA> --tags boveda-pki

# 2. Emitir el certificado del servidor con la IP pública en el SAN
$env:PKI_SERVER_IP = "<IP_NUEVA>"
python proyecto3-pki\pki\emitir_cert_servidor.py

# 3. Copiar a la VM
#    api/server.py                -> /opt/boveda-pki/api/server.py
#    api/boveda-pki.service       -> /opt/boveda-pki/api/boveda-pki.service
#    pki/certs/ca.crt             -> /opt/boveda-pki/pki/certs/ca.crt
#    pki/certs/server-vm.crt      -> /opt/boveda-pki/pki/certs/server.crt
#    pki/certs/crl.pem            -> /opt/boveda-pki/pki/certs/crl.pem
#    pki/certs/private/server-vm.key -> /opt/boveda-pki/pki/certs/private/server.key

# 4. Instalar el servicio
sudo chmod 600 /opt/boveda-pki/pki/certs/private/server.key
sudo cp /opt/boveda-pki/api/boveda-pki.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now boveda-pki.service
```

> 💸 **Limpieza después de cada demo** (evita cobros):
> ```powershell
> gcloud compute instances delete boveda-pki-vm --zone southamerica-west1-a --project boveda-segura-512214 --quiet
> gcloud compute addresses delete boveda-pki-vm-ip --region southamerica-west1 --project boveda-segura-512214 --quiet
> gcloud compute firewall-rules delete allow-pki-mtls --project boveda-segura-512214 --quiet
> ```

---

## 🔒 Variables de entorno relevantes

| Variable | Uso |
|---|---|
| `PKI_CHALLENGE_SECRET` | Secreto HMAC para firmar los retos. **Configurar en producción.** |
| `PKI_REVOKED_SERIALS` | Series revocados adicionales por coma (respaldo; la fuente principal es la CRL). |
| `PKI_PFX_PASSWORD` | Contraseña del `.pfx` (por defecto `password123`, solo demo). |
| `SERVER_KEY` | Ruta de la llave privada del servidor en Docker/VM. |
| `PKI_SERVER_IP` | IP pública que se agrega al SAN al emitir el certificado de la VM. |
| `API_URL` | URL completa del endpoint para `test_cloud_api.py`. |
| `API_ORIGIN` | Origen del API para `demostrar_pki_cloud.py`. |

---

## 🛡️ Superficie de ataque

- **Llave privada del cliente filtrada** → único punto realmente vulnerable: quien la
  tenga puede firmar retos y suplantar al cliente. Por eso vive fuera de Git.
- **Llave privada de la CA filtrada** → permitiría emitir certificados válidos. También
  fuera de Git; la CA fue rotada tras la exposición.
- **Certificado público filtrado** → sin riesgo por sí solo: no permite firmar retos.
- **Certificado revocado** → la CRL firmada por la CA lo invalida aunque su firma sea válida.
- **Certificado vencido** → se rechaza por `notBefore` / `notAfter` aunque la firma sea válida.
- **CRL vencida o manipulada** → la validación falla cerrado; no se acepta el certificado.
