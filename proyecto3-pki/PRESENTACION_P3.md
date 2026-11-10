# PROYECTO 3 — PKI: API en la Nube con Certificado Digital (mTLS)
> Universidad Nacional de Cañete — UNDC 2026 · Seguridad y Criptografía
> Plataforma: Google Cloud Run (reto-firma) + servidor local/VM con mTLS real
> Guión de Exposición Slide por Slide (Tiempo sugerido: 10–12 minutos)

---

## Slide 1 — Portada
- **Título:** Proyecto 3 — PKI: API en la Nube con Certificado Digital
- **Subtítulo:** Autenticación con Certificado Digital para Aplicativo de Escritorio, sin Contraseñas ni API Keys
- **Plataforma:** Google Cloud Run + OpenSSL Mini-PKI + Aplicativo Python X.509
- **Integrantes y Docente:** UNDC 2026

---

## Slide 2 — El Problema de las Contraseñas y API Keys
- **Problema de contraseñas:** Son vulnerables a phishing, fuerza bruta, reutilización y deben viajar por la red (o su hash).
- **Problema de API Keys:** Si se filtran en el código cliente o en el tráfico, cualquiera puede usarlas (son secretos portables).
- **La Solución Criptográfica:** **mTLS (Mutual TLS)**. El cliente no envía ningún secreto; demuestra que posee la llave privada firmando un reto criptográfico durante el apretón de manos (handshake TLS).

---

## Slide 3 — Componentes del Sistema

| Componente | Tecnología | Para qué sirve |
|---|---|---|
| **Autoridad Certificadora (CA)** | OpenSSL (RSA 4096 + SHA-256) | Crea la llave privada y el certificado raíz de la CA; con ellos firma los certificados que emite |
| **Certificado de Cliente** | CSR + Certificado X.509 (.pfx / .crt) | El aplicativo genera su par de llaves y pide su certificado; la privada nunca sale de su equipo |
| **Lista de Revocación (CRL)** | `openssl ca -gencrl` (X.509 v2) | La CA publica qué certificados quedaron invalidados antes de vencer; el validador la verifica |
| **Autenticación** | mTLS real (VM) + reto-firma (Cloud Run) | El cliente prueba la posesión de la llave privada firmando datos únicos; nada secreto viaja |
| **Aplicativo Cliente** | App de Escritorio Python (GUI Tkinter) | Presenta el certificado digital y firma el reto para consumir el API sin contraseñas |
| **API en la Nube** | Google Cloud Run + validador X.509 | Valida la CA propia, vigencia, CRL y la firma del reto con la llave pública |

---

## Slide 4 — Arquitectura y Cadena de Confianza (PKI)

```
                     [ Bóveda Segura Root CA ]
                      (ca.key + ca.crt - 4096)
                                 |
                 +---------------+---------------+
                 v               v               v
       [ Certificado     [ Certificado     [ CRL firmada ]
         Servidor ]         Cliente ]       (crl.pem)
      (server-vm.crt)   (client.crt/pfx)
                 |               |
                 v               v
    [ VM API mTLS ]      [ App de Escritorio ]
    https://<IP_VM>:8443        (Presenta Certificado Digital)
```

- **Cadena de Confianza:** El servidor solo confía en certificados cuya firma provenga matemáticamente de su CA Raíz (`ca.crt`).

---

## Slide 5 — Flujo 1: Crear la CA y Emitir el Certificado
1. **Crear la CA:**
   - Se genera la llave privada `ca.key` (RSA 4096) y el certificado raíz autofirmado `ca.crt` con extensiones `v3_ca`.
2. **Generar llaves del cliente:**
   - La llave privada `client.key` se genera **en el equipo del cliente y NUNCA sale de él**.
3. **Crear el CSR (Certificate Signing Request):**
   - El cliente empaqueta su nombre (CN), organización y su **llave pública** en un CSR.
4. **Firma por la CA:**
   - La CA recibe el CSR, verifica la identidad y firma con `ca.key` generando `client.crt`.
5. **Empaquetado PKCS#12 (.pfx):**
   - Se une el certificado y la llave en `client.pfx` protegido con contraseña para su instalación o consumo.

---

## Slide 6 — Flujo 2: Consumo del API (nube y local)

**A) Cloud Run — reto + firma (implementación desplegada)**
```
App de escritorio                                  API Next.js en Cloud Run
   │ ─── 1. GET /api/pki/challenge ───────────────────────► │
   │ ◄── 2. nonce + token HMAC (TTL 120 s, un solo uso) ─── │
   │     (firma el nonce localmente con client.key)         │
   │ ─── 3. POST /api/pki/operaciones ────────────────────► │
   │        { clientCertificate, challengeToken, signature } │
   │ ◄── 4. 200 OK + Datos Autorizados (JSON) ───────────── │
```

**B) VM Compute Engine — mTLS real en el handshake (verificado en `34.176.58.90:8443`; VM desmontada el 2026-11-09)**
```
   │ ─── 1. ClientHello (TLS 1.2 / 1.3) ──────────────────► │
   │ ◄── 2. ServerHello + Certificado Servidor ──────────── │
   │ ◄── 3. CertificateRequest (servidor pide cert cliente) │
   │ ─── 4. Certificate (client.crt) ─────────────────────► │
   │ ─── 5. CertificateVerify (firma con client.key) ─────► │
   │ ─── 6. Finished (canal seguro) ──────────────────────► │
   │ ─── 7. GET /api/operaciones (sin contraseñas) ───────► │
```
- **Principio Zero-Secret:** nunca viajan contraseñas ni la llave privada; solo la firma digital del reto.
- **Cloud Run** no permite mTLS con CA propia (termina TLS en el borde), por eso ahí se aplica el mismo principio a nivel de aplicación: reto firmado + validación X.509.
- **La VM** sí valida el certificado durante el handshake (`ssl.CERT_REQUIRED`) y además consulta la CRL con `openssl verify -crl_check` antes de responder.

---

## Slide 7 — Flujo 3: Validación en el API en la Nube
1. **Certificado obligatorio:**
   - Sin certificado → `401 MISSING_CLIENT_CERTIFICATE`.
2. **Verificación de la firma de la CA:**
   - Se comprueba matemáticamente contra `ca.crt`. Si proviene de otra CA → `403 INVALID_ISSUER_CA`.
3. **Validación de vigencia:**
   - Se revisan `notBefore` / `notAfter` → `403 CERTIFICATE_EXPIRED`.
4. **Verificación de revocación (CRL real):**
   - La CA mantiene `index.txt` y firma una **CRL X.509** (`crl.pem`).
   - El API decodifica la CRL, verifica su firma con `ca.crt`, revisa `thisUpdate` / `nextUpdate` y busca la serie.
   - Serie revocado → `403 CERTIFICATE_REVOKED`. Si la CRL está vencida o mal firmada, se **falla cerrado** (`CRL_*`).
5. **Prueba de posesión del reto:**
   - Token HMAC válido, vigente y no usado + firma RSA-SHA256 verificada con la llave pública del certificado.
   - Sin firma → `403 PROOF_OF_POSSESSION_REQUIRED`; reto reutilizado → `403 CHALLENGE_ALREADY_USED`.
6. **Identificación por Sujeto (CN):**
   - El API extrae el `commonName` (ej. `cliente-desktop-01`) y autoriza la operación.

---

## Slide 8 — Demostración en Vivo (Guión de 3 minutos)

1. **Modo Nube (principal):**
   - Ejecutar `python proyecto3-pki\test_cloud_api.py` o la app de escritorio en modo ☁️ Nube.
   - Muestra: reto → firma local → `200 OK`, y los rechazos `401` / `403`.
2. **Modo Local / VM (mTLS real):**
   - En la app, seleccionar 🖥️ Local contra `https://127.0.0.1:8443`, o contra la VM si se vuelve a desplegar.
   - El handshake exige certificado de cliente: sin cert, otra CA o vencido se cortan en TLS.
3. **Prueba 1 — Acceso Autorizado:**
   - Clic en **"🟢 Certificado Válido + Reto Firmado"**.
   - Se observa el nombre del cliente y los datos confidenciales de la cuenta.
4. **Prueba 2 — Ataque Sin Certificado:**
   - Clic en **"🔴 Ataque: Sin Certificado"** → `401`.
5. **Prueba 3 — Ataque con Certificado de Otra CA:**
   - Clic en **"🟠 Ataque: Otra CA"** → `403 INVALID_ISSUER_CA`.
6. **Prueba 4 — Copiar el certificado público (sin llave):**
   - Clic en **"🟡 Ataque: Certificado sin Llave"** → `403 PROOF_OF_POSSESSION_REQUIRED`.
7. **Prueba 5 — Certificado revocado (CRL):**
   - Clic en la tarjeta **"Certificado Revocado"** → `403 CERTIFICATE_REVOKED`.
8. **Prueba 6 — Certificado vencido:**
   - Clic en la tarjeta **"Certificado Vencido"** → `403 CERTIFICATE_EXPIRED`.
9. **Prueba 7 — Acceso con PKCS#12 (.pfx):**
   - Clic en **"🔐 Acceso con PKCS#12 (.pfx)"** → `200 OK` usando un único archivo protegido.

---

## Slide 9 — Cierre: Superficie de Ataque y Seguridad

| Escenario | Comportamiento del Sistema |
|---|---|
| **Certificado + reto firmado** | **Acceso permitido:** el API identifica al cliente y verifica la posesión de la llave privada |
| **Sin Certificado** | **Rechazado:** `401 MISSING_CLIENT_CERTIFICATE` (o corte TLS en modo local) |
| **Certificado de Otra CA** | **Rechazado:** `403 INVALID_ISSUER_CA` (o `UNKNOWN_CA` en mTLS local) |
| **Certificado público copiado (sin llave)** | **Rechazado:** `403 PROOF_OF_POSSESSION_REQUIRED` |
| **Reto reutilizado** | **Rechazado:** `403 CHALLENGE_ALREADY_USED` (anti-replay) |
| **Certificado revocado** | **Rechazado:** `403 CERTIFICATE_REVOKED` — la CRL firmada por la CA lo invalida aunque su firma sea correcta |
| **Certificado vencido** | **Rechazado:** `403 CERTIFICATE_EXPIRED` (o corte TLS en la VM) |
| **Archivo `.pfx` comprometido** | **Único secreto real:** el `.pfx` contiene la llave privada; se protege con contraseña y nunca se versiona |
| **Llave privada del cliente filtrada** | **Único punto realmente vulnerable:** Quien tenga la llave privada se hace pasar por el cliente (mitigable con HSM o TPM de Windows) |

---

## Slide 10 — Conclusiones y Aplicación en el Mundo Real
- **mTLS es el estándar de oro** en la industria financiera (APIs bancarias interbancarias, ISO 20022).
- Utilizado en arquitecturas **Zero Trust** (Google BeyondCorp), redes Kubernetes (Service Mesh / Istio) y VPNs corporativas.
- No depende de contraseñas humanas, eliminando el 99% de los ataques de ingeniería social.

