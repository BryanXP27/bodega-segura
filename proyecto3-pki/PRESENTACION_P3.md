# PROYECTO 3 — PKI: API en la Nube con Certificado Digital Digital (mTLS)
> Universidad Nacional de Cañete — UNDC 2026 · Seguridad y Criptografía
> Plataforma: Google Cloud Run / Servidor HTTPS mTLS
> Guión de Exposición Slide por Slide (Tiempo sugerido: 10–12 minutos)

---

## Slide 1 — Portada
- **Título:** Proyecto 3 — PKI: API en la Nube con Certificado Digital
- **Subtítulo:** Autenticación Mutua TLS (mTLS) para Aplicativo de Escritorio sin Contraseñas ni API Keys
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
| **Autenticación Mutua** | TLS 1.3 / 1.2 con Certificado de Cliente | El cliente prueba la posesión de la llave privada firmando datos únicos; nada secreto viaja |
| **Aplicativo Cliente** | App de Escritorio Python (GUI Tkinter) | Presenta el certificado digital y firma el reto para consumir el API sin contraseñas |
| **API en la Nube** | Google Cloud Run / Servidor HTTPS mTLS | Valida que la CA propia firmó el certificado, verifica vigencia y lista de revocación (CRL) |

---

## Slide 4 — Arquitectura y Cadena de Confianza (PKI)

```
                     [ Bóveda Segura Root CA ]
                      (ca.key + ca.crt - 4096)
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
       [ Certificado Servidor ]        [ Certificado Cliente ]
          (server.crt - API)          (client.crt / client.pfx)
                 │                               │
                 ▼                               ▼
    [ Servidor API Google Cloud ]    [ App de Escritorio ]
          (https://api)           (Presenta Certificado Digital)
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

## Slide 6 — Flujo 2: Consumo del API mediante Handshake mTLS
```
Cliente                                               Servidor API (mTLS)
   │ ─── 1. ClientHello (Soporte TLS 1.3 / Ciphers) ──────► │
   │ ◄── 2. ServerHello + Certificado Servidor + Reto ───── │
   │     (Cliente valida el certificado del servidor)       │
   │ ◄── 3. CertificateRequest (Servidor pide cert cliente) │
   │ ─── 4. Certificate (Cliente envía client.crt) ───────► │
   │ ─── 5. CertificateVerify (Firma del reto con client.key) │
   │ ─── 6. Finished (Canal seguro establecido) ──────────► │
   │                                                        │
   │ ─── 7. GET /api/operaciones (Sin contraseñas) ───────► │
   │ ◄── 8. 200 OK + Datos Autorizados (JSON) ───────────── │
```
- **Principio Zero-Secret:** En ningún momento viajan contraseñas ni la llave privada; solo viaja la firma digital del reto.

---

## Slide 7 — Flujo 3: Validación en el API en la Nube
1. **Terminación TLS con `CERT_REQUIRED`:**
   - Si el cliente no presenta certificado, el handshake se cancela de inmediato (`TLSV13_ALERT_CERTIFICATE_REQUIRED`).
2. **Verificación de la firma de la CA:**
   - El servidor comprueba la validez matemática contra `ca.crt`. Si proviene de otra CA (Rogue CA), responde `TLSV1_ALERT_UNKNOWN_CA`.
3. **Validación de vigencia:**
   - Se revisan las fechas `notBefore` y `notAfter`.
4. **Verificación contra lista de revocación (CRL):**
   - Si el número de serie está revocado, se deniega con código `403 CERTIFICATE_REVOKED`.
5. **Identificación por Sujeto (CN):**
   - El API extrae el `commonName` (ej. `cliente-desktop-01`) y autoriza la operación.

---

## Slide 8 — Demostración en Vivo (Guión de 3 minutos)

1. **Abrir Servidor API:**
   - Ejecutar `proyecto3-pki/api/iniciar_servidor.bat` (Escuchando en puerto 8443 con mTLS forzado).
2. **Abrir Aplicativo de Escritorio:**
   - Ejecutar `proyecto3-pki/app_escritorio/run_app.bat` (interfaz gráfica moderna).
3. **Prueba 1 — Acceso Autorizado:**
   - Clic en **"🟢 Consumir con Certificado Válido"**.
   - Se observa el handshake exitoso, el nombre del cliente y los datos confidenciales de la cuenta.
4. **Prueba 2 — Ataque Sin Certificado:**
   - Clic en **"🔴 Probar Ataque: Sin Certificado"**.
   - El servidor corta la conexión con alerta TLS.
5. **Prueba 3 — Ataque con Certificado de Otra CA:**
   - Clic en **"🟠 Probar Ataque: Certificado de Otra CA"**.
   - Bloqueado con alerta `UNKNOWN_CA`.

---

## Slide 9 — Cierre: Superficie de Ataque y Seguridad

| Escenario | Comportamiento del Sistema |
|---|---|
| **Certificado Válido** | **Acceso permitido:** El API identifica al cliente matemáticamente por su certificado X.509 |
| **Sin Certificado** | **Rechazado:** La conexión TLS se cierra antes de enviar cualquier mensaje HTTP |
| **Certificado de Otra CA** | **Rechazado:** La CA propia de la Bóveda no lo firmó (`UNKNOWN_CA`) |
| **Certificado Revocado / Vencido** | **Rechazado:** Se quita el acceso en el servidor sin tener que cambiar contraseñas |
| **Llave privada del cliente filtrada** | **Único punto realmente vulnerable:** Quien tenga la llave privada se hace pasar por el cliente (mitigable con HSM o TPM de Windows) |

---

## Slide 10 — Conclusiones y Aplicación en el Mundo Real
- **mTLS es el estándar de oro** en la industria financiera (APIs bancarias interbancarias, ISO 20022).
- Utilizado en arquitecturas **Zero Trust** (Google BeyondCorp), redes Kubernetes (Service Mesh / Istio) y VPNs corporativas.
- No depende de contraseñas humanas, eliminando el 99% de los ataques de ingeniería social.

