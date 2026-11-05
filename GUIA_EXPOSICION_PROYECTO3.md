# GUÍA DE EXPOSICIÓN — PROYECTO 3: PKI Y API EN LA NUBE CON CERTIFICADO DIGITAL
> **Universidad Nacional de Cañete — UNDC 2026**  
> **Curso:** Seguridad y Criptografía  
> **Proyecto:** Mini-PKI y Autenticación con Certificados Digitales X.509 (mTLS / Zero-Secret)  
> **Plataforma:** Google Cloud Run (southamerica-west1) · OpenSSL · Node.js Cryptography

---

## 📌 1. Ficha Técnica del Proyecto

| Parámetro | Detalle de Implementación |
| :--- | :--- |
| **Objetivo Principal** | Proteger un API crítico en la nube eliminando contraseñas y API Keys, usando autenticación asimétrica basada en certificados digitales. |
| **Entidad Certificadora (CA)** | **Bóveda Segura Root CA** (RSA 4096 bits, SHA-256, extensiones `v3_ca`). |
| **Formato de Credenciales** | Certificados digitales **X.509 v3** (RFC 5280) y contenedor **PKCS#12 (`.pfx`)**. |
| **API en la Nube** | **Google Cloud Run:** `https://boveda-segura-git-931747537260.southamerica-west1.run.app/api/pki/operaciones`. |
| **API con mTLS real** | **VM Compute Engine:** `https://34.176.58.90:8443/api/operaciones` (`e2-micro`, IP estática, `ssl.CERT_REQUIRED`). |
| **Motor de Validación Criptográfica** | Módulo nativo `crypto.X509Certificate` de Node.js en Cloud Run + `crypto.verify` para el reto firmado. En la VM, `ssl` de Python + `openssl verify -crl_check`. |
| **Revocación** | **CRL X.509 v2 real** generada con `openssl ca -gencrl`, firmada por la Root CA (`certs/crl.pem`). |
| **Prueba de Posesión** | Reto (nonce) de un solo uso con TTL de 120 s, firmado localmente con RSA-SHA256 (PKCS#1 v1.5). |
| **Superficie de Demostración** | Portal Web en vivo (`/pki`) con auditoría en DevTools (F12), app de escritorio Python y script CLI interactivo. |

---

## 🎯 2. ¿Orientado a qué se hizo? (El Caso de Negocio)

### El Problema de la Seguridad Tradicional:
1. **Contraseñas humanas:** Son vulnerables a ataques de phishing, fuerza bruta, reutilización y filtraciones en tránsito.
2. **API Keys / Tokens estáticos:** Son secretos compartidos portables. Si un atacante extrae una API Key del código o intercepta la red, obtiene acceso irrestricto.

### El Caso de Uso en la "Bóveda Segura":
* En el **Proyecto 2**, los usuarios finales suben y bajan archivos personales identificándose con su usuario y contraseña mediante PBKDF2 y AES.
* En el **Proyecto 3**, nos enfocamos en el **nivel institucional / interbancario**:  
  El endpoint `/api/pki/operaciones` representa el **servicio de operaciones financieras y transferencias de alta seguridad de la Bóveda Central** (`CTA-UNDC-2026-9948`, saldo disponible `$1,500,000.00 USD`).
* **Regla de Negocio Zero Trust:** Este API **no acepta usuarios, contraseñas ni tokens estáticos**. La única forma de invocarlo es demostrando matemáticamente la posesión de un **Certificado Digital emitido por la Root CA propia de la entidad**.

---

## 🏗️ 3. Arquitectura y Componentes del Sistema

```
                    ┌─────────────────────────────────┐
                    │     Bóveda Segura Root CA       │
                    │   (ca.key + ca.crt - RSA 4096)  │
                    └────────────────┬────────────────┘
                                     │
                     Firma matemática del CSR
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           ▼                                                   ▼
┌─────────────────────────────────┐         ┌─────────────────────────────────┐
│     Cliente / Aplicativo        │         │   Servidor en Google Cloud Run  │
│  - client.key (Privada local)   │         │  - ca.crt incorporada           │
│  - client.crt (Cert X.509)      │         │  - Validador X.509 nativo       │
│  - client.pfx (PKCS#12)         │         │  - /api/pki/challenge           │
│  - certs/private/ (git-ignored) │         │  - /api/pki/operaciones         │
└────────────────┬────────────────┘         └─────────────────▲───────────────┘
                 │                                            │
                 │  1) GET /api/pki/challenge  ──────────────►│
                 │  ◄──────── nonce + token HMAC (120 s)      │
                 │  2) firma nonce con client.key (local)     │
                 │  3) POST certificado + token + firma ─────►│
                 │  ◄──────── 200 OK / 401 / 403              │
                         (CERO contraseñas en el mensaje)
```

### Detalle de Componentes:

1. **Autoridad Certificadora (Root CA):**
   * Generada con OpenSSL: `ca.key` (clave privada maestra) y `ca.crt` (certificado raíz autofirmado por 10 años).
   * Custodia la clave que avala la identidad de todos los clientes autorizados.

2. **Certificado de Cliente (X.509):**
   * **Principio de Mínima Exposición:** La clave privada del cliente (`client.key`) se genera en el equipo local del operador y **nunca sale de él ni se envía a la nube**.
   * A la CA solo viaja la solicitud de firma (**CSR**) con el nombre del cliente (`CN=cliente-desktop-01`, `OU=Operaciones Bancarias`) y su clave pública.
   * La CA firma el CSR y devuelve `client.crt`. Se empaqueta en `client.pfx` protegido con contraseña para importación en el almacén de Windows.
   * En el repositorio solo se publican `ca.crt`, `client.crt`, `server.crt`, `attacker.crt`, `client-revocado.crt`, `client-vencido.crt`, `crl.pem` y los CSR. Las llaves viven en `pki/certs/private/` (**ignorada por Git**).

3. **Lista de Revocación de Certificados (CRL):**
   * La CA mantiene una base de datos real (`index.txt`, `serial`, `crlnumber`).
   * `pki/04_revocar.py` ejecuta `openssl ca -revoke` y `openssl ca -gencrl`, publicando `certs/crl.pem`.
   * El script también actualiza `src/lib/pki/crl.ts` para que Cloud Run use la CRL nueva en el siguiente despliegue.
   * La CRL se versiona porque es material **público**; sin ella el validador no puede detectar revocaciones.

4. **Validador Criptográfico en Google Cloud Run (`src/lib/pki/x509-validator.ts` + `challenge.ts` + `crl-parser.ts`):**
   * Al recibir la petición, el servidor decodifica el certificado X.509 y ejecuta:
     ```typescript
     const isSignedByCA = clientCert.verify(caCert.publicKey);
     ```
   * Valida la vigencia temporal (`validFrom` / `validTo`).
   * Verifica la **CRL**: decodifica el DER con un lector ASN.1, valida la firma de la CA, revisa `thisUpdate` / `nextUpdate` y busca el número de serie.
   * **Verifica la prueba de posesión:** valida el token HMAC del reto, su vigencia, que no haya sido usado y la firma RSA-SHA256 del nonce con la llave pública del certificado.
   * Extrae la identidad institucional del cliente (`commonName`).

---

## 🔄 4. Flujo de Ejecución Explicado (Paso a Paso)

Cuando el cliente realiza una operación, el flujo criptográfico ocurre en milisegundos:

```
[Cliente]                                              [Google Cloud Run API]
   │                                                             │
   │ ─── 1. GET /api/pki/challenge ────────────────────────────► │
   │ ◄── 2. nonce + token HMAC (TTL 120 s, un solo uso) ─────── │
   │                                                             │
   │ ─── 3. Firma el nonce con client.key (local) ────────────── │
   │        (la llave privada NO viaja)                          │
   │                                                             │
   │ ─── 4. POST { clientCertificate, challengeToken, ────────► │
   │              signature }                                    │ ─── 5. Decodifica X.509
   │                                                             │ ─── 6. clientCert.verify(caCert.publicKey)
   │                                                             │ ─── 7. Comprueba vigencia y CRL
   │                                                             │ ─── 8. Verifica token + firma del nonce
   │                                                             │ ─── 9. Extrae identidad: cliente-desktop-01
   │ ◄── 10. HTTP 200 OK + Datos Protegidos de la Bóveda ─────── │
```

* **Paso 1-2:** El cliente solicita un reto; el servidor genera un nonce aleatorio y lo protege con un token HMAC de un solo uso.
* **Paso 3:** El cliente firma el nonce localmente con su llave privada (RSA-SHA256). La llave nunca se transmite.
* **Paso 4:** Envía certificado público + token + firma.
* **Paso 5-7:** Se verifica la cadena de confianza contra la CA, la vigencia y la revocación.
* **Paso 8:** Se verifica la firma del nonce con la llave pública del certificado. Sin la llave privada es inviable.
* **Paso 9-10:** Se autoriza identificando al operador por su Sujeto X.509.

---

## 🛡️ 5. Pruebas de Seguridad y Superficie de Ataque (La Rúbrica)

Durante la sustentación se demuestran los escenarios de seguridad requeridos por la rúbrica:

### 🟢 Caso 1: Certificado Válido + Reto Firmado (Acceso Autorizado)
* **Acción:** El cliente presenta `client.crt` firmado por la Root CA y firma el nonce del reto con `client.key`.
* **Respuesta del Servidor:** `HTTP 200 OK`.
* **Resultado:** Reconoce al cliente como `cliente-desktop-01`, valida la cadena de confianza y la posesión de la llave privada, y entrega los datos de la cuenta `CTA-UNDC-2026-9948` sin haber solicitado contraseñas.

### 🔴 Caso 2: Intento de Acceso SIN Certificado (Ataque 1)
* **Acción:** Un atacante intenta invocar `/api/pki/operaciones` sin enviar credenciales digitales.
* **Respuesta del Servidor:** `HTTP 401 Unauthorized` (`MISSING_CLIENT_CERTIFICATE`).
* **Resultado:** El servidor bloquea la petición antes de ejecutar cualquier lógica de negocio.

### 🟠 Caso 3: Certificado de Otra CA / Atacante (Ataque 2 - Rogue CA)
* **Acción:** Un atacante presenta un certificado digital válido, pero firmado por otra entidad externa (`Rogue Malicious Root CA`).
* **Respuesta del Servidor:** `HTTP 403 Forbidden` (`INVALID_ISSUER_CA`).
* **Resultado:** Cloud Run ejecuta `clientCert.verify(caCert.publicKey)` devolviendo `false`. La cadena de confianza se quiebra y el atacante es expulsado inmediatamente.

### 🟡 Caso 4: Copiar el Certificado Público sin la Llave Privada (Ataque 3)
* **Acción:** Un atacante descarga `client.crt` (material público) y lo presenta sin firmar el reto.
* **Respuesta del Servidor:** `HTTP 403 Forbidden` (`PROOF_OF_POSSESSION_REQUIRED`).
* **Resultado:** El certificado por sí solo ya **no** autentica. Se exige la firma del nonce con la llave privada, que no está publicada.

### 🔁 Caso 5: Reutilizar un Reto ya Usado (Anti-Replay)
* **Acción:** Se reenvía exactamente el mismo token y firma de una petición exitosa.
* **Respuesta del Servidor:** `HTTP 403 Forbidden` (`CHALLENGE_ALREADY_USED`).
* **Resultado:** Cada reto es de un solo uso y expira en 120 segundos.

### 🧾 Caso 6: Certificado Revocado (CRL real)
* **Acción:** El cliente presenta `client-revocado.crt` y firma correctamente el reto con su llave privada.
* **Respuesta del Servidor:** `HTTP 403 Forbidden` (`CERTIFICATE_REVOKED`).
* **Resultado:** La firma de la CA es válida, pero la serie `1002` aparece en la **CRL firmada** (`crl.pem`). Demuestra que la revocación es inmediata y no requiere cambiar contraseñas.
* **Detalle técnico:** el servidor verifica la firma de la CRL con la llave pública de la CA y su vigencia (`thisUpdate` / `nextUpdate`). Si la CRL no es confiable, **falla cerrado**.

### 🕒 Caso 7: Certificado Vencido
* **Acción:** El cliente presenta `client-vencido.crt` (emitido con `notAfter = 2021-01-01`).
* **Respuesta del Servidor:** `HTTP 403 Forbidden` (`CERTIFICATE_EXPIRED`). En la VM el corte ocurre en el handshake TLS (`certificate expired`).
* **Resultado:** Un certificado con firma correcta pero fuera de vigencia no autentica.

### 🔐 Caso 8: Acceso con PKCS#12 (`.pfx`)
* **Acción:** La app de escritorio usa un único archivo `client.pfx` protegido con contraseña.
* **Respuesta del Servidor:** `HTTP 200 OK`.
* **Resultado:** El cliente extrae temporalmente certificado y llave a un directorio seguro (permisos restringidos), firma el reto y borra los temporales. El `.pfx` **nunca se publica** y su contraseña no viaja al servidor.

### 🖥️ Caso 9: mTLS real en VM (handshake)
* **Acción:** Se invoca `https://34.176.58.90:8443/api/operaciones` con `ssl.CERT_REQUIRED`.
* **Resultados reales:**
  * Certificado válido → `200 OK`.
  * Sin certificado → corte TLS (`certificate required`).
  * Certificado de otra CA → corte TLS (`unknown ca`).
  * Certificado revocado → `403 CERTIFICATE_REVOKED` (OpenSSL `-crl_check`).
  * Certificado vencido → corte TLS (`certificate expired`).

---

## 🚀 6. Guía Rápida para la Demostración en Vivo

Tienes dos opciones listas para proyectar ante el profesor:

### Opción A: Demostración en la Web (Google Cloud Run en vivo)
1. Abre en el navegador:  
   👉 **[https://boveda-segura-git-931747537260.southamerica-west1.run.app/pki](https://boveda-segura-git-931747537260.southamerica-west1.run.app/pki)**
2. Presiona **F12** y ve a la pestaña **Consola**.
3. Haz clic en los botones de la interfaz:
   * **🟢 Probar Certificado sin Firma:** Demuestra que copiar `client.crt` ya **no** concede acceso (`403 PROOF_OF_POSSESSION_REQUIRED`).
   * **🔴 Probar Sin Certificado:** Bloqueo `401`.
   * **🟠 Probar CA Atacante:** Rechazo `403 INVALID_ISSUER_CA`.
   * **🧾 Probar Certificado Revocado:** Rechazo `403 CERTIFICATE_REVOKED` (CRL real).
   * **🕒 Probar Certificado Vencido:** Rechazo `403 CERTIFICATE_EXPIRED`.
   * **🔐 Obtener reto:** Muestra el nonce y el token que el aplicativo de escritorio debe firmar.
   > El acceso **válido** (200) requiere la llave privada, por eso se ejecuta desde la app de escritorio o el CLI, no desde el navegador.

### Opción B: Demostración con la App de Escritorio (recomendada)
1. Ejecuta `proyecto3-pki\app_escritorio\run_app.bat`.
2. Deja el modo **☁️ Nube** seleccionado.
3. Clic en **🟢 Certificado Válido + Reto Firmado** → `200 OK` con los datos de la bóveda.
4. Prueba los ataques **🔴 Sin Certificado**, **🟠 Otra CA** y **🟡 Certificado sin Llave**.
5. Clic en **🔐 Acceso con PKCS#12 (.pfx)** → `200 OK` con `client.pfx` y su contraseña.
6. Clic en **🧾 Verificar CRL (revocado)** → `403 CERTIFICATE_REVOKED`.

### Opción B2: mTLS real contra la VM (máxima fidelidad al enunciado)
1. Verifica que la VM esté encendida y el servicio activo (`boveda-pki.service`).
2. En la app, selecciona modo **🖥️ Local** y usa `https://34.176.58.90:8443/api/operaciones`.
3. Repite las pruebas: válido `200`, sin certificado/otra CA/vencido cortados en TLS, revocado `403`.
4. Desde PowerShell también se puede ejecutar la batería de 8 pruebas con `python proyecto3-pki\test_cloud_api.py`.

### Opción C: Demostración por Terminal de Windows (CLI)
1. Abre la carpeta `proyecto3-pki\`.
2. Haz doble clic en **`demostrar_pki_cloud.bat`**.
3. Se ejecutará el flujo completo: healthcheck, reto, firma local, llamada en vivo y los rechazos de la rúbrica.

---

## ❓ 7. Preguntas Frecuentes del Jurado y Respuestas Clave

### P1: ¿Por qué usamos Google Cloud Run en lugar de Azure Functions?
> *"El profesor autorizó el cambio de proveedor de nube siempre que se cumpliera la arquitectura técnica. Cloud Run no permite mTLS con una CA propia porque termina TLS en el borde; por eso implementamos el mismo principio a nivel de aplicación: certificado X.509 + reto firmado con la llave privada, validación de CA, vigencia y revocación. Además, el proyecto incluye un servidor con mTLS real (`api/server.py`, `ssl.CERT_REQUIRED`) para ejecución local o en una VM."*

### P2: ¿Por qué la llave privada nunca debe salir del equipo del cliente?
> *"Porque el principio fundamental de la criptografía asimétrica es que la llave privada es el único secreto. Si la llave privada viajara a la CA o al servidor, dejaría de ser un modelo Zero-Knowledge y se convertiría en un secreto compartido vulnerable a interceptación."*

### P3: ¿Qué diferencia hay entre una CA propia y una CA pública como Let's Encrypt?
> *"Una CA pública sirve para autenticar servidores ante todo el público general de internet (los navegadores ya confían en ella). Una CA propia se utiliza en redes corporativas, financieras o militares cerradas (Zero Trust): solo confían en ella los servidores y clientes de la propia institución, garantizando que nadie de afuera pueda entrar."*

### P4: ¿Dónde se aplica esto en la vida real?
> *"En los sistemas de mensajería interbancaria (SWIFT / ISO 20022), en la autenticación de servidores en arquitecturas Kubernetes (Service Mesh / Istio con mTLS automático), en VPNs empresariales basadas en certificados y en pasarelas de pago bancarias seguras."*

### P5: ¿Cómo funciona la revocación si el certificado todavía no vence?
> *"La CA mantiene una base de datos (`index.txt`) y publica una CRL firmada con su llave privada. El validador comprueba la firma de la CRL, sus fechas y busca el número de serie del certificado. Si aparece, responde `403 CERTIFICATE_REVOKED` aunque la firma del certificado siga siendo matemáticamente válida. Para revocar se ejecuta `python pki/04_revocar.py --cert ...` y se redespliega la CRL."*

### P6: ¿Qué pasa si la CRL está vencida o alguien la modifica?
> *"Se falla cerrado. El validador rechaza el certificado con un código `CRL_EXPIRED`, `CRL_SIGNATURE_INVALID` o `CRL_MALFORMED`. Una CRL sin firma válida de la CA no se usa nunca; por eso `crl.pem` es público pero no manipulable."*

### P7: ¿Cuánto cuesta la VM y qué se debe hacer al terminar?
> *"La VM `e2-micro` con IP estática cuesta aproximadamente entre 7 y 10 dólares al mes. Al finalizar la presentación se elimina la instancia, la IP reservada y la regla de firewall para evitar cobros. El código y los certificados quedan versionados en el repositorio."*
> ```powershell
> gcloud compute instances delete boveda-pki-vm --zone southamerica-west1-a --project boveda-segura-512214 --quiet
> gcloud compute addresses delete boveda-pki-vm-ip --region southamerica-west1 --project boveda-segura-512214 --quiet
> gcloud compute firewall-rules delete allow-pki-mtls --project boveda-segura-512214 --quiet
> ```

