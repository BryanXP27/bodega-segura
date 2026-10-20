# BÓVEDA SEGURA — Presentación del Proyecto 2: Cifrado Híbrido de Archivos en la Nube
> Universidad Nacional de Cañete — UNDC 2026 · Seguridad y Criptografía
> Plataforma: Google Cloud (Cloud Run + Cloud SQL + Cloud Storage)
> Contenido slide por slide. Tiempo sugerido: 10–12 minutos.

---

## Slide 1 — Portada
- **Título:** Proyecto 2 — Cifrado Híbrido de Archivos en la Nube
- **Subtítulo:** Bóveda de archivos cifrados con acceso multi-dispositivo, combinando cifrado simétrico y asimétrico
- **Plataforma:** Google Cloud — Cloud Run · Cloud SQL (PostgreSQL) · Cloud Storage
- *(Agrega aquí: integrantes, docente y fecha)*

## Slide 2 — El objetivo
> "Proteger los datos con cifrado híbrido (simétrico + asimétrico) para que sigan seguros incluso si el servidor es vulnerado."
- Construir una bóveda de archivos cifrados en la nube, con acceso multi-dispositivo.
- Combinar cifrado simétrico (rápido, para el archivo) y asimétrico (para proteger la clave).

## Slide 3 — Componentes tecnológicos
| Componente | Tecnología | Para qué sirve |
|---|---|---|
| Cifrado de archivo | **AES-256 (simétrico)** | Cifra el archivo completo en el dispositivo antes de subirlo — rápido, ideal para archivos grandes |
| Protección de la clave | **RSA-OAEP-2048 / clave pública (asimétrico)** | Cifra la clave AES (no el archivo) para que solo el dueño la abra con su privada |
| Derivación de clave | **PBKDF2-SHA256 (310 000 iteraciones)** | Genera la clave que protege la privada del usuario, para recuperarla desde cualquier dispositivo |
| Integridad | **HMAC-SHA256 (con la clave AES)** | Verifica que el archivo no fue alterado ni manipulado (integridad autenticada) |
| APIs y despliegue | **Cloud Run + Cloud SQL + Cloud Storage** | 4 endpoints: crear usuario, login, subir y descargar — la BD guarda lo consultable, el Storage lo cifrado |

## Slide 4 — Arquitectura (Google Cloud)
```
                [ Usuario: navegador — multi-dispositivo ]
      Next.js · cifrado y descifrado local con Web Crypto API
                          ⇅
                 [ Cloud Run ]  ← app Next.js + 4 endpoints de API
                          ⇅
      [ Cloud SQL · PostgreSQL ]        [ Cloud Storage ]
  perfiles, clave pública, metadatos   objetos .enc + clave cifrada
```
- **Cloud Run:** corre la app Next.js y sus rutas de servidor (`/api/*`).
- **Cloud SQL (PostgreSQL):** lo consultable (usuarios, pública, metadatos).
- **Cloud Storage:** lo cifrado (archivos `.enc` y clave privada protegida).
- Regla de oro: el par de claves **nunca sale del cliente en texto plano** — solo su versión cifrada llega a la nube.

## Slide 5 — Flujo: Crear cuenta
1. Generar par de claves **en el cliente** (pública y privada).
2. Derivar clave desde la contraseña (**PBKDF2-SHA256**, 310k).
3. Cifrar la clave privada con la clave derivada (**AES**).
4. Guardar **clave pública** en la base de datos.
5. Guardar **privada cifrada** en Cloud Storage (bucket privado).
- *(En nuestra implementación la privada cifrada vive en Cloud SQL; es el mismo dato cifrado, solo cambia el almacén.)*

## Slide 6 — Flujo: Subir archivo
1. Generar clave AES aleatoria — nueva, solo para este archivo.
2. Calcular HMAC del archivo — HMAC-SHA256 con la clave AES.
3. Cifrar el archivo con la clave AES (simétrico).
4. Cifrar la clave AES con la pública (asimétrico).
5. Subir a Cloud Storage: **archivo + clave cifrada + HMAC**.

## Slide 7 — Flujo: Descargar archivo (multi-dispositivo)
1. Derivar clave desde la contraseña (PBKDF2) — se recalcula en cada dispositivo.
2. Descifrar la clave privada con la clave derivada.
3. Descargar archivo cifrado + clave AES cifrada + HMAC.
4. Descifrar la clave AES con la clave privada.
5. Descifrar el archivo con la AES y **verificar el HMAC**.
- Si el HMAC no coincide (o AES-GCM falla), la descarga y la vista previa quedan **bloqueadas** con aviso.

## Slide 8 — Demo en vivo (guion de 5 min)
1. F12 → Console, filtrar `Bóveda`. Registrar usuario → expandir 📝 (RSA + PBKDF2 + cuenta).
2. Subir archivo → expandir ⬆️ y leer la secuencia `🔑 → 📦 → 🧬 → 🔏 → ☁️ → 🗄️`.
3. En Cloud Storage, descargar el `.enc` y abrirlo en texto: ilegible. Descargarlo desde la app: perfecto.
4. Tamper de 1 byte → tarjeta roja de bloqueo (sin refrescar la página).
5. Network: solo viajan `.enc` y metadatos cifrados.

## Slide 9 — Cierre: superficie de ataque
| Si… | Qué pasa |
|---|---|
| Servidor hackeado | Solo hay datos cifrados — inútil sin la clave |
| Transferencia interceptada | HTTPS + contenido ya cifrado — inútil sin la clave |
| Contraseña filtrada | Deriva la clave localmente — el 2FA no interviene |
- **Único punto realmente vulnerable:** la contraseña del usuario.
- **Conclusión:** la seguridad del sistema depende de la contraseña del usuario.

## Slide 10 — Aplicado hoy en…
- AWS/Azure/**Google KMS**, HSMs bancarios (PCI-DSS), Bitwarden/1Password, TLS/HTTPS, firma digital (SUNAT, DocuSign).

## Slide 11 — Migración ordenada a Google Cloud
1. **Fundación:** proyecto GCP + billing + APIs (Cloud Run, Cloud SQL, Cloud Storage, Secret Manager).
2. **Datos:** Cloud SQL PostgreSQL + ejecutar `azure-schema.sql` (reutilizable).
3. **Archivos:** bucket privado `encrypted-files`.
4. **App:** Next.js en Cloud Run (`output: standalone`) + 4 endpoints en `/api`.
5. **Auth:** propia contra Cloud SQL (`bcrypt` + tabla `sessions`).
6. **Blobs:** adaptador `@google-cloud/storage`.
7. **Verificar:** demo + `/api/health`.

## Slide 12 — Conclusiones
- Sistema funcional donde el servidor es "ciego": almacena, no lee.
- Cumple todos los componentes y flujos del Proyecto 2.
- Código conmutable: mismo proyecto sirve Vercel+Supabase o Google Cloud vía `NEXT_PUBLIC_BACKEND`.
- **Futuro (Proyecto 3):** continuar sobre esta base cloud-native.

## Slide 13 — Preguntas
- Gracias + demo libre para el jurado.
