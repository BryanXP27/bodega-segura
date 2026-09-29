# BÓVEDA SEGURA — Presentación del Proyecto 2: Cifrado Híbrido
> Universidad Nacional de Cañete · Seguridad y Criptografía
> Contenido slide por slide para armar el PPT. Tiempo sugerido: 10–12 minutos.

---

## Slide 1 — Portada
- **Título:** Bóveda Segura: almacenamiento de archivos con cifrado híbrido
- **Subtítulo:** Proyecto 2 — AES-256-GCM + RSA-OAEP-2048 + PBKDF2 + HMAC-SHA256
- **Datos:** Universidad Nacional de Cañete · curso Seguridad y Criptografía
- *(Agrega aquí: integrantes, docente y fecha)*

## Slide 2 — El problema
- Guardar archivos en la nube implica confiar en el proveedor: un administrador, una filtración o un atacante con acceso a la base de datos podría leerlos.
- **Pregunta guía:** ¿cómo lograr que ni siquiera el dueño del servidor pueda leer mis archivos?
- **Respuesta:** cifrar todo en el dispositivo del usuario *antes* de subirlo, y que el servidor solo guarde bytes ilegibles.

## Slide 3 — Lo que exige el Proyecto 2 (y cómo lo cumplimos)
| Requisito | Cumplimiento |
|---|---|
| Cifrado simétrico de archivos | AES-256-GCM, una clave única por archivo |
| Cifrado asimétrico de claves | RSA-OAEP-2048-SHA256 envuelve cada clave AES |
| Protección con contraseña | PBKDF2-SHA256 con 310 000 iteraciones (mínimo OWASP) |
| Integridad verificable | HMAC-SHA256 por archivo + descifrado autenticado AES-GCM |
| Nada en claro en el servidor | Solo viajan bytes cifrados y metadatos no sensibles |

## Slide 4 — Arquitectura
- **Cliente (navegador):** Next.js + Web Crypto API. AQUÍ ocurre el 100 % de la criptografía.
- **Servidor (Supabase):** Auth (sesiones) + PostgreSQL (perfiles, claves cifradas, metadatos) + Storage (blobs `.enc`).
- **Regla de oro:** la clave privada y los archivos jamás salen del navegador sin cifrar.
- Diagrama sugerido: `[Usuario] → (cifra) → [Supabase: bytes ilegibles] → (descifra) → [Usuario]`

## Slide 5 — Registro: nace tu identidad criptográfica
1. Se genera tu par de claves RSA-2048 (una vez por cuenta).
2. La **pública** se publica en `profiles` (es pública, no es secreto).
3. La **privada** se cifra con tu contraseña (PBKDF2 310k + AES-GCM) y se guarda en `encrypted_private_keys`.
4. Sin tu contraseña, nadie —ni nosotros— puede abrir tu privada.

## Slide 6 — Subida: el cifrado híbrido en 5 pasos
1. 🔑 Se genera una clave AES-256 efímera y aleatoria (una por archivo).
2. 📦 El archivo se cifra con AES-GCM (rápido para datos grandes).
3. 🧬 Se calcula el HMAC-SHA256 sobre los bytes cifrados (huella de integridad).
4. 🔏 La clave AES se envuelve con tu pública RSA (lento pero seguro para claves).
5. ☁️ Se sube el `.enc` ilegible + sus metadatos. El servidor nunca ve el contenido.

## Slide 7 — Descarga: verificación antes de confiar
1. Se traen metadatos y bytes **frescos** del servidor (sin caché).
2. Se abre tu privada con tu contraseña (PBKDF2).
3. Se recupera la clave AES con tu privada RSA.
4. El descifrado AES-GCM valida su etiqueta: si 1 bit cambió, falla aquí.
5. Se verifica el HMAC: si no coincide, **descarga bloqueada** con tarjeta de aviso.
6. Solo entonces se entrega el archivo original.

## Slide 8 — Integridad HMAC (demo en vivo)
- Cambiamos 1 byte del `.enc` en Storage y lo re-subimos a la misma ruta.
- Al intentar verlo/descargarlo con la contraseña **correcta**, la app muestra **"Archivo bloqueado por seguridad"**: huella no coincide → vista y descarga bloqueadas.
- Mensaje clave: *"Tu contraseña está bien; el problema es el contenido. Ni el administrador de la base de datos puede alterar tus archivos sin que lo notes."*
- Doble red: primero lo detecta AES-GCM, y si pasara, lo detecta el HMAC.

## Slide 9 — Stack tecnológico
- Next.js 16 + React 19 + TypeScript + Tailwind CSS (desplegado en Vercel).
- Supabase: Auth, PostgreSQL con RLS (cada usuario solo ve lo suyo), Storage privado.
- Web Crypto API del navegador (estándar, sin librerías inventadas).
- Bitácora `[Bóveda]` en DevTools: cada operación cripto deja huella visible **sin exponer secretos**.

## Slide 10 — Demo en vivo (guion de 5 min)
1. F12 → Console, filtrar `Bóveda`. Registrar usuario → expandir 📝 (RSA + PBKDF2 + cuenta).
2. Subir archivo → expandir ⬆️ y leer la secuencia `🔑 → 📦 → 🧬 → 🔏 → ☁️ → 🗄️`.
3. En Supabase Storage, descargar el `.enc` y abrirlo en texto: ilegible. Descargarlo desde la app: perfecto.
4. Tamper de 1 byte → tarjeta roja de bloqueo (sin refrescar la página).
5. Network: mostrar que solo viajan `.enc` y metadatos cifrados.

## Slide 11 — Seguridad y decisiones honestas
- Si olvidas tu contraseña, **no hay recuperación**: es propiedad del diseño, no un bug.
- El login viaja por TLS a Supabase Auth (estándar); la contraseña de descifrado nunca sale del navegador salvo ese login.
- La consola del navegador nunca imprime contraseñas, claves ni contenido.
- Mejoras aplicadas durante el desarrollo: cliente Supabase único, bloqueo visible por integridad, responsive completo, inputs sin exponer valores.

## Slide 12 — Conclusiones y trabajo futuro
- Se demostró un sistema funcional donde el servidor es "ciego": almacena, no lee.
- Se cumplen todos los requisitos del Proyecto 2 con algoritmos y parámetros estándar.
- Futuro: backend propio en Azure (PostgreSQL + Blob + auth propia, ya diseñado), más formatos de vista previa y borrado seguro.
- **Cierre:** *"Bóveda Segura prueba que la privacidad no se pide: se construye con criptografía."*

## Slide 13 — Preguntas
- Gracias + demo libre para el jurado.
