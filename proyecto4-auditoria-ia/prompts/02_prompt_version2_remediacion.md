# PROMPT 2 — Generación de la Versión 2 (Remediación Defensiva)
> **Universidad Nacional de Cañete — UNDC 2026**  
> **Proyecto 4:** Auditoría de una Aplicación Generada con IA  
> **Propósito:** Documentar el prompt de remediación alimentado con los hallazgos del Pentest Report para guiar a la IA en la corrección de la Versión 1.

---

## 📝 Metadatos del Prompt de Remediación

* **Fecha de generación:** Noviembre de 2026
* **Herramienta / Modelo de IA:** Asistente de IA (DeepMind / Claude Sonnet / GPT-4o)
* **Entrada del Prompt:** Los 7 hallazgos técnicos identificados en el **Pentest Report** con sus categorías OWASP Top 10:2025 y vectores CVSS v3.1.
* **Objetivo:** Instruir a la IA para reescribir la aplicación aplicando el principio de **Defensa en Profundidad (Defense-in-Depth)** y **Diseño Seguro (Secure by Design)**.

---

## 📜 Texto Exacto del Prompt de Remediación Entregado a la IA

```text
Actúa como un Ingeniero de Seguridad de Aplicaciones (AppSec / DevSecOps) y reescribe completamente el código del "Portal de Soporte y Comunidad" de Bóveda Segura para corregir todas las vulnerabilidades críticas detectadas en el informe de auditoría OWASP Top 10:2025.

Aplica las siguientes directivas obligatorias de seguridad en cada funcionalidad:

1. REMEDIACIÓN DE INYECCIÓN SQL (OWASP A03:2025 - CVSS 9.8):
   - Prohíbe cualquier concatenación de variables en sentencias SQL.
   - Utiliza exclusivamente Prepared Statements con parámetros tipados ($1, $2) en el motor de búsqueda (/api/v1/search).
   - Valida y sanea la longitud y caracteres del parámetro de búsqueda antes de consultar la base de datos.

2. REMEDIACIÓN DE CARGA DE ARCHIVOS MALICIOSOS (OWASP A04:2025 - CVSS 8.8):
   - No confíes en la extensión enviada por el cliente ni en la cabecera Content-Type.
   - Valida el archivo inspeccionando los primeros bytes (Magic Bytes binarios) para permitir únicamente imágenes reales (JPEG: FF D8 FF, PNG: 89 50 4E 47) o documentos PDF (25 50 44 46).
   - Rechaza archivos ejecutables, scripts (.php, .sh, .bat) y archivos SVG.
   - Renombra automáticamente el archivo en el servidor con un identificador UUID v4 aleatorio y almacénalo fuera del directorio público.
   - Sirve los archivos con cabeceras de seguridad: Content-Disposition: attachment y X-Content-Type-Options: nosniff.

3. REMEDIACIÓN DE STORED CROSS-SITE SCRIPTING (OWASP A03:2025 - CVSS 8.0):
   - En el formulario de comentarios (/api/v1/comments), aplica sanitización en backend y frontend utilizando DOMPurify antes de persistir o renderizar cualquier texto.
   - Renderiza el contenido en React como texto plano sin innerHTML ni dangerouslySetInnerHTML.
   - Aplica una política de seguridad de contenido (CSP) estricta: default-src 'self'; script-src 'self'.

4. REMEDIACIÓN DE CONTROL DE ACCESO (OWASP A01:2025 - CVSS 8.8):
   - Implementa un middleware de Control de Acceso Basado en Roles (RBAC) que se ejecute en el SERVIDOR en cada endpoint administrativo (/api/v1/admin/*).
   - Verifica la sesión del usuario en la base de datos y comprueba que su rol registrado sea estrictamente 'admin'.
   - No aceptes ningún parámetro de rol enviado en el cuerpo de la petición o en la URL.

5. REMEDIACIÓN DE AUTENTICACIÓN Y SESIONES (OWASP A07:2025 - CVSS 7.5 y 6.1):
   - Implementa un limitador de tasa (Rate Limiting) en el endpoint de login: máximo 5 intentos fallidos en 15 minutos por IP y cuenta.
   - Aplica hashing de contraseñas con bcrypt (mínimo 12 rondas de costo).
   - Almacena los tokens de sesión en Cookies seguras con flags HttpOnly, Secure, SameSite=Lax. Elimina cualquier almacenamiento en window.localStorage.

6. REMEDIACIÓN DE FUGA DE INFORMACIÓN (OWASP A05:2025 - CVSS 5.3):
   - Implementa un manejador centralizado de errores.
   - Nunca expongas stack traces, versiones de librerías ni errores crudos de la base de datos al cliente. Devuelve mensajes genéricos y registra el detalle únicamente en logs protegidos del servidor.

Genera el código corregido de la Versión 2, explicando cómo cada cambio neutraliza el vector de ataque correspondiente.
```

---

## 📊 Evaluación Comparativa: ¿Qué corrigió la IA y qué le faltó al prompt?

### 1. Lo que la IA corrigió con éxito:
* ✅ Reemplazó el 100% de las consultas SQL concatenadas por **consultas preparadas parametrizadas**, eliminando la inyección SQL clásica.
* ✅ Implementó la verificación de **Magic Bytes** binarios y UUID en la subida de archivos, bloqueando la subida de scripts maliciosos.
* ✅ Incorporó sanitización con **DOMPurify** y renderizado como texto plano para mitigar Stored XSS.
* ✅ Añadió el middleware **RBAC** en servidor para proteger el panel `/admin`.
* ✅ Migró los tokens a **Cookies HttpOnly**, protegiendo la sesión contra robo vía JavaScript.

### 2. Lo que la IA aún tendió a omitir (y requirió refinamiento humano):
* ⚠️ **Manejo de Race Conditions en el Rate Limiter:** La IA implementó el limitador de intentos en memoria (Map local) en lugar de un almacén distribuido o base de datos, lo que en entornos serverless con múltiples instancias podría ser eludido.
* ⚠️ **Validación de tamaño de payload a nivel de servidor web:** La IA validó el tamaño del archivo en el código de la ruta, pero no configuró el límite a nivel de servidor web/reverse proxy (`client_max_body_size` o Next.js `bodyParser`), lo que podría abrir la puerta a ataques de consumo de memoria.

### 3. Conclusión sobre el rol del Prompt:
Un prompt con directivas de seguridad **reduce en más de un 90% las vulnerabilidades comunes** generadas por modelos de lenguaje, pero la verificación humana y las pruebas dinámicas (DAST) continúan siendo indispensables en el ciclo de vida del software.
