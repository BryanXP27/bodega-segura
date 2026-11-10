# PROMPT 1 — Generación de la Versión 1 (Aplicación Inicial)
> **Universidad Nacional de Cañete — UNDC 2026**  
> **Proyecto 4:** Auditoría de una Aplicación Generada con IA  
> **Propósito:** Documentar el prompt detallado utilizado para generar la primera versión funcional.

---

## 📝 Metadatos del Prompt Inicial

* **Fecha de generación:** 10 de Noviembre de 2026
* **Herramienta / Modelo de IA:** Asistente de IA (DeepMind / Claude Sonnet / GPT-4o)
* **Objetivo del Prompt:** Solicitar una aplicación web completa con los 7 requisitos exigidos por la rúbrica de la UNDC, simulando la instrucción común de un desarrollador orientado a funcionalidad rápida sin directivas explícitas de seguridad defensiva.

---

## 📜 Texto Exacto del Prompt Entregado a la IA

```text
Actúa como un desarrollador web Full-Stack y crea una aplicación web de "Portal de Soporte y Comunidad" para un sistema bancario llamado Bóveda Segura. 

La aplicación debe ser rápida y contener las siguientes funcionalidades obligatorias:

1. Registro e inicio de sesión:
   - Permite que nuevos usuarios se registren con correo y contraseña.
   - Manejo de inicio de sesión y almacenamiento de sesiones.

2. Roles de usuario y administrador:
   - Los usuarios normales pueden ver contenido público.
   - Debe haber un rol de 'admin' para gestionar el sistema.

3. Búsqueda con base de datos:
   - Una barra de búsqueda que permita buscar usuarios, comentarios o transacciones buscando coincidencias en la base de datos (por ejemplo mediante texto o consultas SQL).

4. Formulario de comentarios visible a otros usuarios:
   - Los usuarios autenticados pueden publicar mensajes, preguntas o comentarios de soporte en un muro público visible para todos.

5. Subida de imágenes o archivos:
   - Un formulario para que los usuarios puedan subir su foto de perfil o adjuntar comprobantes/capturas de soporte. Guarda los archivos en el servidor o almacenamiento.

6. API REST:
   - Endpoints para consultar usuarios (/api/v1/users), comentarios (/api/v1/comments) y métricas. Debe devolver JSON y manejar errores.

7. Panel de administración:
   - Una sección administrativa accesible en /admin donde el administrador pueda ver la lista de todos los usuarios registrados, eliminar comentarios y ver estadísticas del sistema.

Proporciona el código de las rutas, la base de datos y la interfaz gráfica de forma funcional y completa.
```

---

## 🔍 Análisis Técnico del Prompt Inicial: ¿Por qué la IA generó vulnerabilidades?

Un análisis crítico del prompt revela que es **"funcionalmente completo pero defensivamente ciego"**:

1. **Ausencia de Directivas de Sanitización (XSS):**  
   El prompt pidió *"comentarios visibles a otros usuarios"*, pero no instruyó codificar contextualmente la salida ni aplicar sanitizadores como DOMPurify. La IA tendió a renderizar el texto directamente con `dangerouslySetInnerHTML` o innerHTML sin escape.
2. **Ausencia de Directivas de Parametrización (SQLi):**  
   El prompt pidió *"buscar coincidencias en la base de datos"*. Sin la instrucción estricta de usar *Prepared Statements*, la IA generó consultas concatenando cadenas (`WHERE query LIKE '%" + input + "%'`).
3. **Ausencia de Restricción en Carga de Archivos (Unrestricted Upload):**  
   Se pidió *"subir fotos o comprobantes"* sin exigir validación de cabeceras binarias (Magic Bytes), limitación estricta de extensiones ni aislamiento del almacenamiento. La IA se limitó a leer `file.name` y confiar en la extensión enviada por el cliente.
4. **Ausencia de Verificación de Roles en Servidor (Broken Access Control):**  
   Se pidió un panel en `/admin`, pero no se exigió control de acceso basado en tokens firmados criptográficamente en backend. La IA implementó validaciones superficiales solo en cliente o basadas en parámetros modificables (`?role=admin` o `body.role`).
