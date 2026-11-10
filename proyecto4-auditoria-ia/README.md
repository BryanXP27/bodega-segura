# PROYECTO 4 — Auditoría de una Aplicación Web Generada con IA
> **Universidad Nacional de Cañete — UNDC 2026**  
> **Asignatura:** Seguridad y Criptografía  
> **Tema:** Ciclo DevSecOps: Generación con IA, Auditoría Dinámica (OWASP ZAP), Clasificación CVSS v3.1 y Remediación (V1 vs. V2).

---

## 🎯 Objetivo del Proyecto 4
Demostrar el impacto de la Inteligencia Artificial en el desarrollo de software y en la seguridad de aplicaciones web:
1. Generar la **Versión 1** a partir de un prompt inicial que solicita funcionalidades de negocio pero sin restricciones defensivas estrictas.
2. Identificar las vulnerabilidades críticas introducidas por la IA mapeándolas al estándar vigente **OWASP Top 10:2025** y calculando su severidad con **CVSS v3.1**.
3. Construir el **Prompt de Remediación** alimentado con los hallazgos técnicos de la auditoría.
4. Generar y desplegar la **Versión 2 (Corregida)**, contrastando la efectividad de las defensas y analizando qué riesgos persisten.

---

## 📋 Requisitos de la Aplicación y Superficies de Ataque

| # | Requisito de la Aplicación | Superficie de Ataque que Abre | Vulnerabilidades en Versión 1 (V1) | Contramedidas en Versión 2 (V2) |
|---|---|---|---|---|
| **1** | **Registro e inicio de sesión** | Contraseñas, sesiones y autenticación | Almacenamiento débil o sin salt, session hijacking, sin rate limit. | Hash robusto (bcrypt 12 rounds), cookies HttpOnly/SameSite/Secure, bloqueo por fuerza bruta. |
| **2** | **Roles: usuario y administrador** | Control de acceso y escalada de privilegios | Broken Access Control (BOLA/IDOR), bypass de rol mediante manipulación de parámetros. | Middleware RBAC en servidor, validación estricta de token/sesión criptográfica en cada endpoint. |
| **3** | **Búsqueda con base de datos** | Inyección y validación de entradas | **SQL Injection (SQLi)** por concatenación directa de parámetros en la consulta. | Consultas preparadas parametrizadas (Prepared Statements con `$1, $2`) y validación de tipos. |
| **4** | **Formulario de comentarios público** | XSS y manejo de datos del usuario | **Stored XSS (Cross-Site Scripting)** por renderizado sin escape de HTML/scripts. | Sanitización estricta con DOMPurify, codificación contextual de salida y política CSP estricta. |
| **5** | **Subida de imágenes o archivos** | Tipos, tamaños y archivos maliciosos | **Unrestricted File Upload** (subida de scripts ejecutables `.php`, `.html`, `.svg`, path traversal). | Validación por números mágicos (Magic Bytes), lista blanca de extensiones `.jpg, .png, .pdf`, nombres UUID aleatorios y storage aislado sin permisos de ejecución. |
| **6** | **API REST** | Autorización y manejo de errores | Información sensible expuesta en stack traces (Information Disclosure), endpoints sin auth. | Manejo centralizado de excepciones sin stack traces, autorización en cada verbo HTTP, esquemas DTO. |
| **7** | **Panel de administración** | Acceso privilegiado y configuración | Acceso directo por URL sin validar rol en servidor (`/admin`), exposición de métricas internas. | Autorización estricta por roles (`role === 'admin'`), auditoría de acciones administrativas y denegación por defecto. |

---

## 📁 Estructura del Proyecto 4 en este Repositorio

```
proyecto4-auditoria-ia/
├── README.md                            # Guía general del Proyecto 4
├── prompts/                             # Documentación de los prompts entregados a la IA
│   ├── 01_prompt_version1_inicial.md    # Prompt con el que se generó la Versión 1
│   └── 02_prompt_version2_remediacion.md# Prompt alimentado con los hallazgos del pentest
│
├── auditoria_pentest/                   # Entregable: Informe Formal de Penetration Testing
│   ├── PENTEST_REPORT_OWASP_2025.md     # Informe completo con CVSS, PoCs y remediaciones
│   ├── zap_scan_guide.md                # Guía para escaneo con OWASP ZAP (baja intensidad)
│   └── tabla_comparativa_v1_vs_v2.md    # Análisis: qué corrigió la IA y qué le faltó al prompt
│
├── src_v1_vulnerable/                   # Código de referencia Versión 1 (Vulnerable)
│   └── ...                              # Muestra las fallas generadas por la IA
│
└── src_v2_remediada/                    # Código de referencia Versión 2 (Corregida)
    └── ...                              # Muestra las defensas implementadas
```

---

## 🌐 Módulo Interactivo en la Nube (Google Cloud Run)
Se integra una vista interactiva en la aplicación web (`/auditoria`) que permite:
* Cambiar entre **Modo Versión 1 (Vulnerable)** y **Modo Versión 2 (Protegido)**.
* Ejecutar las pruebas de inyección SQL, Cross-Site Scripting (XSS), escalada de privilegios y subida de archivos maliciosos en tiempo real con evidencia inmediata.
