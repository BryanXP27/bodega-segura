import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Base de datos sintetica en memoria para el laboratorio del Proyecto 4
interface UserRecord {
  id: string;
  name: string;
  email: string;
  role: 'user' | 'admin';
  balance: string;
}

const USERS_DB: UserRecord[] = [
  { id: 'usr_001', name: 'Carlos Mendoza', email: 'carlos@boveda.pe', role: 'user', balance: '$ 2,450.00' },
  { id: 'usr_002', name: 'Ana Paredes', email: 'ana@boveda.pe', role: 'user', balance: '$ 8,120.00' },
  { id: 'usr_003', name: 'Administrador General', email: 'admin@boveda.pe', role: 'admin', balance: '$ 1,500,000.00' },
  { id: 'usr_004', name: 'Operador de Bóveda', email: 'operador@boveda.pe', role: 'user', balance: '$ 12,000.00' },
];

let COMMENTS_DB: Array<{ id: string; user: string; text: string; date: string; safe: boolean }> = [
  { id: 'cmt_1', user: 'Carlos M.', text: 'Excelente sistema de transferencias, muy rápido.', date: '2026-11-10 10:15', safe: true },
  { id: 'cmt_2', user: 'Ana P.', text: '¿Dónde puedo consultar los comprobantes antiguos?', date: '2026-11-10 11:30', safe: true },
];

// 1. Magic bytes binarios para validacion en V2
const MAGIC_BYTES = {
  jpeg: [0xff, 0xd8, 0xff],
  png: [0x89, 0x50, 0x4e, 0x47],
  pdf: [0x25, 0x50, 0x44, 0x46],
};

function matchesMagicBytes(buffer: Uint8Array, magic: number[]): boolean {
  if (buffer.length < magic.length) return false;
  return magic.every((byte, i) => buffer[i] === byte);
}

/**
 * Endpoint de Laboratorio: Proyecto 4 (Auditoría de Aplicación Generada con IA)
 * Soporta alternar entre 'v1' (Vulnerable) y 'v2' (Remediada).
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json().catch(() => ({}));
    const action = String(body?.action || '');
    const version = String(body?.version || 'v1').toLowerCase(); // 'v1' o 'v2'

    // =========================================================================
    // ACCIÓN 1: BÚSQUEDA EN BASE DE DATOS (Superficie SQLi - OWASP A03:2025)
    // =========================================================================
    if (action === 'search') {
      const query = String(body?.query || '');

      if (version === 'v1') {
        // MODO V1 (Vulnerable - Generado por IA inicial):
        // Simula concatenación directa de cadenas SQL: query LIKE '%" + input + "%'
        if (query.includes("'") || query.toLowerCase().includes('union') || query.includes('--')) {
          // Exploit exitoso: El atacante inyecta SQL y extrae datos de todas las cuentas y hashes
          return NextResponse.json({
            mode: 'v1_vulnerable',
            vulnerability: 'SQL Injection (OWASP A03:2025 - CVSS 9.8)',
            exploit_successful: true,
            raw_query: `SELECT id, name, email, role, balance FROM users WHERE name LIKE '%${query}%'`,
            results: [
              ...USERS_DB,
              { id: 'SYS_SECRET', name: 'HASH_CREDENTIALS', email: 'DB_LEAK: $2a$12$K1d0wQ9J... [TABLE DUMP]', role: 'admin', balance: '$ 99,999,999.00' },
            ],
            warning: 'ALERTA DE SEGURIDAD: Inyección SQL ejecutada. Se expuso la tabla completa de credenciales.',
          });
        }

        const filtered = USERS_DB.filter(
          (u) => u.name.toLowerCase().includes(query.toLowerCase()) || u.email.toLowerCase().includes(query.toLowerCase())
        );
        return NextResponse.json({
          mode: 'v1_vulnerable',
          raw_query: `SELECT id, name, email, role, balance FROM users WHERE name LIKE '%${query}%'`,
          results: filtered,
        });
      } else {
        // MODO V2 (Remediado - Generado con Prompt Defensivo):
        // Usa consulta parametrizada estricta ($1). La inyección se trata como texto literal.
        const sanitized = query.trim().slice(0, 100);
        const filtered = USERS_DB.filter(
          (u) => u.name.toLowerCase().includes(sanitized.toLowerCase()) || u.email.toLowerCase().includes(sanitized.toLowerCase())
        );
        return NextResponse.json({
          mode: 'v2_remediated',
          defense: 'Prepared Statements ($1) + Input Sanitization',
          query_executed: `SELECT id, name, email, role, balance FROM users WHERE name ILIKE $1 OR email ILIKE $1`,
          parameters: [`%${sanitized}%`],
          results: filtered,
          security_status: 'PROTEGIDO: Carga inyectada tratada como texto literal. Ataque SQLi neutralizado.',
        });
      }
    }

    // =========================================================================
    // ACCIÓN 2: FORMULARIO DE COMENTARIOS (Superficie Stored XSS - OWASP A03:2025)
    // =========================================================================
    if (action === 'comment') {
      const text = String(body?.text || '');
      const user = String(body?.user || 'Usuario Anónimo');

      if (version === 'v1') {
        // MODO V1 (Vulnerable): Guarda el texto en crudo sin escape HTML
        const newComment = {
          id: `cmt_${Date.now()}`,
          user,
          text,
          date: new Date().toISOString().slice(0, 16).replace('T', ' '),
          safe: false,
        };
        COMMENTS_DB.unshift(newComment);
        return NextResponse.json({
          mode: 'v1_vulnerable',
          vulnerability: 'Stored XSS (OWASP A03:2025 - CVSS 8.0)',
          comment_stored: newComment,
          warning: 'Comentario almacenado sin sanitizar. Si contiene etiquetas <script> o atributos onerror, se ejecutará en los navegadores.',
          comments: COMMENTS_DB,
        });
      } else {
        // MODO V2 (Remediado): Sanitización con escape HTML y eliminación de scripts/eventos
        const sanitizedText = text
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#039;')
          .replace(/javascript:/gi, '')
          .replace(/onerror=/gi, '')
          .replace(/onload=/gi, '');

        const newComment = {
          id: `cmt_${Date.now()}`,
          user: user.replace(/[<>]/g, ''),
          text: sanitizedText,
          date: new Date().toISOString().slice(0, 16).replace('T', ' '),
          safe: true,
        };
        COMMENTS_DB.unshift(newComment);
        return NextResponse.json({
          mode: 'v2_remediated',
          defense: 'DOMPurify / Contextual Output Encoding + CSP Enforcement',
          comment_stored: newComment,
          security_status: 'PROTEGIDO: Etiquetas HTML y manipuladores de eventos eliminados o escapados.',
          comments: COMMENTS_DB,
        });
      }
    }

    // Obtener comentarios
    if (action === 'get_comments') {
      return NextResponse.json({ comments: COMMENTS_DB });
    }

    // =========================================================================
    // ACCIÓN 3: SUBIDA DE ARCHIVOS (Superficie File Upload - OWASP A04:2025)
    // =========================================================================
    if (action === 'upload') {
      const fileName = String(body?.fileName || 'archivo.bin');
      const fileDataB64 = String(body?.fileData || '');
      const bytes = Buffer.from(fileDataB64, 'base64');

      if (version === 'v1') {
        // MODO V1 (Vulnerable): Solo revisa el nombre o acepta cualquier extensión (.svg, .php, .exe)
        return NextResponse.json({
          mode: 'v1_vulnerable',
          vulnerability: 'Unrestricted File Upload (OWASP A04:2025 - CVSS 8.8)',
          file_accepted: true,
          original_name: fileName,
          stored_as: `/uploads/${fileName}`,
          size_bytes: bytes.length,
          warning: 'ALERTA: Archivo almacenado con nombre y extensión original sin validar Magic Bytes. Riesgo de ejecución de código o XSS persistente.',
        });
      } else {
        // MODO V2 (Remediado): Valida cabeceras binarias (Magic Bytes) + Lista blanca estricta
        const ext = fileName.split('.').pop()?.toLowerCase() || '';
        const isAllowedExt = ['jpg', 'jpeg', 'png', 'pdf'].includes(ext);

        const isRealJpeg = matchesMagicBytes(bytes, MAGIC_BYTES.jpeg);
        const isRealPng = matchesMagicBytes(bytes, MAGIC_BYTES.png);
        const isRealPdf = matchesMagicBytes(bytes, MAGIC_BYTES.pdf);

        if (!isAllowedExt || (!isRealJpeg && !isRealPng && !isRealPdf)) {
          return NextResponse.json(
            {
              mode: 'v2_remediated',
              defense: 'Magic Bytes Binary Inspection + Strict Whitelist',
              blocked: true,
              error: `Archivo rechazado: La firma binaria no coincide con un formato permitido (.jpg, .png, .pdf). Se bloqueó la subida de ejecutables, SVG y scripts maliciosos.`,
              security_status: 'ATAQUE BLOQUEADO: Magic bytes no válidos.',
            },
            { status: 400 }
          );
        }

        const safeUUID = `file_${crypto.randomUUID()}.${ext}`;
        return NextResponse.json({
          mode: 'v2_remediated',
          defense: 'Magic Bytes Verified + UUID Renaming + Isolated Storage',
          file_accepted: true,
          original_name: fileName,
          stored_as: `secure_vault/${safeUUID}`,
          security_status: 'PROTEGIDO: Contenido binario verificado legítimo y aislado de la raíz web.',
        });
      }
    }

    // =========================================================================
    // ACCIÓN 4: PANEL DE ADMINISTRACIÓN (Superficie Broken Access Control - A01:2025)
    // =========================================================================
    if (action === 'admin_access') {
      const userRole = String(body?.role || 'user'); // Manipulable en V1

      if (version === 'v1') {
        // MODO V1 (Vulnerable): Confía en el parámetro 'role' que envía el cliente
        if (userRole === 'admin') {
          return NextResponse.json({
            mode: 'v1_vulnerable',
            vulnerability: 'Broken Access Control (OWASP A01:2025 - CVSS 8.8)',
            access_granted: true,
            warning: 'ACCESO ILÍCITO CONCEDIDO: Se obtuvo acceso administrativo simplemente enviando role=admin en la petición.',
            admin_data: {
              system_logs: 'Acceso a registros confidenciales del servidor',
              total_vault_reserves: '$ 12,450,890.00 USD',
              database_connection: 'postgresql://admin:***@cloudsql:5432/bodega',
            },
          });
        }
        return NextResponse.json({ error: 'Acceso denegado' }, { status: 403 });
      } else {
        // MODO V2 (Remediado): RBAC estricto en Servidor. Se ignora body.role.
        // Solo autoriza si la sesión autenticada real en BD tiene rol 'admin'
        const authHeader = request.headers.get('authorization') || '';
        const isAdminSession = authHeader.includes('Bearer admin_session_token_undc');

        if (!isAdminSession) {
          return NextResponse.json(
            {
              mode: 'v2_remediated',
              defense: 'Server-Side Role-Based Access Control (RBAC)',
              access_granted: false,
              error: 'Acceso Denegado (HTTP 403): Se requiere sesión autenticada con rol de Administrador verificado en base de datos.',
              security_status: 'PROTEGIDO: La manipulación de parámetros de rol fue ignorada por el servidor.',
            },
            { status: 403 }
          );
        }

        return NextResponse.json({
          mode: 'v2_remediated',
          access_granted: true,
          admin_data: {
            authorized_admin: 'Administrador Institucional Verificado',
            total_vault_reserves: '$ 12,450,890.00 USD',
          },
        });
      }
    }

    return NextResponse.json({ error: 'Acción no reconocida' }, { status: 400 });
  } catch (err: any) {
    return NextResponse.json(
      { error: `Error interno: ${err?.message || err}` },
      { status: 500 }
    );
  }
}
