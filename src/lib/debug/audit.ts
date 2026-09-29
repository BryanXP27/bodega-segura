// Bitácora de auditoría visible en DevTools (F12 > Console).
// Pensada para la exposición del Proyecto 2: cada operación cripto y de
// red deja una huella legible con hora, tamaños y fingerprints truncados.
// REGLA: aquí NUNCA se registran contraseñas, claves, ni contenido en claro.

const ENABLED = process.env.NEXT_PUBLIC_AUDIT_LOG !== 'false';

function ts(): string {
  return new Date().toISOString().slice(11, 23);
}

export function shortHex(data: ArrayBuffer | Uint8Array, chars = 16): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const shown = Array.from(bytes.slice(0, Math.ceil(chars / 2)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, chars);
  return `${shown}… (${bytes.byteLength} B)`;
}

export function audit(icon: string, title: string, details?: unknown): void {
  if (!ENABLED) return;
  if (details !== undefined) {
    console.log(`[Bóveda ${ts()}] ${icon} ${title}`, details);
  } else {
    console.log(`[Bóveda ${ts()}] ${icon} ${title}`);
  }
}

export function auditWarn(icon: string, title: string, details?: unknown): void {
  if (!ENABLED) return;
  console.warn(`[Bóveda ${ts()}] ${icon} ${title}`, details ?? '');
}

// Agrupa una operación completa (se colapsa en la consola). Devuelve
// la función para cerrar el grupo: const end = auditGroup('...'); ... end();
export function auditGroup(title: string): () => void {
  if (!ENABLED) return () => {};
  console.groupCollapsed(`[Bóveda ${ts()}] ${title}`);
  return () => console.groupEnd();
}
