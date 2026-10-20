// Variables de entorno SOLO SERVIDOR para Google Cloud.
// Nunca importar este módulo desde componentes cliente.

export const SESSION_COOKIE_NAME =
  process.env.SESSION_COOKIE_NAME || 'bodega_session';

export const SESSION_TTL_DAYS = Number(process.env.SESSION_TTL_DAYS || '7');

export const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || '12');

export const STORAGE_BUCKET = process.env.STORAGE_BUCKET || 'encrypted-files';

export function isProd(): boolean {
  return process.env.NODE_ENV === 'production';
}

export function getDatabaseUrl(): string {
  if (typeof window !== 'undefined') {
    throw new Error('DATABASE_URL solo está disponible en el servidor');
  }
  const url = process.env.DATABASE_URL || '';
  if (!url) {
    throw new Error(
      'Falta DATABASE_URL (Cloud Run > Revisar y modificar > Variables)'
    );
  }
  return url;
}
