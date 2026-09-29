// Helpers de entorno SOLO SERVIDOR para el backend Azure.
// Nunca importar este módulo desde componentes cliente.

export const SESSION_COOKIE_NAME =
  process.env.SESSION_COOKIE_NAME || 'bodega_session';

export const SESSION_TTL_DAYS = Number(process.env.SESSION_TTL_DAYS || '7');

export const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || '12');

export const AZURE_STORAGE_CONTAINER =
  process.env.AZURE_STORAGE_CONTAINER || 'encrypted-files';

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
      'Falta DATABASE_URL en las variables de entorno del servidor (App Service > Configuration)'
    );
  }
  return url;
}
