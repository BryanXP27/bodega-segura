// Pool de PostgreSQL SOLO SERVIDOR (Google Cloud SQL).
// Cloud SQL es PostgreSQL, por lo que el esquema de google-schema.sql
// funciona igual que el de Supabase/Azure.

import { Pool } from 'pg';
import { getDatabaseUrl } from './env';

declare global {
  // eslint-disable-next-line no-var
  var __bodegaPgPool: Pool | undefined;
}

let pool: Pool | null = null;

// pg-connection-string trata 'require'/'prefer'/'verify-ca' como verify-full
// (TLS estricto) y esa configuración pisa la del Pool. Cloud SQL firma su
// certificado con la CA propia de la instancia (no pública), por lo que la
// verificación estricta siempre falla con "unable to verify the first
// certificate". Removemos sslmode de la URL y dejamos que el objeto ssl de
// abajo controle el comportamiento.
function stripSslMode(url: string): string {
  const [base, qs = ''] = url.split('?');
  if (!qs) return url;
  const kept = qs.split('&').filter((kv) => !/^sslmode=/i.test(kv));
  return kept.length ? `${base}?${kept.join('&')}` : base;
}

export function getPool(): Pool {
  if (typeof window !== 'undefined') {
    throw new Error('El pool de PostgreSQL solo puede usarse en el servidor');
  }
  if (global.__bodegaPgPool) return global.__bodegaPgPool;
  if (pool) return pool;

  const connectionString = stripSslMode(getDatabaseUrl());
  const sslDisabled = process.env.GCP_PG_SSL === 'disable';

  pool = new Pool({
    connectionString,
    ssl: sslDisabled ? undefined : { rejectUnauthorized: false },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 15000,
  });

  pool.on('error', (err) => {
    console.error('[gcp-pg] pool error', err);
  });

  global.__bodegaPgPool = pool;
  return pool;
}

export async function query<T = Record<string, unknown>>(
  text: string,
  params: unknown[] = []
): Promise<{ rows: T[]; rowCount: number }> {
  const result = await getPool().query(text, params as unknown[]);
  return { rows: result.rows as T[], rowCount: result.rowCount ?? 0 };
}
