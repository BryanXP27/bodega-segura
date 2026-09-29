// Pool de PostgreSQL SOLO SERVIDOR (Azure Database for PostgreSQL).
// No importar desde componentes cliente: usa los adaptadores cliente vía /api.

import { Pool } from 'pg';
import { getDatabaseUrl } from './env';

declare global {
  // eslint-disable-next-line no-var
  var __bodegaPgPool: Pool | undefined;
}

let pool: Pool | null = null;

export function getPool(): Pool {
  if (typeof window !== 'undefined') {
    throw new Error('El pool de PostgreSQL solo puede usarse en el servidor');
  }
  if (global.__bodegaPgPool) return global.__bodegaPgPool;
  if (pool) return pool;

  const connectionString = getDatabaseUrl();
  const sslDisabled = process.env.AZURE_PG_SSL === 'disable';

  pool = new Pool({
    connectionString,
    ssl: sslDisabled ? undefined : { rejectUnauthorized: false },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 15000,
  });

  pool.on('error', (err) => {
    console.error('[azure-pg] pool error', err);
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
