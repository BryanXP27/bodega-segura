import { NextResponse } from 'next/server';
import { query } from '@/lib/gcp/pg';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Health para Cloud Run. No expone secretos ni datos.
export async function GET() {
  const backend = (process.env.NEXT_PUBLIC_BACKEND || 'auto').toLowerCase();
  let db: 'ok' | 'not-configured' | 'error' = 'not-configured';
  if (process.env.DATABASE_URL) {
    try {
      await query('SELECT 1 AS ok');
      db = 'ok';
    } catch {
      db = 'error';
    }
  }
  const blob = process.env.STORAGE_BUCKET || process.env.AZURE_STORAGE_CONNECTION_STRING
    ? 'configured'
    : 'not-configured';
  return NextResponse.json({
    status: 'ok',
    service: 'bodega-segura',
    backend,
    db,
    blob,
    crypto: {
      algorithms: ['AES-256-GCM', 'RSA-OAEP-SHA256', 'PBKDF2-SHA256', 'HMAC-SHA256'],
      version: '1.0',
    },
    timestamp: new Date().toISOString(),
  });
}
