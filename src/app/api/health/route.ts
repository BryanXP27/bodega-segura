import { NextResponse } from 'next/server';
import { query } from '@/lib/azure/pg';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Health para Azure App Service. No expone secretos ni datos.
export async function GET() {
  let db: 'ok' | 'not-configured' | 'error' = 'not-configured';
  if (process.env.DATABASE_URL) {
    try {
      await query('SELECT 1 AS ok');
      db = 'ok';
    } catch {
      db = 'error';
    }
  }
  const blob = process.env.AZURE_STORAGE_CONNECTION_STRING || process.env.AZURE_STORAGE_ACCOUNT_URL
    ? 'configured'
    : 'not-configured';
  return NextResponse.json({
    status: 'ok',
    service: 'bodega-segura',
    backend: 'azure',
    db,
    blob,
    crypto: {
      algorithms: ['AES-256-GCM', 'RSA-OAEP-SHA256', 'PBKDF2-SHA256', 'HMAC-SHA256'],
      version: '1.0',
    },
    timestamp: new Date().toISOString(),
  });
}
