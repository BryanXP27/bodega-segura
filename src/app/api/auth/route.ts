import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  return NextResponse.json({
    status: 'ok',
    service: 'bodega-segura',
    backend: process.env.NEXT_PUBLIC_BACKEND || 'auto',
    timestamp: new Date().toISOString(),
    crypto: {
      algorithms: ['AES-256-GCM', 'RSA-OAEP-SHA256', 'PBKDF2-SHA256', 'HMAC-SHA256'],
      version: '1.0',
    },
  });
}

// El stub anterior devolvía { authorized: true } sin validar: se desactiva.
// Usa /api/auth/register, /api/auth/login, /api/auth/logout y /api/users/me.
export async function POST(_request: NextRequest) {
  return NextResponse.json(
    { error: 'Ruta desactivada. Usa /api/auth/register, /api/auth/login o /api/auth/logout.' },
    { status: 410 }
  );
}
