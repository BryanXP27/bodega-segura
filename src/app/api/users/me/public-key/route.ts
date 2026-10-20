import { NextRequest, NextResponse } from 'next/server';
import { getAuthServer } from '@/lib/backend';
import { query } from '@/lib/gcp/pg';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function PUT(request: NextRequest) {
  try {
    const auth = await getAuthServer();
    const session = await auth.requireSession(request);
    const body = await request.json().catch(() => ({}));
    const publicKeyJwk = body?.publicKeyJwk;
    if (!publicKeyJwk || typeof publicKeyJwk !== 'object') {
      return NextResponse.json({ error: 'Clave pública inválida' }, { status: 400 });
    }
    await query('UPDATE profiles SET public_key_jwk = $1 WHERE id = $2', [
      JSON.stringify(publicKeyJwk),
      session.userId,
    ]);
    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: 'No autenticado' }, { status: 401 });
  }
}
