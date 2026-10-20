import { NextRequest, NextResponse } from 'next/server';
import { getAuthServer, getBlobServer } from '@/lib/backend';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function DELETE(request: NextRequest) {
  try {
    const auth = await getAuthServer();
    const session = await auth.requireSession(request);
    const key = request.nextUrl.searchParams.get('key') || '';
    const blob = await getBlobServer();
    blob.assertOwnKey(key, session.userId);
    await blob.remove(key);
    return NextResponse.json({ ok: true });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'No se pudo eliminar';
    const status = message === 'No autenticado' ? 401 : 400;
    return NextResponse.json({ error: message }, { status });
  }
}
