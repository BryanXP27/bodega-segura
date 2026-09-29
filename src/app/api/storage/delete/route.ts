import { NextRequest, NextResponse } from 'next/server';
import { requireSession } from '@/lib/azure/auth-server';
import { assertOwnKey, deleteEncryptedBlob } from '@/lib/azure/blob-server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function DELETE(request: NextRequest) {
  try {
    const session = await requireSession(request);
    const key = request.nextUrl.searchParams.get('key') || '';
    assertOwnKey(key, session.userId);
    await deleteEncryptedBlob(key);
    return NextResponse.json({ ok: true });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'No se pudo eliminar';
    const status = message === 'No autenticado' ? 401 : 400;
    return NextResponse.json({ error: message }, { status });
  }
}
