import { NextRequest, NextResponse } from 'next/server';
import { requireSession } from '@/lib/azure/auth-server';
import { assertOwnKey, uploadEncryptedBlob } from '@/lib/azure/blob-server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Sube bytes YA CIFRADOS en el navegador. Límite 25 MB por request (curso).
export async function POST(request: NextRequest) {
  try {
    const session = await requireSession(request);
    const key = request.nextUrl.searchParams.get('key') || '';
    assertOwnKey(key, session.userId);
    const data = await request.arrayBuffer();
    if (data.byteLength === 0) {
      return NextResponse.json({ error: 'Archivo vacío' }, { status: 400 });
    }
    if (data.byteLength > 25 * 1024 * 1024) {
      return NextResponse.json({ error: 'Archivo mayor a 25 MB' }, { status: 413 });
    }
    const path = await uploadEncryptedBlob(key, data);
    return NextResponse.json({ ok: true, storageName: key, path });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'No se pudo subir';
    const status = message === 'No autenticado' ? 401 : 400;
    return NextResponse.json({ error: message }, { status });
  }
}
