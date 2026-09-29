import { NextRequest, NextResponse } from 'next/server';
import { requireSession } from '@/lib/azure/auth-server';
import { assertOwnKey, downloadEncryptedBlob } from '@/lib/azure/blob-server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  try {
    const session = await requireSession(request);
    const key = request.nextUrl.searchParams.get('key') || '';
    assertOwnKey(key, session.userId);
    const data = await downloadEncryptedBlob(key);
    if (!data) return NextResponse.json({ error: 'Archivo no encontrado' }, { status: 404 });
    return new NextResponse(data, {
      headers: {
        'Content-Type': 'application/octet-stream',
        'Cache-Control': 'private, no-store',
      },
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'No se pudo descargar';
    const status = message === 'No autenticado' ? 401 : 400;
    return NextResponse.json({ error: message }, { status });
  }
}
