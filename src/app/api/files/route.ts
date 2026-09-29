import { NextRequest, NextResponse } from 'next/server';
import { requireSession } from '@/lib/azure/auth-server';
import { query } from '@/lib/azure/pg';
import { base64ToBuffer, mapFile, type FileRow } from '@/lib/azure/rows';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  try {
    const session = await requireSession(request);
    const result = await query<FileRow>(
      `SELECT id, user_id, original_name, storage_name, encrypted_aes_key, iv, hmac,
              original_size, created_at, version
       FROM files WHERE user_id = $1 ORDER BY created_at DESC`,
      [session.userId]
    );
    return NextResponse.json({ files: result.rows.map(mapFile) });
  } catch {
    return NextResponse.json({ error: 'No autenticado' }, { status: 401 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const session = await requireSession(request);
    const body = await request.json().catch(() => ({}));
    const id = String(body?.id || '');
    const originalName = String(body?.originalName || '');
    const storageName = String(body?.storageName || '');
    const originalSize = Number(body?.originalSize ?? 0);
    const version = String(body?.version || '1.0');
    if (!id || !originalName || !storageName || !body?.encryptedAesKey || !body?.iv || !body?.hmac) {
      return NextResponse.json({ error: 'Metadatos incompletos' }, { status: 400 });
    }
    if (!storageName.startsWith(`${session.userId}/`)) {
      return NextResponse.json({ error: 'Archivo no autorizado' }, { status: 403 });
    }
    await query(
      `INSERT INTO files
        (id, user_id, original_name, storage_name, encrypted_aes_key, iv, hmac, original_size, version)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        id,
        session.userId,
        originalName,
        storageName,
        base64ToBuffer(String(body.encryptedAesKey)),
        base64ToBuffer(String(body.iv)),
        base64ToBuffer(String(body.hmac)),
        originalSize,
        version,
      ]
    );
    return NextResponse.json({ ok: true, id });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'No se pudo guardar';
    const status = message === 'No autenticado' ? 401 : 400;
    return NextResponse.json({ error: message }, { status });
  }
}
