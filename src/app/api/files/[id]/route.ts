import { NextRequest, NextResponse } from 'next/server';
import { requireSession } from '@/lib/azure/auth-server';
import { query } from '@/lib/azure/pg';
import { mapFile, type FileRow } from '@/lib/azure/rows';
import { deleteEncryptedBlob } from '@/lib/azure/blob-server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

async function getOwnedFile(userId: string, fileId: string) {
  const result = await query<FileRow>(
    `SELECT id, user_id, original_name, storage_name, encrypted_aes_key, iv, hmac,
            original_size, created_at, version
     FROM files WHERE id = $1 AND user_id = $2`,
    [fileId, userId]
  );
  return result.rows[0] || null;
}

export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    const session = await requireSession(_request);
    const { id } = await context.params;
    const row = await getOwnedFile(session.userId, id);
    if (!row) return NextResponse.json({ error: 'Archivo no encontrado' }, { status: 404 });
    return NextResponse.json(mapFile(row));
  } catch {
    return NextResponse.json({ error: 'No autenticado' }, { status: 401 });
  }
}

export async function DELETE(
  request: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    const session = await requireSession(request);
    const { id } = await context.params;
    const row = await getOwnedFile(session.userId, id);
    if (!row) return NextResponse.json({ error: 'Archivo no encontrado' }, { status: 404 });
    try {
      await deleteEncryptedBlob(row.storage_name);
    } catch (err) {
      console.error('[files] no se pudo borrar el blob, se borra el metadato', err);
    }
    await query('DELETE FROM files WHERE id = $1 AND user_id = $2', [id, session.userId]);
    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: 'No autenticado' }, { status: 401 });
  }
}
