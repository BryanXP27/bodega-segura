import { NextRequest, NextResponse } from 'next/server';
import { requireSession } from '@/lib/azure/auth-server';
import { query } from '@/lib/azure/pg';
import { base64ToBuffer, mapEncryptedKey, type EncryptedKeyRow } from '@/lib/azure/rows';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  try {
    const session = await requireSession(request);
    const result = await query<EncryptedKeyRow>(
      'SELECT user_id, ciphertext, iv, salt, iterations, algorithm, key_length FROM encrypted_private_keys WHERE user_id = $1',
      [session.userId]
    );
    if (result.rows.length === 0) {
      return NextResponse.json({ error: 'Clave no encontrada' }, { status: 404 });
    }
    return NextResponse.json(mapEncryptedKey(result.rows[0]));
  } catch {
    return NextResponse.json({ error: 'No autenticado' }, { status: 401 });
  }
}

export async function PUT(request: NextRequest) {
  try {
    const session = await requireSession(request);
    const body = await request.json().catch(() => ({}));
    const iterations = Number(body?.iterations ?? 310000);
    const algorithm = String(body?.algorithm || 'AES-GCM');
    const keyLength = Number(body?.keyLength ?? 256);
    if (!body?.ciphertext || !body?.iv || !body?.salt) {
      return NextResponse.json({ error: 'Clave cifrada incompleta' }, { status: 400 });
    }
    await query(
      `INSERT INTO encrypted_private_keys
        (user_id, ciphertext, iv, salt, iterations, algorithm, key_length, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       ON CONFLICT (user_id) DO UPDATE SET
         ciphertext = EXCLUDED.ciphertext,
         iv = EXCLUDED.iv,
         salt = EXCLUDED.salt,
         iterations = EXCLUDED.iterations,
         algorithm = EXCLUDED.algorithm,
         key_length = EXCLUDED.key_length,
         updated_at = NOW()`,
      [
        session.userId,
        base64ToBuffer(String(body.ciphertext)),
        base64ToBuffer(String(body.iv)),
        base64ToBuffer(String(body.salt)),
        iterations,
        algorithm,
        keyLength,
      ]
    );
    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: 'No autenticado' }, { status: 401 });
  }
}
