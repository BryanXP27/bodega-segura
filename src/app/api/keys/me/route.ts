import { NextRequest, NextResponse } from 'next/server';
import { getAuthServer, getKeysServer } from '@/lib/backend';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Clave privada CIFRADA: se guarda como objeto "<userId>/private-key.enc"
// en el bucket privado (alineado al enunciado del Proyecto 2).
const toBytes = (v: string) => Uint8Array.from(atob(v), (c) => c.charCodeAt(0));

export async function GET(request: NextRequest) {
  try {
    const auth = await getAuthServer();
    const session = await auth.requireSession(request);
    const keys = await getKeysServer();
    const data = await keys.load(session.userId);
    if (!data) {
      return NextResponse.json({ error: 'Clave no encontrada' }, { status: 404 });
    }
    return NextResponse.json({
      ciphertext: Buffer.from(data.ciphertext as Uint8Array).toString('base64'),
      iv: Buffer.from(data.iv as Uint8Array).toString('base64'),
      salt: Buffer.from(data.salt as Uint8Array).toString('base64'),
      iterations: data.iterations,
      algorithm: data.algorithm,
      keyLength: data.keyLength,
    });
  } catch {
    return NextResponse.json({ error: 'No autenticado' }, { status: 401 });
  }
}

export async function PUT(request: NextRequest) {
  try {
    const auth = await getAuthServer();
    const session = await auth.requireSession(request);
    const body = await request.json().catch(() => ({}));
    if (!body?.ciphertext || !body?.iv || !body?.salt) {
      return NextResponse.json({ error: 'Clave cifrada incompleta' }, { status: 400 });
    }
    const keys = await getKeysServer();
    await keys.save(session.userId, {
      ciphertext: toBytes(String(body.ciphertext)),
      iv: toBytes(String(body.iv)),
      salt: toBytes(String(body.salt)),
      iterations: Number(body?.iterations ?? 310000),
      algorithm: String(body?.algorithm || 'AES-GCM'),
      keyLength: Number(body?.keyLength ?? 256),
    });
    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: 'No autenticado' }, { status: 401 });
  }
}
