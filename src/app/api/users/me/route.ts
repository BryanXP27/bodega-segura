import { NextRequest, NextResponse } from 'next/server';
import { getAuthServer } from '@/lib/backend';
import { query } from '@/lib/gcp/pg';
import { mapProfile, type ProfileRow } from '@/lib/azure/rows';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  try {
    const auth = await getAuthServer();
    const session = await auth.requireSession(request);
    const result = await query<ProfileRow>(
      'SELECT id, email, public_key_jwk, created_at FROM profiles WHERE id = $1',
      [session.userId]
    );
    if (result.rows.length === 0) {
      return NextResponse.json({ error: 'Perfil no encontrado' }, { status: 404 });
    }
    return NextResponse.json(mapProfile(result.rows[0]));
  } catch {
    return NextResponse.json({ error: 'No autenticado' }, { status: 401 });
  }
}
