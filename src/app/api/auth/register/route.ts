import { NextRequest, NextResponse } from 'next/server';
import { getAuthServer } from '@/lib/backend';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json().catch(() => ({}));
    const auth = await getAuthServer();
    const { userId, token, expiresAt } = await auth.registerUser(
      String(body?.email || ''),
      String(body?.password || '')
    );
    const res = NextResponse.json({ userId, sessionId: token });
    auth.setSessionCookie(res, token, expiresAt);
    return res;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'No se pudo registrar';
    const auth = await getAuthServer();
    return NextResponse.json({ error: message }, { status: auth.httpStatus(err) });
  }
}
