import { NextRequest, NextResponse } from 'next/server';
import { httpStatus, registerUser, setSessionCookie } from '@/lib/azure/auth-server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json().catch(() => ({}));
    const { userId, token, expiresAt } = await registerUser(
      String(body?.email || ''),
      String(body?.password || '')
    );
    const res = NextResponse.json({ userId, sessionId: token });
    setSessionCookie(res, token, expiresAt);
    return res;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'No se pudo registrar';
    return NextResponse.json({ error: message }, { status: httpStatus(err) });
  }
}
