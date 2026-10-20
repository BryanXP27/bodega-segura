import { NextRequest, NextResponse } from 'next/server';
import { getAuthServer } from '@/lib/backend';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request: NextRequest) {
  const auth = await getAuthServer();
  await auth.revokeSession(auth.getRequestToken(request));
  const res = NextResponse.json({ ok: true });
  auth.clearSessionCookie(res);
  return res;
}
