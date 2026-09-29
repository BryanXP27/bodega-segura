import { NextRequest, NextResponse } from 'next/server';
import { clearSessionCookie, getRequestToken, revokeSession } from '@/lib/azure/auth-server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request: NextRequest) {
  await revokeSession(getRequestToken(request));
  const res = NextResponse.json({ ok: true });
  clearSessionCookie(res);
  return res;
}
