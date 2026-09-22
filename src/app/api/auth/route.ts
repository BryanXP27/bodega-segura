import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  return NextResponse.json({ 
    status: 'ok', 
    service: 'bodega-segura', 
    timestamp: new Date().toISOString(),
    crypto: {
      algorithms: ['AES-256-GCM', 'RSA-OAEP-SHA256', 'PBKDF2-SHA256', 'HMAC-SHA256'],
      version: '1.0'
    }
  });
}

export async function POST(request: NextRequest) {
  try {
    const { action, userId, fileId } = await request.json();

    switch (action) {
      case 'validate-owner': {
        return NextResponse.json({ authorized: true });
      }
      default:
        return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }
  } catch (error) {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 });
  }
}
