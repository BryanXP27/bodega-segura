import { NextResponse } from 'next/server';

export async function POST() {
  return NextResponse.json({
    config: {
      rsaKeySize: 2048,
      pbkdf2Iterations: 310000,
      pbkdf2Hash: 'SHA-256',
      aesKeyLength: 256,
      aesAlgorithm: 'AES-GCM',
      rsaAlgorithm: 'RSA-OAEP',
      hashAlgorithm: 'SHA-256',
      ivLength: 12,
      saltLength: 16,
    }
  });
}

export async function GET() {
  return NextResponse.json({
    algorithms: ['AES-GCM-256', 'RSA-OAEP-SHA256', 'PBKDF2-SHA256', 'HMAC-SHA256'],
    version: '1.0'
  });
}
