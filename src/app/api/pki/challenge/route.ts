import { NextRequest, NextResponse } from 'next/server';
import { issueChallenge } from '@/lib/pki/challenge';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function challengeResponse(request: NextRequest) {
  const ttlParam = Number(request.nextUrl.searchParams.get('ttl'));
  const ttl = Number.isFinite(ttlParam) && ttlParam > 0 ? ttlParam : undefined;
  const challenge = issueChallenge(ttl);

  return NextResponse.json(
    {
      success: true,
      message:
        'Firma el campo nonce con tu llave privada RSA (SHA-256, PKCS#1 v1.5) y envíalo junto a tu certificado.',
      challenge: {
        token: challenge.token,
        nonce: challenge.nonce,
        algorithm: challenge.algorithm,
        issuedAt: challenge.issuedAt,
        expiresAt: challenge.expiresAt,
        ttlSeconds: challenge.ttlSeconds,
        singleUse: true,
      },
      next_step: {
        method: 'POST',
        endpoint: '/api/pki/operaciones',
        body: {
          clientCertificate: '<PEM o base64 del certificado X.509>',
          challengeToken: '<token recibido en este endpoint>',
          signature: '<firma RSA-SHA256 del nonce, en base64>',
        },
        openssl_example:
          'openssl dgst -sha256 -sign client.key -out firma.bin nonce.txt && base64 -w0 firma.bin',
      },
      timestamp: new Date().toISOString(),
    },
    {
      status: 200,
      headers: {
        'Cache-Control': 'no-store, max-age=0',
        'X-Content-Type-Options': 'nosniff',
      },
    }
  );
}

export async function GET(request: NextRequest) {
  return challengeResponse(request);
}

export async function POST(request: NextRequest) {
  return challengeResponse(request);
}
