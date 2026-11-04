import { NextResponse } from 'next/server';
import { ATTACKER_CERT, DEMO_CLIENT_CERT } from '@/lib/pki/x509-validator';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Entrega certificados PUBLICOS para la demostracion web.
 *
 * Un certificado X.509 es informacion publica: puede compartirse sin riesgo.
 * Lo que NUNCA se publica es la llave privada. Por eso este endpoint expone
 * `client.crt` y `attacker.crt` para que la pagina /pki pueda demostrar que
 * presentar solo el certificado ya NO concede acceso (HTTP 403).
 */
export async function GET() {
  return NextResponse.json(
    {
      clientCertificate: DEMO_CLIENT_CERT,
      attackerCertificate: ATTACKER_CERT,
      note:
        'Certificados publicos. La autenticacion exige ademas firmar el reto con la llave privada, que no se distribuye.',
    },
    {
      status: 200,
      headers: { 'Cache-Control': 'no-store, max-age=0' },
    }
  );
}
