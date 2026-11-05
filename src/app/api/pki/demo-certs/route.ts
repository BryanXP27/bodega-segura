import { NextResponse } from 'next/server';
import {
  DEMO_CLIENT_CERT,
  DEMO_ATTACKER_CERT,
  DEMO_REVOKED_CERT,
  DEMO_EXPIRED_CERT,
} from '@/lib/pki/x509-validator';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Entrega certificados PUBLICOS para la demostracion web.
 *
 * Un certificado X.509 es informacion publica: puede compartirse sin riesgo.
 * Lo que NUNCA se publica es la llave privada. Por eso este endpoint expone
 * certificados de demo para que la pagina /pki pueda mostrar los rechazos:
 *  - client.crt          -> valido, pero sin firma del reto (403)
 *  - attacker.crt        -> firmado por otra CA (403)
 *  - client-revocado.crt -> aparece en la CRL firmada por la CA (403)
 *  - client-vencido.crt  -> expirado (403)
 */
export async function GET() {
  return NextResponse.json(
    {
      clientCertificate: DEMO_CLIENT_CERT,
      attackerCertificate: DEMO_ATTACKER_CERT,
      revokedCertificate: DEMO_REVOKED_CERT,
      expiredCertificate: DEMO_EXPIRED_CERT,
      note:
        'Certificados publicos. La autenticacion exige ademas firmar el reto con la llave privada, que no se distribuye.',
    },
    {
      status: 200,
      headers: { 'Cache-Control': 'no-store, max-age=0' },
    }
  );
}
