import { NextRequest, NextResponse } from 'next/server';
import { generateInteractivePkiSession, getLatestPkiSession, getPkiSession } from '@/lib/pki/session-pki';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Endpoint para Generar una Mini-PKI y Llaves Únicas e Interactivas (Proyecto 3 - UNDC 2026)
 *
 * Cada invocación genera:
 * 1. Una nueva Root CA (llave privada + certificado raíz X.509 único).
 * 2. Un par de llaves de cliente y su certificado X.509 firmado por la CA.
 * 3. Escenarios de prueba únicos: CA Atacante (Rogue), Certificado Revocado en CRL y Certificado Vencido.
 * 4. Cuota autorizada de 3 usos antes de requerir renovación (Zero-Trust).
 */
export async function POST(request: NextRequest) {
  try {
    const session = generateInteractivePkiSession();

    console.log(`\n============================================================`);
    console.log(`[Mini-PKI Dinámica] 🔑 NUEVA CA Y LLAVES GENERADAS`);
    console.log(`[Mini-PKI Dinámica] Sesión ID: ${session.sessionId}`);
    console.log(`[Mini-PKI Dinámica] Root CA: ${session.ca.commonName}`);
    console.log(`[Mini-PKI Dinámica] Cliente: ${session.client.commonName} (Serie: ${session.client.serialNumber})`);
    console.log(`[Mini-PKI Dinámica] Cuota: ${session.maxUses} usos autorizados`);
    console.log(`============================================================\n`);

    return NextResponse.json({
      success: true,
      message: `Nueva Mini-PKI y credenciales generadas exitosamente para la sesión ${session.sessionId}.`,
      session: {
        sessionId: session.sessionId,
        sessionNumber: session.sessionNumber,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        quota: {
          maxUses: session.maxUses,
          usesCount: session.usesCount,
          remainingUses: session.remainingUses,
        },
        // Material de la CA
        ca: {
          commonName: session.ca.commonName,
          organization: session.ca.organization,
          serialNumber: session.ca.serialNumber,
          fingerprint256: session.ca.fingerprint256,
          certPem: session.ca.certPem,
          privateKeyPem: session.ca.privateKeyPem,
        },
        // Credenciales de Cliente Válidas
        client: {
          commonName: session.client.commonName,
          organization: session.client.organization,
          serialNumber: session.client.serialNumber,
          fingerprint256: session.client.fingerprint256,
          certPem: session.client.certPem,
          privateKeyPem: session.client.privateKeyPem,
        },
        // Escenarios para las 6 pruebas de seguridad
        testCases: {
          valid: {
            name: 'Certificado Válido',
            description: 'Firmado por la Root CA propia + Reto firmado con la llave privada',
            certPem: session.client.certPem,
            privateKeyPem: session.client.privateKeyPem,
            expectedHttp: 200,
          },
          noCert: {
            name: 'Ataque: Sin Certificado',
            description: 'Petición vacía sin credencial X.509',
            expectedHttp: 401,
          },
          rogueCa: {
            name: 'Ataque: Otra CA (Rogue)',
            description: 'Certificado emitido por una CA atacante no autorizada',
            certPem: session.attacker.certPem,
            expectedHttp: 403,
          },
          revoked: {
            name: 'Certificado Revocado',
            description: 'Figura en la CRL firmada por la Root CA',
            certPem: session.revoked.certPem,
            serialNumber: session.revoked.serialNumber,
            expectedHttp: 403,
          },
          expired: {
            name: 'Certificado Vencido',
            description: `Expiró el ${session.expired.expiredDate}`,
            certPem: session.expired.certPem,
            serialNumber: session.expired.serialNumber,
            expectedHttp: 403,
          },
          noKey: {
            name: 'Robo de Certificado (Copia sin Llave)',
            description: 'Certificado legítimo pero sin firma del reto (sin llave privada)',
            certPem: session.client.certPem,
            expectedHttp: 403,
          },
        },
        opensslCommands: {
          viewCert: `openssl x509 -in client.crt -text -noout`,
          viewCa: `openssl x509 -in ca.crt -text -noout`,
          verifyCert: `openssl verify -CAfile ca.crt client.crt`,
          signChallenge: `openssl dgst -sha256 -sign client.key -out firma.bin nonce.txt`,
          exportPfx: `openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt -certfile ca.crt`,
        },
      },
    });
  } catch (err: any) {
    console.error('[Mini-PKI Dinámica] Error al generar sesión:', err);
    return NextResponse.json(
      { success: false, error: `Error generando sesión PKI: ${err.message}` },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('sessionId');

  if (sessionId) {
    const session = getPkiSession(sessionId);
    if (!session) {
      return NextResponse.json(
        { success: false, error: 'Sesión no encontrada' },
        { status: 404 }
      );
    }
    return NextResponse.json({
      success: true,
      session: {
        sessionId: session.sessionId,
        quota: {
          maxUses: session.maxUses,
          usesCount: session.usesCount,
          remainingUses: session.remainingUses,
        },
        auditLog: session.auditLog,
      },
    });
  }

  // Si no se pasa ID, generar una nueva
  return POST(request);
}
