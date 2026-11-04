import { NextResponse } from 'next/server';
import { BOVEDA_ROOT_CA_CERT, REVOKED_SERIAL_NUMBERS } from '@/lib/pki/x509-validator';
import crypto from 'crypto';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const caCert = new crypto.X509Certificate(BOVEDA_ROOT_CA_CERT);
    return NextResponse.json(
      {
        status: 'ok',
        service: 'boveda-segura-pki',
        cloud_provider: 'Google Cloud Run',
        pki: {
          root_ca_installed: true,
          ca_subject: caCert.subject.replace(/\n/g, ', '),
          ca_issuer: caCert.issuer.replace(/\n/g, ', '),
          ca_serial: caCert.serialNumber,
          ca_valid_until: caCert.validTo,
          signature_algorithm: 'SHA256withRSA',
          key_type: 'RSA 4096 bits',
        },
        authentication: {
          certificate_chain: 'required (Root CA propia)',
          validity_window: 'required (notBefore / notAfter)',
          revocation: 'required (lista de series revocados)',
          proof_of_possession: 'required (challenge-response RSA-SHA256)',
          passwords: 'not used',
          api_keys: 'not used',
        },
        supported_methods: [
          'GET  /api/pki/challenge  -> emite un reto de un solo uso (TTL 120 s)',
          'POST /api/pki/operaciones { clientCertificate, challengeToken, signature }',
          'Header X-Client-Cert + X-PKI-Challenge + X-PKI-Signature',
          'Header X-ARR-ClientCert (compatibilidad Azure Functions)',
        ],
        revoked_serials: REVOKED_SERIAL_NUMBERS.length,
        timestamp: new Date().toISOString(),
      },
      {
        status: 200,
        headers: { 'Cache-Control': 'no-store, max-age=0' },
      }
    );
  } catch (err: any) {
    return NextResponse.json(
      { status: 'error', message: err?.message || err },
      { status: 500 }
    );
  }
}
