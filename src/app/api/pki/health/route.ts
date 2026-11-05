import { NextResponse } from 'next/server';
import {
  BOVEDA_ROOT_CA_CERT,
  BOVEDA_CRL_GENERATED_AT,
  DEMO_REVOKED_CERT,
  DEMO_EXPIRED_CERT,
  REVOKED_SERIAL_NUMBERS,
} from '@/lib/pki/x509-validator';
import { verifyCrl } from '@/lib/pki/crl-parser';
import crypto from 'crypto';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const caCert = new crypto.X509Certificate(BOVEDA_ROOT_CA_CERT);
    const revokedDemo = new crypto.X509Certificate(DEMO_REVOKED_CERT);
    const expiredDemo = new crypto.X509Certificate(DEMO_EXPIRED_CERT);
    const crl = verifyCrl();

    return NextResponse.json(
      {
        status: crl.valid ? 'ok' : 'degraded',
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
        revocation: crl.valid
          ? {
              source: 'CRL X.509 firmada por la Root CA (OpenSSL)',
              crl_signature_verified: true,
              signature_algorithm: crl.signatureAlgorithm,
              this_update: crl.thisUpdate.toISOString(),
              next_update: crl.nextUpdate.toISOString(),
              revoked_count: crl.revokedSerials.length,
              generated_at: BOVEDA_CRL_GENERATED_AT,
              env_fallback_serials: REVOKED_SERIAL_NUMBERS.length,
            }
          : {
              source: 'CRL X.509 firmada por la Root CA (OpenSSL)',
              crl_signature_verified: false,
              error_code: crl.code,
              error: crl.error,
              env_fallback_serials: REVOKED_SERIAL_NUMBERS.length,
            },
        authentication: {
          certificate_chain: 'required (Root CA propia)',
          validity_window: 'required (notBefore / notAfter)',
          revocation: 'required (CRL X.509 firmada por la Root CA)',
          proof_of_possession: 'required (challenge-response RSA-SHA256)',
          passwords: 'not used',
          api_keys: 'not used',
        },
        demo_certificates: {
          revoked_certificate_serial: revokedDemo.serialNumber,
          expired_certificate_not_after: expiredDemo.validTo,
        },
        supported_methods: [
          'GET  /api/pki/challenge  -> emite un reto de un solo uso (TTL 120 s)',
          'POST /api/pki/operaciones { clientCertificate, challengeToken, signature }',
          'Header X-Client-Cert + X-PKI-Challenge + X-PKI-Signature',
          'Header X-ARR-ClientCert (compatibilidad Azure Functions)',
        ],
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
