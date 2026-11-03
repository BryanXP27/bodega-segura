import { NextResponse } from 'next/server';
import { BOVEDA_ROOT_CA_CERT } from '@/lib/pki/x509-validator';
import crypto from 'crypto';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const caCert = new crypto.X509Certificate(BOVEDA_ROOT_CA_CERT);
    return NextResponse.json({
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
      supported_methods: [
        'X-Client-Cert Header',
        'X-ARR-ClientCert Header',
        'Authorization: Certificate <base64>',
        'POST /api/pki/operaciones { clientCertificate }',
      ],
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    return NextResponse.json(
      { status: 'error', message: err?.message || err },
      { status: 500 }
    );
  }
}

