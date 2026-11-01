import { NextRequest, NextResponse } from 'next/server';
import { validateClientCertificate } from '@/lib/pki/x509-validator';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Endpoint Protegido con Certificado Digital X.509 (Proyecto 3 - UNDC 2026)
 * Valida el certificado de cliente sin requerir contraseñas ni API Keys.
 */
export async function POST(request: NextRequest) {
  try {
    // 1. Extraer certificado desde headers (modo proxy / Cloud Run / Azure Functions)
    let certHeader =
      request.headers.get('x-client-cert') ||
      request.headers.get('x-arr-clientcert') ||
      request.headers.get('ssl-client-cert');

    // 2. Extraer desde Authorization: Certificate <base64>
    const authHeader = request.headers.get('authorization');
    if (!certHeader && authHeader?.toLowerCase().startsWith('certificate ')) {
      certHeader = authHeader.slice(12).trim();
    }

    // 3. Extraer desde Body JSON (modo cliente web / API JSON)
    let certBody: string | null = null;
    try {
      const body = await request.json().catch(() => ({}));
      certBody = body?.clientCertificate || body?.certificate || null;
    } catch {
      // Ignorar si el body no es JSON
    }

    const certToValidate = certHeader || certBody;

    // A. Caso 1: No se envió ningún certificado
    if (!certToValidate) {
      return NextResponse.json(
        {
          success: false,
          error:
            'Acceso Denegado: No se presentó ningún Certificado Digital de cliente.',
          code: 'MISSING_CLIENT_CERTIFICATE',
          detail:
            'Este endpoint requiere autenticación con certificado X.509 emitido por la Root CA de la Bóveda Segura.',
          timestamp: new Date().toISOString(),
        },
        { status: 401 }
      );
    }

    // B. Validación criptográfica de la firma, vigencia y revocación
    const result = validateClientCertificate(certToValidate);

    if (!result.valid) {
      return NextResponse.json(
        {
          success: false,
          error: result.error,
          code: result.code,
          timestamp: new Date().toISOString(),
        },
        { status: 403 }
      );
    }

    // C. Certificado Válido: Entregar datos protegidos
    return NextResponse.json({
      success: true,
      message: `Autenticación PKI Exitosa. Bienvenido, ${result.client?.commonName}.`,
      auth_details: {
        client: result.client,
        auth_method: 'Digital Certificate X.509 / PKI (Zero-Secret Transmission)',
        passwords_used: 'Ninguna (Autenticación basada en Criptografía Asimétrica)',
        api_keys_used: 'Ninguna',
        verified_by: 'Bóveda Segura Root CA (RSA 4096 / SHA-256)',
        cloud_platform: 'Google Cloud Run',
      },
      boveda_data: {
        cuenta_id: 'CTA-UNDC-2026-9948',
        titular: 'Sistema Financiero Bóveda Segura',
        saldo_disponible: '$ 1,500,000.00 USD',
        nivel_acceso: 'OPERACIONES_CRITICAS_AUTORIZADAS',
        estado_auditoria: 'VERIFICADO_EN_NUBE',
      },
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    return NextResponse.json(
      {
        success: false,
        error: `Error interno al validar certificado: ${err?.message || err}`,
      },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  // Permitir GET si el certificado viene en header
  return POST(request);
}
