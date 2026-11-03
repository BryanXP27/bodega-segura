import { NextRequest, NextResponse } from 'next/server';
import { validateClientCertificate } from '@/lib/pki/x509-validator';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function ts(): string {
  return new Date().toISOString().slice(11, 23);
}

/**
 * Endpoint Protegido con Certificado Digital X.509 (Proyecto 3 - UNDC 2026)
 * Valida el certificado de cliente sin requerir contraseñas ni API Keys.
 */
export async function POST(request: NextRequest) {
  const timestamp = ts();
  console.log(`\n============================================================`);
  console.log(`[Bóveda Cloud ${timestamp}] 🛡️ [PROYECTO 3] PETICIÓN AL API PROTEGIDO /api/pki/operaciones`);
  console.log(`============================================================`);

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
      console.warn(`[Bóveda Cloud ${timestamp}] ❌ ATAQUE DETECTADO: Petición recibida SIN certificado digital.`);
      console.warn(`[Bóveda Cloud ${timestamp}] 🛑 RESULTADO: HTTP 401 Unauthorized (MISSING_CLIENT_CERTIFICATE).`);
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

    console.log(`[Bóveda Cloud ${timestamp}] 📜 Certificado X.509 recibido. Decodificando estructura...`);

    // B. Validación criptográfica de la firma, vigencia y revocación
    const result = validateClientCertificate(certToValidate);

    if (!result.valid) {
      console.warn(`[Bóveda Cloud ${timestamp}] ❌ VALIDACIÓN FALLIDA: ${result.error}`);
      console.warn(`[Bóveda Cloud ${timestamp}] 🛑 RESULTADO: HTTP 403 Forbidden [${result.code}].`);
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
    console.log(`[Bóveda Cloud ${timestamp}] ✔ FIRMA VERIFICADA matemáticamente contra la Root CA de la Bóveda.`);
    console.log(`[Bóveda Cloud ${timestamp}] ✔ FECHAS DE VIGENCIA Y CRL: Certificado válido y no revocado.`);
    console.log(`[Bóveda Cloud ${timestamp}] 👤 CLIENTE AUTENTICADO: CN=${result.client?.commonName} | Org=${result.client?.organization}`);
    console.log(`[Bóveda Cloud ${timestamp}] 💰 AUTORIZANDO ACCESO A LA BÓVEDA CENTRAL (CTA-UNDC-2026-9948).`);

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
    console.error(`[Bóveda Cloud ${timestamp}] 💥 Error interno en validación:`, err);
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
  return POST(request);
}
