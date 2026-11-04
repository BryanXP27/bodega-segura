import { NextRequest, NextResponse } from 'next/server';
import { validateClientCertificate } from '@/lib/pki/x509-validator';
import { verifyChallengeSignature, verifyChallengeToken } from '@/lib/pki/challenge';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function ts(): string {
  return new Date().toISOString().slice(11, 23);
}

/**
 * Endpoint Protegido con Certificado Digital X.509 (Proyecto 3 - UNDC 2026)
 *
 * Autenticacion en dos factores criptograficos, sin contrasenas ni API Keys:
 *   A) El certificado X.509 debe estar firmado por la Root CA propia, vigente
 *      y no revocado.
 *   B) El cliente debe demostrar POSESION de la llave privada firmando el reto
 *      emitido por GET /api/pki/challenge (RSA-SHA256, un solo uso, 2 min).
 *
 * Presentar solo el certificado (material publico) ya NO concede acceso.
 */
export async function POST(request: NextRequest) {
  const timestamp = ts();
  console.log(`\n============================================================`);
  console.log(`[Bóveda Cloud ${timestamp}] 🛡️ [PROYECTO 3] PETICIÓN AL API PROTEGIDO /api/pki/operaciones`);
  console.log(`============================================================`);

  try {
    // 1. Body JSON: certificado, token de reto y firma
    let body: any = {};
    try {
      body = await request.json();
    } catch {
      body = {};
    }

    // 2. Compatibilidad con proxies que reenvían el certificado en headers
    const certHeader =
      request.headers.get('x-client-cert') ||
      request.headers.get('x-arr-clientcert') ||
      request.headers.get('ssl-client-cert');

    let authHeader = request.headers.get('authorization');
    if (!certHeader && authHeader?.toLowerCase().startsWith('certificate ')) {
      authHeader = authHeader.slice(12).trim();
    } else {
      authHeader = null;
    }

    const certToValidate: string | null =
      certHeader || authHeader || body?.clientCertificate || body?.certificate || null;

    const challengeToken: string | null =
      body?.challengeToken ||
      body?.challenge_token ||
      request.headers.get('x-pki-challenge') ||
      null;

    const signature: string | null =
      body?.signature ||
      body?.challengeSignature ||
      request.headers.get('x-pki-signature') ||
      null;

    // A. Caso 1: No se envió ningún certificado
    if (!certToValidate) {
      console.warn(`[Bóveda Cloud ${timestamp}] ❌ ATAQUE DETECTADO: Petición recibida SIN certificado digital.`);
      console.warn(`[Bóveda Cloud ${timestamp}] 🛑 RESULTADO: HTTP 401 Unauthorized (MISSING_CLIENT_CERTIFICATE).`);
      return NextResponse.json(
        {
          success: false,
          error: 'Acceso Denegado: No se presentó ningún Certificado Digital de cliente.',
          code: 'MISSING_CLIENT_CERTIFICATE',
          detail:
            'Este endpoint requiere autenticación con certificado X.509 emitido por la Root CA de la Bóveda Segura.',
          timestamp: new Date().toISOString(),
        },
        { status: 401 }
      );
    }

    console.log(`[Bóveda Cloud ${timestamp}] 📜 Certificado X.509 recibido. Decodificando estructura...`);

    // B. Validación criptográfica de la firma de la CA, vigencia y revocación
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

    // C. Prueba de posesión: el certificado por sí solo NO autentica
    if (!challengeToken || !signature) {
      console.warn(
        `[Bóveda Cloud ${timestamp}] ⚠️ CERTIFICADO VÁLIDO PERO SIN PRUEBA DE POSESIÓN. ` +
          `No se recibió ${!challengeToken ? 'challengeToken' : 'signature'}.`
      );
      console.warn(`[Bóveda Cloud ${timestamp}] 🛑 RESULTADO: HTTP 403 Forbidden (PROOF_OF_POSSESSION_REQUIRED).`);
      return NextResponse.json(
        {
          success: false,
          error:
            'Prueba de posesión requerida: el certificado X.509 es público. Debes firmar el reto con tu llave privada.',
          code: 'PROOF_OF_POSSESSION_REQUIRED',
          detail:
            'Solicita un reto en GET /api/pki/challenge, firma el nonce con tu llave privada (RSA-SHA256) y reenvía signature + challengeToken.',
          timestamp: new Date().toISOString(),
        },
        { status: 403 }
      );
    }

    // D. Verificar el token del reto (HMAC, vigencia y un solo uso)
    const challengeCheck = verifyChallengeToken(challengeToken);
    if (!challengeCheck.valid) {
      console.warn(`[Bóveda Cloud ${timestamp}] ❌ RETO INVÁLIDO [${challengeCheck.code}]: ${challengeCheck.error}`);
      console.warn(`[Bóveda Cloud ${timestamp}] 🛑 RESULTADO: HTTP 403 Forbidden.`);
      return NextResponse.json(
        {
          success: false,
          error: challengeCheck.error,
          code: challengeCheck.code,
          timestamp: new Date().toISOString(),
        },
        { status: 403 }
      );
    }

    // E. Verificar la firma del nonce con la llave pública del certificado
    const signatureCheck = verifyChallengeSignature(
      challengeCheck.payload.nonce,
      signature,
      certToValidate
    );

    if (!signatureCheck.valid) {
      console.warn(`[Bóveda Cloud ${timestamp}] ❌ FIRMA DEL RETO INVÁLIDA: ${signatureCheck.error}`);
      console.warn(`[Bóveda Cloud ${timestamp}] 🛑 RESULTADO: HTTP 403 Forbidden (INVALID_CHALLENGE_SIGNATURE).`);
      return NextResponse.json(
        {
          success: false,
          error: signatureCheck.error,
          code: 'INVALID_CHALLENGE_SIGNATURE',
          timestamp: new Date().toISOString(),
        },
        { status: 403 }
      );
    }

    // F. Certificado válido + posesión de la llave privada demostrada
    console.log(`[Bóveda Cloud ${timestamp}] ✔ FIRMA VERIFICADA matemáticamente contra la Root CA de la Bóveda.`);
    console.log(`[Bóveda Cloud ${timestamp}] ✔ FECHAS DE VIGENCIA Y CRL: Certificado válido y no revocado.`);
    console.log(`[Bóveda Cloud ${timestamp}] ✔ RETO ${challengeCheck.payload.jti}: firma RSA-SHA256 válida (un solo uso).`);
    console.log(`[Bóveda Cloud ${timestamp}] 👤 CLIENTE AUTENTICADO: CN=${result.client?.commonName} | Org=${result.client?.organization}`);
    console.log(`[Bóveda Cloud ${timestamp}] 💰 AUTORIZANDO ACCESO A LA BÓVEDA CENTRAL (CTA-UNDC-2026-9948).`);

    return NextResponse.json({
      success: true,
      message: `Autenticación PKI Exitosa. Bienvenido, ${result.client?.commonName}.`,
      auth_details: {
        client: result.client,
        auth_method: 'Digital Certificate X.509 + Proof of Possession (challenge-response)',
        proof_of_possession: 'RSA-SHA256 (PKCS#1 v1.5) verificada con la llave pública del certificado',
        challenge_id: challengeCheck.payload.jti,
        challenge_expires_at: new Date(challengeCheck.payload.exp * 1000).toISOString(),
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
