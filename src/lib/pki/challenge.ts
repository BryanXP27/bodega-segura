import crypto from 'crypto';

/**
 * Reto criptográfico de un solo uso (Prueba de Posesión de la llave privada).
 *
 * Flujo:
 *  1. El cliente pide un reto a GET /api/pki/challenge.
 *  2. El servidor devuelve { token, nonce, expiresAt }. El token es un JWT-like
 *     firmado con HMAC-SHA256 por el propio servidor (no requiere almacenamiento).
 *  3. El cliente firma el `nonce` con su llave privada RSA (SHA-256, PKCS#1 v1.5)
 *     y envía { clientCertificate, challengeToken, signature }.
 *  4. El servidor valida el token, su vigencia, que no haya sido usado y verifica
 *     la firma con la llave pública del certificado presentado.
 *
 * Esto demuestra que quien llama posee la llave privada: el certificado X.509 es
 * público, la llave privada nunca viaja.
 */

const DEFAULT_TTL_SECONDS = 120;
const MAX_TTL_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 10;

export interface ChallengePayload {
  jti: string;
  nonce: string;
  iat: number;
  exp: number;
}

export interface IssuedChallenge {
  token: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  ttlSeconds: number;
  algorithm: string;
}

export type ChallengeFailureCode =
  | 'CHALLENGE_MALFORMED'
  | 'CHALLENGE_BAD_SIGNATURE'
  | 'CHALLENGE_EXPIRED'
  | 'CHALLENGE_NOT_YET_VALID'
  | 'CHALLENGE_ALREADY_USED';

export type ChallengeVerification =
  | { valid: true; payload: ChallengePayload }
  | { valid: false; code: ChallengeFailureCode; error: string };

// Almacén de retos ya consumidos (jti -> exp en ms).
// Nota: en Cloud Run con maxScale=1 la memoria es consistente. Si se escala a
// varias instancias, reemplazar por Firestore/Redis para garantizar single-use.
const globalStore = globalThis as unknown as {
  __bovedaPkiUsedChallenges?: Map<string, number>;
};

function usedChallenges(): Map<string, number> {
  if (!globalStore.__bovedaPkiUsedChallenges) {
    globalStore.__bovedaPkiUsedChallenges = new Map<string, number>();
  }
  return globalStore.__bovedaPkiUsedChallenges;
}

function purgeExpired(nowMs: number): void {
  const store = usedChallenges();
  for (const [jti, expMs] of store) {
    if (expMs < nowMs) store.delete(jti);
  }
}

function getSecret(): string {
  const secret =
    process.env.PKI_CHALLENGE_SECRET ||
    process.env.NEXTAUTH_SECRET ||
    'boveda-pki-demo-secret-change-in-production';
  return secret;
}

function hmac(body: string): Buffer {
  return crypto.createHmac('sha256', getSecret()).update(body, 'utf8').digest();
}

export function issueChallenge(ttlSeconds: number = DEFAULT_TTL_SECONDS): IssuedChallenge {
  const ttl = Math.min(Math.max(Math.trunc(ttlSeconds), 30), MAX_TTL_SECONDS);
  const now = Math.floor(Date.now() / 1000);

  const payload: ChallengePayload = {
    jti: crypto.randomUUID(),
    nonce: crypto.randomBytes(32).toString('base64url'),
    iat: now,
    exp: now + ttl,
  };

  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const mac = hmac(body).toString('base64url');

  return {
    token: `${body}.${mac}`,
    nonce: payload.nonce,
    issuedAt: new Date(payload.iat * 1000).toISOString(),
    expiresAt: new Date(payload.exp * 1000).toISOString(),
    ttlSeconds: ttl,
    algorithm: 'RSA-SHA256 (PKCS#1 v1.5)',
  };
}

export function verifyChallengeToken(token: string): ChallengeVerification {
  try {
    if (!token || typeof token !== 'string') {
      return {
        valid: false,
        code: 'CHALLENGE_MALFORMED',
        error: 'No se recibió un token de reto válido.',
      };
    }

    const parts = token.trim().split('.');
    if (parts.length !== 2) {
      return {
        valid: false,
        code: 'CHALLENGE_MALFORMED',
        error: 'Formato de token de reto inválido.',
      };
    }

    const [body, mac] = parts;
    const expected = hmac(body);
    const received = Buffer.from(mac, 'base64url');

    if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
      return {
        valid: false,
        code: 'CHALLENGE_BAD_SIGNATURE',
        error: 'El token de reto fue alterado o no lo emitió este servidor.',
      };
    }

    const payload = JSON.parse(
      Buffer.from(body, 'base64url').toString('utf8')
    ) as ChallengePayload;

    if (
      !payload ||
      typeof payload.jti !== 'string' ||
      typeof payload.nonce !== 'string' ||
      !Number.isFinite(payload.iat) ||
      !Number.isFinite(payload.exp)
    ) {
      return {
        valid: false,
        code: 'CHALLENGE_MALFORMED',
        error: 'Contenido del reto inválido.',
      };
    }

    const now = Math.floor(Date.now() / 1000);

    if (payload.iat > now + CLOCK_SKEW_SECONDS) {
      return {
        valid: false,
        code: 'CHALLENGE_NOT_YET_VALID',
        error: 'El reto aún no es válido (reloj del servidor adelantado).',
      };
    }

    if (now > payload.exp) {
      return {
        valid: false,
        code: 'CHALLENGE_EXPIRED',
        error: 'El reto expiró. Solicita uno nuevo (vigencia de 2 minutos).',
      };
    }

    purgeExpired(now * 1000);
    const store = usedChallenges();

    if (store.has(payload.jti)) {
      return {
        valid: false,
        code: 'CHALLENGE_ALREADY_USED',
        error: 'El reto ya fue utilizado. Cada reto es de un solo uso (anti-replay).',
      };
    }

    // Se consume el reto antes de validar la firma: un intento fallido también
    // invalida el token, evitando ataques de fuerza bruta sobre el mismo nonce.
    store.set(payload.jti, payload.exp * 1000);

    return { valid: true, payload };
  } catch {
    return {
      valid: false,
      code: 'CHALLENGE_MALFORMED',
      error: 'No se pudo decodificar el token de reto.',
    };
  }
}

export type SignatureVerification =
  | { valid: true }
  | { valid: false; error: string };

/**
 * Verifica una firma RSA-SHA256 (PKCS#1 v1.5) del nonce usando la llave pública
 * del certificado X.509 presentado por el cliente.
 */
export function verifyChallengeSignature(
  nonce: string,
  signatureBase64: string,
  certPem: string
): SignatureVerification {
  try {
    if (!signatureBase64 || typeof signatureBase64 !== 'string') {
      return { valid: false, error: 'No se recibió la firma del reto.' };
    }

    const cleaned = signatureBase64.replace(/\s+/g, '');
    const signature = Buffer.from(cleaned, 'base64');

    if (signature.length === 0) {
      return { valid: false, error: 'La firma del reto está vacía o no es base64 válido.' };
    }

    const cert = new crypto.X509Certificate(certPem);
    const isValid = crypto.verify(
      'sha256',
      Buffer.from(nonce, 'utf8'),
      cert.publicKey,
      signature
    );

    if (!isValid) {
      return {
        valid: false,
        error:
          'La firma del reto no corresponde a la llave privada del certificado presentado.',
      };
    }

    return { valid: true };
  } catch (err: any) {
    return {
      valid: false,
      error: `No se pudo verificar la firma del reto: ${err?.message || err}`,
    };
  }
}
