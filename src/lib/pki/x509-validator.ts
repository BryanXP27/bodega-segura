import crypto from 'crypto';
import {
  BOVEDA_ROOT_CA_CERT,
  DEMO_CLIENT_CERT,
  DEMO_ATTACKER_CERT,
  DEMO_REVOKED_CERT,
  DEMO_EXPIRED_CERT,
} from './certs';
import { BOVEDA_CRL_PEM, BOVEDA_CRL_GENERATED_AT } from './crl';
import { normalizeSerialNumber, verifyCrl } from './crl-parser';
import { findSessionByCertificate, getPkiSession } from './session-pki';

// Reexporta el material público para que las rutas de la app lo consuman
export {
  BOVEDA_ROOT_CA_CERT,
  DEMO_CLIENT_CERT,
  DEMO_ATTACKER_CERT,
  DEMO_REVOKED_CERT,
  DEMO_EXPIRED_CERT,
  BOVEDA_CRL_PEM,
  BOVEDA_CRL_GENERATED_AT,
};

export const REVOKED_SERIAL_NUMBERS = (process.env.PKI_REVOKED_SERIALS || '')
  .split(',')
  .map((s) => normalizeSerialNumber(s))
  .filter((s) => s !== '0');

export interface ValidationResult {
  valid: boolean;
  code?: string;
  error?: string;
  sessionId?: string;
  sessionRemainingUses?: number;
  sessionMaxUses?: number;
  client?: {
    commonName: string;
    organization?: string;
    organizationalUnit?: string;
    country?: string;
    email?: string;
    serialNumber: string;
    fingerprint256: string;
    validFrom: string;
    validTo: string;
    issuer: string;
  };
}

function parseDN(dnString: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = dnString.split('\n');
  for (const line of lines) {
    const parts = line.split('=');
    if (parts.length >= 2) {
      const key = parts[0].trim();
      const val = parts.slice(1).join('=').trim();
      result[key] = val;
    }
  }
  return result;
}

/**
 * Valida un certificado de cliente X.509 contra la Root CA (estática o dinámica de sesión)
 * y la CRL correspondiente.
 */
export function validateClientCertificate(
  certDataOrPem: string,
  caPem?: string,
  sessionHintId?: string
): ValidationResult {
  try {
    let pem = certDataOrPem.trim();
    if (!pem.includes('-----BEGIN CERTIFICATE-----')) {
      pem = `-----BEGIN CERTIFICATE-----\n${pem}\n-----END CERTIFICATE-----`;
    }

    const clientCert = new crypto.X509Certificate(pem);

    // 1. Verificar si pertenece a una Sesión Dinámica Interactiva
    let activeSession = sessionHintId ? getPkiSession(sessionHintId) : undefined;
    if (!activeSession) {
      activeSession = findSessionByCertificate(pem);
    }

    // Determinar la CA a usar
    const effectiveCaPem = caPem || activeSession?.ca.certPem || BOVEDA_ROOT_CA_CERT;
    const caCert = new crypto.X509Certificate(effectiveCaPem);

    // 2. Firma de la Root CA (cadena de confianza PKI)
    const isSignedByCA = clientCert.verify(caCert.publicKey);
    if (!isSignedByCA) {
      return {
        valid: false,
        code: 'INVALID_ISSUER_CA',
        error:
          'Firma no confiable: El certificado presentado NO fue emitido ni firmado por la Root CA de la Bóveda Segura.',
      };
    }

    // 3. Un certificado de CA no puede usarse como credencial de cliente.
    const isCa = (clientCert as unknown as { ca?: boolean }).ca === true;
    if (isCa) {
      return {
        valid: false,
        code: 'CA_CERTIFICATE_NOT_ALLOWED',
        error: 'El certificado presentado es una CA y no puede autenticarse como cliente.',
      };
    }

    // 4. Fechas de vigencia temporal
    const now = new Date();
    const validFrom = new Date(clientCert.validFrom);
    const validTo = new Date(clientCert.validTo);

    if (now < validFrom) {
      return {
        valid: false,
        code: 'CERTIFICATE_NOT_YET_VALID',
        error: `El certificado aún no es válido. Vigencia inicia el: ${clientCert.validFrom}`,
      };
    }

    if (now > validTo) {
      return {
        valid: false,
        code: 'CERTIFICATE_EXPIRED',
        error: `El certificado digital ha expirado. Expiró el: ${clientCert.validTo}`,
      };
    }

    // 5. Revocación (Sesión dinámica o CRL estática)
    const serial = normalizeSerialNumber(clientCert.serialNumber);

    if (activeSession) {
      if (
        serial === normalizeSerialNumber(activeSession.revoked.serialNumber) ||
        clientCert.subject.includes('despedido')
      ) {
        return {
          valid: false,
          code: 'CERTIFICATE_REVOKED',
          error: `El certificado con serie ${clientCert.serialNumber} se encuentra en la Lista de Revocación de Certificados (CRL) de la sesión ${activeSession.sessionId}.`,
        };
      }
    } else {
      const crl = verifyCrl(BOVEDA_CRL_PEM, effectiveCaPem);
      if (!crl.valid) {
        return {
          valid: false,
          code: crl.code,
          error: `No se pudo validar la Lista de Revocación de Certificados (CRL): ${crl.error}`,
        };
      }

      const revokedByCrl = crl.revokedSerials.includes(serial);
      const revokedByEnv = REVOKED_SERIAL_NUMBERS.includes(serial);

      if (revokedByCrl || revokedByEnv) {
        return {
          valid: false,
          code: 'CERTIFICATE_REVOKED',
          error: `El certificado con serie ${clientCert.serialNumber} se encuentra en la Lista de Revocación de Certificados (CRL) firmada por la Root CA.`,
        };
      }
    }

    const subjectParsed = parseDN(clientCert.subject);

    return {
      valid: true,
      sessionId: activeSession?.sessionId,
      sessionRemainingUses: activeSession?.remainingUses,
      sessionMaxUses: activeSession?.maxUses,
      client: {
        commonName: subjectParsed['CN'] || 'desconocido',
        organization: subjectParsed['O'],
        organizationalUnit: subjectParsed['OU'],
        country: subjectParsed['C'],
        email: subjectParsed['emailAddress'],
        serialNumber: clientCert.serialNumber,
        fingerprint256: clientCert.fingerprint256,
        validFrom: clientCert.validFrom,
        validTo: clientCert.validTo,
        issuer: clientCert.issuer.replace(/\n/g, ', '),
      },
    };
  } catch (err: any) {
    return {
      valid: false,
      code: 'MALFORMED_CERTIFICATE',
      error: `Formato de certificado X.509 inválido: ${err?.message || err}`,
    };
  }
}
