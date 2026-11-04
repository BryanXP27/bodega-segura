import crypto from 'crypto';

// ============================================================================
// Certificado Raiz de la Boveda Segura (Root CA) - ROTADO 2026-11-04
// Generado con OpenSSL (RSA 4096 + SHA-256). Es material PUBLICO.
// La llave privada (ca.key) vive fuera del repositorio: certs/private/ (git-ignored).
// ============================================================================
export const BOVEDA_ROOT_CA_CERT = `-----BEGIN CERTIFICATE-----
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
R0g3iWJcQSVzK7U2Xqa1rw1UCA==
-----END CERTIFICATE-----`;

// Certificado PUBLICO del cliente autorizado (demo web).
// No es un secreto: los certificados X.509 son publicos por diseno. El acceso
// solo se concede si el cliente ADEMAS firma el reto con client.key (nunca publicada).
export const DEMO_CLIENT_CERT = `-----BEGIN CERTIFICATE-----
MIIFoTCCA4mgAwIBAgIUTVTMjyNZ3qxYIe26NqOdHcs5G8IwDQYJKoZIhvcNAQEL
BQAwgaYxCzAJBgNVBAYTAlBFMQ0wCwYDVQQIDARMaW1hMQ8wDQYDVQQHDAZDYW5l
dGUxJTAjBgNVBAoMHFVOREMgLSBTZWd1cmlkYWQgSW5mb3JtYXRpY2ExEDAOBgNV
BAsMB1Jvb3QgQ0ExHjAcBgNVBAMMFUJvdmVkYSBTZWd1cmEgUm9vdCBDQTEeMBwG
CSqGSIb3DQEJARYPcGtpQHVuZGMuZWR1LnBlMB4XDTI2MTEwNDIzMjIzNloXDTI3
MTEwNDIzMjIzNlowgaExCzAJBgNVBAYTAlBFMQ0wCwYDVQQIDARMaW1hMQ8wDQYD
VQQHDAZDYW5ldGUxDTALBgNVBAoMBFVOREMxHjAcBgNVBAsMFU9wZXJhY2lvbmVz
IEJhbmNhcmlhczEbMBkGA1UEAwwSY2xpZW50ZS1kZXNrdG9wLTAxMSYwJAYJKoZI
hvcNAQkBFhdvcGVyYWRvckBib3ZlZGEudW5kYy5wZTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAMwauHBXM1i+FWNkc3U96giRmVSCEdWkdGXHlxQJKnjw
4BYVM9fZcwNLZR17DqIDA0Qg6g/zuYGyqZqioM/5iUqavREN59pZv8I10zmEO2kD
Q7+/6Q7eLzy6STcrfyju5ulMzpGx8pSkNiWY/BsCDOmmg129fHZQrZJR9wOZtCvA
mhqZDphREA8eX6AOSBkqQzT7XbO1SYmvQM6ok7ySDxGG3kJ+/IOtBOQk3CVkVTR3
EIHb1wwqkwU21NjPZgANr0EmRGkjQwD2JnY3R3cROCzEMx/gotM2GHhm5/HKo4vH
ki/XURHBqk/HpGzK8n+02RU+bvsAzQq/Z4G0fC1XLV0CAwEAAaOByTCBxjAJBgNV
HRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIFoDA3BglghkgBhvhCAQ0EKhYoQ2VydGlm
aWNhZG8gZGUgQ2xpZW50ZSBtVExTIC0gUHJveWVjdG8gMzAdBgNVHQ4EFgQU1im8
cL3uq82uE1IRKW+X7hLFZjowHwYDVR0jBBgwFoAUv/rnPulLLxxwZhn401DGmf51
0/cwDgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
BDANBgkqhkiG9w0BAQsFAAOCAgEAth6py8ntRC4kH10Y2n7GqLNDpQmw8ArZ3AEy
Ff6kSuzWLlS2ehzL+9ZQWrTmfe3EW1DMDCfWFyzPRFIPg3xpx9l1EkpgfFfYvWJi
+GMN8yQHJ4liZPgZq+QHMXWjoSNA6dXB4Wxqz5tw8Cy0uOIv+/7vBv7jzgBIClCv
IhKs6lcPByAK4aqUTaRyMmp+Ezd+Ddz+UzZR3dNmTeqhFXwxPZER/9tXPBESxYP5
Cpn27CE6GhDH4OhyFeWlvUGFQj2ELJ4LrvQwXTyYIe5INiQm/rRIU2h1IAe1jlSv
fsxae9GbtiLzszrONPlidIaGtJChDOS6TEBCfUegrqjg09Wnp2PK274kO3tMlER+
E7cijd8xKQpOtAvLiNvLtb4F5RdtiuOqYVZ1DABSQWPxIuRpEwh717z9g2hGlc8j
aLu5Ulsl5XsOfb0UTxz1sfTV8KOVtxFQhstKvI3Zd1KS7/yQjbh0OglS0aMEECQf
QMB1nBa1k9RFCqRTz11WjXzjfV1gl214TfGehkydhCdCzZUcJxo0cIvqK+LLwqPK
n+sESFjGRjxoVO6nOTpEPkXr388A/HxK6af8zG4opqYp2q+RbhUi6nPX9MIjigsO
f98tXO6TrN7YUx1ZwK97kRnz1uFNOkuY0O02xKb5FpMHJYmXhMMJtVv/JRv5evG4
+KHAvW8=
-----END CERTIFICATE-----`;

// Certificado de OTRA CA no autorizada (Rogue CA) - material publico de demo.
export const ATTACKER_CERT = `-----BEGIN CERTIFICATE-----
MIIDlTCCAn2gAwIBAgIUAmwGU0a9syLbG4Ui187J5XBXsGUwDQYJKoZIhvcNAQEL
BQAwaTELMAkGA1UEBhMCWFgxEDAOBgNVBAgMB1Vua25vd24xEDAOBgNVBAcMB05v
d2hlcmUxFDASBgNVBAoMC0NBIEF0YWNhbnRlMSAwHgYDVQQDDBdSb2d1ZSBNYWxp
Y2lvdXMgUm9vdCBDQTAeFw0yNjExMDQyMzIyMzZaFw0yNzExMDQyMzIyMzZaMFwx
CzAJBgNVBAYTAlhYMRAwDgYDVQQIDAdVbmtub3duMRAwDgYDVQQHDAdOb3doZXJl
MREwDwYDVQQKDAhBdGFjYW50ZTEWMBQGA1UEAwwNaGFja2VyLWNsaWVudDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI4acBBefDL+yo6uGTH7wUo+vnVj
xJvcin1WG0vZAJnRXlrhvW0uJMxFQTsOKLbU8hXJkSSJw8zHpwiQEOr2eB4tHWLm
KgT09SrNKpkBNvaP82VO3lkmHWHfdWsUiFaZtEzh9mNXLxmMffWdnPBtuZHiZdfn
zAImYLH7LDal3tIOY/HV/qtza69wtbTUrru9ydy/cxW2xTj8EQXYBEi5o3o5SknQ
xf6OUsF3Bus9RIK7UTMUUWQAxpVa++L4uNB2V3YkTdT2FoOAy+vewkiwbtPhtZyf
EiL6K9PPyv8hWVH7C/pRGsgbuAdnfF0eogHszCpYb5/wBf/UZ1ZfGz6nmk0CAwEA
AaNCMEAwHQYDVR0OBBYEFPxB7rxa2ZJ6t6+cW/+P4WpxISKvMB8GA1UdIwQYMBaA
FBM+PHyoQygEJED/kCSL0YTHIG+3MA0GCSqGSIb3DQEBCwUAA4IBAQBeu8xwB7sx
TT0z0eddLTOQCn2P5MN6ROxKuGYRrgpInRzAW8XZRRyrEQDRiWJFrpLP4TrLjTAb
CoWl+mRnwYQNE91RJrp/V+GXomrjBhmC4ayOLiafOghVJVXU/uw3d9f7R1AA/l7s
zgbGTU9PxnAiq0/9z5uuuHKELlDzC0keedvrBE3J8ikOneaCQb/pByWg8EjChHCM
3u5Anldb6ayNQFTPejV6nOCKkXArfeUW1F+fY/ILppKioZ6+aNnNvAc89oDuNlUq
Q4135lUijmeeyUa9dsQdDKnKJ93tdIDWNCMYOAcOCvIYUyINXVADUquoaYZEXgxM
5gqsXRIN+Xf3
-----END CERTIFICATE-----`;

// Numeros de serie revocados. Se pueden cargar por variable de entorno para
// revocar sin recompilar: PKI_REVOKED_SERIALS="ABC123,DEF456".
// (La CRL firmada por OpenSSL se incorpora en la fase P1.)
export const REVOKED_SERIAL_NUMBERS = (process.env.PKI_REVOKED_SERIALS || '')
  .split(',')
  .map((s) => s.replace(/[^0-9a-fA-F]/g, '').toUpperCase())
  .filter(Boolean);

export interface ValidationResult {
  valid: boolean;
  code?: string;
  error?: string;
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

export function validateClientCertificate(
  certDataOrPem: string,
  caPem: string = BOVEDA_ROOT_CA_CERT
): ValidationResult {
  try {
    let pem = certDataOrPem.trim();
    if (!pem.includes('-----BEGIN CERTIFICATE-----')) {
      pem = `-----BEGIN CERTIFICATE-----\n${pem}\n-----END CERTIFICATE-----`;
    }

    const clientCert = new crypto.X509Certificate(pem);
    const caCert = new crypto.X509Certificate(caPem);

    const now = new Date();
    const validFrom = new Date(clientCert.validFrom);
    const validTo = new Date(clientCert.validTo);

    // 1. Fechas de vigencia
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

    // 2. Lista de revocación (CRL)
    const serial = clientCert.serialNumber.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
    if (REVOKED_SERIAL_NUMBERS.includes(serial)) {
      return {
        valid: false,
        code: 'CERTIFICATE_REVOKED',
        error: `El certificado con serie ${clientCert.serialNumber} se encuentra en la Lista de Revocación de Certificados (CRL).`,
      };
    }

    // 3. Verificación de la firma de la Root CA (Cadena de Confianza PKI)
    const isSignedByCA = clientCert.verify(caCert.publicKey);
    if (!isSignedByCA) {
      return {
        valid: false,
        code: 'INVALID_ISSUER_CA',
        error:
          'Firma no confiable: El certificado presentado NO fue emitido ni firmado por la Root CA de la Bóveda Segura.',
      };
    }

    // 4. Un certificado de CA no puede usarse como credencial de cliente.
    const isCa = (clientCert as unknown as { ca?: boolean }).ca === true;
    if (isCa) {
      return {
        valid: false,
        code: 'CA_CERTIFICATE_NOT_ALLOWED',
        error: 'El certificado presentado es una CA y no puede autenticarse como cliente.',
      };
    }

    const subjectParsed = parseDN(clientCert.subject);

    return {
      valid: true,
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
