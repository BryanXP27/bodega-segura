import crypto from 'crypto';

// Certificado Raiz de la Boveda Segura (Root CA)
// Generado con OpenSSL (RSA 4096 + SHA-256)
export const BOVEDA_ROOT_CA_CERT = `-----BEGIN CERTIFICATE-----
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
uy7NqJfYUBSOPU62mEhHAXZ3kw==
-----END CERTIFICATE-----`;

// Certificado Valido de Cliente emitido por la CA (para pruebas en la nube)
export const CLIENT_VALID_CERT = `-----BEGIN CERTIFICATE-----
MIIFoTCCA4mgAwIBAgIUGWarGS6ysSIqw/HZiTu42NO/GScwDQYJKoZIhvcNAQEL
BQAwgaYxCzAJBgNVBAYTAlBFMQ0wCwYDVQQIDARMaW1hMQ8wDQYDVQQHDAZDYW5l
dGUxJTAjBgNVBAoMHFVOREMgLSBTZWd1cmlkYWQgSW5mb3JtYXRpY2ExEDAOBgNV
BAsMB1Jvb3QgQ0ExHjAcBgNVBAMMFUJvdmVkYSBTZWd1cmEgUm9vdCBDQTEeMBwG
CSqGSIb3DQEJARYPcGtpQHVuZGMuZWR1LnBlMB4XDTI2MTEwMTE2NTUyM1oXDTI3
MTEwMTE2NTUyM1owgaExCzAJBgNVBAYTAlBFMQ0wCwYDVQQIDARMaW1hMQ8wDQYD
VQQHDAZDYW5ldGUxDTALBgNVBAoMBFVOREMxHjAcBgNVBAsMFU9wZXJhY2lvbmVz
IEJhbmNhcmlhczEbMBkGA1UEAwwSY2xpZW50ZS1kZXNrdG9wLTAxMSYwJAYJKoZI
hvcNAQkBFhdvcGVyYWRvckBib3ZlZGEudW5kYy5wZTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALowA+roxFr59aR7A/q9iFiMe5juZLWbkq1eZzoK/o6a
PtH8MnxNlUUt+PidLRnS/PHqx52ug2TDo0SnecQyKURIAie+2AKW8Y+K9iNEtGmz
lG3buPrSLQlnS2nm3O8pQxpo2YwZ8guAcxMr90HJDUJKh5vOS3OvufdmB7rvZD02
26LtJgTl4FFuaFQbHfmDid6A39l3EYKR9R54HcDpsemisCuMtUucRwMH9W6ING1F
y7jjVWokVQXrFFyRBSFcATkzhF9rK9BCTKbc+TarVs+jN+0d5LNWTiHtIrTV/etq
nDLnVUaCjYmJqbNTZhHibttObGVs08L8jgMsFmQYiq8CAwEAAaOByTCBxjAJBgNV
HRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIFoDA3BglghkgBhvhCAQ0EKhYoQ2VydGlm
aWNhZG8gZGUgQ2xpZW50ZSBtVExTIC0gUHJveWVjdG8gMzAdBgNVHQ4EFgQUxEbA
q0cn8XX2dN2QQnIfg1zhHR4wHwYDVR0jBBgwFoAUEny/v6sjc4dfUe05oifz/zY/
ivowDgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
BDANBgkqhkiG9w0BAQsFAAOCAgEAff6Jp9JihCMdvNqIrXIzp6Q1pwthT3dUIxmy
5Y4aB9OoH3WrmS0fVQtmH50RXvhW8IscYaTdO2C34q/qWjXJXaBXaS3tFzURc4/T
9YXhyeAU8v+zmoj2cqHO/HcLQUUKKe7u+TW++8f94fz2BycpNEh3vVzzP1eF9SPd
hPLHCgW8tCjvKEE/J45yv/HsitrJenfzfaLTL4ogP4KNbqw52qZiBgQpN29rQEBn
PUtuRpL+9aA2VTXIGfP73v9U3jSJh/qNqSgZfa3+b1iINzSYQbXeYgG8OWPzFTFJ
atxStOqQvcK6rDBbNWZ5skw2bM2PLO5PldsozYyyFhzKTVGiIq2JTGLJdWbeZv8N
U4fAtiZQ3GEIObL18GT/QLnydkj79m5N4L3h8cvFy8ja8e5gxvHVimmGhCpXHzkU
v4c/Q4YJ+lk01wRm9vPsiTb65F0dd0gcHn9JcdYVp+4TYKm8hzgDeyUcMgy4v2EX
y7kEc7Lx5HBecBBD+91DhJZ3W0Chr1nIWfNoYHOwc5mtXXcOTeYjoud9bBFHQ5ii
i+humDGTzBiFVoJNg5g2d/7JKb2UvDlyzlErzfLUfkSOA/gHZ0BzMqZ1f9tmB2wT
kkkdsxojqIRFHSK0/RDx2wb2fdhIkby4/fxIKBHA2Wmriw6o9XokvyPkSmp3n0Lw
ZoeBBUA=
-----END CERTIFICATE-----`;

// Certificado de OTRA CA no autorizada (Rogue CA)
export const ATTACKER_CERT = `-----BEGIN CERTIFICATE-----
MIIDlTCCAn2gAwIBAgIUDHkpgwPoLrXYhfP3op7t11CC7rEwDQYJKoZIhvcNAQEL
BQAwaTELMAkGA1UEBhMCWFgxEDAOBgNVBAgMB1Vua25vd24xEDAOBgNVBAcMB05v
d2hlcmUxFDASBgNVBAoMC0NBIEF0YWNhbnRlMSAwHgYDVQQDDBdSb2d1ZSBNYWxp
Y2lvdXMgUm9vdCBDQTAeFw0yNjExMDExNjU1MjNaFw0yNzExMDExNjU1MjNaMFwx
CzAJBgNVBAYTAlhYMRAwDgYDVQQIDAdVbmtub3duMRAwDgYDVQQHDAdOb3doZXJl
MREwDwYDVQQKDAhBdGFjYW50ZTEWMBQGA1UEAwwNaGFja2VyLWNsaWVudDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANcuYmGMWnqyU0FEm+5ccppEWs27
1jLR3U8hsMEqCbjhZ6yng9DC93G+WH669oBtdmkkR0TAyEMrFZH2VrBoKLDe4ax3
OvSgVl/IT1Y6CYw4qaOTtAWnWaeyLqA2pkDPyCUNvLAKgtd5aYPhbfJWo1KdALjW
LoPq4ocA3CNYy3F2VwyrQo6y4cjEijUtoIJlPGePl4k0iu+saFS0+CucHOFgAeno
xHPAd2SGanxS88c1qNaV4rC2y15x9TYQL8zU8jE0L6bXT5e9Cp1sCHg2Pc1FEKg5
m49v7Dz4h8G7yXjkfaZb56sZiXXW0WS7W6yDSzdutKWL/DbjXitkLa42ZVkCAwEA
AaNCMEAwHQYDVR0OBBYEFNFRrxqDlG275XGOYonrPyLE+II9MB8GA1UdIwQYMBaA
FPrTfLpfY7F0XMlRZY6suvohqSZKMA0GCSqGSIb3DQEBCwUAA4IBAQA0KZE4J9hI
DJcC21BK8LvRtLxWUghUEZU8AzpCTvepk2M2Ep57RLEhYvxwMXgVx00XKeliZ/3H
ifGq5fMf22nfGWMO3QnP64tvHrijQCM5koN9u5kKlg985HQ7kSwpe14+b7PW5aSJ
+uMGbBKaZZZ1OCOr1dcY8BDxnanLpK+NvpuVN/AxB9zW6DgA6mwa0lbkvaxKdWfi
g00MJu2w343GIH6FfVZv3IBSZAZ3iwy949mFBRMFCqXvE4X/QXgdNWKYSRZyTheH
NwEFirDp58BQGJcRVJfvkgKXviNnWjEYKiKoxVDo+vHTkaoiyYIVujLCPZoZZRoX
WTUWsWokrbjp
-----END CERTIFICATE-----`;

// Lista de numeros de serie revocados (CRL)
export const REVOKED_SERIAL_NUMBERS = [
  '9999999999',
];

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
    if (REVOKED_SERIAL_NUMBERS.includes(clientCert.serialNumber)) {
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
