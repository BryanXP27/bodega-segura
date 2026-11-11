import crypto from 'crypto';
// eslint-disable-next-line @typescript-eslint/no-require-imports
import forge from 'node-forge';

export interface PkiSession {
  sessionId: string;
  sessionNumber: number;
  createdAt: string;
  expiresAt: string;
  maxUses: number;
  usesCount: number;
  remainingUses: number;
  
  // Autoridad Certificadora (Root CA)
  ca: {
    commonName: string;
    organization: string;
    serialNumber: string;
    fingerprint256: string;
    certPem: string;
    privateKeyPem: string;
  };

  // Certificado de Cliente Válido (firmado por la CA propia)
  client: {
    commonName: string;
    organization: string;
    serialNumber: string;
    fingerprint256: string;
    certPem: string;
    privateKeyPem: string;
  };

  // Escenarios de prueba generados específicamente para esta sesión:
  attacker: {
    commonName: string;
    caName: string;
    certPem: string;
    privateKeyPem: string;
  };

  revoked: {
    commonName: string;
    serialNumber: string;
    certPem: string;
    crlPem: string;
  };

  expired: {
    commonName: string;
    serialNumber: string;
    expiredDate: string;
    certPem: string;
  };

  auditLog: Array<{
    timestamp: string;
    action: string;
    status: string;
    detail: string;
    usesLeft: number;
  }>;
}

// Almacén en memoria de sesiones activas (persistente durante la vida del proceso)
declare global {
  // eslint-disable-next-line no-var
  var __PKI_SESSIONS__: Map<string, PkiSession> | undefined;
  // eslint-disable-next-line no-var
  var __PKI_SESSION_COUNTER__: number | undefined;
}

const sessions: Map<string, PkiSession> = globalThis.__PKI_SESSIONS__ || new Map();
globalThis.__PKI_SESSIONS__ = sessions;

let sessionCounter: number = globalThis.__PKI_SESSION_COUNTER__ || 100;
globalThis.__PKI_SESSION_COUNTER__ = sessionCounter;

/**
 * Genera una nueva Autoridad Certificadora (CA) y certificados de cliente únicos
 * con cuota de 3 usos.
 */
export function generateInteractivePkiSession(): PkiSession {
  sessionCounter += 1;
  globalThis.__PKI_SESSION_COUNTER__ = sessionCounter;

  const sessionRandom = crypto.randomBytes(3).toString('hex').toUpperCase();
  const sessionId = `PKI-SESION-${sessionCounter}-${sessionRandom}`;

  // 1. Generar llaves RSA ultra rápidas con native crypto
  const caKeys = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const clientKeys = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const attackerCaKeys = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const attackerClientKeys = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const revokedKeys = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const expiredKeys = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Convertir a objetos Forge
  const caPrivateForge = forge.pki.privateKeyFromPem(caKeys.privateKey);
  const caPublicForge = forge.pki.publicKeyFromPem(caKeys.publicKey);

  const now = new Date();
  const oneYearLater = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  // 2. Crear Certificado Root CA institucional propio
  const caCommonName = `Bóveda Segura Root CA [${sessionId}]`;
  const caCert = forge.pki.createCertificate();
  caCert.publicKey = caPublicForge;
  caCert.serialNumber = '01' + crypto.randomBytes(6).toString('hex');
  caCert.validity.notBefore = now;
  caCert.validity.notAfter = oneYearLater;

  const caAttrs = [
    { name: 'commonName', value: caCommonName },
    { name: 'countryName', value: 'PE' },
    { name: 'organizationName', value: 'Universidad Nacional de Cañete' },
    { name: 'organizationalUnitName', value: 'Laboratorio de Seguridad Criptográfica' },
  ];
  caCert.setSubject(caAttrs);
  caCert.setIssuer(caAttrs);
  caCert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, digitalSignature: true },
  ]);
  caCert.sign(caPrivateForge, forge.md.sha256.create());
  const caCertPem = forge.pki.certificateToPem(caCert);

  const nodeCaCert = new crypto.X509Certificate(caCertPem);

  // 3. Crear Certificado de Cliente Válido (firmado por la CA)
  const clientCommonName = `cliente-${sessionCounter}-${sessionRandom.toLowerCase()}@undc.edu.pe`;
  const clientCert = forge.pki.createCertificate();
  clientCert.publicKey = forge.pki.publicKeyFromPem(clientKeys.publicKey);
  const clientSerial = '02' + crypto.randomBytes(6).toString('hex');
  clientCert.serialNumber = clientSerial;
  clientCert.validity.notBefore = now;
  clientCert.validity.notAfter = oneYearLater;

  const clientAttrs = [
    { name: 'commonName', value: clientCommonName },
    { name: 'countryName', value: 'PE' },
    { name: 'organizationName', value: 'Universidad Nacional de Cañete' },
    { name: 'organizationalUnitName', value: 'Terminal Financiero Autorizado' },
  ];
  clientCert.setSubject(clientAttrs);
  clientCert.setIssuer(caAttrs);
  clientCert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
  ]);
  clientCert.sign(caPrivateForge, forge.md.sha256.create());
  const clientCertPem = forge.pki.certificateToPem(clientCert);
  const nodeClientCert = new crypto.X509Certificate(clientCertPem);

  // 4. Crear Certificado Rogue / Atacante (firmado por CA Falsa)
  const attackerCaPrivate = forge.pki.privateKeyFromPem(attackerCaKeys.privateKey);
  const attackerCaPublic = forge.pki.publicKeyFromPem(attackerCaKeys.publicKey);
  const rogueCaAttrs = [
    { name: 'commonName', value: `Rogue Malicious Root CA [${sessionRandom}]` },
    { name: 'countryName', value: 'RU' },
    { name: 'organizationName', value: 'DarkWeb Syndicate' },
  ];
  const rogueCaCert = forge.pki.createCertificate();
  rogueCaCert.publicKey = attackerCaPublic;
  rogueCaCert.serialNumber = '66' + crypto.randomBytes(6).toString('hex');
  rogueCaCert.validity.notBefore = now;
  rogueCaCert.validity.notAfter = oneYearLater;
  rogueCaCert.setSubject(rogueCaAttrs);
  rogueCaCert.setIssuer(rogueCaAttrs);
  rogueCaCert.setExtensions([{ name: 'basicConstraints', cA: true }]);
  rogueCaCert.sign(attackerCaPrivate, forge.md.sha256.create());

  const attackerCert = forge.pki.createCertificate();
  attackerCert.publicKey = forge.pki.publicKeyFromPem(attackerClientKeys.publicKey);
  attackerCert.serialNumber = '67' + crypto.randomBytes(6).toString('hex');
  attackerCert.validity.notBefore = now;
  attackerCert.validity.notAfter = oneYearLater;
  attackerCert.setSubject([
    { name: 'commonName', value: `hacker-${sessionRandom}@darkweb.org` },
    { name: 'organizationName', value: 'Fake Organization' },
  ]);
  attackerCert.setIssuer(rogueCaAttrs);
  attackerCert.setExtensions([{ name: 'basicConstraints', cA: false }]);
  attackerCert.sign(attackerCaPrivate, forge.md.sha256.create());
  const attackerCertPem = forge.pki.certificateToPem(attackerCert);

  // 5. Crear Certificado Revocado + CRL
  const revokedSerial = '03' + crypto.randomBytes(6).toString('hex');
  const revokedCert = forge.pki.createCertificate();
  revokedCert.publicKey = forge.pki.publicKeyFromPem(revokedKeys.publicKey);
  revokedCert.serialNumber = revokedSerial;
  revokedCert.validity.notBefore = now;
  revokedCert.validity.notAfter = oneYearLater;
  revokedCert.setSubject([
    { name: 'commonName', value: `empleado-despedido-${sessionRandom}@undc.edu.pe` },
    { name: 'organizationName', value: 'Universidad Nacional de Cañete' },
  ]);
  revokedCert.setIssuer(caAttrs);
  revokedCert.sign(caPrivateForge, forge.md.sha256.create());
  const revokedCertPem = forge.pki.certificateToPem(revokedCert);

  // CRL simbólica para la sesión (almacenamos el serial revocado en memoria)
  const crlPem = `-----BEGIN X509 CRL-----
${Buffer.from(`CRL_SESSION_${sessionId}_REVOKED_SERIALS:${revokedSerial}`).toString('base64')}
-----END X509 CRL-----`;

  // 6. Crear Certificado Vencido (notBefore 2020, notAfter 2021)
  const expiredCert = forge.pki.createCertificate();
  expiredCert.publicKey = forge.pki.publicKeyFromPem(expiredKeys.publicKey);
  expiredCert.serialNumber = '04' + crypto.randomBytes(6).toString('hex');
  expiredCert.validity.notBefore = new Date('2020-01-01T00:00:00Z');
  expiredCert.validity.notAfter = new Date('2021-12-31T23:59:59Z');
  expiredCert.setSubject([
    { name: 'commonName', value: `certificado-antiguo-${sessionRandom}@undc.edu.pe` },
    { name: 'organizationName', value: 'Universidad Nacional de Cañete' },
  ]);
  expiredCert.setIssuer(caAttrs);
  expiredCert.sign(caPrivateForge, forge.md.sha256.create());
  const expiredCertPem = forge.pki.certificateToPem(expiredCert);

  const session: PkiSession = {
    sessionId,
    sessionNumber: sessionCounter,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 2 * 60 * 60 * 1000).toISOString(),
    maxUses: 3,
    usesCount: 0,
    remainingUses: 3,
    ca: {
      commonName: caCommonName,
      organization: 'Universidad Nacional de Cañete',
      serialNumber: nodeCaCert.serialNumber,
      fingerprint256: nodeCaCert.fingerprint256,
      certPem: caCertPem,
      privateKeyPem: caKeys.privateKey,
    },
    client: {
      commonName: clientCommonName,
      organization: 'Universidad Nacional de Cañete',
      serialNumber: nodeClientCert.serialNumber,
      fingerprint256: nodeClientCert.fingerprint256,
      certPem: clientCertPem,
      privateKeyPem: clientKeys.privateKey,
    },
    attacker: {
      commonName: `hacker-${sessionRandom}@darkweb.org`,
      caName: `Rogue Malicious Root CA [${sessionRandom}]`,
      certPem: attackerCertPem,
      privateKeyPem: attackerClientKeys.privateKey,
    },
    revoked: {
      commonName: `empleado-despedido-${sessionRandom}@undc.edu.pe`,
      serialNumber: revokedSerial,
      certPem: revokedCertPem,
      crlPem,
    },
    expired: {
      commonName: `certificado-antiguo-${sessionRandom}@undc.edu.pe`,
      serialNumber: expiredCert.serialNumber,
      expiredDate: '2021-12-31 23:59:59 UTC',
      certPem: expiredCertPem,
    },
    auditLog: [
      {
        timestamp: now.toISOString(),
        action: 'GENERAR_PKI',
        status: 'OK',
        detail: `Autoridad Certificadora y llaves RSA 2048 generadas para ${sessionId}. Cuota asignada: 3 usos.`,
        usesLeft: 3,
      },
    ],
  };

  sessions.set(sessionId, session);
  return session;
}

/**
 * Obtiene una sesión PKI por su ID.
 */
export function getPkiSession(sessionId: string): PkiSession | undefined {
  return sessions.get(sessionId);
}

/**
 * Busca una sesión activa que coincida con el certificado presentado (por serial o fingerprint).
 */
export function findSessionByCertificate(certPem: string): PkiSession | undefined {
  try {
    const cert = new crypto.X509Certificate(certPem);
    for (const session of sessions.values()) {
      // Coincidencia con el certificado de cliente de la sesión
      if (
        session.client.fingerprint256 === cert.fingerprint256 ||
        session.client.serialNumber === cert.serialNumber ||
        cert.issuer.includes(session.sessionId)
      ) {
        return session;
      }
      // O si fue emitido por la CA de esta sesión
      if (cert.issuer.includes(session.sessionId)) {
        return session;
      }
    }
  } catch {
    // Si no es un cert válido, devolver undefined
  }
  return undefined;
}

/**
 * Consume 1 uso de la cuota autorizada (máximo 3 usos).
 */
export function consumeSessionUse(sessionId: string): {
  allowed: boolean;
  remainingUses: number;
  usesCount: number;
  maxUses: number;
  error?: string;
} {
  const session = sessions.get(sessionId);
  if (!session) {
    return {
      allowed: false,
      remainingUses: 0,
      usesCount: 0,
      maxUses: 3,
      error: 'Sesión PKI no encontrada o expirada. Por favor genera una nueva CA.',
    };
  }

  if (session.remainingUses <= 0) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      action: 'OPERACION_BLOQUEADA',
      status: 'RECHAZADO_403',
      detail: `Intento de acceso bloqueado: límite de ${session.maxUses} usos alcanzado.`,
      usesLeft: 0,
    };
    session.auditLog.push(logEntry);

    return {
      allowed: false,
      remainingUses: 0,
      usesCount: session.usesCount,
      maxUses: session.maxUses,
      error: `CUOTA EXCEDIDA (${session.usesCount}/${session.maxUses} usos consumidos): Este par de llaves y certificado ya agotó su límite de 3 operaciones autorizadas por política Zero-Trust. Por favor genera una nueva CA y llaves.`,
    };
  }

  session.usesCount += 1;
  session.remainingUses = session.maxUses - session.usesCount;

  const logEntry = {
    timestamp: new Date().toISOString(),
    action: 'OPERACION_AUTORIZADA',
    status: 'EXITO_200',
    detail: `Uso ${session.usesCount} de ${session.maxUses} consumido satisfactoriamente.`,
    usesLeft: session.remainingUses,
  };
  session.auditLog.push(logEntry);

  return {
    allowed: true,
    remainingUses: session.remainingUses,
    usesCount: session.usesCount,
    maxUses: session.maxUses,
  };
}

/**
 * Devuelve la lista o última sesión activa.
 */
export function getLatestPkiSession(): PkiSession | undefined {
  const all = Array.from(sessions.values());
  return all.length > 0 ? all[all.length - 1] : undefined;
}
