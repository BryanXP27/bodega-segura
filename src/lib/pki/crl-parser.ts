import crypto from 'crypto';
import { BOVEDA_CRL_PEM } from './crl';
import { BOVEDA_ROOT_CA_CERT } from './certs';

/**
 * Parser y verificador mínimo de CRL X.509 (RFC 5280).
 *
 * Node.js no expone una API para CRL en `crypto.X509Certificate`, así que se
 * decodifica el DER de la CRL con un lector ASN.1 acotado. Solo se necesita:
 *  - TBSCertList (para verificar la firma de la CA)
 *  - thisUpdate / nextUpdate (vigencia de la CRL)
 *  - lista de números de serie revocados
 *
 * La firma se valida con `crypto.verify` usando la llave pública de la Root CA.
 * Si la CRL no es válida, el validador falla cerrado (no se acepta el certificado).
 */

interface Tlv {
  tag: number;
  start: number;
  headerLength: number;
  length: number;
  contentStart: number;
  end: number;
}

export type CrlVerification =
  | {
      valid: true;
      thisUpdate: Date;
      nextUpdate: Date;
      revokedSerials: string[];
      signatureAlgorithm: string;
    }
  | {
      valid: false;
      code: 'CRL_MALFORMED' | 'CRL_SIGNATURE_INVALID' | 'CRL_EXPIRED' | 'CRL_NOT_YET_VALID';
      error: string;
    };

const SIGNATURE_ALGORITHMS: Record<string, string> = {
  '1.2.840.113549.1.1.5': 'sha1',
  '1.2.840.113549.1.1.11': 'sha256',
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
};

function readTlv(buf: Buffer, offset: number): Tlv {
  if (offset + 2 > buf.length) {
    throw new Error('ASN.1 truncado: no hay cabecera TLV completa.');
  }

  const tag = buf[offset];
  let cursor = offset + 1;
  const firstLengthByte = buf[cursor++];
  let length = firstLengthByte;

  if ((firstLengthByte & 0x80) !== 0) {
    const lengthBytes = firstLengthByte & 0x7f;
    if (lengthBytes === 0) {
      throw new Error('ASN.1: longitud indefinida no soportada.');
    }
    if (lengthBytes > 4 || cursor + lengthBytes > buf.length) {
      throw new Error('ASN.1: longitud DER inválida.');
    }
    length = 0;
    for (let i = 0; i < lengthBytes; i++) {
      length = length * 256 + buf[cursor++];
    }
  }

  const contentStart = cursor;
  const end = contentStart + length;
  if (end > buf.length) {
    throw new Error('ASN.1: contenido TLV fuera de los límites del buffer.');
  }

  return {
    tag,
    start: offset,
    headerLength: contentStart - offset,
    length,
    contentStart,
    end,
  };
}

function readChildren(buf: Buffer, parent: Tlv): Tlv[] {
  const children: Tlv[] = [];
  let cursor = parent.contentStart;
  while (cursor < parent.end) {
    const child = readTlv(buf, cursor);
    if (child.end > parent.end) {
      throw new Error('ASN.1: hijo excede el contenedor.');
    }
    children.push(child);
    cursor = child.end;
  }
  return children;
}

function decodeOid(buf: Buffer, tlv: Tlv): string {
  if (tlv.tag !== 0x06 || tlv.length === 0) {
    throw new Error('ASN.1: se esperaba OBJECT IDENTIFIER.');
  }
  const bytes = buf.subarray(tlv.contentStart, tlv.end);
  const first = bytes[0];
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = value * 128 + (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

function parseTime(buf: Buffer, tlv: Tlv): Date {
  const value = buf.toString('ascii', tlv.contentStart, tlv.end);

  if (tlv.tag === 0x17) {
    // UTCTime: YYMMDDHHMMSSZ (o YYMMDDHHMMZ)
    const match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(value);
    if (!match) throw new Error(`UTCTime inválido: ${value}`);
    const yy = Number(match[1]);
    const year = yy < 50 ? 2000 + yy : 1900 + yy;
    return new Date(
      Date.UTC(
        year,
        Number(match[2]) - 1,
        Number(match[3]),
        Number(match[4]),
        Number(match[5]),
        Number(match[6] || '0')
      )
    );
  }

  if (tlv.tag === 0x18) {
    // GeneralizedTime: YYYYMMDDHHMMSSZ
    const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(value);
    if (!match) throw new Error(`GeneralizedTime inválido: ${value}`);
    return new Date(
      Date.UTC(
        Number(match[1]),
        Number(match[2]) - 1,
        Number(match[3]),
        Number(match[4]),
        Number(match[5]),
        Number(match[6])
      )
    );
  }

  throw new Error('Se esperaba UTCTime o GeneralizedTime.');
}

function normalizeSerialFromDer(buf: Buffer, tlv: Tlv): string {
  if (tlv.tag !== 0x02) {
    throw new Error('Se esperaba INTEGER (serial).');
  }
  let hex = buf
    .subarray(tlv.contentStart, tlv.end)
    .toString('hex')
    .replace(/^0+/, '')
    .toUpperCase();
  if (!hex) hex = '0';
  return hex;
}

export function normalizeSerialNumber(serial: string): string {
  const hex = serial.replace(/[^0-9a-fA-F]/g, '').replace(/^0+/, '').toUpperCase();
  return hex || '0';
}

function parseAndVerifyInternal(crlPem: string, caPem: string): CrlVerification {
  try {
    const match = /-----BEGIN X509 CRL-----([\s\S]+?)-----END X509 CRL-----/.exec(crlPem);
    if (!match) {
      return {
        valid: false,
        code: 'CRL_MALFORMED',
        error: 'La CRL no está en formato PEM.',
      };
    }

    const der = Buffer.from(match[1].replace(/\s+/g, ''), 'base64');
    const root = readTlv(der, 0);
    if (root.tag !== 0x30) {
      return { valid: false, code: 'CRL_MALFORMED', error: 'La CRL no es una SEQUENCE DER.' };
    }

    const rootChildren = readChildren(der, root);
    if (rootChildren.length < 3) {
      return {
        valid: false,
        code: 'CRL_MALFORMED',
        error: 'La CRL no tiene los 3 campos esperados (TBS, algoritmo, firma).',
      };
    }

    const [tbs, sigAlg, sigValue] = rootChildren;
    const sigAlgChildren = readChildren(der, sigAlg);
    const oid = decodeOid(der, sigAlgChildren[0]);
    const algorithm = SIGNATURE_ALGORITHMS[oid];
    if (!algorithm) {
      return {
        valid: false,
        code: 'CRL_MALFORMED',
        error: `Algoritmo de firma de CRL no soportado: ${oid}`,
      };
    }

    const tbsChildren = readChildren(der, tbs);
    let idx = 0;
    if (tbsChildren[idx]?.tag === 0x02) idx++;
    idx++; // signature
    idx++; // issuer

    const thisUpdate = parseTime(der, tbsChildren[idx++]);
    let nextUpdate: Date | null = null;
    if (tbsChildren[idx] && (tbsChildren[idx].tag === 0x17 || tbsChildren[idx].tag === 0x18)) {
      nextUpdate = parseTime(der, tbsChildren[idx++]);
    }

    const revokedSerials: string[] = [];
    const revokedList = tbsChildren[idx];
    if (revokedList && revokedList.tag === 0x30) {
      for (const entry of readChildren(der, revokedList)) {
        if (entry.tag !== 0x30) continue;
        const entryChildren = readChildren(der, entry);
        if (entryChildren[0]) {
          revokedSerials.push(normalizeSerialFromDer(der, entryChildren[0]));
        }
      }
    }

    if (!nextUpdate) {
      return {
        valid: false,
        code: 'CRL_MALFORMED',
        error: 'La CRL no declara nextUpdate.',
      };
    }

    const caCert = new crypto.X509Certificate(caPem);
    const signature = der.subarray(sigValue.contentStart + 1, sigValue.end);
    const tbsDer = der.subarray(tbs.start, tbs.end);

    const signatureValid = crypto.verify(algorithm, tbsDer, caCert.publicKey, signature);
    if (!signatureValid) {
      return {
        valid: false,
        code: 'CRL_SIGNATURE_INVALID',
        error: 'La CRL no está firmada por la Root CA de la Bóveda Segura.',
      };
    }

    const now = Date.now();
    const skewMs = 5 * 60 * 1000;
    if (thisUpdate.getTime() > now + skewMs) {
      return {
        valid: false,
        code: 'CRL_NOT_YET_VALID',
        error: `La CRL aún no es válida (thisUpdate: ${thisUpdate.toISOString()}).`,
      };
    }
    if (nextUpdate.getTime() < now - skewMs) {
      return {
        valid: false,
        code: 'CRL_EXPIRED',
        error: `La CRL está vencida (nextUpdate: ${nextUpdate.toISOString()}). Regenera la CRL.`,
      };
    }

    return {
      valid: true,
      thisUpdate,
      nextUpdate,
      revokedSerials,
      signatureAlgorithm: algorithm,
    };
  } catch (err: any) {
    return {
      valid: false,
      code: 'CRL_MALFORMED',
      error: `No se pudo decodificar la CRL: ${err?.message || err}`,
    };
  }
}

let cached:
  | {
      crlPem: string;
      caPem: string;
      result: CrlVerification;
    }
  | undefined;

export function verifyCrl(
  crlPem: string = BOVEDA_CRL_PEM,
  caPem: string = BOVEDA_ROOT_CA_CERT
): CrlVerification {
  if (cached && cached.crlPem === crlPem && cached.caPem === caPem) {
    return cached.result;
  }
  const result = parseAndVerifyInternal(crlPem, caPem);
  cached = { crlPem, caPem, result };
  return result;
}

export function isRevoked(serialNumber: string, crlPem: string = BOVEDA_CRL_PEM): boolean {
  const crl = verifyCrl(crlPem);
  if (!crl.valid) return false;
  const serial = normalizeSerialNumber(serialNumber);
  return crl.revokedSerials.includes(serial);
}
