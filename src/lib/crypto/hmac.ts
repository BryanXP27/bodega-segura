import { audit, auditWarn, shortHex } from '@/lib/debug/audit';

export async function calculateHmac(
  data: ArrayBuffer,
  key: CryptoKey
): Promise<ArrayBuffer> {
  const mac = await crypto.subtle.sign('HMAC', key, data);
  audit('🧬', 'HMAC-SHA256 calculado sobre bytes cifrados', {
    huella: shortHex(mac),
  });
  return mac;
}

export async function verifyHmac(
  data: ArrayBuffer,
  key: CryptoKey,
  expectedHmac: ArrayBuffer
): Promise<boolean> {
  const computedHmac = await crypto.subtle.sign('HMAC', key, data);
  const computedArray = new Uint8Array(computedHmac);
  const expectedArray = new Uint8Array(expectedHmac);

  if (computedArray.length !== expectedArray.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < computedArray.length; i++) {
    result |= computedArray[i] ^ expectedArray[i];
  }

  const ok = result === 0;
  if (ok) {
    audit('✅', 'HMAC verificado: huella coincide, archivo íntegro', {
      huella: shortHex(computedHmac),
    });
  } else {
    auditWarn('🚫', 'HMAC NO coincide: archivo manipulado o corrupto, descarga bloqueada', {
      calculado: shortHex(computedHmac),
      esperado: shortHex(expectedHmac),
    });
  }
  return ok;
}

export async function deriveHmacKey(aesKeyRaw: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    aesKeyRaw,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}
