export async function calculateHmac(
  data: ArrayBuffer,
  key: CryptoKey
): Promise<ArrayBuffer> {
  return crypto.subtle.sign('HMAC', key, data);
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

  return result === 0;
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
