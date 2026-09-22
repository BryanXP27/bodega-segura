export async function generateAesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function encryptFileWithAes(
  fileData: ArrayBuffer,
  aesKey: CryptoKey
): Promise<{ encryptedData: ArrayBuffer; iv: ArrayBuffer }> {
  const iv = new Uint8Array(crypto.getRandomValues(new Uint8Array(12)));
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv.buffer },
    aesKey,
    fileData
  );
  return { encryptedData, iv: iv.buffer };
}

export async function decryptFileWithAes(
  encryptedData: ArrayBuffer,
  aesKey: CryptoKey,
  iv: ArrayBuffer
): Promise<ArrayBuffer> {
  const decryptedData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    aesKey,
    encryptedData
  );
  return decryptedData;
}

export async function exportAesKey(key: CryptoKey): Promise<ArrayBuffer> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return raw as ArrayBuffer;
}

export async function importAesKey(rawKey: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}
