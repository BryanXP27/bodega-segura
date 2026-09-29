import { audit, shortHex } from '@/lib/debug/audit';

export async function generateAesKey(): Promise<CryptoKey> {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  audit('🔑', 'AES-256-GCM: clave efímera generada (32 B aleatorios, una por archivo)');
  return key;
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
  audit('📦', 'AES-GCM: archivo cifrado', {
    plano: `${fileData.byteLength} B`,
    cifrado: `${encryptedData.byteLength} B`,
    iv: shortHex(iv),
  });
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
  audit('📂', 'AES-GCM: descifrado autenticado OK (tag válido)', {
    cifrado: `${encryptedData.byteLength} B`,
    plano: `${decryptedData.byteLength} B`,
  });
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
