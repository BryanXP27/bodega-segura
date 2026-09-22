import { deriveKeyFromPassword } from '@/lib/crypto/pbkdf2';

export async function generateRsaKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    } as RsaHashedKeyGenParams,
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportPublicKeyJwk(key: CryptoKey): Promise<JsonWebKey> {
  const jwk = await crypto.subtle.exportKey('jwk', key);
  return jwk;
}

export async function importPublicKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}

export async function exportPrivateKeyRaw(key: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.exportKey('pkcs8', key);
}

export async function importPrivateKeyRaw(raw: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'pkcs8',
    raw,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}

export async function encryptAesKeyWithRsa(
  aesKeyRaw: ArrayBuffer,
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt(
    { name: 'RSA-OAEP', hash: 'SHA-256' } as RsaOaepParams,
    publicKey,
    aesKeyRaw
  );
}

export async function decryptAesKeyWithRsa(
  encryptedAesKey: ArrayBuffer,
  privateKey: CryptoKey
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: 'RSA-OAEP', hash: 'SHA-256' } as RsaOaepParams,
    privateKey,
    encryptedAesKey
  );
}

export async function encryptPrivateKeyWithPassword(
  privateKey: CryptoKey,
  password: string
): Promise<{ encryptedData: ArrayBuffer; iv: ArrayBuffer; salt: ArrayBuffer }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 310000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  const privateKeyRaw = await crypto.subtle.exportKey('pkcs8', privateKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as ArrayBuffer },
    derivedKey,
    privateKeyRaw
  );

  return { encryptedData, iv: iv as unknown as ArrayBuffer, salt: salt as unknown as ArrayBuffer };
}

export async function decryptPrivateKeyWithPassword(
  encryptedData: ArrayBuffer,
  iv: ArrayBuffer,
  salt: ArrayBuffer,
  password: string
): Promise<CryptoKey> {
  const derivedKey = await deriveKeyFromPassword(password, salt);
  const decryptedRaw = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    derivedKey,
    encryptedData
  );
  return crypto.subtle.importKey(
    'pkcs8',
    decryptedRaw,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}
