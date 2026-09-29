import { deriveKeyFromPassword } from '@/lib/crypto/pbkdf2';
import { audit, shortHex } from '@/lib/debug/audit';

export async function generateRsaKeyPair(): Promise<CryptoKeyPair> {
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    } as RsaHashedKeyGenParams,
    true,
    ['encrypt', 'decrypt']
  );
  audit('🔐', 'RSA-OAEP-2048-SHA256: par de claves generado (una vez por cuenta)');
  return pair;
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
  const wrapped = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP', hash: 'SHA-256' } as RsaOaepParams,
    publicKey,
    aesKeyRaw
  );
  audit('🔏', 'RSA: clave AES envuelta con la pública', {
    claveAes: `${aesKeyRaw.byteLength} B`,
    envuelta: `${wrapped.byteLength} B (solo la privada la abre)`,
  });
  return wrapped;
}

export async function decryptAesKeyWithRsa(
  encryptedAesKey: ArrayBuffer,
  privateKey: CryptoKey
): Promise<ArrayBuffer> {
  const raw = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP', hash: 'SHA-256' } as RsaOaepParams,
    privateKey,
    encryptedAesKey
  );
  audit('🔓', 'RSA: clave AES recuperada con la privada');
  return raw;
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

  audit('🛡️', 'PBKDF2-SHA256 310k + AES-GCM: privada protegida con la contraseña', {
    salt: shortHex(salt),
    cifrado: `${encryptedData.byteLength} B (el servidor jamás la ve en claro)`,
  });
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
  audit('🛡️', 'PBKDF2: privada desbloqueada con la contraseña');
  return crypto.subtle.importKey(
    'pkcs8',
    decryptedRaw,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}
