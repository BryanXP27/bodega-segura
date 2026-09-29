import { audit } from '@/lib/debug/audit';

export async function deriveKeyFromPassword(
  password: string,
  salt: ArrayBuffer
): Promise<CryptoKey> {
  // PBKDF2 transforma la contraseña en una clave AES; nunca se guarda la
  // contraseña ni se usa como clave directamente. Salt y parámetros deben
  // ser los mismos que se guardaron al proteger la clave privada.
  const encoder = new TextEncoder();
  // Web Crypto recibe bytes UTF-8 de la contraseña como material de entrada.
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
      // Estos valores deben coincidir exactamente con rsa.ts; si cambian, no se
      // derivará la misma clave y la privada guardada no podrá abrirse.
      iterations: 310000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  audit('🧪', 'PBKDF2-SHA256: 310000 iteraciones aplicadas');

  return derivedKey;
}

export async function deriveRawKeyFromPassword(
  password: string,
  salt: ArrayBuffer
): Promise<ArrayBuffer> {
  // Variante que devuelve bytes de clave en vez de un CryptoKey no exportable.
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 310000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  return derivedBits as ArrayBuffer;
}

export function generateSalt(): ArrayBuffer {
  // Salt público de 16 bytes para que cada derivación tenga una entrada única.
  return crypto.getRandomValues(new Uint8Array(16)).buffer as ArrayBuffer;
}

export function getPbkdf2Params(): { iterations: number; hash: string; saltLength: number } {
  // Centraliza los parámetros descriptivos que deben documentarse/guardarse.
  return {
    iterations: 310000,
    hash: 'SHA-256',
    saltLength: 16,
  };
}
