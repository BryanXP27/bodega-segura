import { deriveKeyFromPassword } from '@/lib/crypto/pbkdf2';
import { audit, shortHex } from '@/lib/debug/audit';

export async function generateRsaKeyPair(): Promise<CryptoKeyPair> {
  // RSA se usa una vez por cuenta como envoltura de claves, no para cifrar archivos:
  // el límite de tamaño de RSA hace que AES sea la opción correcta para los datos.
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      // 2048 bits es el tamaño del módulo. El exponente 65537 es el valor estándar.
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      // SHA-256 forma parte del esquema OAEP para codificar cada operación RSA.
      hash: 'SHA-256',
    } as RsaHashedKeyGenParams,
    true,
    // La clave pública cifra; la privada descifra. No se intercambian sus roles.
    ['encrypt', 'decrypt']
  );
  audit('🔐', 'RSA-OAEP-2048-SHA256: par de claves generado (una vez por cuenta)');
  return pair;
}

export async function exportPublicKeyJwk(key: CryptoKey): Promise<JsonWebKey> {
  // JWK es una representación JSON apta para guardar/compartir la parte pública.
  const jwk = await crypto.subtle.exportKey('jwk', key);
  return jwk;
}

export async function importPublicKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  // Convierte la JWK guardada en un objeto utilizable por Web Crypto para cifrar.
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}

export async function exportPrivateKeyRaw(key: CryptoKey): Promise<ArrayBuffer> {
  // PKCS#8 es el formato binario estándar de una clave privada; debe cifrarse
  // con la contraseña antes de persistirse, nunca almacenarse directamente.
  return crypto.subtle.exportKey('pkcs8', key);
}

export async function importPrivateKeyRaw(raw: ArrayBuffer): Promise<CryptoKey> {
  // Importa el PKCS#8 solo después de haberlo descifrado localmente.
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
  // Cifrado híbrido: cifra únicamente los 32 bytes de la clave AES del archivo.
  // Esta clave pública puede estar en la base de datos; solo la privada pareja
  // podrá desenvolverla más tarde.
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
  // Recupera los bytes originales de la clave AES. Si la privada no corresponde
  // o el envoltorio cambió, Web Crypto falla en vez de producir una clave válida.
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
  // La contraseña no cifra directamente: PBKDF2 la convierte en una clave AES.
  // El salt aleatorio se guarda junto al resultado; no es secreto, pero hace que
  // la misma contraseña produzca claves distintas para cada cifrado.
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const encoder = new TextEncoder();
  // La contraseña se representa como bytes UTF-8 antes de entregarla a PBKDF2.
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
      // Se deben usar los mismos valores al desbloquear la privada. Las iteraciones
      // elevan el costo de probar contraseñas robadas sin conexión.
      iterations: 310000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // La privada se exporta solo en memoria para cifrarla; encryptedData es lo único
  // que se guarda. El IV de GCM y el salt se guardan porque no son secretos.
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
  // Deriva exactamente la misma clave a partir de contraseña, salt e iteraciones.
  const derivedKey = await deriveKeyFromPassword(password, salt);
  // Una contraseña incorrecta o bytes alterados hacen fallar la autenticación GCM.
  const decryptedRaw = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    derivedKey,
    encryptedData
  );
  audit('🛡️', 'PBKDF2: privada desbloqueada con la contraseña');
  // Solo después de autenticar y descifrar los bytes se reconstruye la clave RSA.
  return crypto.subtle.importKey(
    'pkcs8',
    decryptedRaw,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}
