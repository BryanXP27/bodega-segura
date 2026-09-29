import { audit, shortHex } from '@/lib/debug/audit';

export async function generateAesKey(): Promise<CryptoKey> {
  // AES cifra el contenido completo del archivo porque es mucho más eficiente
  // que RSA para datos grandes. Se genera una clave nueva para cada archivo:
  // así, comprometer una clave no expone los demás archivos del usuario.
  const key = await crypto.subtle.generateKey(
    // GCM aporta confidencialidad y una etiqueta de autenticación integrada.
    // 256 indica el tamaño de la clave en bits (32 bytes).
    { name: 'AES-GCM', length: 256 },
    true,
    // La clave se exporta temporalmente para envolverla con RSA y crear el HMAC.
    ['encrypt', 'decrypt']
  );
  audit('🔑', 'AES-256-GCM: clave efímera generada (32 B aleatorios, una por archivo)');
  return key;
}

export async function encryptFileWithAes(
  fileData: ArrayBuffer,
  aesKey: CryptoKey
): Promise<{ encryptedData: ArrayBuffer; iv: ArrayBuffer }> {
  // El IV/nonce no es una contraseña ni necesita ocultarse; se guarda junto al
  // texto cifrado para poder descifrarlo. GCM requiere no repetirlo con la misma
  // clave. Aquí tiene 12 bytes aleatorios y cada archivo usa su propia clave.
  const iv = new Uint8Array(crypto.getRandomValues(new Uint8Array(12)));
  const encryptedData = await crypto.subtle.encrypt(
    // Web Crypto añade al resultado la etiqueta GCM que comprobará al descifrar.
    { name: 'AES-GCM', iv: iv.buffer },
    aesKey,
    fileData
  );
  audit('📦', 'AES-GCM: archivo cifrado', {
    plano: `${fileData.byteLength} B`,
    cifrado: `${encryptedData.byteLength} B`,
    iv: shortHex(iv),
  });
  // Se conservan ambos valores: encryptedData se almacena; iv es necesario para
  // revertir el cifrado. Ninguno permite descifrar sin la clave AES.
  return { encryptedData, iv: iv.buffer };
}

export async function decryptFileWithAes(
  encryptedData: ArrayBuffer,
  aesKey: CryptoKey,
  iv: ArrayBuffer
): Promise<ArrayBuffer> {
  // La misma clave y el IV del cifrado recuperan el original. AES-GCM también
  // comprueba aquí su etiqueta integrada: si el contenido fue alterado, lanza
  // una excepción y no devuelve bytes parcialmente descifrados.
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
  // Se exporta el formato binario solo para cifrar esta clave con RSA y obtener
  // una clave HMAC; la aplicación no guarda esta copia sin proteger.
  const raw = await crypto.subtle.exportKey('raw', key);
  return raw as ArrayBuffer;
}

export async function importAesKey(rawKey: ArrayBuffer): Promise<CryptoKey> {
  // Reconstruye el objeto CryptoKey a partir de los bytes recuperados con RSA.
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}
