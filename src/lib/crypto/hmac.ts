import { audit, auditWarn, shortHex } from '@/lib/debug/audit';

export async function calculateHmac(
  data: ArrayBuffer,
  key: CryptoKey
): Promise<ArrayBuffer> {
  // HMAC no cifra: calcula una huella autenticada del texto cifrado para detectar
  // cambios o corrupción mientras está almacenado. La huella se guarda en metadata.
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
  // Recalcula la huella sobre los bytes recibidos. La comparación se hace en
  // tiempo constante respecto al contenido para no filtrar prefijos coincidentes.
  const computedHmac = await crypto.subtle.sign('HMAC', key, data);
  const computedArray = new Uint8Array(computedHmac);
  const expectedArray = new Uint8Array(expectedHmac);

  if (computedArray.length !== expectedArray.length) {
    // Un SHA-256 válido siempre tiene el mismo tamaño; distinto tamaño es inválido.
    return false;
  }

  // OR acumulado evita salir al primer byte distinto (comparación de tiempo constante).
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
  // Importa los bytes de la clave AES con uso HMAC-SHA256; no descifra ni modifica
  // el archivo. Se usa para firmar/verificar los mismos bytes cifrados.
  return crypto.subtle.importKey(
    'raw',
    aesKeyRaw,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}
