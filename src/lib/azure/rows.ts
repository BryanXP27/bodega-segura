// Mapeos fila Postgres (snake_case) <-> API/cliente (camelCase).
// Centraliza la conversión BYTEA Buffer <-> base64 para el transporte JSON.

function bufferToBase64(value: Buffer | Uint8Array | string): string {
  if (typeof value === 'string') return value;
  return Buffer.from(value).toString('base64');
}

export interface ProfileRow {
  id: string;
  email: string;
  public_key_jwk: JsonWebKey | null;
  created_at: string;
}

export function mapProfile(row: ProfileRow) {
  return {
    id: row.id,
    email: row.email,
    publicKey: null,
    publicKeyJwk: row.public_key_jwk ?? undefined,
    createdAt:
      typeof row.created_at === 'string'
        ? row.created_at
        : new Date(row.created_at).toISOString(),
  };
}

export interface EncryptedKeyRow {
  user_id: string;
  ciphertext: Buffer;
  iv: Buffer;
  salt: Buffer;
  iterations: number;
  algorithm: string;
  key_length: number;
}

export function mapEncryptedKey(row: EncryptedKeyRow) {
  return {
    userId: row.user_id,
    ciphertext: bufferToBase64(row.ciphertext),
    iv: bufferToBase64(row.iv),
    salt: bufferToBase64(row.salt),
    iterations: row.iterations,
    algorithm: row.algorithm,
    keyLength: row.key_length,
  };
}

export interface FileRow {
  id: string;
  user_id: string;
  original_name: string;
  storage_name: string;
  encrypted_aes_key: Buffer;
  iv: Buffer;
  hmac: Buffer;
  original_size: number | string | null;
  created_at: string;
  version: string;
}

export function mapFile(row: FileRow) {
  return {
    id: row.id,
    userId: row.user_id,
    originalName: row.original_name,
    storageName: row.storage_name,
    encryptedAesKey: bufferToBase64(row.encrypted_aes_key),
    iv: bufferToBase64(row.iv),
    hmac: bufferToBase64(row.hmac),
    originalSize:
      typeof row.original_size === 'string'
        ? Number(row.original_size)
        : (row.original_size ?? 0),
    createdAt:
      typeof row.created_at === 'string'
        ? row.created_at
        : new Date(row.created_at).toISOString(),
    version: row.version,
  };
}

export function base64ToBuffer(value: string): Buffer {
  if (!value || typeof value !== 'string') {
    throw new Error('Se esperaba un campo en base64');
  }
  return Buffer.from(value, 'base64');
}
