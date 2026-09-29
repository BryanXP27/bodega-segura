// Adaptador de base de datos Azure para el navegador.
// NO usa `pg` directo: llama a /api/* que valida la sesión.
// Convierte base64 <-> ArrayBuffer para transportar bytes cifrados en JSON.

import type { DatabaseAdapter, EncryptedPrivateKey, FileMetadata, UserProfile } from '@/types';
import { azureFetch, b64ToBytes, bytesToB64 } from '@/lib/auth/azure-token';

type EncryptedKeyInput = EncryptedPrivateKey & { userId: string };

async function readError(res: Response, fallback: string): Promise<Error> {
  const data = await res.json().catch(() => null);
  const message =
    data && typeof data.error === 'string' && data.error.length > 0 ? data.error : fallback;
  return new Error(message);
}

function mapUser(data: {
  id: string;
  email: string;
  publicKeyJwk?: JsonWebKey;
  createdAt: string;
}): UserProfile {
  return {
    id: data.id,
    email: data.email,
    publicKey: null,
    publicKeyJwk: data.publicKeyJwk,
    createdAt: data.createdAt,
  };
}

function mapKey(data: {
  userId: string;
  ciphertext: string;
  iv: string;
  salt: string;
  iterations: number;
  algorithm: string;
  keyLength: number;
}): EncryptedKeyInput {
  return {
    userId: data.userId,
    ciphertext: b64ToBytes(data.ciphertext),
    iv: b64ToBytes(data.iv),
    salt: b64ToBytes(data.salt),
    iterations: data.iterations,
    algorithm: data.algorithm,
    keyLength: data.keyLength,
  };
}

function mapFile(data: {
  id: string;
  userId: string;
  originalName: string;
  storageName: string;
  encryptedAesKey: string;
  iv: string;
  hmac: string;
  originalSize: number;
  createdAt: string;
  version: string;
}): FileMetadata {
  return {
    id: data.id,
    userId: data.userId,
    originalName: data.originalName,
    storageName: data.storageName,
    encryptedAesKey: b64ToBytes(data.encryptedAesKey),
    iv: b64ToBytes(data.iv),
    hmac: b64ToBytes(data.hmac),
    originalSize: data.originalSize,
    createdAt: data.createdAt,
    version: data.version,
  };
}

async function putEncryptedKey(encKey: EncryptedKeyInput): Promise<void> {
  const res = await azureFetch('/api/keys/me', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ciphertext: bytesToB64(encKey.ciphertext),
      iv: bytesToB64(encKey.iv),
      salt: bytesToB64(encKey.salt),
      iterations: encKey.iterations,
      algorithm: encKey.algorithm,
      keyLength: encKey.keyLength,
    }),
  });
  if (!res.ok) throw await readError(res, 'No se pudo guardar la clave cifrada');
}

export const azureDb: DatabaseAdapter & {
  saveEncryptedPrivateKey(userId: string, encKey: EncryptedKeyInput): Promise<void>;
} = {
  async createUser() {
    throw new Error('En modo Azure el usuario se crea en /api/auth/register');
  },

  async getUserById() {
    const res = await azureFetch('/api/users/me');
    if (res.status === 401) return null;
    if (!res.ok) throw await readError(res, 'No se pudo obtener el perfil');
    return mapUser(await res.json());
  },

  async getUserByEmail(email: string) {
    const res = await azureFetch('/api/users/me');
    if (res.status === 401) return null;
    if (!res.ok) throw await readError(res, 'No se pudo obtener el perfil');
    const user = mapUser(await res.json());
    if (user.email.toLowerCase() !== email.trim().toLowerCase()) {
      throw new Error('El perfil no corresponde a la sesión actual');
    }
    return user;
  },

  async updateUserPublicKey(_userId: string, publicKey: JsonWebKey) {
    const res = await azureFetch('/api/users/me/public-key', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ publicKeyJwk: publicKey }),
    });
    if (!res.ok) throw await readError(res, 'No se pudo guardar la clave pública');
  },

  async updateUserEncryptedKey(_userId: string, encryptedKey: EncryptedPrivateKey) {
    await putEncryptedKey(encryptedKey as EncryptedKeyInput);
  },

  async saveEncryptedPrivateKey(_userId: string, encKey: EncryptedKeyInput) {
    await putEncryptedKey(encKey);
  },

  async getEncryptedPrivateKey() {
    const res = await azureFetch('/api/keys/me');
    if (res.status === 404) return null;
    if (res.status === 401) return null;
    if (!res.ok) throw await readError(res, 'No se pudo obtener la clave cifrada');
    return mapKey(await res.json());
  },

  async createFileMetadata(metadata: FileMetadata) {
    const res = await azureFetch('/api/files', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: metadata.id,
        originalName: metadata.originalName,
        storageName: metadata.storageName,
        encryptedAesKey: bytesToB64(metadata.encryptedAesKey),
        iv: bytesToB64(metadata.iv),
        hmac: bytesToB64(metadata.hmac),
        originalSize: metadata.originalSize,
        version: metadata.version,
      }),
    });
    if (!res.ok) throw await readError(res, 'No se pudo guardar el archivo');
  },

  async getFileMetadata(fileId: string) {
    const res = await azureFetch(`/api/files/${encodeURIComponent(fileId)}`);
    if (res.status === 404 || res.status === 401) return null;
    if (!res.ok) throw await readError(res, 'No se pudo obtener el archivo');
    return mapFile(await res.json());
  },

  async getUserFiles() {
    const res = await azureFetch('/api/files');
    if (res.status === 401) return [];
    if (!res.ok) throw await readError(res, 'No se pudieron listar los archivos');
    const data = await res.json();
    const files = Array.isArray(data?.files) ? data.files : [];
    return files.map(mapFile);
  },

  async deleteFileMetadata(fileId: string) {
    const res = await azureFetch(`/api/files/${encodeURIComponent(fileId)}`, {
      method: 'DELETE',
    });
    if (!res.ok && res.status !== 404) {
      throw await readError(res, 'No se pudo eliminar el archivo');
    }
  },
};
