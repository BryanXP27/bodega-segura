// Almacenamiento en Google Cloud Storage - SOLO SERVIDOR.
// El navegador nunca ve las credenciales: pide al /api/storage/*,
// y la API valida que la clave pertenezca al usuario de la sesión.
// Guarda los objetos CIFRADOS (archivos .enc y privada cifrada).

import { Storage } from '@google-cloud/storage';
import { STORAGE_BUCKET } from './env';

let storage: Storage | null = null;

function getStorage(): Storage {
  if (typeof window !== 'undefined') {
    throw new Error('El acceso a Cloud Storage solo puede usarse en el servidor');
  }
  if (storage) return storage;
  // Credenciales automáticas en Cloud Run (Application Default Credentials).
  // Local: GOOGLE_APPLICATION_CREDENTIALS apuntando al JSON de la service account.
  storage = new Storage();
  return storage;
}

export function getBucket() {
  return getStorage().bucket(STORAGE_BUCKET);
}

export function sanitizeObjectKey(key: string): string {
  if (!key || key.length > 512) throw new Error('Clave de objeto inválida');
  if (key.includes('..') || key.includes('\\') || key.startsWith('/')) {
    throw new Error('Clave de objeto inválida');
  }
  if (!/^[A-Za-z0-9._\-/]+$/.test(key)) throw new Error('Clave de objeto inválida');
  return key;
}

export function objectKeyFor(key: string): string {
  const clean = sanitizeObjectKey(key);
  return clean.endsWith('.enc') ? clean : `${clean}.enc`;
}

export function assertOwnKey(key: string, userId: string): void {
  const clean = sanitizeObjectKey(key);
  if (!clean.startsWith(`${userId}/`)) {
    throw new Error('Archivo no autorizado');
  }
}

export async function uploadEncryptedObject(key: string, data: ArrayBuffer | Uint8Array): Promise<string> {
  const file = getBucket().file(objectKeyFor(key));
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  await file.save(Buffer.from(bytes), {
    contentType: 'application/octet-stream',
    metadata: { cacheControl: 'no-store' },
  });
  return file.name;
}

export async function downloadEncryptedObject(key: string): Promise<ArrayBuffer | null> {
  const file = getBucket().file(objectKeyFor(key));
  const [exists] = await file.exists();
  if (!exists) return null;
  const [contents] = await file.download();
  const copy = new Uint8Array(contents.byteLength);
  copy.set(contents);
  return copy.buffer;
}

export async function deleteEncryptedObject(key: string): Promise<void> {
  await getBucket().file(objectKeyFor(key)).delete({ ignoreNotFound: true });
}
