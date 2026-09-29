// Adaptador de almacenamiento Azure para el navegador.
// Los bytes cifrados viajan al Blob via /api/storage/* (la API valida la sesión
// y que la clave pertenezca al usuario). Los metadatos van por /api/files.

import type { FileMetadata, StorageAdapter } from '@/types';
import { azureFetch } from '@/lib/auth/azure-token';
import { azureDb } from '@/lib/database/azure-client-adapter';

async function readError(res: Response, fallback: string): Promise<Error> {
  if (res.status === 401) return new Error('Sesión expirada, vuelve a iniciar sesión');
  const data = await res.json().catch(() => null);
  const message =
    data && typeof data.error === 'string' && data.error.length > 0 ? data.error : fallback;
  return new Error(message);
}

export const azureStorageAdapter: StorageAdapter = {
  async storeFile(key: string, data: ArrayBuffer): Promise<string> {
    const res = await azureFetch(`/api/storage/upload?key=${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: data,
    });
    if (!res.ok) throw await readError(res, 'No se pudo subir el archivo cifrado');
    const body = await res.json().catch(() => ({}));
    return typeof body?.storageName === 'string' ? body.storageName : key;
  },

  async getFile(key: string): Promise<ArrayBuffer | null> {
    const res = await azureFetch(`/api/storage/download?key=${encodeURIComponent(key)}`);
    if (res.status === 404) return null;
    if (!res.ok) throw await readError(res, 'No se pudo descargar el archivo cifrado');
    return res.arrayBuffer();
  },

  async deleteFile(key: string): Promise<void> {
    const res = await azureFetch(`/api/storage/delete?key=${encodeURIComponent(key)}`, {
      method: 'DELETE',
    });
    if (!res.ok && res.status !== 404) {
      throw await readError(res, 'No se pudo eliminar el archivo cifrado');
    }
  },

  async storeMetadata(metadata: FileMetadata): Promise<void> {
    await azureDb.createFileMetadata(metadata);
  },

  async getMetadata(fileId: string): Promise<FileMetadata | null> {
    return azureDb.getFileMetadata(fileId);
  },

  async getUserFiles(userId: string): Promise<FileMetadata[]> {
    void userId;
    return azureDb.getUserFiles(userId);
  },
};
