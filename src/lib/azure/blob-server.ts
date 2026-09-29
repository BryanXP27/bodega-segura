// Acceso a Azure Blob Storage SOLO SERVIDOR.
// El navegador nunca ve la connection string: pide al /api/storage/*
// y la API valida que la clave pertenezca al usuario de la sesión.

import { BlobServiceClient, type ContainerClient } from '@azure/storage-blob';
import { DefaultAzureCredential } from '@azure/identity';
import { AZURE_STORAGE_CONTAINER } from './env';

let container: ContainerClient | null = null;

export function getContainer(): ContainerClient {
  if (typeof window !== 'undefined') {
    throw new Error('El acceso a Blob Storage solo puede usarse en el servidor');
  }
  if (container) return container;

  const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING || '';
  const accountUrl = process.env.AZURE_STORAGE_ACCOUNT_URL || '';
  let service: BlobServiceClient;
  if (connectionString) {
    service = BlobServiceClient.fromConnectionString(connectionString);
  } else if (accountUrl) {
    service = new BlobServiceClient(accountUrl, new DefaultAzureCredential());
  } else {
    throw new Error(
      'Falta AZURE_STORAGE_CONNECTION_STRING o AZURE_STORAGE_ACCOUNT_URL en el servidor'
    );
  }
  container = service.getContainerClient(AZURE_STORAGE_CONTAINER);
  return container;
}

async function ensureContainer(): Promise<ContainerClient> {
  const client = getContainer();
  // Sin `access`: contenedor privado por defecto (sin acceso anónimo).
  await client.createIfNotExists();
  return client;
}

export function sanitizeBlobKey(key: string): string {
  if (!key || key.length > 512) throw new Error('Clave de blob inválida');
  if (key.includes('..') || key.includes('\\') || key.startsWith('/')) {
    throw new Error('Clave de blob inválida');
  }
  if (!/^[A-Za-z0-9._\-/]+$/.test(key)) throw new Error('Clave de blob inválida');
  return key;
}

export function blobPathFor(key: string): string {
  const clean = sanitizeBlobKey(key);
  return clean.endsWith('.enc') ? clean : `${clean}.enc`;
}

export function assertOwnKey(key: string, userId: string): void {
  const clean = sanitizeBlobKey(key);
  if (!clean.startsWith(`${userId}/`)) {
    throw new Error('Archivo no autorizado');
  }
}

export async function uploadEncryptedBlob(key: string, data: ArrayBuffer | Uint8Array): Promise<string> {
  const client = await ensureContainer();
  const path = blobPathFor(key);
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  await client.getBlockBlobClient(path).uploadData(bytes, {
    blobHTTPHeaders: { blobContentType: 'application/octet-stream' },
  });
  return path;
}

export async function downloadEncryptedBlob(key: string): Promise<ArrayBuffer | null> {
  try {
    const buffer = await getContainer().getBlockBlobClient(blobPathFor(key)).downloadToBuffer();
    const copy = new Uint8Array(buffer.byteLength);
    copy.set(buffer);
    return copy.buffer;
  } catch (err: unknown) {
    const code = (err as { statusCode?: number; code?: string }).statusCode;
    const name = (err as { code?: string }).code;
    if (code === 404 || name === 'BlobNotFound') return null;
    throw err;
  }
}

export async function deleteEncryptedBlob(key: string): Promise<void> {
  await getContainer().getBlockBlobClient(blobPathFor(key)).deleteIfExists();
}
