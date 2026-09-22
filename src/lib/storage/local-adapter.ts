import { StorageAdapter } from '@/types';
import { db } from '@/lib/database/local-adapter';

export const localStorageAdapter: StorageAdapter = {
  async storeFile(key: string, data: ArrayBuffer): Promise<string> {
    const filesDB = await openFilesDB();
    return new Promise((resolve, reject) => {
      const tx = filesDB.transaction('files', 'readwrite');
      tx.objectStore('files').put({ key, data });
      tx.oncomplete = () => resolve(key);
      tx.onerror = () => reject(tx.error);
    });
  },

  async getFile(key: string): Promise<ArrayBuffer | null> {
    const filesDB = await openFilesDB();
    return new Promise((resolve, reject) => {
      const tx = filesDB.transaction('files', 'readonly');
      const request = tx.objectStore('files').get(key);
      request.onsuccess = () => { resolve(request.result ? request.result.data : null); };
      request.onerror = () => reject(request.error);
    });
  },

  async deleteFile(key: string): Promise<void> {
    const filesDB = await openFilesDB();
    return new Promise((resolve, reject) => {
      const tx = filesDB.transaction('files', 'readwrite');
      tx.objectStore('files').delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },

  async storeMetadata(metadata: any): Promise<void> {
    await db.createFileMetadata(metadata);
  },

  async getMetadata(fileId: string): Promise<any | null> {
    const result = await db.getFileMetadata(fileId);
    return result || null;
  },

  async getUserFiles(userId: string): Promise<any[]> {
    return db.getUserFiles(userId);
  },
};

function openFilesDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('bodega-files', 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('files')) {
        db.createObjectStore('files', { keyPath: 'key' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
