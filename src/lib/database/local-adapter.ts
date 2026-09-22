import { openDB, DBSchema, IDBPDatabase } from 'idb';
import { UserProfile, FileMetadata, EncryptedPrivateKey } from '@/types';

interface BodegaDB extends DBSchema {
  users: {
    key: string;
    value: UserProfile;
    indexes: {
      'by-email': string;
    };
  };
  files: {
    key: string;
    value: FileMetadata;
    indexes: {
      'by-user': string;
    };
  };
  encryptedKeys: {
    key: string;
    value: EncryptedPrivateKey & { userId: string };
  };
}

let dbInstance: IDBPDatabase<BodegaDB> | null = null;

async function getDB(): Promise<IDBPDatabase<BodegaDB>> {
  if (dbInstance) return dbInstance;

  dbInstance = await openDB<BodegaDB>('bodega-segura-db', 1, {
    upgrade(db) {
      const userStore = db.createObjectStore('users', { keyPath: 'id' });
      userStore.createIndex('by-email', 'email', { unique: true });

      const fileStore = db.createObjectStore('files', { keyPath: 'id' });
      fileStore.createIndex('by-user', 'userId');

      db.createObjectStore('encryptedKeys', { keyPath: 'userId' });
    },
  });

  return dbInstance;
}

export const db = {
  async createUser(profile: UserProfile): Promise<void> {
    const database = await getDB();
    await database.put('users', profile);
  },

  async getUserById(id: string): Promise<UserProfile | undefined> {
    const database = await getDB();
    return database.get('users', id);
  },

  async getUserByEmail(email: string): Promise<UserProfile | undefined> {
    const database = await getDB();
    return database.getFromIndex('users', 'by-email', email);
  },

  async updateUserPublicKey(userId: string, publicKey: JsonWebKey): Promise<void> {
    const database = await getDB();
    const user = await database.get('users', userId);
    if (user) {
      user.publicKeyJwk = publicKey;
      await database.put('users', user);
    }
  },

  async saveEncryptedPrivateKey(userId: string, encKey: EncryptedPrivateKey & { userId: string }): Promise<void> {
    const database = await getDB();
    await database.put('encryptedKeys', encKey);
  },

  async getEncryptedPrivateKey(userId: string): Promise<(EncryptedPrivateKey & { userId: string }) | undefined> {
    const database = await getDB();
    return database.get('encryptedKeys', userId);
  },

  async createFileMetadata(metadata: FileMetadata): Promise<void> {
    const database = await getDB();
    await database.put('files', metadata);
  },

  async getFileMetadata(fileId: string): Promise<FileMetadata | undefined> {
    const database = await getDB();
    return database.get('files', fileId);
  },

  async getUserFiles(userId: string): Promise<FileMetadata[]> {
    const database = await getDB();
    return database.getAllFromIndex('files', 'by-user', userId);
  },

  async deleteFileMetadata(fileId: string): Promise<void> {
    const database = await getDB();
    await database.delete('files', fileId);
  },
};
