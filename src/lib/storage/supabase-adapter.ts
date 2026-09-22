import { StorageAdapter } from '@/types';

export const supabaseStorageAdapter: StorageAdapter = {
  async storeFile(key: string, data: ArrayBuffer): Promise<string> {
    // Supabase implementation placeholder
    // Replaced when Supabase is configured
    throw new Error('Supabase storage not configured. Use local adapter or configure Supabase.');
  },

  async getFile(key: string): Promise<ArrayBuffer | null> {
    throw new Error('Supabase storage not configured.');
  },

  async deleteFile(key: string): Promise<void> {
    throw new Error('Supabase storage not configured.');
  },

  async storeMetadata(metadata: any): Promise<void> {
    throw new Error('Supabase database not configured.');
  },

  async getMetadata(fileId: string): Promise<any | null> {
    throw new Error('Supabase database not configured.');
  },

  async getUserFiles(userId: string): Promise<any[]> {
    throw new Error('Supabase database not configured.');
  },
};

export const supabaseDbAdapter = {
  async createUser(profile: any): Promise<void> {
    throw new Error('Supabase database not configured.');
  },
  async getUserById(id: string): Promise<any | null> {
    throw new Error('Supabase database not configured.');
  },
  async getUserByEmail(email: string): Promise<any | null> {
    throw new Error('Supabase database not configured.');
  },
  async updateUserPublicKey(userId: string, publicKey: any): Promise<void> {
    throw new Error('Supabase database not configured.');
  },
  async updateUserEncryptedKey(userId: string, encryptedKey: any): Promise<void> {
    throw new Error('Supabase database not configured.');
  },
  async getEncryptedPrivateKey(userId: string): Promise<any | null> {
    throw new Error('Supabase database not configured.');
  },
  async createFileMetadata(metadata: any): Promise<void> {
    throw new Error('Supabase database not configured.');
  },
  async getFileMetadata(fileId: string): Promise<any | null> {
    throw new Error('Supabase database not configured.');
  },
  async getUserFiles(userId: string): Promise<any[]> {
    throw new Error('Supabase database not configured.');
  },
  async deleteFileMetadata(fileId: string): Promise<void> {
    throw new Error('Supabase database not configured.');
  },
};
