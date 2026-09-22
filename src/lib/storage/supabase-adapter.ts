import { supabaseDb } from '@/lib/database/supabase-adapter';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { StorageAdapter } from '@/types';

let supabaseClient: SupabaseClient | null = null;

function getSupabase(): SupabaseClient {
  if (supabaseClient) return supabaseClient;

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!url || !anonKey) {
    throw new Error('Supabase URL and ANON_KEY environment variables are required');
  }

  supabaseClient = createClient(url, anonKey);
  return supabaseClient;
}

export const supabaseStorageAdapter: StorageAdapter = {
  async storeFile(key: string, data: ArrayBuffer): Promise<string> {
    const supabase = getSupabase();
    const fileName = `${key}.enc`;
    const { data: uploadData, error } = await supabase.storage
      .from('encrypted-files')
      .upload(fileName, data, { cacheControl: '3600', upsert: true });
    if (error) throw new Error(`Failed to upload file: ${error.message}`);
    return uploadData.path;
  },

  async getFile(key: string): Promise<ArrayBuffer | null> {
    const supabase = getSupabase();
    const fileName = `${key}.enc`;
    const { data, error } = await supabase.storage.from('encrypted-files').download(fileName);
    if (error) return null;
    if (!data) return null;
    const buffer = await data.arrayBuffer();
    return buffer;
  },

  async deleteFile(key: string): Promise<void> {
    const supabase = getSupabase();
    const fileName = `${key}.enc`;
    const { error } = await supabase.storage.from('encrypted-files').remove([fileName]);
    if (error) throw new Error(`Failed to delete file: ${error.message}`);
  },

  async storeMetadata(metadata: any): Promise<void> {
    await supabaseDb.createFileMetadata(metadata);
  },

  async getMetadata(fileId: string): Promise<any | null> {
    return supabaseDb.getFileMetadata(fileId);
  },

  async getUserFiles(userId: string): Promise<any[]> {
    return supabaseDb.getUserFiles(userId);
  },
};
