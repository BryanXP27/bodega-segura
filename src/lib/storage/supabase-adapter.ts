import { supabaseDb } from '@/lib/database/supabase-adapter';
import { getSupabaseClient as getSupabase } from '@/lib/supabase/client';
import { StorageAdapter } from '@/types';
import { audit } from '@/lib/debug/audit';

export const supabaseStorageAdapter: StorageAdapter = {
  async storeFile(key: string, data: ArrayBuffer): Promise<string> {
    const supabase = getSupabase();
    const fileName = `${key}.enc`;
    const { data: uploadData, error } = await supabase.storage
      .from('encrypted-files')
      .upload(fileName, data, { cacheControl: '3600', upsert: true });
    if (error) throw new Error(`Failed to upload file: ${error.message}`);
    audit('☁️', 'Storage (encrypted-files): bytes CIFRADOS subidos', {
      objeto: uploadData.path,
      tamaño: `${data.byteLength} B (ilegibles sin la clave)`,
    });
    return uploadData.path;
  },

  async getFile(key: string): Promise<ArrayBuffer | null> {
    const supabase = getSupabase();
    const fileName = `${key}.enc`;
    const { data, error } = await supabase.storage.from('encrypted-files').download(fileName);
    if (error) return null;
    if (!data) return null;
    const buffer = await data.arrayBuffer();
    audit('☁️', 'Storage (encrypted-files): bytes cifrados descargados', {
      objeto: fileName,
      tamaño: `${buffer.byteLength} B`,
    });
    return buffer;
  },

  async deleteFile(key: string): Promise<void> {
    const supabase = getSupabase();
    const fileName = `${key}.enc`;
    const { error } = await supabase.storage.from('encrypted-files').remove([fileName]);
    if (error) throw new Error(`Failed to delete file: ${error.message}`);
    audit('☁️', 'Storage (encrypted-files): objeto eliminado', { objeto: fileName });
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
