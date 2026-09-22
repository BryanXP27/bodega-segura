import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { UserProfile, FileMetadata, EncryptedPrivateKey } from '@/types';

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

export const supabaseDb = {
  async createUser(profile: UserProfile): Promise<void> {
    const supabase = getSupabase();
    const { error } = await supabase.from('profiles').upsert({
      id: profile.id,
      email: profile.email,
      publicKeyJwk: profile.publicKeyJwk ?? null,
      createdAt: profile.createdAt,
    });
    if (error) throw new Error(`Failed to create user: ${error.message}`);
  },

  async getUserById(id: string): Promise<UserProfile | null> {
    const supabase = getSupabase();
    const { data, error } = await supabase.from('profiles').select('*').eq('id', id).single();
    if (error) return null;
    return data;
  },

  async getUserByEmail(email: string): Promise<UserProfile | null> {
    const supabase = getSupabase();
    const { data, error } = await supabase.from('profiles').select('*').eq('email', email).single();
    if (error) return null;
    return data;
  },

  async updateUserPublicKey(userId: string, publicKey: JsonWebKey): Promise<void> {
    const supabase = getSupabase();
    const { error } = await supabase.from('profiles').update({ publicKeyJwk: publicKey }).eq('id', userId);
    if (error) throw new Error(`Failed to update public key: ${error.message}`);
  },

  async saveEncryptedPrivateKey(userId: string, encKey: EncryptedPrivateKey & { userId: string }): Promise<void> {
    const supabase = getSupabase();
    const { error } = await supabase.from('encrypted_private_keys').upsert(encKey);
    if (error) throw new Error(`Failed to save encrypted key: ${error.message}`);
  },

  async getEncryptedPrivateKey(userId: string): Promise<(EncryptedPrivateKey & { userId: string }) | null> {
    const supabase = getSupabase();
    const { data, error } = await supabase.from('encrypted_private_keys').select('*').eq('userId', userId).single();
    if (error) return null;
    return data;
  },

  async createFileMetadata(metadata: FileMetadata): Promise<void> {
    const supabase = getSupabase();
    const { error } = await supabase.from('files').insert(metadata);
    if (error) throw new Error(`Failed to create file metadata: ${error.message}`);
  },

  async getFileMetadata(fileId: string): Promise<FileMetadata | null> {
    const supabase = getSupabase();
    const { data, error } = await supabase.from('files').select('*').eq('id', fileId).single();
    if (error) return null;
    return data;
  },

  async getUserFiles(userId: string): Promise<FileMetadata[]> {
    const supabase = getSupabase();
    const { data, error } = await supabase.from('files').select('*').eq('userId', userId).order('createdAt', { ascending: false });
    if (error) return [];
    return data || [];
  },

  async deleteFileMetadata(fileId: string): Promise<void> {
    const supabase = getSupabase();
    const { error } = await supabase.from('files').delete().eq('id', fileId);
    if (error) throw new Error(`Failed to delete file metadata: ${error.message}`);
  },
};
