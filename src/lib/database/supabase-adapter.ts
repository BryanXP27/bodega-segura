import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { UserProfile, FileMetadata, EncryptedPrivateKey } from '@/types';

let supabaseClient: SupabaseClient | null = null;

function toBytea(value: ArrayBuffer): string {
  return `\\x${Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

function fromBytea(value: ArrayBuffer | Uint8Array | string): ArrayBuffer {
  if (value instanceof ArrayBuffer) return value;
  if (value instanceof Uint8Array) {
    const copy = new Uint8Array(value.byteLength);
    copy.set(value);
    return copy.buffer;
  }
  if (value.startsWith('\\x')) {
    const hex = value.slice(2);
    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes.buffer;
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

function normalizeEncryptedKey(data: EncryptedPrivateKey & { userId: string }): EncryptedPrivateKey & { userId: string } {
  return {
    ...data,
    ciphertext: fromBytea(data.ciphertext),
    iv: fromBytea(data.iv),
    salt: fromBytea(data.salt),
  };
}

function normalizeFileMetadata(data: FileMetadata): FileMetadata {
  return {
    ...data,
    encryptedAesKey: fromBytea(data.encryptedAesKey),
    iv: fromBytea(data.iv),
    hmac: fromBytea(data.hmac),
  };
}

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
    const { error } = await supabase.from('encrypted_private_keys').upsert({
      userId,
      ciphertext: toBytea(encKey.ciphertext),
      iv: toBytea(encKey.iv),
      salt: toBytea(encKey.salt),
      iterations: encKey.iterations,
      algorithm: encKey.algorithm,
      keyLength: encKey.keyLength,
    });
    if (error) throw new Error(`Failed to save encrypted key: ${error.message}`);
  },

  async getEncryptedPrivateKey(userId: string): Promise<(EncryptedPrivateKey & { userId: string }) | null> {
    const supabase = getSupabase();
    const { data, error } = await supabase.from('encrypted_private_keys').select('*').eq('userId', userId).single();
    if (error) return null;
    return normalizeEncryptedKey(data);
  },

  async createFileMetadata(metadata: FileMetadata): Promise<void> {
    const supabase = getSupabase();
    const { error } = await supabase.from('files').insert({
      id: metadata.id,
      userId: metadata.userId,
      originalName: metadata.originalName,
      storageName: metadata.storageName,
      encryptedAesKey: toBytea(metadata.encryptedAesKey),
      iv: toBytea(metadata.iv),
      hmac: toBytea(metadata.hmac),
      originalSize: metadata.originalSize,
      createdAt: metadata.createdAt,
      version: metadata.version,
    });
    if (error) throw new Error(`Failed to create file metadata: ${error.message}`);
  },

  async getFileMetadata(fileId: string): Promise<FileMetadata | null> {
    const supabase = getSupabase();
    const { data, error } = await supabase.from('files').select('*').eq('id', fileId).single();
    if (error) return null;
    return normalizeFileMetadata(data);
  },

  async getUserFiles(userId: string): Promise<FileMetadata[]> {
    const supabase = getSupabase();
    const { data, error } = await supabase.from('files').select('*').eq('userId', userId).order('createdAt', { ascending: false });
    if (error) return [];
    return (data || []).map(normalizeFileMetadata);
  },

  async deleteFileMetadata(fileId: string): Promise<void> {
    const supabase = getSupabase();
    const { error } = await supabase.from('files').delete().eq('id', fileId);
    if (error) throw new Error(`Failed to delete file metadata: ${error.message}`);
  },
};
