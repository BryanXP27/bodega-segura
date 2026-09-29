import { getSupabaseClient as getSupabase } from '@/lib/supabase/client';
import { UserProfile, FileMetadata, EncryptedPrivateKey } from '@/types';
import { audit, shortHex } from '@/lib/debug/audit';

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
    audit('🗄️', 'Postgres (profiles): perfil guardado', { email: profile.email });
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
    audit('🗄️', 'Postgres (profiles): clave pública RSA publicada (legible, no es secreto)');
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
    audit('🗄️', 'Postgres (encrypted_private_keys): privada cifrada guardada', {
      huella: shortHex(encKey.ciphertext),
    });
  },

  async getEncryptedPrivateKey(userId: string): Promise<(EncryptedPrivateKey & { userId: string }) | null> {
    const supabase = getSupabase();
    const { data, error } = await supabase.from('encrypted_private_keys').select('*').eq('userId', userId).single();
    if (error) return null;
    audit('🗄️', 'Postgres (encrypted_private_keys): privada cifrada leída');
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
    audit('🗄️', 'Postgres (files): metadatos guardados', {
      archivo: metadata.originalName,
      tamaño: `${metadata.originalSize} B`,
      hmac: shortHex(metadata.hmac),
    });
  },

  async getFileMetadata(fileId: string): Promise<FileMetadata | null> {
    const supabase = getSupabase();
    const { data, error } = await supabase.from('files').select('*').eq('id', fileId).single();
    if (error) return null;
    audit('🗄️', 'Postgres (files): metadatos leídos', { fileId });
    return normalizeFileMetadata(data);
  },

  async getUserFiles(userId: string): Promise<FileMetadata[]> {
    const supabase = getSupabase();
    const { data, error } = await supabase.from('files').select('*').eq('userId', userId).order('createdAt', { ascending: false });
    if (error) return [];
    audit('🗄️', 'Postgres (files): lista de archivos leída', { n: (data || []).length });
    return (data || []).map(normalizeFileMetadata);
  },

  async deleteFileMetadata(fileId: string): Promise<void> {
    const supabase = getSupabase();
    const { error } = await supabase.from('files').delete().eq('id', fileId);
    if (error) throw new Error(`Failed to delete file metadata: ${error.message}`);
    audit('🗄️', 'Postgres (files): metadatos eliminados', { fileId });
  },
};
