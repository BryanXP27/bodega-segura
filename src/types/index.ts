export interface UserProfile {
  id: string;
  email: string;
  passwordHash?: string;
  publicKey: JsonWebKey | null;
  publicKeyJwk?: JsonWebKey;
  createdAt: string;
}

export interface EncryptedPrivateKey {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
  salt: ArrayBuffer;
  iterations: number;
  algorithm: string;
  keyLength: number;
}

export interface FileMetadata {
  id: string;
  userId: string;
  originalName: string;
  storageName: string;
  encryptedAesKey: ArrayBuffer;
  iv: ArrayBuffer;
  hmac: ArrayBuffer;
  originalSize: number;
  createdAt: string;
  version: string;
}

export interface CryptoParams {
  aesKey: CryptoKey;
  iv: ArrayBuffer;
  encryptedKey: ArrayBuffer;
  hmac: ArrayBuffer;
  fileData: ArrayBuffer;
}

export interface UploadResult {
  fileId: string;
  originalName: string;
  storageName: string;
  encryptedAesKey: ArrayBuffer;
  iv: ArrayBuffer;
  hmac: ArrayBuffer;
  originalSize: number;
}

export interface DownloadResult {
  fileData: ArrayBuffer;
  originalName: string;
}

export interface AuthState {
  user: UserProfile | null;
  sessionId: string | null;
  isAuthenticated: boolean;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  email: string;
  password: string;
  confirmPassword: string;
}

export interface CryptoConfig {
  rsaKeySize: number;
  pbkdf2Iterations: number;
  pbkdf2Hash: string;
  aesKeyLength: number;
  aesAlgorithm: string;
  rsaAlgorithm: string;
  hashAlgorithm: string;
  ivLength: number;
}

export type StorageAdapterType = 'local' | 'supabase';

export interface StorageAdapter {
  storeFile(key: string, data: ArrayBuffer): Promise<string>;
  getFile(key: string): Promise<ArrayBuffer | null>;
  deleteFile(key: string): Promise<void>;
  storeMetadata(metadata: FileMetadata): Promise<void>;
  getMetadata(fileId: string): Promise<FileMetadata | null>;
  getUserFiles(userId: string): Promise<FileMetadata[]>;
}

export interface DatabaseAdapter {
  createUser(profile: UserProfile): Promise<void>;
  getUserById(id: string): Promise<UserProfile | null>;
  getUserByEmail(email: string): Promise<UserProfile | null>;
  updateUserPublicKey(userId: string, publicKey: JsonWebKey): Promise<void>;
  updateUserEncryptedKey(userId: string, encryptedKey: EncryptedPrivateKey): Promise<void>;
  getEncryptedPrivateKey(userId: string): Promise<EncryptedPrivateKey | null>;
  createFileMetadata(metadata: FileMetadata): Promise<void>;
  getFileMetadata(fileId: string): Promise<FileMetadata | null>;
  getUserFiles(userId: string): Promise<FileMetadata[]>;
  deleteFileMetadata(fileId: string): Promise<void>;
}

export interface AuthAdapter {
  register(email: string, password: string): Promise<{ userId: string; sessionId: string }>;
  login(email: string, password: string): Promise<{ userId: string; sessionId: string }>;
  logout(sessionId: string): Promise<void>;
  getSession(sessionId: string): Promise<{ userId: string } | null>;
  verifyPassword(password: string, hash: string): Promise<boolean>;
  hashPassword(password: string): Promise<string>;
}
