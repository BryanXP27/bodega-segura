// Capa backend unificada SOLO SERVIDOR.
// Las rutas /api/* dependen de aquí, no de Azure ni GCP directamente,
// para poder cambiar de backend sin tocar las rutas.

const isGoogle = () =>
  (process.env.NEXT_PUBLIC_BACKEND || '').toLowerCase() === 'google' ||
  process.env.NEXT_PUBLIC_GCP_ENABLED === 'true';

export interface AuthServer {
  registerUser(email: string, password: string): Promise<{ userId: string; token: string; expiresAt: Date }>;
  loginUser(email: string, password: string): Promise<{ userId: string; token: string; expiresAt: Date }>;
  getSessionUser(token: string | null): Promise<{ userId: string; email: string } | null>;
  requireSession(req: any): Promise<{ userId: string; email: string }>;
  getRequestToken(req: any): string | null;
  revokeSession(token: string | null): Promise<void>;
  setSessionCookie(res: any, token: string, expiresAt: Date): void;
  clearSessionCookie(res: any): void;
  httpStatus(err: unknown): number;
}

export interface BlobServer {
  upload(key: string, data: ArrayBuffer | Uint8Array): Promise<string>;
  download(key: string): Promise<ArrayBuffer | null>;
  remove(key: string): Promise<void>;
  assertOwnKey(key: string, userId: string): void;
}

export interface KeysServer {
  save(userId: string, payload: {
    ciphertext: ArrayBuffer | Uint8Array;
    iv: ArrayBuffer | Uint8Array;
    salt: ArrayBuffer | Uint8Array;
    iterations: number;
    algorithm: string;
    keyLength: number;
  }): Promise<void>;
  load(userId: string): Promise<{
    ciphertext: ArrayBuffer | Uint8Array;
    iv: ArrayBuffer | Uint8Array;
    salt: ArrayBuffer | Uint8Array;
    iterations: number;
    algorithm: string;
    keyLength: number;
  } | null>;
}

export async function getAuthServer(): Promise<AuthServer> {
  if (isGoogle()) {
    const mod = await import('@/lib/gcp/auth-server');
    return mod as unknown as AuthServer;
  }
  const mod = await import('@/lib/azure/auth-server');
  return mod as unknown as AuthServer;
}

export async function getBlobServer(): Promise<BlobServer> {
  if (isGoogle()) {
    const mod = await import('@/lib/gcp/storage-server');
    return {
      upload: (k, d) => mod.uploadEncryptedObject(k, d),
      download: (k) => mod.downloadEncryptedObject(k),
      remove: (k) => mod.deleteEncryptedObject(k),
      assertOwnKey: (k, u) => mod.assertOwnKey(k, u),
    };
  }
  const mod = await import('@/lib/azure/blob-server');
  return {
    upload: (k, d) => mod.uploadEncryptedBlob(k, d),
    download: (k) => mod.downloadEncryptedBlob(k),
    remove: (k) => mod.deleteEncryptedBlob(k),
    assertOwnKey: (k, u) => mod.assertOwnKey(k, u),
  };
}

// La clave privada cifrada se guarda como objeto "<userId>/private-key.enc"
// dentro del bucket privado (alineado al enunciado del Proyecto 2).
export async function getKeysServer(): Promise<KeysServer> {
  const blob = await getBlobServer();
  const keyFor = (userId: string) => `${userId}/private-key`;
  return {
    async save(userId, payload) {
      blob.assertOwnKey(keyFor(userId), userId);
      const body = JSON.stringify({
        ciphertext: Buffer.from(payload.ciphertext as Uint8Array).toString('base64'),
        iv: Buffer.from(payload.iv as Uint8Array).toString('base64'),
        salt: Buffer.from(payload.salt as Uint8Array).toString('base64'),
        iterations: payload.iterations,
        algorithm: payload.algorithm,
        keyLength: payload.keyLength,
      });
      const bytes = new TextEncoder().encode(body);
      await blob.upload(keyFor(userId), bytes);
    },
    async load(userId) {
      const data = await blob.download(keyFor(userId));
      if (!data) return null;
      const json = JSON.parse(new TextDecoder().decode(data));
      const toBytes = (v: string) => Uint8Array.from(atob(v), (c) => c.charCodeAt(0));
      return {
        ciphertext: toBytes(json.ciphertext),
        iv: toBytes(json.iv),
        salt: toBytes(json.salt),
        iterations: json.iterations,
        algorithm: json.algorithm,
        keyLength: json.keyLength,
      };
    },
  };
}
