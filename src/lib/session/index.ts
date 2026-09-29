import { create } from 'zustand';
import { AuthState, FileMetadata } from '@/types';
import { authAdapter, storageAdapter, databaseAdapter } from '@/lib/config';
import { generateRsaKeyPair, exportPublicKeyJwk, encryptPrivateKeyWithPassword, importPublicKeyJwk, decryptAesKeyWithRsa, decryptPrivateKeyWithPassword, encryptAesKeyWithRsa } from '@/lib/crypto/rsa';
import { generateAesKey, exportAesKey, encryptFileWithAes, decryptFileWithAes, importAesKey } from '@/lib/crypto/aes';
import { deriveHmacKey, calculateHmac, verifyHmac } from '@/lib/crypto/hmac';
import { auditGroup } from '@/lib/debug/audit';

interface AppState extends AuthState {
  files: FileMetadata[];
  loading: boolean;
  error: string | null;
  message: string | null;
  activeFileId: string | null;
  downloadLoading: boolean;
  register: (email: string, password: string, confirmPassword: string) => Promise<void>;
  login: (email: string, password: string) => Promise<{ userId: string; sessionId: string; repaired: boolean }>;
  logout: () => Promise<void>;
  uploadFile: (file: File) => Promise<void>;
  downloadFile: (fileId: string, password: string) => Promise<ArrayBuffer>;
  loadFiles: () => Promise<void>;
  setUser: (user: any) => void;
  setSessionId: (sessionId: string | null) => void;
  setAuthenticated: (isAuthenticated: boolean) => void;
  setFiles: (files: FileMetadata[]) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setMessage: (message: string | null) => void;
  setActiveFileId: (activeFileId: string | null) => void;
  setDownloadLoading: (downloadLoading: boolean) => void;
  clearError: () => void;
  clearMessage: () => void;
}

export const useAppStore = create<AppState>((set, get) => ({
  user: null,
  sessionId: null,
  isAuthenticated: false,
  files: [],
  loading: false,
  error: null,
  message: null,
  activeFileId: null,
  downloadLoading: false,

  setUser: (user) => set({ user }),
  setSessionId: (sessionId) => set({ sessionId }),
  setAuthenticated: (isAuthenticated) => set({ isAuthenticated }),
  setFiles: (files) => set({ files }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),
  setMessage: (message) => set({ message }),
  setActiveFileId: (activeFileId) => set({ activeFileId }),
  setDownloadLoading: (downloadLoading) => set({ downloadLoading }),

  register: async (email, password, confirmPassword) => {
    set({ loading: true, error: null });
    const endAudit = auditGroup(`📝 REGISTRO: ${email}`);
    try {
      if (password !== confirmPassword) throw new Error('Las contraseñas no coinciden');
      if (password.length < 8) throw new Error('La contraseña debe tener al menos 8 caracteres');
      if (!email.includes('@')) throw new Error('Formato de correo inválido');
      const { userId, sessionId } = await authAdapter.register(email, password);
      if (!sessionId) {
        endAudit();
        set({
          user: null,
          sessionId: null,
          isAuthenticated: false,
          loading: false,
          message: 'Cuenta creada. Revisa tu correo y confirma la cuenta antes de iniciar sesión.',
        });
        return;
      }
      const keyPair = await generateRsaKeyPair();
      const publicKeyJwk = await exportPublicKeyJwk(keyPair.publicKey);
      await databaseAdapter.updateUserPublicKey(userId, publicKeyJwk);
      const { encryptedData, iv, salt } = await encryptPrivateKeyWithPassword(keyPair.privateKey, password);
      await databaseAdapter.saveEncryptedPrivateKey(userId, { ciphertext: encryptedData, iv, salt, iterations: 310000, algorithm: 'AES-GCM', keyLength: 256, userId });
      set({ user: { id: userId, email, publicKey: null, createdAt: new Date().toISOString() }, sessionId, isAuthenticated: true, loading: false, message: 'Registro completado exitosamente' });
      endAudit();
    } catch (err: any) {
      endAudit();
      set({ loading: false, error: err.message });
      throw err;
    }
  },

  login: async (email, password) => {
    set({ loading: true, error: null });
    const endAudit = auditGroup(`🔑 LOGIN: ${email}`);
    try {
      const { userId, sessionId } = await authAdapter.login(email, password);
      let user = await databaseAdapter.getUserById(userId);
      let repaired = false;
      if (!user) {
        await databaseAdapter.createUser({
          id: userId,
          email,
          publicKey: null,
          createdAt: new Date().toISOString(),
        });
      }
      const encryptedKey = await databaseAdapter.getEncryptedPrivateKey(userId);
      let needsKeyRepair = !encryptedKey;
      if (encryptedKey) {
        try {
          await decryptPrivateKeyWithPassword(encryptedKey.ciphertext, encryptedKey.iv, encryptedKey.salt, password);
        } catch {
          needsKeyRepair = true;
        }
      }
      if (needsKeyRepair) {
        repaired = true;
        const keyPair = await generateRsaKeyPair();
        const publicKeyJwk = await exportPublicKeyJwk(keyPair.publicKey);
        await databaseAdapter.updateUserPublicKey(userId, publicKeyJwk);
        const { encryptedData, iv, salt } = await encryptPrivateKeyWithPassword(keyPair.privateKey, password);
        await databaseAdapter.saveEncryptedPrivateKey(userId, {
          ciphertext: encryptedData,
          iv,
          salt,
          iterations: 310000,
          algorithm: 'AES-GCM',
          keyLength: 256,
          userId,
        });
        set({ message: 'Se repararon las claves de la cuenta. Vuelve a subir los archivos anteriores.' });
      }
      user = await databaseAdapter.getUserById(userId);
      set({ user: user ? { ...user, publicKey: null } : null, sessionId, isAuthenticated: true, loading: false });
      endAudit();
      return { userId, sessionId, repaired };
    } catch (err: any) {
      endAudit();
      set({ loading: false, error: err.message });
      throw err;
    }
  },

  logout: async () => {
    const { sessionId } = get();
    if (sessionId) await authAdapter.logout(sessionId);
    set({ user: null, sessionId: null, isAuthenticated: false, files: [], activeFileId: null });
  },

  uploadFile: async (file: File) => {
    const { user, sessionId } = get();
    if (!sessionId || !user) throw new Error('Debe iniciar sesión para subir archivos');
    set({ loading: true, error: null });
    const endAudit = auditGroup(`⬆️ SUBIDA: ${file.name} (${file.size} B)`);
    try {
      // 1. Leer el archivo como bytes en memoria; el archivo original no se envía al servidor.
      const fileData = await file.arrayBuffer();
      // 2. Crear una clave AES aleatoria exclusiva para este archivo.
      const aesKey = await generateAesKey();
      const aesKeyRaw = await exportAesKey(aesKey);
      // 3. Cifrar el contenido con AES-GCM; se conservan ciphertext e IV para abrirlo.
      const { encryptedData, iv } = await encryptFileWithAes(fileData, aesKey);
      // 4. Preparar la clave HMAC a partir de la clave AES y firmar el ciphertext.
      const hmacKey = await deriveHmacKey(aesKeyRaw);
      const hmac = await calculateHmac(encryptedData, hmacKey);
      // 5. Obtener la clave pública del usuario; solo sirve para envolver la clave AES.
      const publicKeyJwk = user.publicKeyJwk || (await databaseAdapter.getUserById(user.id))?.publicKeyJwk;
      if (!publicKeyJwk) throw new Error('Clave pública no encontrada');
      const publicKey = await importPublicKeyJwk(publicKeyJwk);
      const encryptedAesKey = await encryptAesKeyWithRsa(aesKeyRaw, publicKey);
      // 6. Guardar en Storage únicamente los bytes cifrados, no los bytes originales.
      const storageName = `${user.id}/${file.name}_${Date.now()}`;
      await storageAdapter.storeFile(storageName, encryptedData);
      // 7. Guardar metadatos para localizar/verificar/descifrar: nombre, IV, HMAC
      //    y clave AES envuelta. Ninguno revela por sí solo el contenido del archivo.
      const fileId = `file_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const metadata = { id: fileId, userId: user.id, originalName: file.name, storageName, encryptedAesKey, iv, hmac, originalSize: file.size, createdAt: new Date().toISOString(), version: '1.0' };
      await storageAdapter.storeMetadata(metadata);
      const files = await storageAdapter.getUserFiles(user.id);
      set({ files, loading: false, message: 'Archivo cifrado y almacenado exitosamente' });
      endAudit();
    } catch (err: any) {
      endAudit();
      set({ loading: false, error: err.message });
      throw err;
    }
  },

  downloadFile: async (fileId, password) => {
    const { user } = get();
    if (!user) throw new Error('Debe iniciar sesión');
    set({ downloadLoading: true, error: null });
    const endAudit = auditGroup(`⬇️ DESCARGA VERIFICADA: ${fileId}`);
    try {
      const metadata = await storageAdapter.getMetadata(fileId) as any;
      if (!metadata || metadata.userId !== user.id) throw new Error('Archivo no autorizado');
      const encryptedData = await storageAdapter.getFile(metadata.storageName);
      if (!encryptedData) throw new Error('Archivo cifrado no encontrado');
      const encPrivateKey = await databaseAdapter.getEncryptedPrivateKey(user.id);
      if (!encPrivateKey) throw new Error('Clave privada cifrada no encontrada');
      // La contraseña del usuario desbloquea su clave privada RSA, cifrada al crear la cuenta.
      const privateKey = await decryptPrivateKeyWithPassword(encPrivateKey.ciphertext, encPrivateKey.iv, encPrivateKey.salt, password);
      // RSA desenvuelve la clave AES concreta que protegió este archivo.
      const aesKeyRaw = await decryptAesKeyWithRsa(metadata.encryptedAesKey, privateKey);
      const aesKey = await importAesKey(aesKeyRaw);
      // Comprobar integridad ANTES de descifrar o entregar el archivo: si el objeto
      // almacenado cambió, se detiene el flujo aunque el registro de metadata exista.
      const hmacKey = await deriveHmacKey(aesKeyRaw);
      const isValid = await verifyHmac(encryptedData, hmacKey, metadata.hmac);
      if (!isValid) throw new Error('Integridad comprometida: el archivo fue modificado fuera de la aplicación y se bloqueó la descarga por seguridad');
      // AES-GCM hace una segunda comprobación criptográfica integrada al descifrar.
      let fileData: ArrayBuffer;
      try {
        fileData = await decryptFileWithAes(encryptedData, aesKey, metadata.iv);
      } catch {
        throw new Error('Integridad comprometida: el archivo fue modificado fuera de la aplicación y se bloqueó la descarga por seguridad');
      }
      const blob = new Blob([fileData], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = metadata.originalName;
      document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
      set({ downloadLoading: false, message: 'Archivo descargado verificado correctamente' });
      endAudit();
      return fileData;
    } catch (err: any) {
      endAudit();
      set({ downloadLoading: false, error: err.message });
      throw err;
    }
  },

  loadFiles: async () => {
    const { user, sessionId } = get();
    if (!sessionId || !user) return;
    set({ loading: true });
    try {
      const files = await storageAdapter.getUserFiles(user.id);
      set({ files, loading: false });
    } catch (err: any) {
      set({ loading: false, error: err.message });
    }
  },

  clearError: () => set({ error: null }),
  clearMessage: () => set({ message: null }),
}));
