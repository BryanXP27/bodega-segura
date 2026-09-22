import { hashPassword, verifyPassword } from './password-hash';
import { db } from '@/lib/database/local-adapter';
import { AuthAdapter } from '@/types';

const sessions = new Map<string, { userId: string; createdAt: string }>();

const localAuthAdapter: AuthAdapter = {
  async register(email: string, password: string) {
    const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const sessionId = `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const passwordHash = await hashPassword(password);

    await db.createUser({
      id: userId,
      email,
      passwordHash,
      publicKey: null,
      createdAt: new Date().toISOString(),
    });

    sessions.set(sessionId, { userId, createdAt: new Date().toISOString() });

    return { userId, sessionId };
  },

  async login(email: string, password: string) {
    const user = await db.getUserByEmail(email);
    if (!user) {
      throw new Error('Credenciales inválidas');
    }

    if (!user.passwordHash) {
      throw new Error('Cuenta incompleta');
    }

    const isValid = await verifyPassword(password, user.passwordHash);
    if (!isValid) {
      throw new Error('Credenciales inválidas');
    }

    const sessionId = `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    sessions.set(sessionId, { userId: user.id, createdAt: new Date().toISOString() });

    return { userId: user.id, sessionId };
  },

  async logout(sessionId: string) {
    sessions.delete(sessionId);
  },

  async getSession(sessionId: string) {
    const session = sessions.get(sessionId);
    if (!session) return null;
    return { userId: session.userId };
  },

  async verifyPassword(password: string, hash: string) {
    return verifyPassword(password, hash);
  },

  async hashPassword(password: string) {
    return hashPassword(password);
  },
};

export default localAuthAdapter;
export { hashPassword, verifyPassword };