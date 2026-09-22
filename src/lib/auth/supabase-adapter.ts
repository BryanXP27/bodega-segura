import { AuthAdapter } from '@/types';

export const supabaseAuthAdapter: AuthAdapter = {
  async register(email: string, password: string): Promise<{ userId: string; sessionId: string }> {
    throw new Error('Supabase Auth not configured.');
  },

  async login(email: string, password: string): Promise<{ userId: string; sessionId: string }> {
    throw new Error('Supabase Auth not configured.');
  },

  async logout(sessionId: string): Promise<void> {
    throw new Error('Supabase Auth not configured.');
  },

  async getSession(sessionId: string): Promise<{ userId: string } | null> {
    throw new Error('Supabase Auth not configured.');
  },

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    throw new Error('Supabase Auth not configured.');
  },

  async hashPassword(password: string): Promise<string> {
    throw new Error('Supabase Auth not configured.');
  },
};
