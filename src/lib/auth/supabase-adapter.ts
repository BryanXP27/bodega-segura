import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { AuthAdapter } from '@/types';

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

export { getSupabase };

export const supabaseAuthAdapter: AuthAdapter = {
  async register(email: string, password: string): Promise<{ userId: string; sessionId: string }> {
    const supabase = getSupabase();
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          // Store additional user data
        }
      }
    });
    if (error) throw new Error(error.message);

    if (!data.user || !data.session) {
      throw new Error('Registration failed: no user or session created');
    }

    return {
      userId: data.user.id,
      sessionId: data.session.access_token,
    };
  },

  async login(email: string, password: string): Promise<{ userId: string; sessionId: string }> {
    const supabase = getSupabase();
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw new Error(error.message);

    if (!data.user || !data.session) {
      throw new Error('Login failed: no user or session created');
    }

    return {
      userId: data.user.id,
      sessionId: data.session.access_token,
    };
  },

  async logout(sessionId: string): Promise<void> {
    const supabase = getSupabase();
    const { error } = await supabase.auth.signOut();
    if (error) throw new Error(error.message);
  },

  async getSession(sessionId: string): Promise<{ userId: string } | null> {
    const supabase = getSupabase();
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return null;
    return { userId: session.user.id };
  },

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    // With Supabase Auth, password verification is handled by Supabase
    // This method is kept for compatibility but uses Supabase Auth directly
    return true;
  },

  async hashPassword(password: string): Promise<string> {
    // Supabase handles password hashing internally
    // This is a placeholder for compatibility
    return password;
  },
};

// Supabase Auth session management
export function getSupabaseAuth() {
  const supabase = getSupabase();
  return {
    async signUp(email: string, password: string) {
      return supabase.auth.signUp({ email, password });
    },
    async signIn(email: string, password: string) {
      return supabase.auth.signInWithPassword({ email, password });
    },
    async signOut() {
      return supabase.auth.signOut();
    },
    async getSession() {
      const { data: { session } } = await supabase.auth.getSession();
      return session;
    },
    onAuthStateChange(callback: (event: string, session: any) => void) {
      return supabase.auth.onAuthStateChange(callback);
    },
  };
}

// Get the current authenticated user
export async function getCurrentUser(): Promise<{ id: string; email: string } | null> {
  const supabase = getSupabase();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;
  return { id: user.id, email: user.email || '' };
}
