import localAuthAdapter from '@/lib/auth/local-adapter';
import { supabaseStorageAdapter } from '@/lib/storage/supabase-adapter';
import { localStorageAdapter } from '@/lib/storage/local-adapter';
import { supabaseDb } from '@/lib/database/supabase-adapter';
import { db } from '@/lib/database/local-adapter';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';

export const isSupabaseConfigured =
  Boolean(supabaseUrl) &&
  Boolean(supabaseAnonKey) &&
  supabaseUrl !== 'https://tu-proyecto.supabase.co';

export const authAdapter = isSupabaseConfigured
  ? require('@/lib/auth/supabase-adapter').supabaseAuthAdapter
  : localAuthAdapter;

export const storageAdapter = isSupabaseConfigured
  ? supabaseStorageAdapter
  : localStorageAdapter;

export const databaseAdapter = isSupabaseConfigured
  ? supabaseDb
  : db;
