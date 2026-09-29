import localAuthAdapter from '@/lib/auth/local-adapter';
import { supabaseAuthAdapter } from '@/lib/auth/supabase-adapter';
import { azureAuthAdapter } from '@/lib/auth/azure-client-adapter';
import { supabaseStorageAdapter } from '@/lib/storage/supabase-adapter';
import { localStorageAdapter } from '@/lib/storage/local-adapter';
import { azureStorageAdapter } from '@/lib/storage/azure-client-adapter';
import { supabaseDb } from '@/lib/database/supabase-adapter';
import { db } from '@/lib/database/local-adapter';
import { azureDb } from '@/lib/database/azure-client-adapter';

// NEXT_PUBLIC_BACKEND: 'azure' | 'supabase' | 'local' | 'auto' (default).
// - azure: auth propia + PostgreSQL + Blob via /api (listo para Azure Portal).
// - supabase: comportamiento actual con Supabase.
// - local: IndexedDB del navegador (demo sin backend).
// - auto: supabase si hay credenciales, si no local.
const backend = (process.env.NEXT_PUBLIC_BACKEND || 'auto').toLowerCase();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';

export const isSupabaseConfigured =
  Boolean(supabaseUrl) &&
  Boolean(supabaseAnonKey) &&
  supabaseUrl !== 'https://tu-proyecto.supabase.co';

export const isAzureBackend =
  backend === 'azure' || process.env.NEXT_PUBLIC_AZURE_ENABLED === 'true';

export const backendName: 'azure' | 'supabase' | 'local' = isAzureBackend
  ? 'azure'
  : backend === 'supabase' || (backend === 'auto' && isSupabaseConfigured)
    ? 'supabase'
    : 'local';

export const authAdapter =
  backendName === 'azure'
    ? azureAuthAdapter
    : backendName === 'supabase'
      ? supabaseAuthAdapter
      : localAuthAdapter;

export const storageAdapter =
  backendName === 'azure'
    ? azureStorageAdapter
    : backendName === 'supabase'
      ? supabaseStorageAdapter
      : localStorageAdapter;

export const databaseAdapter =
  backendName === 'azure' ? azureDb : backendName === 'supabase' ? supabaseDb : db;
