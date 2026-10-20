import localAuthAdapter from '@/lib/auth/local-adapter';
import { supabaseAuthAdapter } from '@/lib/auth/supabase-adapter';
import { azureAuthAdapter } from '@/lib/auth/azure-client-adapter';
import { supabaseStorageAdapter } from '@/lib/storage/supabase-adapter';
import { localStorageAdapter } from '@/lib/storage/local-adapter';
import { azureStorageAdapter } from '@/lib/storage/azure-client-adapter';
import { googleStorageAdapter } from '@/lib/storage/google-client-adapter';
import { supabaseDb } from '@/lib/database/supabase-adapter';
import { db } from '@/lib/database/local-adapter';
import { azureDb } from '@/lib/database/azure-client-adapter';
import { googleDb } from '@/lib/database/google-client-adapter';

// NEXT_PUBLIC_BACKEND: 'google' | 'azure' | 'supabase' | 'local' | 'auto' (default).
// - google: Cloud Run + Cloud SQL + Cloud Storage via /api (auth propia).
// - azure: PostgreSQL + Blob via /api.
// - supabase: comportamiento con Supabase (Vercel).
// - local: IndexedDB del navegador (demo sin backend).
// - auto: supabase si hay credenciales, si no local.
const backend = (process.env.NEXT_PUBLIC_BACKEND || 'auto').toLowerCase();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';

export const isSupabaseConfigured =
  Boolean(supabaseUrl) &&
  Boolean(supabaseAnonKey) &&
  supabaseUrl !== 'https://tu-proyecto.supabase.co';

const explicit = backend === 'google' || backend === 'azure' || backend === 'supabase' || backend === 'local';

export const backendName: 'google' | 'azure' | 'supabase' | 'local' =
  backend === 'google'
    ? 'google'
    : backend === 'azure'
      ? 'azure'
      : backend === 'supabase'
        ? 'supabase'
        : backend === 'local'
          ? 'local'
          : isSupabaseConfigured
            ? 'supabase'
            : 'local';

export const isGoogleBackend = backendName === 'google';
export const isAzureBackend = backendName === 'azure';
export const isSupabaseBackend = backendName === 'supabase';

export const authAdapter =
  backendName === 'google'
    ? azureAuthAdapter
    : backendName === 'azure'
      ? azureAuthAdapter
      : backendName === 'supabase'
        ? supabaseAuthAdapter
        : localAuthAdapter;

export const storageAdapter =
  backendName === 'google'
    ? googleStorageAdapter
    : backendName === 'azure'
      ? azureStorageAdapter
      : backendName === 'supabase'
        ? supabaseStorageAdapter
        : localStorageAdapter;

export const databaseAdapter =
  backendName === 'google'
    ? googleDb
    : backendName === 'azure'
      ? azureDb
      : backendName === 'supabase'
        ? supabaseDb
        : db;

export const backendLabel: string = explicit
  ? backendName
  : `auto → ${backendName}`;
