// Cliente Supabase compartido (singleton).
// Todos los adaptadores deben usar getSupabaseClient() en vez de crear
// su propio createClient: múltiples instancias GoTrue con la misma
// storage key producen el warning "Multiple GoTrueClient instances"
// y pueden dar comportamiento indefinido en concurrencia.

import { createClient, type SupabaseClient } from '@supabase/supabase-js';

let client: SupabaseClient | null = null;

export function getSupabaseClient(): SupabaseClient {
  if (client) return client;
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !anonKey) {
    throw new Error('Supabase URL and ANON_KEY environment variables are required');
  }
  client = createClient(url, anonKey, {
    global: {
      // Los objetos se suben con cacheControl 3600 y el navegador cachearía
      // los bytes descargados: tras una manipulación externa serviría la
      // copia vieja (HMAC válido) hasta refrescar. no-store obliga a traer
      // bytes frescos en cada descarga/vista previa.
      fetch: (input, init) => fetch(input, { ...(init || {}), cache: 'no-store' }),
    },
  });
  return client;
}
