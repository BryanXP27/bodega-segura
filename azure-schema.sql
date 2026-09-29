-- ============================================
-- Bóveda Segura - Esquema Azure Database for PostgreSQL
-- Arranque desde cero (sin Supabase)
-- Universidad Nacional de Cañete - Proyecto 2
-- ============================================
-- Ejecutar en Azure Portal > PostgreSQL Flexible > Query editor / psql.
-- La autorización por usuario se aplica en la API (WHERE user_id = $1),
-- NO con RLS de Supabase. No exponer este pool fuera del App Service.

CREATE TABLE IF NOT EXISTS profiles (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  public_key_jwk JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Credenciales de login (auth propia). Separada de profiles para
-- no exponer jamás el hash al cliente. Solo la API la lee.
CREATE TABLE IF NOT EXISTS auth_credentials (
  user_id TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Clave privada RSA del usuario, cifrada en CLIENTE con su contraseña
-- (PBKDF2 310k + AES-GCM). El servidor solo guarda bytes opacos.
CREATE TABLE IF NOT EXISTS encrypted_private_keys (
  user_id TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
  ciphertext BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  salt BYTEA NOT NULL,
  iterations INTEGER NOT NULL DEFAULT 310000,
  algorithm TEXT NOT NULL DEFAULT 'AES-GCM',
  key_length INTEGER NOT NULL DEFAULT 256,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Metadatos de archivos. Los bytes cifrados viven en Azure Blob Storage
-- (contenedor privado "encrypted-files", objetos "<userId>/...enc").
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  original_name TEXT NOT NULL,
  storage_name TEXT NOT NULL UNIQUE,
  encrypted_aes_key BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  hmac BYTEA NOT NULL,
  original_size BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  version TEXT NOT NULL DEFAULT '1.0'
);

-- Sesiones opacas. Se guarda el HASH del token, nunca el token crudo.
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  token_hash TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);
CREATE INDEX IF NOT EXISTS idx_files_created_at ON files(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);

-- ============================================
-- NOTAS DE SEGURIDAD (Proyecto 2)
-- ============================================
-- 1. Solo la API del App Service accede a estas tablas (pool con DATABASE_URL).
-- 2. El archivo original y la clave privada NUNCA viajan en claro.
-- 3. El HMAC-SHA256 se verifica en el navegador antes de aceptar descargas.
-- 4. El contenedor de blobs debe ser privado, sin acceso anónimo.
