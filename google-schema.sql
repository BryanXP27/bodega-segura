-- ============================================
-- Bóveda Segura - Esquema Google Cloud SQL (PostgreSQL)
-- Arranque desde cero (reemplazo de Azure)
-- UNDC 2026 - Proyecto 2: Cifrado Híbrido
-- ============================================
-- Cloud SQL es PostgreSQL: misma sintaxis que azure-schema.sql.
-- Ejecutar en Cloud Shell / Cloud SQL Studio contra la base "bodega".

CREATE TABLE IF NOT EXISTS profiles (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  public_key_jwk JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Credenciales de login (auth propia). Separada de profiles para
-- no exponer jamás el hash al cliente.
CREATE TABLE IF NOT EXISTS auth_credentials (
  user_id TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Metadatos de archivos. Los bytes cifrados viven en Cloud Storage.
-- NOTA: la clave privada cifrada ya NO vive aquí; se guarda en el bucket
-- privado "encrypted-files" (alineado al enunciado del Proyecto 2).
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
-- 1. Solo la app en Cloud Run accede a estas tablas.
-- 2. El archivo original y la clave privada NUNCA viajan en claro.
-- 3. El HMAC-SHA256 se verifica en el navegador antes de aceptar descargas.
-- 4. El bucket "encrypted-files" debe ser privado, sin acceso anónimo.
-- 5. La clave privada cifrada se guarda como objeto:
--    "<userId>/private-key.enc" (base64) dentro del bucket.
