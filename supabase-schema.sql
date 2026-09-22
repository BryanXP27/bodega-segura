-- ============================================
-- Bóveda Segura - Esquema de Base de Datos Supabase
-- Proyecto 2: Cifrado Híbrido
-- Universidad Nacional de Cañete
-- ============================================

-- ============================================
-- 1. TABLA DE PERFILES (profiles)
-- ============================================
CREATE TABLE IF NOT EXISTS profiles (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  publicKeyJwk JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Habilitar Row Level Security (RLS)
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Política: Los usuarios pueden ver su propio perfil
CREATE POLICY "Users can view own profile" ON profiles
  FOR SELECT USING (auth.uid() = id);

-- Política: Los usuarios pueden actualizar su propio perfil
CREATE POLICY "Users can update own profile" ON profiles
  FOR UPDATE USING (auth.uid() = id);

-- Política: Los usuarios pueden insertar su propio perfil
CREATE POLICY "Users can insert own profile" ON profiles
  FOR INSERT WITH CHECK (auth.uid() = id);

-- ============================================
-- 2. TABLA DE CLAVES PRIVADAS CIFRADAS
-- ============================================
CREATE TABLE IF NOT EXISTS encrypted_private_keys (
  userId TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
  ciphertext BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  salt BYTEA NOT NULL,
  iterations INTEGER NOT NULL DEFAULT 310000,
  algorithm TEXT NOT NULL DEFAULT 'AES-GCM',
  keyLength INTEGER NOT NULL DEFAULT 256,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Habilitar RLS
ALTER TABLE encrypted_private_keys ENABLE ROW LEVEL SECURITY;

-- Política: Los usuarios pueden ver su propia clave privada cifrada
CREATE POLICY "Users can view own encrypted key" ON encrypted_private_keys
  FOR SELECT USING (auth.uid() = userId);

-- Política: Los usuarios pueden actualizar su propia clave privada cifrada
CREATE POLICY "Users can update own encrypted key" ON encrypted_private_keys
  FOR UPDATE USING (auth.uid() = userId);

-- Política: Los usuarios pueden insertar su propia clave privada cifrada
CREATE POLICY "Users can insert own encrypted key" ON encrypted_private_keys
  FOR INSERT WITH CHECK (auth.uid() = userId);

-- ============================================
-- 3. TABLA DE ARCHIVOS
-- ============================================
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  userId TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  originalName TEXT NOT NULL,
  storageName TEXT NOT NULL,
  encryptedAesKey BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  hmac BYTEA NOT NULL,
  originalSize BIGINT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  version TEXT NOT NULL DEFAULT '1.0'
);

-- Habilitar RLS
ALTER TABLE files ENABLE ROW LEVEL SECURITY;

-- Política: Los usuarios pueden ver sus propios archivos
CREATE POLICY "Users can view own files" ON files
  FOR SELECT USING (auth.uid() = userId);

-- Política: Los usuarios pueden insertar sus propios archivos
CREATE POLICY "Users can insert own files" ON files
  FOR INSERT WITH CHECK (auth.uid() = userId);

-- Política: Los usuarios pueden actualizar sus propios archivos
CREATE POLICY "Users can update own files" ON files
  FOR UPDATE USING (auth.uid() = userId);

-- Política: Los usuarios pueden eliminar sus propios archivos
CREATE POLICY "Users can delete own files" ON files
  FOR DELETE USING (auth.uid() = userId);

-- Índice para búsquedas por usuario
CREATE INDEX idx_files_userId ON files(userId);
CREATE INDEX idx_files_createdAt ON files(created_at DESC);

-- ============================================
-- 4. CONFIGURACIÓN DE ALMACENAMIENTO (Storage)
-- ============================================
-- Crear el bucket para archivos cifrados
-- Esto se hace desde el panel de Supabase o con SQL:

-- NOTA: El bucket "encrypted-files" debe crearse desde el
-- panel de Supabase Storage o con la API.
-- En la consola de Supabase: Storage > New Bucket > encrypted-files
-- Con RLS habilitado.

-- ============================================
-- 5. FUNCIONES DE SEGURIDAD (RLS Policies)
-- ============================================

-- Función helper para verificar que el usuario es propietario
CREATE OR REPLACE FUNCTION is_owner(user_id TEXT)
RETURNS BOOLEAN AS $$
BEGIN
  RETURN auth.uid() = user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- 6. POLÍTICAS ADICIONALES CON FUNCIONES
-- ============================================

-- Actualizar políticas para usar la función helper
DROP POLICY IF EXISTS "Users can view own files" ON files;
CREATE POLICY "Users can view own files" ON files
  FOR SELECT USING (is_owner(userId));

DROP POLICY IF EXISTS "Users can update own files" ON files;
CREATE POLICY "Users can update own files" ON files
  FOR UPDATE USING (is_owner(userId));

DROP POLICY IF EXISTS "Users can delete own files" ON files;
CREATE POLICY "Users can delete own files" ON files
  FOR DELETE USING (is_owner(userId));

-- ============================================
-- 7. CONFIGURACIÓN DE AUTENTICACIÓN
-- ============================================

-- Habilitar correo electrónico en Supabase Auth
-- En el panel de Supabase: Authentication > Settings
-- Asegurarse de que "Enable email sign-up" esté activado
-- Asegurarse de que "Enable email confirmations" esté configurado según prefiera

-- ============================================
-- NOTAS IMPORTANTES
-- ============================================
-- 1. NO exponga la clave service_role en el frontend
-- 2. Use la clave anónima (anon key) para el frontend
-- 3. Las políticas RLS protegen los datos a nivel de fila
-- 4. El usuario autenticado solo puede acceder a sus propios datos
-- 5. La clave privada del usuario NUNCA se almacena en texto plano
-- 6. El archivo original NUNCA se sube sin cifrar
-- 7. El HMAC-SHA256 se verifica antes de cualquier descarga
-- ============================================
