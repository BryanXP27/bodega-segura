-- ============================================
-- Bóveda Segura - Esquema de Base de Datos Supabase
-- Proyecto 2: Cifrado Híbrido
-- Universidad Nacional de Cañete
-- ============================================

-- ============================================
-- 1. TABLA DE PERFILES (profiles)
-- ============================================
CREATE TABLE IF NOT EXISTS public.profiles (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  "publicKeyJwk" JSONB,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Habilitar Row Level Security (RLS)
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Política: Los usuarios pueden ver su propio perfil
DROP POLICY IF EXISTS "Users can view own profile" ON profiles;
CREATE POLICY "Users can view own profile" ON profiles
  FOR SELECT USING (auth.uid()::TEXT = id);

-- Política: Los usuarios pueden actualizar su propio perfil
DROP POLICY IF EXISTS "Users can update own profile" ON profiles;
CREATE POLICY "Users can update own profile" ON profiles
  FOR UPDATE USING (auth.uid()::TEXT = id);

-- Política: Los usuarios pueden insertar su propio perfil
DROP POLICY IF EXISTS "Users can insert own profile" ON profiles;
CREATE POLICY "Users can insert own profile" ON profiles
  FOR INSERT WITH CHECK (auth.uid()::TEXT = id);

-- ============================================
-- 2. TABLA DE CLAVES PRIVADAS CIFRADAS
-- ============================================
CREATE TABLE IF NOT EXISTS public.encrypted_private_keys (
  "userId" TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
  ciphertext BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  salt BYTEA NOT NULL,
  iterations INTEGER NOT NULL DEFAULT 310000,
  algorithm TEXT NOT NULL DEFAULT 'AES-GCM',
  "keyLength" INTEGER NOT NULL DEFAULT 256,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Migración para instalaciones creadas con keyLength sin comillas.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'encrypted_private_keys'
      AND column_name = 'keylength'
  ) AND NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'encrypted_private_keys'
      AND column_name = 'keyLength'
  ) THEN
    ALTER TABLE public.encrypted_private_keys RENAME COLUMN keylength TO "keyLength";
  END IF;
END $$;

-- Habilitar RLS
ALTER TABLE encrypted_private_keys ENABLE ROW LEVEL SECURITY;

-- Política: Los usuarios pueden ver su propia clave privada cifrada
DROP POLICY IF EXISTS "Users can view own encrypted key" ON encrypted_private_keys;
CREATE POLICY "Users can view own encrypted key" ON encrypted_private_keys
  FOR SELECT USING (auth.uid()::TEXT = "userId");

-- Política: Los usuarios pueden actualizar su propia clave privada cifrada
DROP POLICY IF EXISTS "Users can update own encrypted key" ON encrypted_private_keys;
CREATE POLICY "Users can update own encrypted key" ON encrypted_private_keys
  FOR UPDATE USING (auth.uid()::TEXT = "userId");

-- Política: Los usuarios pueden insertar su propia clave privada cifrada
DROP POLICY IF EXISTS "Users can insert own encrypted key" ON encrypted_private_keys;
CREATE POLICY "Users can insert own encrypted key" ON encrypted_private_keys
  FOR INSERT WITH CHECK (auth.uid()::TEXT = "userId");

-- ============================================
-- 3. TABLA DE ARCHIVOS
-- ============================================
CREATE TABLE IF NOT EXISTS public.files (
  id TEXT PRIMARY KEY,
  "userId" TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  "originalName" TEXT NOT NULL,
  "storageName" TEXT NOT NULL,
  "encryptedAesKey" BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  hmac BYTEA NOT NULL,
  "originalSize" BIGINT,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  version TEXT NOT NULL DEFAULT '1.0'
);

-- Habilitar RLS
ALTER TABLE files ENABLE ROW LEVEL SECURITY;

-- Política: Los usuarios pueden ver sus propios archivos
DROP POLICY IF EXISTS "Users can view own files" ON files;
CREATE POLICY "Users can view own files" ON files
  FOR SELECT USING (auth.uid()::TEXT = "userId");

-- Política: Los usuarios pueden insertar sus propios archivos
DROP POLICY IF EXISTS "Users can insert own files" ON files;
CREATE POLICY "Users can insert own files" ON files
  FOR INSERT WITH CHECK (auth.uid()::TEXT = "userId");

-- Política: Los usuarios pueden actualizar sus propios archivos
DROP POLICY IF EXISTS "Users can update own files" ON files;
CREATE POLICY "Users can update own files" ON files
  FOR UPDATE USING (auth.uid()::TEXT = "userId");

-- Política: Los usuarios pueden eliminar sus propios archivos
DROP POLICY IF EXISTS "Users can delete own files" ON files;
CREATE POLICY "Users can delete own files" ON files
  FOR DELETE USING (auth.uid()::TEXT = "userId");

-- Índice para búsquedas por usuario
CREATE INDEX IF NOT EXISTS idx_files_userId ON files("userId");
CREATE INDEX IF NOT EXISTS idx_files_createdAt ON files("createdAt" DESC);

-- ============================================
-- 4. CONFIGURACIÓN DE ALMACENAMIENTO (Storage)
-- ============================================
-- Crear el bucket privado para archivos cifrados.
-- La operación es idempotente y también puede hacerse desde Storage.

INSERT INTO storage.buckets (id, name, public)
VALUES ('encrypted-files', 'encrypted-files', false)
ON CONFLICT (id) DO NOTHING;

DROP POLICY IF EXISTS "Users can upload own encrypted files" ON storage.objects;
CREATE POLICY "Users can upload own encrypted files" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'encrypted-files'
    AND (storage.foldername(name))[1] = (auth.uid())::TEXT
  );

DROP POLICY IF EXISTS "Users can read own encrypted files" ON storage.objects;
CREATE POLICY "Users can read own encrypted files" ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'encrypted-files'
    AND (storage.foldername(name))[1] = (auth.uid())::TEXT
  );

DROP POLICY IF EXISTS "Users can delete own encrypted files" ON storage.objects;
CREATE POLICY "Users can delete own encrypted files" ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'encrypted-files'
    AND (storage.foldername(name))[1] = (auth.uid())::TEXT
  );

-- ============================================
-- 5. FUNCIONES DE SEGURIDAD (RLS Policies)
-- ============================================

-- Función helper para verificar que el usuario es propietario
CREATE OR REPLACE FUNCTION public.is_owner(user_id TEXT)
RETURNS BOOLEAN AS $$
BEGIN
  RETURN auth.uid()::TEXT = user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- 6. POLÍTICAS ADICIONALES CON FUNCIONES
-- ============================================

-- Actualizar políticas para usar la función helper
DROP POLICY IF EXISTS "Users can view own files" ON files;
CREATE POLICY "Users can view own files" ON files
  FOR SELECT USING (is_owner("userId"));

DROP POLICY IF EXISTS "Users can update own files" ON files;
CREATE POLICY "Users can update own files" ON files
  FOR UPDATE USING (is_owner("userId"));

DROP POLICY IF EXISTS "Users can delete own files" ON files;
CREATE POLICY "Users can delete own files" ON files
  FOR DELETE USING (is_owner("userId"));

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
