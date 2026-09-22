# 🔐 Bóveda Segura - Guía de Configuración de Supabase

## Descripción

Esta guía explica paso a paso cómo configurar Supabase para conectar la aplicación Bóveda Segura con servicios en la nube (Auth, Storage, PostgreSQL).

---

## Paso 1: Crear cuenta en Supabase

1. Ve a [https://supabase.com](https://supabase.com)
2. Haz clic en **"Start your project"**
3. Inicia sesión con tu cuenta de GitHub o correo electrónico
4. Crea un nuevo proyecto
   - **Nombre del proyecto**: `bodega-segura`
   - **Región**: Selecciona la más cercana a tu ubicación
   - **Plan**: Free tier (suficiente para desarrollo)
5. Espera a que el proyecto se provisione (1-2 minutos)

---

## Paso 2: Obtener las credenciales

1. En el panel de Supabase, ve a **Settings > API**
2. Copia las siguientes credenciales:
   - **Project URL** → `NEXT_PUBLIC_SUPABASE_URL`
   - **anon public key** → `NEXT_PUBLIC_SUPABASE_ANON_KEY`

3. Pega estas credenciales en tu archivo `.env.local`:

```env
NEXT_PUBLIC_SUPABASE_URL=https://tu-proyecto.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=tu-clave-anonima-aqui
```

> ⚠️ **NUNCA** subas las credenciales reales a GitHub. Solo usa `.env.example` como plantilla.

---

## Paso 3: Configurar la base de datos (PostgreSQL)

### 3.1 Ejecutar el esquema SQL

1. En el panel de Supabase, ve a **SQL Editor**
2. Haz clic en **"New Query"**
3. Copia y pega el contenido de `supabase-schema.sql`
4. Haz clic en **"Run"**

Esto creará:
- Tabla `profiles` (información de usuarios)
- Tabla `encrypted_private_keys` (claves privadas cifradas)
- Tabla `files` (metadatos de archivos)
- Políticas RLS para seguridad
- Funciones helper para Row Level Security

### 3.2 Verificar las tablas

En el panel de Supabase, ve a **Table Editor** y verifica que existan:
- `profiles`
- `encrypted_private_keys`
- `files`

---

## Paso 4: Configurar Supabase Storage

### 4.1 Crear el bucket

1. En el panel de Supabase, ve a **Storage**
2. Haz clic en **"New Bucket"**
3. Configura:
   - **Bucket name**: `encrypted-files`
   - **Public bucket**: ❌ NO (desmarcado)
   - **File size limit**: 100MB o según necesites
4. Haz clic en **"Create bucket"**

### 4.2 Configurar políticas de almacenamiento

En la pestaña **Policies** del bucket `encrypted-files`:

1. **Enable RLS** (si no está habilitado)
2. Crear política: **"Users can upload own files"**
   - Tipo: `INSERT`
   - Policy: `auth.role() = 'authenticated' AND (SELECT auth.uid() = userId FROM profiles WHERE id = auth.uid())`
3. Crear política: **"Users can view own files"**
   - Tipo: `SELECT`
   - Policy: similar a la anterior
4. Crear política: **"Users can delete own files"**
   - Tipo: `DELETE`
   - Policy: similar a la anterior

### 4.3 Usar la política RLS del bucket:
```sql
CREATE POLICY "Users can manage own encrypted files" ON storage.objects
FOR ALL
USING (
  auth.role() = 'authenticated'
  AND bucket_id = 'encrypted-files'
  AND (SELECT userId FROM profiles WHERE id = auth.uid()) IS NOT NULL
);
```

---

## Paso 5: Configurar Supabase Auth

### 5.1 Habilitar autenticación por correo

1. En el panel de Supabase, ve a **Authentication > Settings**
2. Asegúrate de que:
   - ✅ **Enable email sign-ups** está activado
   - ✅ **Enable email confirmations** está configurado según tus preferencias
   - ✅ **Enable email updates** está activado

### 5.2 Configurar redirecciones (opcional)

En **Authentication > Settings > Redirect URLs**:
- Agrega: `http://localhost:3000` (para desarrollo)
- Agrega tu URL de producción en Vercel

---

## Paso 6: Configurar variables de entorno

### 6.1 Variables de entorno para desarrollo

Crea un archivo `.env.local` en la raíz del proyecto:

```env
# Supabase
NEXT_PUBLIC_SUPABASE_URL=https://tu-proyecto.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=tu-clave-anonima-aqui

# Aplicación
NODE_ENV=development
```

### 6.2 Variables de entorno para producción (Vercel)

En el panel de Vercel:
1. Ve a tu proyecto
2. **Settings > Environment Variables**
3. Agrega:
   - `NEXT_PUBLIC_SUPABASE_URL`
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY`

---

## Paso 7: Actualizar la aplicación para usar Supabase

### 7.1 Instalar dependencias

```bash
npm install @supabase/supabase-js
```

### 7.2 Cambiar el adaptador de autenticación

En `src/lib/session/index.ts`, el adaptador se selecciona automáticamente según las variables de entorno. Si `NEXT_PUBLIC_SUPABASE_URL` está configurado, se usan los adaptadores de Supabase.

### 7.3 Configurar el adaptador de almacenamiento

El `localStorageAdapter` se usa por defecto para desarrollo. Para producción con Supabase:

```typescript
// Usar supabaseStorageAdapter en lugar de localStorageAdapter
import { supabaseStorageAdapter } from '@/lib/storage/supabase-adapter';
```

### 7.4 (Opcional) Crear un archivo de configuración centralizado

Crea `src/lib/config.ts`:

```typescript
export const isSupabaseConfigured = Boolean(process.env.NEXT_PUBLIC_SUPABASE_URL);

export const storageAdapter = isSupabaseConfigured
  ? require('@/lib/storage/supabase-adapter').supabaseStorageAdapter
  : require('@/lib/storage/local-adapter').localStorageAdapter;

export const authAdapter = isSupabaseConfigured
  ? require('@/lib/auth/supabase-adapter').supabaseAuthAdapter
  : require('@/lib/auth/local-adapter').default;

export const dbAdapter = isSupabaseConfigured
  ? require('@/lib/database/supabase-adapter').supabaseDb
  : require('@/lib/database/local-adapter').db;
```

---

## Paso 8: Probar la conexión

1. Reinicia el servidor de desarrollo:
```bash
npm run dev
```

2. Ve a `http://localhost:3000`
3. Registra un nuevo usuario
4. Verifica que:
   - El usuario se crea en Supabase Auth
   - El perfil se crea en la tabla `profiles`
   - La clave pública se guarda en `profiles`
   - La clave privada cifrada se guarda en `encrypted_private_keys`
   - Los archivos se guardan en `files` y `encrypted-files` bucket

---

## Paso 9: Desplegar en Vercel

1. Ve a [https://vercel.com](https://vercel.com)
2. Importa tu repositorio de GitHub
3. Configura las variables de entorno:
   - `NEXT_PUBLIC_SUPABASE_URL`
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY`
4. Despliega
5. Verifica que todo funcione en producción

---

## Arquitectura de seguridad

```
┌─────────────────────────────────────────────────────────┐
│                    Navegador del Usuario                  │
│                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐ │
│  │  Registro/   │  │  Cifrado     │  │  Descifrado    │ │
│  │  Login       │  │  (AES-RSA)   │  │  (RSA-AES)     │ │
│  │  (Supabase   │  │  (Web Crypto │  │  (Web Crypto)  │ │
│  │   Auth)      │  │   API)       │  │                │ │
│  └──────┬───────┘  └──────┬───────┘  └───────┬────────┘ │
│         │                 │                   │          │
└─────────┼─────────────────┼───────────────────┼──────────┘
          │                 │                   │
          ▼                 ▼                   ▼
┌─────────────────────────────────────────────────────────┐
│                    Supabase                              │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐ │
│  │   Auth       │  │   PostgreSQL │  │   Storage     │ │
│  │   (correo)   │  │   (datos)    │  │   (archivos)  │ │
│  │              │  │              │  │               │ │
│  │ • perfiles   │  │ • profiles   │  │ • .enc files  │ │
│  │ • sesiones   │  │ • files      │  │ • bucket      │ │
│  │ • claves     │  │ • enc_keys   │  │   encrypted   │ │
│  └──────────────┘  └──────────────┘  └───────────────┘ │
│                                                         │
│  🔒 RLS protege cada tabla a nivel de fila              │
│  🔒 Solo el usuario autenticado accede a sus datos      │
│  🔒 La clave privada NUNCA se expone en texto plano     │
│  🔒 Los archivos siempre están cifrados                 │
└─────────────────────────────────────────────────────────┘
```

---

## Estructura de archivos del proyecto

```
src/
├── lib/
│   ├── auth/
│   │   ├── local-adapter.ts        # Adaptador local (desarrollo)
│   │   ├── supabase-adapter.ts     # Adaptador Supabase (producción)
│   │   └── password-hash.ts        # PBKDF2 hashing local
│   ├── storage/
│   │   ├── local-adapter.ts        # IndexedDB (desarrollo)
│   │   └── supabase-adapter.ts     # Supabase Storage (producción)
│   ├── database/
│   │   ├── local-adapter.ts        # IndexedDB (desarrollo)
│   │   └── supabase-adapter.ts     # PostgreSQL (producción)
│   └── session/
│       └── index.ts                # Zustand store
├── supabase-schema.sql             # Esquema de base de datos
└── .env.example                    # Plantilla de variables
```

---

## Buenas prácticas de seguridad

1. **NUNCA** expongas `service_role` en el frontend
2. **NUNCA** subas `.env` a GitHub
3. **SIEMPRE** usa `anon` key para el frontend
4. **SIEMPRE** habilita RLS en todas las tablas
5. **SIEMPRE** verifica que el usuario es propietario antes de cada operación
6. **SIEMPRE** verifica HMAC antes de entregar archivos
7. **SIEMPRE** almacena la clave privada cifrada
8. **NUNCA** almacenes contraseñas en texto plano

---

## Solución de problemas

### Error: "Supabase URL and ANON_KEY environment variables are required"
→ Verifica que las variables de entorno están correctamente configuradas

### Error: "Failed to create user" en Supabase Auth
→ Verifica que el correo electrónico no esté ya registrado
→ Verifica que las políticas RLS estén configuradas correctamente

### Error: "Bucket not found" en Storage
→ Verifica que el bucket `encrypted-files` existe
→ Verifica que el RLS está habilitado en el bucket

### Error: "Policy violation" en RLS
→ Verifica que `auth.uid()` coincide con el `userId` en la tabla
→ Verifica que las políticas RLS están correctamente definidas

---

## Enlaces útiles

- [Supabase Documentation](https://supabase.com/docs)
- [Supabase Auth](https://supabase.com/docs/guides/auth)
- [Supabase Storage](https://supabase.com/docs/guides/storage)
- [Supabase Row Level Security](https://supabase.com/docs/guides/auth/row-level-security)
- [Supabase PostgreSQL](https://supabase.com/docs/guides/database)
