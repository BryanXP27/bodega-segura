# Bóveda Segura - Proyecto 2: Cifrado Híbrido

## Descripción

Aplicación web académica para el curso de Seguridad y Criptografía de la Universidad Nacional de Cañete. Sistema de bóveda de archivos cifrados utilizando cifrado híbrido.

### Algoritmos implementados

- **AES-256-GCM**: Cifrado de archivos
- **RSA-OAEP (SHA-256)**: Protección de claves AES (2048 bits)
- **PBKDF2 (310,000 iteraciones, SHA-256)**: Derivación de claves desde contraseñas
- **HMAC-SHA256**: Verificación de integridad de archivos

## Instalación

### Requisitos previos

- Node.js 20+
- npm

### Instalación local

```bash
# Clonar el repositorio
git clone <url-del-repo>
cd bodega-segura

# Instalar dependencias
npm install

# Ejecutar en desarrollo
npm run dev
```

La aplicación estará disponible en `http://localhost:3000`.

### Variables de entorno

Copie el archivo `.env.example`:

```bash
cp .env.example .env
```

## Estructura del proyecto

```
src/
├── app/                      # Páginas Next.js (App Router)
│   ├── page.tsx             # Página de inicio
│   ├── login/
│   ├── register/
│   ├── dashboard/
│   └── api/                 # Rutas API
├── lib/
│   ├── crypto/              # Módulo criptográfico
│   │   ├── aes.ts           # Cifrado AES-256-GCM
│   │   ├── rsa.ts           # RSA-OAEP
│   │   ├── pbkdf2.ts        # Derivación PBKDF2
│   │   ├── hmac.ts          # HMAC-SHA256
│   │   └── index.ts
│   ├── auth/                # Módulo de autenticación
│   │   ├── local-adapter.ts # Adaptador local
│   │   └── supabase-adapter.ts # Adaptador Supabase (placeholder)
│   ├── storage/             # Módulo de almacenamiento
│   │   ├── local-adapter.ts # IndexedDB para desarrollo
│   │   └── supabase-adapter.ts # Supabase Storage (placeholder)
│   ├── database/            # Módulo de base de datos
│   │   └── local-adapter.ts # IndexedDB
│   └── session/             # Gestión de sesión (Zustand)
├── components/              # Componentes React
│   ├── ui/                  # Componentes de UI
│   └── forms/               # Formularios
└── hooks/                   # Hooks personalizados
```

## Arquitectura Modular

La aplicación está organizada en módulos independientes con interfaces claras:

- **Autenticación**: Adaptable de local a Supabase Auth
- **Criptografía**: Web Crypto API (ejecutado en el navegador)
- **Almacenamiento**: IndexedDB local, reemplazable por Supabase Storage
- **Base de datos**: IndexedDB local, reemplazable por PostgreSQL

## Migración a Supabase

Para conectar Supabase:

1. Configurar las variables de entorno en `.env`:
   ```
   NEXT_PUBLIC_SUPABASE_URL=https://tu-proyecto.supabase.co
   NEXT_PUBLIC_SUPABASE_ANON_KEY=tu-clave-anonima
   ```
2. Reemplazar los adaptadores locales por las implementaciones de `supabase-adapter.ts`
3. Las páginas y componentes frontend no necesitan cambios

## Despliegue en Vercel

1. Conectar el repositorio GitHub con Vercel
2. Configurar las variables de entorno en el panel de Vercel
3. Desplegar

## Seguridad

- Los archivos se cifran **antes** de ser almacenados
- La clave privada del usuario nunca se almacena en texto plano
- La contraseña se usa con PBKDF2 para derivar claves de cifrado
- Los archivos se verifican con HMAC-SHA256 antes de la descarga
- No se almacenan contraseñas ni claves privadas sin cifrar

## Licencia

Proyecto académico - Universidad Nacional de Cañete
