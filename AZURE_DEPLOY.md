# Despliegue en Azure Portal — Bóveda Segura (backend `azure`)

Backend elegido: **Azure Database for PostgreSQL Flexible** + **auth propia** + **Blob Storage**.
Arranque **desde cero** (sin migrar Supabase). La cripto del Proyecto 2 no cambia: sigue
en el navegador (`src/lib/crypto/*`, `src/lib/session/index.ts`).

## 1. Recursos en Azure Portal

1. Resource Group, ej. `rg-boveda-segura`.
2. **PostgreSQL Flexible Server** (Postgres 15/16, Burstable B1ms para curso, SSL forzado).
   Firewall: tu IP + salida del App Service. Crear DB `bodega` y usuario `bodega_app`.
3. Ejecutar `azure-schema.sql` en el Query editor / `psql` contra `bodega`.
   Crea: `profiles`, `auth_credentials`, `encrypted_private_keys`, `files`, `sessions`.
4. **Storage Account V2** + contenedor `encrypted-files` en **privado** (lo crea solo la API
   con `createIfNotExists({ access: 'private' })`, pero créalo tú para verificar).
5. **App Service Linux** (Plan B1, Node 20/22, HTTPS Only, TLS 1.2+).
6. Opcional: **Key Vault** + **Application Insights**.

## 2. Configuration del App Service (variables)

Servidor (sin `NEXT_PUBLIC_`, nunca llegan al navegador):

- `DATABASE_URL=postgresql://bodega_app:***@<servidor>.postgres.database.azure.com:5432/bodega?sslmode=require`
- `SESSION_COOKIE_NAME=bodega_session` (opcional)
- `SESSION_TTL_DAYS=7` (opcional)
- `BCRYPT_ROUNDS=12` (opcional)
- `AZURE_PG_SSL=require` (usa `disable` solo en local sin SSL)
- Blob, UNA de las dos:
  - `AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=***;...`
  - `AZURE_STORAGE_ACCOUNT_URL=https://<cuenta>.blob.core.windows.net` (+ Managed Identity)
- `AZURE_STORAGE_CONTAINER=encrypted-files` (opcional)
- `NODE_ENV=production`

Cliente (se incrustan en el build, repite el deploy si cambian):

- `NEXT_PUBLIC_BACKEND=azure`

Nunca subas `.env.local` al repo. Mejor usa referencias Key Vault
`@Microsoft.KeyVault(SecretUri=...)` en App Settings.

## 3. Deploy

1. Deployment Center > GitHub > repo `bodega-segura` (o despliegue desde tu pipeline).
2. Startup command: `node .next/standalone/server.js` (`output: 'standalone'` ya está en `next.config.ts`).
3. Health: `GET /api/health` → `{ status:'ok', backend:'azure', db:'ok', blob:'configured' }`.

## 4. Verificación Proyecto 2 en Azure

- Registro/login/logout; sesión en cookie HttpOnly + Bearer fallback.
- Subir archivo → Blob `<userId>/...enc` ilegible + fila en `files`.
- Descarga con contraseña correcta OK; con contraseña errónea falla al abrir la privada.
- Manipular 1 byte del blob → `verifyHmac` falla ("integridad comprometida").
- Usuario A no puede leer `/api/files/:id` ni blobs de B (403/404).
- `auth_credentials.password_hash` jamás aparece en respuestas; `sessions` guarda hash, no token.
- HTTPS obligatorio (`HSTS` activo en `next.config.ts`).

## 5. Rollback

`NEXT_PUBLIC_BACKEND=supabase|local` + redeploy vuelve al backend anterior sin tocar código.
Los adaptadores legacy siguen en `src/lib/*/supabase-adapter.ts` y `local-adapter.ts`.
