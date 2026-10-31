# Dockerfile para Bóveda Segura (Next.js standalone) en Cloud Run
# NEXT_PUBLIC_BACKEND es necesaria en BUILD (se inyecta en el bundle cliente)
# y en RUNTIME (las rutas /api la leen con process.env). Se declara global
# para que viaje entre etapas.
ARG NEXT_PUBLIC_BACKEND=google
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
# NEXT_PUBLIC_* se inyectan en el bundle durante el build: sin esto el backend
# queda en 'auto' y la app puede caer a local (IndexedDB) en lugar del backend elegido.
ARG NEXT_PUBLIC_BACKEND
ENV NEXT_PUBLIC_BACKEND=${NEXT_PUBLIC_BACKEND}
RUN npm run build

FROM node:20-alpine AS runner
ARG NEXT_PUBLIC_BACKEND
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_PUBLIC_BACKEND=${NEXT_PUBLIC_BACKEND}
ENV NEXT_TELEMETRY_DISABLED=1
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
# Cloud Run expone el contenedor en el puerto definido por la variable PORT
# (por defecto 8080); el server standalone de Next.js lo respeta.
EXPOSE 8080
ENV PORT=8080
ENV HOSTNAME=0.0.0.0
CMD ["node", "server.js"]
