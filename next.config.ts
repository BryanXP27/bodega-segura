import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // App Service ejecuta `node .next/standalone/server.js` (ver AZURE_DEPLOY.md).
  output: 'standalone',
  // En standalone NO deben incluirse en el bundle los paquetes de servidor
  // con APIs de Node (pg, bcryptjs, storage providers). Se resuelven con require
  // nativo en el runtime del servidor (Cloud Run / App Service).
  serverExternalPackages: [
    '@azure/identity',
    '@azure/storage-blob',
    '@google-cloud/storage',
    '@supabase/supabase-js',
    'bcryptjs',
  ],
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=()',
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload',
          },
        ],
      },
    ];
  },
};

export default nextConfig;
