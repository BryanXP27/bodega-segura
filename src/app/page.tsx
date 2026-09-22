import React from 'react';
import { Button } from '@/components/ui';
import Link from 'next/link';
import { isSupabaseConfigured } from '@/lib/config';

export default function HomePage() {
  return (
    <div className="min-h-screen flex flex-col">
      <main className="flex-1 flex flex-col items-center justify-center px-6 py-20 relative overflow-hidden">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl"></div>
        <div className="absolute top-1/2 left-1/2 w-64 h-64 bg-indigo-500/5 rounded-full blur-3xl"></div>

        <div className="relative z-10 max-w-5xl text-center space-y-12">
          <div className="space-y-6">
            <div className="inline-flex items-center gap-2 glass rounded-full px-4 py-2 text-sm text-gray-300 mb-4">
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></div>
              Cifrado Híbrido · AES-256 · RSA-OAEP
            </div>
            <h1 className="text-6xl md:text-7xl font-bold text-white leading-tight tracking-tight">
              Bóveda<span className="gradient-text">Segura</span>
            </h1>
            <p className="text-xl md:text-2xl text-gray-400 max-w-2xl mx-auto leading-relaxed">
              Almacenamiento de archivos cifrado con tecnología de última generación. 
              Tus archivos se protegen antes de salir de tu dispositivo.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-3xl mx-auto">
            <Link href="/register">
              <div className="feature-card rounded-2xl p-6 cursor-pointer group">
                <div className="w-14 h-14 rounded-xl gradient-bg flex items-center justify-center text-white text-2xl mb-4 shadow-lg group-hover:shadow-glow-strong transition-all">
                  🔒
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">Cifrado AES-256</h3>
                <p className="text-gray-400 text-sm leading-relaxed">Cada archivo se cifra con una clave AES única y aleatoria. Seguridad de nivel militar.</p>
              </div>
            </Link>
            <Link href="/register">
              <div className="feature-card rounded-2xl p-6 cursor-pointer group">
                <div className="w-14 h-14 rounded-xl gradient-bg flex items-center justify-center text-white text-2xl mb-4 shadow-lg group-hover:shadow-glow-strong transition-all">
                  🔑
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">RSA-OAEP</h3>
                <p className="text-gray-400 text-sm leading-relaxed">Las claves AES se protegen con tu clave pública RSA de 2048 bits.</p>
              </div>
            </Link>
            <Link href="/register">
              <div className="feature-card rounded-2xl p-6 cursor-pointer group">
                <div className="w-14 h-14 rounded-xl gradient-bg flex items-center justify-center text-white text-2xl mb-4 shadow-lg group-hover:shadow-glow-strong transition-all">
                  🛡️
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">Integridad HMAC</h3>
                <p className="text-gray-400 text-sm leading-relaxed">Verificación HMAC-SHA256 para garantizar que tus archivos no han sido alterados.</p>
              </div>
            </Link>
          </div>

          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
            <Link href="/register">
              <Button size="lg" className="min-w-[200px]">
                ✨ Crear Cuenta
              </Button>
            </Link>
            <Link href="/login">
              <Button variant="secondary" size="lg" className="min-w-[200px]">
                Iniciar Sesión
              </Button>
            </Link>
          </div>

          <div className="flex flex-wrap justify-center gap-8 mt-12 text-sm text-gray-500">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-emerald-400"></div>
              {isSupabaseConfigured ? 'Supabase' : '100% Local'}
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-emerald-400"></div>
              Sin Texto Plano
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-emerald-400"></div>
              Web Crypto API
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-emerald-400"></div>
              Código Abierto
            </div>
          </div>
        </div>
      </main>

      <footer className="relative z-10 border-t border-white/5 py-6">
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-gray-500">
          <p>Bóveda Segura — Proyecto 2: Cifrado Híbrido</p>
          <p>Universidad Nacional de Cañete · Seguridad y Criptografía</p>
        </div>
      </footer>
    </div>
  );
}
