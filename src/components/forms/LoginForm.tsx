'use client';

import React, { useEffect, useState } from 'react';
import { useAppStore } from '@/lib/session';
import { Button } from '@/components/ui';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

export function LoginForm() {
  const { login, setFiles, setMessage, isAuthenticated } = useAppStore();
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    if (isAuthenticated) router.replace('/dashboard');
  }, [isAuthenticated, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');
    if (!email.includes('@') || !password) {
      setFormError('Complete todos los campos');
      return;
    }
    setLoading(true);
    try {
      await login(email, password);
      setFiles([]);
      setMessage('Inicio de sesión exitoso');
      router.replace('/dashboard');
    } catch (err: any) {
      setFormError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-enter min-h-[calc(100vh-12rem)] flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-5xl grid lg:grid-cols-[1.05fr_0.95fr] overflow-hidden rounded-[2rem] border border-cyan-100/15 bg-[#092331]/85 shadow-2xl shadow-cyan-950/40">
        <div className="hidden lg:flex relative flex-col justify-between p-12 overflow-hidden bg-gradient-to-br from-[#0c4050] via-[#0b2e40] to-[#071a28]">
          <div className="absolute -right-24 -top-24 h-72 w-72 rounded-full border border-cyan-200/20" />
          <div className="absolute right-12 top-20 h-36 w-36 rounded-full border border-teal-200/20" />
          <div className="relative">
            <div className="mb-12 flex items-center gap-3 text-lg font-semibold text-white"><span className="grid h-10 w-10 place-items-center rounded-xl bg-white/10 text-xl">🔐</span>BóvedaSegura</div>
            <p className="mb-4 text-xs font-semibold uppercase tracking-[0.28em] text-cyan-200/70">Tu espacio privado</p>
            <h2 className="max-w-md text-4xl font-semibold leading-tight text-white">Tus archivos, seguros y siempre bajo tu control.</h2>
            <p className="mt-5 max-w-sm text-sm leading-6 text-cyan-50/65">Protección local con cifrado híbrido para que tus documentos nunca viajen sin protección.</p>
          </div>
          <div className="relative grid grid-cols-3 gap-3 text-xs text-cyan-50/70"><span>◈ AES-256</span><span>◈ RSA-2048</span><span>◈ HMAC</span></div>
        </div>
        <div className="p-7 sm:p-12">
          <div className="mb-9 flex items-center gap-3 lg:hidden"><span className="grid h-10 w-10 place-items-center rounded-xl gradient-bg text-xl">🔐</span><span className="font-semibold text-white">BóvedaSegura</span></div>
          <div className="mb-8"><p className="mb-3 text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300">Acceso seguro</p><h1 className="text-3xl font-semibold text-white">Bienvenido de nuevo</h1><p className="mt-2 text-sm text-cyan-50/55">Entra a tu bóveda y continúa donde lo dejaste.</p></div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="text-sm font-medium text-gray-300 mb-2 block">Correo Electrónico</label>
              <div className="relative">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 text-sm">✉</span>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full rounded-xl border border-cyan-100/15 bg-[#071c2a] px-4 py-3.5 text-sm text-white placeholder-cyan-50/35 outline-none transition-all focus:border-cyan-300/60 focus:ring-2 focus:ring-cyan-300/15"
                  placeholder="usuario@example.com"
                  required
                />
              </div>
            </div>
            <div>
              <label className="text-sm font-medium text-gray-300 mb-2 block">Contraseña</label>
              <div className="relative">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 text-sm">🔒</span>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full rounded-xl border border-cyan-100/15 bg-[#071c2a] px-4 py-3.5 text-sm text-white placeholder-cyan-50/35 outline-none transition-all focus:border-cyan-300/60 focus:ring-2 focus:ring-cyan-300/15"
                  placeholder="Tu contraseña"
                  required
                />
              </div>
            </div>

            {formError && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-3 text-sm text-red-300">
                {formError}
              </div>
            )}

            <Button type="submit" size="lg" className="w-full !rounded-xl !bg-[#7be3d0] !text-[#06202c] hover:!bg-cyan-200" isLoading={loading}>
              Iniciar Sesión
            </Button>
          </form>

          <div className="mt-8 border-t border-white/10 pt-6 text-center text-sm text-cyan-50/55">
            ¿Aún no tienes cuenta?{' '}<Link href="/register" className="font-semibold text-cyan-200 transition-colors hover:text-white">Crear cuenta gratis</Link>
          </div>
        </div>
      </div>
    </div>
  );
}
