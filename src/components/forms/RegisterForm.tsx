'use client';

import React, { useState } from 'react';
import { useAppStore } from '@/lib/session';
import { Button } from '@/components/ui';
import Link from 'next/link';

export function RegisterForm() {
  const { register, message, clearMessage } = useAppStore();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [formError, setFormError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');
    clearMessage();
    if (password !== confirmPassword) { setFormError('Las contraseñas no coinciden'); return; }
    if (password.length < 8) { setFormError('La contraseña debe tener al menos 8 caracteres'); return; }
    if (!email.includes('@')) { setFormError('Formato de correo inválido'); return; }
    setLoading(true);
    try {
      await register(email, password, confirmPassword);
    } catch (err: any) {
      setFormError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-enter min-h-[calc(100vh-12rem)] flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-5xl grid lg:grid-cols-[0.95fr_1.05fr] overflow-hidden rounded-[2rem] border border-cyan-100/15 bg-[#092331]/85 shadow-2xl shadow-cyan-950/40">
        <div className="hidden lg:flex flex-col justify-between p-12 bg-gradient-to-br from-[#0c4050] via-[#0b2e40] to-[#071a28]">
          <div><div className="mb-12 flex items-center gap-3 text-lg font-semibold text-white"><span className="grid h-10 w-10 place-items-center rounded-xl bg-white/10 text-xl">🔐</span>BóvedaSegura</div><p className="mb-4 text-xs font-semibold uppercase tracking-[0.28em] text-cyan-200/70">Empieza con privacidad</p><h2 className="max-w-md text-4xl font-semibold leading-tight text-white">Una bóveda limpia para todo lo importante.</h2><p className="mt-5 max-w-sm text-sm leading-6 text-cyan-50/65">Crea tu cuenta y genera tus claves de seguridad automáticamente.</p></div>
          <div className="space-y-3 text-sm text-cyan-50/70"><p>✓ Cifrado antes de almacenar</p><p>✓ Claves privadas protegidas</p><p>✓ Almacenamiento local</p></div>
        </div>
        <div className="p-7 sm:p-12">
          <div className="mb-9 flex items-center gap-3 lg:hidden"><span className="grid h-10 w-10 place-items-center rounded-xl gradient-bg text-xl">🔐</span><span className="font-semibold text-white">BóvedaSegura</span></div>
          <div className="mb-8"><p className="mb-3 text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300">Nuevo espacio</p><h1 className="text-3xl font-semibold text-white">Crea tu cuenta</h1><p className="mt-2 text-sm text-cyan-50/55">Tu bóveda segura estará lista en unos segundos.</p></div>

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
                  placeholder="Mínimo 8 caracteres"
                  required
                  minLength={8}
                />
              </div>
            </div>
            <div>
              <label className="text-sm font-medium text-gray-300 mb-2 block">Confirmar Contraseña</label>
              <div className="relative">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 text-sm">✓</span>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full rounded-xl border border-cyan-100/15 bg-[#071c2a] px-4 py-3.5 text-sm text-white placeholder-cyan-50/35 outline-none transition-all focus:border-cyan-300/60 focus:ring-2 focus:ring-cyan-300/15"
                  placeholder="Repita su contraseña"
                  required
                />
              </div>
            </div>

            <div className="rounded-xl border border-cyan-300/15 bg-cyan-300/5 p-3 text-sm text-cyan-100/70">
              🔑 Se generará un par de claves RSA-2048 y se cifrará tu clave privada con PBKDF2
            </div>

            {message && (
              <div className="rounded-xl border border-emerald-300/20 bg-emerald-300/10 p-3 text-sm text-emerald-100">
                {message}
              </div>
            )}

            {formError && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-3 text-sm text-red-300">
                {formError}
              </div>
            )}

            <Button type="submit" size="lg" className="w-full !rounded-xl !bg-[#7be3d0] !text-[#06202c] hover:!bg-cyan-200" isLoading={loading}>
              Crear Cuenta Segura
            </Button>
          </form>

          <div className="mt-8 border-t border-white/10 pt-6 text-center text-sm text-cyan-50/55">
            ¿Ya tienes una cuenta?{' '}<Link href="/login" className="font-semibold text-cyan-200 transition-colors hover:text-white">Iniciar sesión</Link>
          </div>
        </div>
      </div>
    </div>
  );
}
