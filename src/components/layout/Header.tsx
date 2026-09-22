import React from 'react';
import Link from 'next/link';
import { useAppStore } from '@/lib/session';
import { Button } from '@/components/ui';
import { usePathname } from 'next/navigation';

export function Header() {
  const { isAuthenticated, user, logout } = useAppStore();
  const pathname = usePathname();

  const handleLogout = async () => {
    await logout();
  };

  return (
    <header className="fixed top-0 left-0 right-0 z-50 glass">
      <nav className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-3 group">
          <div className="w-10 h-10 rounded-xl gradient-bg flex items-center justify-center text-white font-bold text-lg shadow-lg group-hover:shadow-glow-strong transition-shadow">
            🔐
          </div>
          <span className="text-xl font-bold text-white tracking-tight">
            Bóveda<span className="gradient-text">Segura</span>
          </span>
        </Link>
        <div className="flex items-center gap-3">
          {isAuthenticated ? (
            <>
              <div className="hidden md:flex items-center gap-2 glass rounded-full px-4 py-2 text-sm text-gray-300">
                <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></div>
                {user?.email}
              </div>
              <Link href="/dashboard">
                <Button variant="ghost" size="sm" className="text-white/80 hover:text-white hover:bg-white/10 border border-white/10">
                  Panel
                </Button>
              </Link>
              <Button variant="ghost" size="sm" onClick={handleLogout} className="text-white/60 hover:text-white hover:bg-white/10 border border-white/10">
                Cerrar Sesión
              </Button>
            </>
          ) : (
            <>
              <Link href="/login">
                <Button variant="ghost" size="sm" className="text-white/80 hover:text-white hover:bg-white/10 border border-white/10">
                  Iniciar Sesión
                </Button>
              </Link>
              <Link href="/register">
                <Button size="sm" className="gradient-bg text-white hover:opacity-90 border-none shadow-lg">
                  Registrarse
                </Button>
              </Link>
            </>
          )}
        </div>
      </nav>
    </header>
  );
}
