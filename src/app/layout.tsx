'use client';

import React from 'react';
import './globals.css';
import { Header } from '@/components/layout/Header';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es" className="h-full">
      <body className="min-h-screen flex flex-col">
        <Header />
        <main className="flex-1 container mx-auto px-6 pt-20 pb-8">
          {children}
        </main>
        <footer className="relative z-10 border-t border-white/5 py-6">
          <div className="max-w-7xl mx-auto px-6 text-center text-sm text-gray-500">
            <p>Bóveda Segura — Proyecto 2: Cifrado Híbrido — Universidad Nacional de Cañete</p>
          </div>
        </footer>
      </body>
    </html>
  );
}
