// Adaptador de autenticación Azure para el navegador.
// Habla con /api/auth/* (auth propia + cookie HttpOnly).
// La cripto del Proyecto 2 no cambia: sigue en src/lib/session.

import type { AuthAdapter } from '@/types';
import { azureFetch, clearAzureToken, setAzureToken } from './azure-token';

async function parseJson(res: Response): Promise<{ userId: string; sessionId: string }> {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(
      typeof data?.error === 'string' ? data.error : 'Error de autenticación'
    );
  }
  return data as { userId: string; sessionId: string };
}

export const azureAuthAdapter: AuthAdapter = {
  async register(email: string, password: string) {
    const res = await azureFetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await parseJson(res);
    setAzureToken(data.sessionId || null);
    return data;
  },

  async login(email: string, password: string) {
    const res = await azureFetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await parseJson(res);
    setAzureToken(data.sessionId || null);
    return data;
  },

  async logout() {
    try {
      await azureFetch('/api/auth/logout', { method: 'POST' });
    } finally {
      clearAzureToken();
    }
  },

  async getSession() {
    const res = await azureFetch('/api/users/me');
    if (!res.ok) return null;
    const data = await res.json().catch(() => null);
    if (!data?.id) return null;
    return { userId: data.id as string };
  },

  async verifyPassword() {
    throw new Error('La verificación de contraseña se hace en el servidor');
  },

  async hashPassword() {
    throw new Error('El hash de contraseña se hace en el servidor');
  },
};
