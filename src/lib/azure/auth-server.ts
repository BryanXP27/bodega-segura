// Auth propia SOLO SERVIDOR contra Azure PostgreSQL.
// - El hash de login (bcrypt) vive en auth_credentials, jamás sale al cliente.
// - Las sesiones son tokens opacos: se guarda su SHA-256, nunca el token crudo.
// - La protección de la clave privada (PBKDF2 cliente) NO cambia: sigue en el navegador.

import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import type { NextRequest, NextResponse } from 'next/server';
import { query } from './pg';
import {
  BCRYPT_ROUNDS,
  SESSION_COOKIE_NAME,
  SESSION_TTL_DAYS,
  isProd,
} from './env';

export interface SessionUser {
  userId: string;
  email: string;
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function validateCredentials(email: string, password: string): void {
  if (!email || !email.includes('@')) throw new Error('Formato de correo inválido');
  if (!password || password.length < 8) {
    throw new Error('La contraseña debe tener al menos 8 caracteres');
  }
}

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

async function createSession(userId: string): Promise<{ token: string; expiresAt: Date }> {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);
  const id = crypto.randomUUID();
  await query(
    'INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)',
    [id, userId, tokenHash, expiresAt.toISOString()]
  );
  return { token, expiresAt };
}

export async function registerUser(
  email: string,
  password: string
): Promise<{ userId: string; token: string; expiresAt: Date }> {
  validateCredentials(email, password);
  const normalized = normalizeEmail(email);

  const existing = await query<{ id: string }>('SELECT id FROM profiles WHERE email = $1', [
    normalized,
  ]);
  if (existing.rows.length > 0) throw new Error('El correo ya está registrado');

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const userId = `user_${crypto.randomUUID()}`;
  const now = new Date().toISOString();

  await query('INSERT INTO profiles (id, email, public_key_jwk, created_at) VALUES ($1, $2, $3, $4)', [
    userId,
    normalized,
    null,
    now,
  ]);
  try {
    await query('INSERT INTO auth_credentials (user_id, password_hash) VALUES ($1, $2)', [
      userId,
      passwordHash,
    ]);
  } catch (err) {
    await query('DELETE FROM profiles WHERE id = $1', [userId]);
    throw err;
  }

  const { token, expiresAt } = await createSession(userId);
  return { userId, token, expiresAt };
}

export async function loginUser(
  email: string,
  password: string
): Promise<{ userId: string; token: string; expiresAt: Date }> {
  validateCredentials(email, password);
  const normalized = normalizeEmail(email);

  const user = await query<{ id: string }>('SELECT id FROM profiles WHERE email = $1', [normalized]);
  if (user.rows.length === 0) throw new Error('Credenciales inválidas');
  const userId = user.rows[0].id;

  const cred = await query<{ password_hash: string }>(
    'SELECT password_hash FROM auth_credentials WHERE user_id = $1',
    [userId]
  );
  if (cred.rows.length === 0) throw new Error('Cuenta incompleta');
  const ok = await bcrypt.compare(password, cred.rows[0].password_hash);
  if (!ok) throw new Error('Credenciales inválidas');

  const { token, expiresAt } = await createSession(userId);
  return { userId, token, expiresAt };
}

export function getRequestToken(req: NextRequest): string | null {
  const fromCookie = req.cookies.get(SESSION_COOKIE_NAME)?.value;
  if (fromCookie) return fromCookie;
  const auth = req.headers.get('authorization');
  if (auth && auth.toLowerCase().startsWith('bearer ')) {
    return auth.slice(7).trim() || null;
  }
  return null;
}

export async function getSessionUser(token: string | null): Promise<SessionUser | null> {
  if (!token) return null;
  const tokenHash = hashToken(token);
  const result = await query<{ user_id: string; email: string; expires_at: string; revoked_at: string | null }>(
    `SELECT s.user_id, p.email, s.expires_at, s.revoked_at
     FROM sessions s JOIN profiles p ON p.id = s.user_id
     WHERE s.token_hash = $1`,
    [tokenHash]
  );
  if (result.rows.length === 0) return null;
  const row = result.rows[0];
  if (row.revoked_at) return null;
  if (new Date(row.expires_at).getTime() <= Date.now()) return null;
  return { userId: row.user_id, email: row.email };
}

export async function requireSession(req: NextRequest): Promise<SessionUser> {
  const user = await getSessionUser(getRequestToken(req));
  if (!user) {
    const err = new Error('No autenticado');
    (err as Error & { status?: number }).status = 401;
    throw err;
  }
  return user;
}

export async function revokeSession(token: string | null): Promise<void> {
  if (!token) return;
  await query('UPDATE sessions SET revoked_at = NOW() WHERE token_hash = $1', [hashToken(token)]);
}

export function setSessionCookie(res: NextResponse, token: string, expiresAt: Date): void {
  res.cookies.set(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProd(),
    sameSite: 'lax',
    path: '/',
    expires: expiresAt,
  });
}

export function clearSessionCookie(res: NextResponse): void {
  res.cookies.set(SESSION_COOKIE_NAME, '', {
    httpOnly: true,
    secure: isProd(),
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });
}

export function httpStatus(err: unknown): number {
  const status = (err as { status?: unknown }).status;
  return typeof status === 'number' ? status : 400;
}
