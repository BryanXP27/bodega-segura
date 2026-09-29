// Token de sesión Azure en el navegador (memoria).
// La cookie HttpOnly la envía el navegador automáticamente;
// este token en memoria es el fallback Authorization: Bearer.

let memToken: string | null = null;

export function setAzureToken(token: string | null): void {
  memToken = token;
}

export function getAzureToken(): string | null {
  return memToken;
}

export function clearAzureToken(): void {
  memToken = null;
}

export async function azureFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers || {});
  if (memToken && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${memToken}`);
  }
  return fetch(path, { ...init, headers, credentials: 'include' });
}

export function bytesToB64(data: ArrayBuffer): string {
  const bytes = new Uint8Array(data);
  let binary = '';
  const chunk = 8192;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function b64ToBytes(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
