/**
 * Utilidad criptográfica del lado cliente para Proyecto 3: PKI y Prueba de Posesión.
 *
 * Simula el comportamiento del aplicativo de escritorio en el navegador:
 * 1. La llave privada vive exclusivamente en la memoria del cliente.
 * 2. El cliente solicita un nonce (reto aleatorio de un solo uso) al servidor en la nube.
 * 3. El cliente firma el nonce localmente usando Web Crypto API (RSA-SHA256 PKCS#1 v1.5).
 * 4. Al servidor solo se le envía la firma en Base64 + el token del reto + el certificado público.
 *    La llave privada NUNCA viaja por la red.
 */

export const DEMO_CLIENT_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDEQEnPDfP9iL5M
HbZ8QYqBYUTFhyADbrUoTy4ck15NiAj+utknP1s8AgY0y70bPP+3Gj83CYkaLeTK
ett9E0sDzi++NgM9/IRYRaJvVHZMnJyRDObk/kwpIvHTzYk05GPwHTXAfws/rLeI
bhv40Ro4Dnj3npWVU9lLNwtWqZhzRE2OdvLG0jK+dcW85yFqj5gZuX65tGfxdaM4
+SHaWbzmUvKioiq6al7ixQkRHXVHtaJteAmmz5qfqJ0ST3SB/ayLyCSLufZzcIUa
rlesA7qkaDfIWQQcPqVEyZpEh9vsx0eyuCBRECH0z3iGiHXMkiuj/7u2D2sUPbr/
hYcGoj/rAgMBAAECggEAOSI8Oq7luwh92jwGPft4vrzaICV8IPOwgtk2Y/RVTn4N
nFc6VA5CWeB+/QzZc54ZFi3qfHPmubvlsTr+PlYJD0UOKjKgVAH5Z5dyODYfMKOh
gyr952nPM2SsgYyDZuYc4DEozm9OD44RaoMf2prJpssz1WcSRkSAbMDMKME8FEYq
Hb2Yqwh75zVwDixd8Iwh03eVHxdl7YY00iqGw4dwcvvuOMQ4M31C1A8nUDLTU2BH
Wzi96PyKekukKe8rOba9izGSbvjSbR5dQb7mlxD862ZY4cQ1lpTIU8sBxvpHs0O6
TeIVpXm35jMn/QgD3YDqzIqV9d+YxTWrKHJBc6jFcQKBgQDr67mJ0KDb3uKmTj+j
uX6awHdb83G7H5aQCJrG8VKPTzoEr5SVqMv+x4jpoyWDxYfFghMk6EvAnG8ocN90
naaY/WYTxy//JI4zw3HQsJFDRfK5RZfAOd7plm23GpDYWwBu7NbmfSZ6qy2NRv+S
tQfHcfrC57uPGdKDOyTnAcju0QKBgQDU9Dw0/mpnrtS1/S7iyYuzk+M0nhFkZlCH
cLN2qejBDM+j3lgHrAWDBXA0ZX5VSsUfXPjoSkJodJZwkGf6/wIKDP1MTP+lXjWu
vtnuQDKUL0XIyeuc5ijQ/LTIyr1liXqdNE0KyrJZGRZLIJ7i82j6RyIrH07yUHWq
SMa1BL7J+wKBgE8qwxAkGlat7JCyIVjnnjx/6Y3Jm5iXeQbMXGP2ByZgB7Aa21l9
Uzcj7iW4wZX+axk0FQiFiyYPWJ3Rgqq3XHhqUB7C8LBFrBJiu4a0OYrBpjnVyJ6Q
zOTFvft7xq9Tmkme4F5oEMmJN7f44zpv1TRwYx2UdbQHjkTLTA7Y4nyBAoGACYVJ
08y0ESKd2+0P1Y/RMRwhgk621FhGrWd6fommIEtkVR0xrlYggPUTSSRoe4O2QGq1
rhzzzxu3Rh0OqQgRnUVrZafjng8SM1fRAnfYSwu6APoWEJOxq3ZA1uFJimqVEsYt
05ewVY9rkbxJnjfnr5jSjD8AFpFGUXCjgaBOr1UCgYA1+XG4M1V+8PpE7+QyNPrF
QeI5wryZO1noLWpibauptXAmb7nyS9hFomJgSq2LRki691epDkBT5yGKQn9V/obs
JbjZK60c1hG90Aq1F56gvOFGur9TvbDdOKlIHFfxOGoxOgvxS8TtUVQp/VjnRQOQ
UI6XSSluLcKs8goitzrKDA==
-----END PRIVATE KEY-----`;

/**
 * Firma un nonce con una llave privada PKCS#8 en formato PEM usando Web Crypto API.
 * Devuelve la firma en formato Base64 estándar.
 */
export async function signNonceInBrowser(
  nonce: string,
  privateKeyPem: string = DEMO_CLIENT_PRIVATE_KEY
): Promise<string> {
  const pemHeader = '-----BEGIN PRIVATE KEY-----';
  const pemFooter = '-----END PRIVATE KEY-----';
  const pemContents = privateKeyPem
    .replace(pemHeader, '')
    .replace(pemFooter, '')
    .replace(/\s+/g, '');

  if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API no está disponible en este entorno.');
  }

  const binaryDerString = window.atob(pemContents);
  const binaryDer = new Uint8Array(binaryDerString.length);
  for (let i = 0; i < binaryDerString.length; i++) {
    binaryDer[i] = binaryDerString.charCodeAt(i);
  }

  const privateKey = await window.crypto.subtle.importKey(
    'pkcs8',
    binaryDer.buffer,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    },
    false,
    ['sign']
  );

  const encoder = new TextEncoder();
  const signatureBuffer = await window.crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    encoder.encode(nonce)
  );

  const signatureBytes = new Uint8Array(signatureBuffer);
  let binary = '';
  for (let i = 0; i < signatureBytes.byteLength; i++) {
    binary += String.fromCharCode(signatureBytes[i]);
  }
  return window.btoa(binary);
}
