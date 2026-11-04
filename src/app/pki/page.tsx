'use client';

import React, { useState } from 'react';
import { Card, Button, Spinner } from '@/components/ui';
import { audit, auditGroup, auditWarn } from '@/lib/debug/audit';

interface DemoCerts {
  clientCertificate: string;
  attackerCertificate: string;
}

export default function PkiPage() {
  const [certInput, setCertInput] = useState<string>('');
  const [challengeToken, setChallengeToken] = useState<string>('');
  const [signature, setSignature] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [activeTest, setActiveTest] = useState<string | null>(null);
  const [responseStatus, setResponseStatus] = useState<number | null>(null);
  const [responseBody, setResponseBody] = useState<any>(null);
  const [challengeInfo, setChallengeInfo] = useState<any>(null);
  const [logMessages, setLogMessages] = useState<string[]>([
    'Sistema PKI en la Nube inicializado.',
    'Root CA instalada: Bóveda Segura Root CA (RSA 4096 / SHA-256).',
    'Autenticación exigida: certificado X.509 + prueba de posesión (reto-firma).',
    'La llave privada del cliente NUNCA se publica: vive en certs/private/ de tu equipo.',
    'Abre DevTools (F12 > Consola) para ver la auditoría criptográfica en vivo.',
  ]);

  const addLog = (msg: string) => {
    const time = new Date().toLocaleTimeString();
    setLogMessages((prev) => [`[${time}] ${msg}`, ...prev.slice(0, 24)]);
  };

  const loadDemoCerts = async (): Promise<DemoCerts> => {
    const res = await fetch('/api/pki/demo-certs', { cache: 'no-store' });
    if (!res.ok) throw new Error(`No se pudieron cargar los certificados de demo (HTTP ${res.status})`);
    return (await res.json()) as DemoCerts;
  };

  const postOperaciones = async (payload: Record<string, unknown>) => {
    const res = await fetch('/api/pki/operaciones', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    setResponseStatus(res.status);
    setResponseBody(data);
    return { res, data };
  };

  const handleRequestChallenge = async () => {
    setActiveTest('challenge');
    setLoading(true);
    addLog('▶ [RETO] Solicitando nonce de un solo uso a /api/pki/challenge...');

    const endAudit = auditGroup('🛡️ PROYECTO 3: EMISIÓN DEL RETO CRIPTOGRÁFICO');
    audit('☁️', 'Paso 1: El cliente solicita un reto al servidor (GET /api/pki/challenge)');
    audit('🎲', 'Paso 2: El servidor genera un nonce aleatorio de 256 bits + token HMAC con TTL de 120 s');
    audit('🔏', 'Paso 3: El cliente debe firmar ese nonce con su llave privada RSA (SHA-256): la llave no viaja');

    try {
      const res = await fetch('/api/pki/challenge', { cache: 'no-store' });
      const data = await res.json();
      setChallengeInfo(data);
      setChallengeToken(data?.challenge?.token || '');
      addLog(`✔ Reto emitido. Expira: ${data?.challenge?.expiresAt} (un solo uso).`);
      addLog('↳ Abre el aplicativo de escritorio Python para firmarlo con client.key.');
      audit('✔', 'Reto listo. Sin la llave privada, la firma es computacionalmente inviable.');
    } catch (err: any) {
      auditWarn('💥', 'Error al solicitar el reto', err);
      addLog(`❌ Error: ${err.message}`);
    } finally {
      endAudit();
      setLoading(false);
    }
  };

  const handleTestCertWithoutProof = async () => {
    setActiveTest('no_proof');
    setLoading(true);
    addLog('▶ [DEMO SEGURIDAD] Presentando el certificado válido SIN firma del reto...');

    const endAudit = auditGroup('🛡️ PROYECTO 3: CERTIFICADO PÚBLICO SIN PRUEBA DE POSESIÓN');
    audit('📜', 'Paso 1: Se obtiene el certificado público client.crt (no es un secreto)');
    audit('🚫', 'Paso 2: NO se envía firma del reto (equivale a copiar el PEM desde GitHub)');
    audit('☁️', 'Paso 3: Enviando a /api/pki/operaciones...');

    try {
      const certs = await loadDemoCerts();
      setCertInput(certs.clientCertificate);
      const { res, data } = await postOperaciones({ clientCertificate: certs.clientCertificate });

      audit('🛑', `Paso 4: Rechazo en Cloud Run: HTTP ${res.status} [${data.code}]`, data.error);
      audit('✔', 'Paso 5: El certificado por sí solo ya NO autentica. Se exige la llave privada.');
      addLog(`🛡️ HTTP ${res.status} BLOQUEADO: ${data.code}`);
      addLog('✔ Copiar el certificado público ya no permite suplantar al cliente.');
    } catch (err: any) {
      auditWarn('💥', 'Error de red en la llamada al API', err);
      addLog(`❌ Error de red: ${err.message}`);
    } finally {
      endAudit();
      setLoading(false);
    }
  };

  const handleTestNoCert = async () => {
    setActiveTest('no_cert');
    setLoading(true);
    setCertInput('');
    setSignature('');
    setChallengeToken('');
    addLog('▶ [ATAQUE 1] Enviando petición a Google Cloud Run SIN certificado digital...');

    const endAudit = auditGroup('🛡️ PROYECTO 3: ATAQUE 1 - ACCESO SIN CREDENCIAL X.509');
    audit('⚠️', 'Paso 1: Atacante intenta consumir /api/pki/operaciones SIN presentar certificado');
    audit('☁️', 'Paso 2: Petición enviada a Google Cloud Run...');

    try {
      const { res, data } = await postOperaciones({});
      audit('🛑', `Paso 3: Bloqueo en Cloud Run: HTTP ${res.status} [${data.code}]`, data.error);
      audit('✔', 'Paso 4: RESULTADO: Ataque mitigado. Ninguna entidad sin certificado digital puede acceder a la Bóveda.');
      addLog(`🛡️ HTTP ${res.status} BLOQUEADO: ${data.error}`);
    } catch (err: any) {
      auditWarn('💥', 'Error de red en la llamada al API', err);
      addLog(`❌ Error de red: ${err.message}`);
    } finally {
      endAudit();
      setLoading(false);
    }
  };

  const handleTestRogueCert = async () => {
    setActiveTest('rogue');
    setLoading(true);
    addLog('▶ [ATAQUE 2] Enviando certificado emitido por OTRA CA (Rogue Malicious Root CA)...');

    const endAudit = auditGroup('🛡️ PROYECTO 3: ATAQUE 2 - CERTIFICADO DE OTRA CA (ROGUE CA)');
    audit('🎭', 'Paso 1: Atacante presenta certificado firmado por "Rogue Malicious Root CA"');
    audit('☁️', 'Paso 2: Enviado a Google Cloud Run (/api/pki/operaciones)...');

    try {
      const certs = await loadDemoCerts();
      setCertInput(certs.attackerCertificate);
      const { res, data } = await postOperaciones({
        clientCertificate: certs.attackerCertificate,
      });

      audit('🔍', 'Paso 3: Cloud Run verifica la firma contra la Root CA institucional: inválida');
      audit('🛑', `Paso 4: Cadena de confianza rota. Rechazo en Cloud Run: HTTP ${res.status} [${data.code}]`, data.error);
      audit('✔', 'Paso 5: RESULTADO: Ataque de suplantación mitigado. Solo la Root CA oficial tiene autoridad.');
      addLog(`🛡️ HTTP ${res.status} RECHAZADO: ${data.error}`);
    } catch (err: any) {
      auditWarn('💥', 'Error de red en la llamada al API', err);
      addLog(`❌ Error de red: ${err.message}`);
    } finally {
      endAudit();
      setLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setCertInput(content);
      addLog(`Archivo cargado: ${file.name} (${file.size} bytes)`);
      audit('📂', `Certificado personalizado cargado: ${file.name} (${file.size} bytes)`);
    };
    reader.readAsText(file);
  };

  const handleCustomSubmit = async () => {
    if (!certInput.trim()) {
      addLog('Ingresa o selecciona un certificado para evaluar.');
      return;
    }
    setActiveTest('custom');
    setLoading(true);

    const hasProof = Boolean(challengeToken.trim() && signature.trim());
    addLog(
      hasProof
        ? 'Enviando certificado + token de reto + firma RSA-SHA256 al API...'
        : 'Enviando certificado SIN firma de reto (se espera 403)...'
    );

    const endAudit = auditGroup('🛡️ PROYECTO 3: EVALUACIÓN DE CERTIFICADO PERSONALIZADO');
    audit('📜', 'Enviando certificado X.509 al API en Google Cloud Run...');
    if (hasProof) {
      audit('🔏', 'Incluyendo token de reto y firma RSA-SHA256 del nonce.');
    } else {
      auditWarn('🚫', 'Sin firma de reto: la prueba de posesión no puede satisfacerse.');
    }

    try {
      const payload: Record<string, unknown> = { clientCertificate: certInput };
      if (hasProof) {
        payload.challengeToken = challengeToken.trim();
        payload.signature = signature.trim();
      }

      const { res, data } = await postOperaciones(payload);

      if (res.ok) {
        audit('✔', `HTTP ${res.status} OK: certificado + prueba de posesión válidos.`, data);
        addLog(`✔ HTTP ${res.status} OK: ${data.message}`);
      } else {
        auditWarn('🛑', `HTTP ${res.status} DENEGADO: ${data.code}`, data.error);
        addLog(`🛡️ HTTP ${res.status} DENEGADO: ${data.error}`);
      }
    } catch (err: any) {
      auditWarn('💥', 'Error al evaluar certificado', err);
      addLog(`❌ Error: ${err.message}`);
    } finally {
      endAudit();
      setLoading(false);
    }
  };

  return (
    <div className="platform-grid -mx-6 min-h-[calc(100vh-12rem)] px-4 py-8 sm:px-6">
      <div className="mx-auto max-w-[1250px] space-y-8">
        {/* Cabecera Principal */}
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between border-b border-cyan-100/10 pb-6">
          <div>
            <div className="inline-flex items-center gap-2 rounded-lg bg-cyan-400/10 px-3 py-1 text-xs font-semibold text-cyan-300">
              <span>PROYECTO 3 — UNDC 2026</span>
              <span>•</span>
              <span>SEGURIDAD EN LA NUBE</span>
            </div>
            <h1 className="mt-3 text-3xl font-bold tracking-tight text-white sm:text-4xl">
              PKI: API en la Nube con Certificado Digital
            </h1>
            <p className="mt-2 text-sm text-cyan-50/60 max-w-2xl">
              Autenticación con certificado X.509 y <strong>prueba de posesión</strong> (reto firmado con la
              llave privada). Desplegado en <strong>Google Cloud Run</strong>, <strong>sin contraseñas ni API Keys</strong>.
            </p>
          </div>
          <div className="flex flex-col items-end gap-1">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-medium text-emerald-300">Google Cloud Run API Activo</span>
            </div>
            <span className="text-[11px] text-cyan-50/45">F12 &gt; Consola para bitácora en vivo</span>
          </div>
        </div>

        {/* Aviso de modelo de seguridad */}
        <Card className="border-cyan-400/20 bg-[#062a36]/50">
          <div className="flex flex-col gap-2 text-xs text-cyan-50/70 sm:flex-row sm:items-center sm:justify-between">
            <p>
              🔐 <strong className="text-cyan-200">Modelo Zero-Secret:</strong> el certificado es público; el acceso
              exige firmar el nonce con la llave privada. La llave vive solo en tu equipo
              (<code className="text-cyan-300">certs/private/client.key</code>) y nunca se envía.
            </p>
            <Button variant="secondary" size="sm" onClick={handleRequestChallenge} isLoading={loading && activeTest === 'challenge'}>
              Obtener reto
            </Button>
          </div>
        </Card>

        {/* Panel de Pruebas de la Rúbrica */}
        <div>
          <h2 className="text-lg font-semibold text-white mb-3">
            🧪 Pruebas de Evaluación (Rúbrica de Seguridad)
          </h2>
          <div className="grid gap-4 sm:grid-cols-3">
            {/* Prueba 1: Certificado público sin firma */}
            <Card className="hover:border-emerald-500/50 transition-all border-emerald-500/20 bg-[#07241f]/40">
              <div className="flex items-start gap-3">
                <span className="text-3xl">🟢</span>
                <div className="flex-1">
                  <h3 className="font-semibold text-emerald-200">Certificado Válido sin Firma</h3>
                  <p className="mt-1 text-xs text-emerald-100/60">
                    Presenta <code>client.crt</code> (público) sin firmar el reto. Debe rechazarse con 403:
                    así se demuestra que copiar el certificado ya no sirve.
                  </p>
                  <Button
                    variant="primary"
                    size="sm"
                    className="mt-4 w-full !bg-emerald-600 hover:!bg-emerald-500"
                    onClick={handleTestCertWithoutProof}
                    isLoading={loading && activeTest === 'no_proof'}
                  >
                    Probar Certificado sin Firma
                  </Button>
                </div>
              </div>
            </Card>

            {/* Prueba 2: Sin Certificado */}
            <Card className="hover:border-red-500/50 transition-all border-red-500/20 bg-[#260f14]/40">
              <div className="flex items-start gap-3">
                <span className="text-3xl">🔴</span>
                <div className="flex-1">
                  <h3 className="font-semibold text-red-200">Ataque: Sin Certificado</h3>
                  <p className="mt-1 text-xs text-red-100/60">
                    Petición vacía sin credencial X.509. Bloqueado con error 401.
                  </p>
                  <Button
                    variant="danger"
                    size="sm"
                    className="mt-4 w-full"
                    onClick={handleTestNoCert}
                    isLoading={loading && activeTest === 'no_cert'}
                  >
                    Probar Sin Certificado
                  </Button>
                </div>
              </div>
            </Card>

            {/* Prueba 3: Certificado Falso */}
            <Card className="hover:border-amber-500/50 transition-all border-amber-500/20 bg-[#271a0e]/40">
              <div className="flex items-start gap-3">
                <span className="text-3xl">🟠</span>
                <div className="flex-1">
                  <h3 className="font-semibold text-amber-200">Ataque: Otra CA (Rogue)</h3>
                  <p className="mt-1 text-xs text-amber-100/60">
                    Certificado emitido por una CA atacante no autorizada. Rechazado con 403.
                  </p>
                  <Button
                    variant="secondary"
                    size="sm"
                    className="mt-4 w-full !bg-amber-600 hover:!bg-amber-500 !text-white"
                    onClick={handleTestRogueCert}
                    isLoading={loading && activeTest === 'rogue'}
                  >
                    Probar CA Atacante
                  </Button>
                </div>
              </div>
            </Card>
          </div>
        </div>

        {/* Panel Central: Editor y Respuesta */}
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Editor de Certificado X.509 */}
          <Card>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-white">
                📜 Certificado Digital X.509 Presentado
              </h3>
              <label className="cursor-pointer text-xs text-cyan-300 hover:text-cyan-200 underline">
                Cargar archivo .crt / .pem
                <input
                  type="file"
                  accept=".crt,.pem,.txt"
                  className="hidden"
                  onChange={handleFileUpload}
                />
              </label>
            </div>
            <textarea
              value={certInput}
              onChange={(e) => setCertInput(e.target.value)}
              placeholder="Pega aquí el certificado X.509 (formato PEM o Base64)..."
              rows={9}
              className="w-full rounded-xl border border-cyan-100/10 bg-[#041622] p-3 text-xs font-mono text-cyan-100 outline-none focus:border-cyan-300/50"
            />

            <details className="mt-3 rounded-xl border border-cyan-100/10 bg-[#041622]/60 p-3">
              <summary className="cursor-pointer text-xs font-semibold text-cyan-300">
                🔏 Firma manual del reto (opcional, para demostrar acceso válido)
              </summary>
              <p className="mt-2 text-[11px] text-cyan-50/50">
                Pulsa <strong>Obtener reto</strong>, guarda el <code>nonce</code> en un archivo y fírmalo con
                OpenSSL usando tu llave privada. Luego pega el token y la firma base64 aquí.
              </p>
              <pre className="mt-2 overflow-x-auto rounded-lg bg-black/40 p-2 text-[10px] text-emerald-200">
{`openssl dgst -sha256 -sign certs/private/client.key -out firma.bin nonce.txt
openssl base64 -A -in firma.bin`}
              </pre>
              <textarea
                value={challengeToken}
                onChange={(e) => setChallengeToken(e.target.value)}
                placeholder="challengeToken (se rellena al pulsar Obtener reto)"
                rows={2}
                className="mt-2 w-full rounded-lg border border-cyan-100/10 bg-[#041622] p-2 text-[10px] font-mono text-cyan-100 outline-none focus:border-cyan-300/50"
              />
              <textarea
                value={signature}
                onChange={(e) => setSignature(e.target.value)}
                placeholder="signature (base64 de la firma RSA-SHA256 del nonce)"
                rows={2}
                className="mt-2 w-full rounded-lg border border-cyan-100/10 bg-[#041622] p-2 text-[10px] font-mono text-cyan-100 outline-none focus:border-cyan-300/50"
              />
            </details>

            <div className="mt-3 flex justify-between items-center">
              <span className="text-[11px] text-cyan-50/40">
                Formato estándar RFC 5280 (PEM / Base64)
              </span>
              <Button
                variant="primary"
                size="sm"
                onClick={handleCustomSubmit}
                isLoading={loading && activeTest === 'custom'}
              >
                Evaluar Certificado
              </Button>
            </div>
          </Card>

          {/* Respuesta del Servidor API en Cloud Run */}
          <Card>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-white">
                ☁️ Respuesta del Servidor Google Cloud Run
              </h3>
              {responseStatus && (
                <span
                  className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                    responseStatus === 200
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      : 'bg-red-500/20 text-red-300 border border-red-500/30'
                  }`}
                >
                  HTTP {responseStatus}
                </span>
              )}
            </div>

            <div className="h-[275px] overflow-auto rounded-xl border border-cyan-100/10 bg-[#041622] p-4 text-xs font-mono">
              {loading ? (
                <div className="flex h-full items-center justify-center gap-2 text-cyan-300">
                  <Spinner />
                  <span>Validando certificado y prueba de posesión en Google Cloud...</span>
                </div>
              ) : responseBody ? (
                <pre className="text-cyan-100/90 whitespace-pre-wrap">
                  {JSON.stringify(responseBody, null, 2)}
                </pre>
              ) : challengeInfo ? (
                <pre className="text-cyan-100/90 whitespace-pre-wrap">
                  {JSON.stringify(challengeInfo, null, 2)}
                </pre>
              ) : (
                <div className="flex h-full items-center justify-center text-cyan-50/40 text-center">
                  Presiona uno de los botones de prueba superiores para consultar el API en Cloud Run.
                </div>
              )}
            </div>
          </Card>
        </div>

        {/* Consola de Auditoría en Tiempo Real */}
        <Card className="!bg-[#041622]/90 border-cyan-500/20">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-cyan-300">
              📋 Consola de Auditoría y Verificación Criptográfica
            </h3>
            <span className="text-[11px] text-cyan-50/40">F12 &gt; Console sincronizada</span>
          </div>
          <div className="space-y-1 font-mono text-xs text-cyan-100/80">
            {logMessages.map((log, i) => (
              <div
                key={i}
                className={
                  log.includes('✔')
                    ? 'text-emerald-300'
                    : log.includes('🛡️') || log.includes('❌')
                    ? 'text-amber-300'
                    : 'text-cyan-100/70'
                }
              >
                {log}
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
