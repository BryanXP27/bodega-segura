'use client';

import React, { useState } from 'react';
import { Card, Button, Alert, Spinner } from '@/components/ui';
import { CLIENT_VALID_CERT, ATTACKER_CERT } from '@/lib/pki/x509-validator';

export default function PkiPage() {
  const [certInput, setCertInput] = useState<string>(CLIENT_VALID_CERT);
  const [loading, setLoading] = useState(false);
  const [activeTest, setActiveTest] = useState<string | null>(null);
  const [responseStatus, setResponseStatus] = useState<number | null>(null);
  const [responseBody, setResponseBody] = useState<any>(null);
  const [logMessages, setLogMessages] = useState<string[]>([
    'Sistema PKI en la Nube inicializado.',
    'Root CA instalada: Bóveda Segura Root CA (RSA 4096 / SHA-256).',
    'Listo para recibir y validar certificados digitales X.509.',
  ]);

  const addLog = (msg: string) => {
    const time = new Date().toLocaleTimeString();
    setLogMessages((prev) => [`[${time}] ${msg}`, ...prev.slice(0, 19)]);
  };

  const handleTestValidCert = async () => {
    setActiveTest('valid');
    setLoading(true);
    setCertInput(CLIENT_VALID_CERT);
    addLog('Enviando petición a /api/pki/operaciones con Certificado Digital Válido...');
    try {
      const res = await fetch('/api/pki/operaciones', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientCertificate: CLIENT_VALID_CERT }),
      });
      const data = await res.json();
      setResponseStatus(res.status);
      setResponseBody(data);
      if (res.ok) {
        addLog(`✔ HTTP 200 OK: Cliente autenticado exitosamente como "${data.auth_details?.client?.commonName}"`);
        addLog(`✔ Cadena de confianza verificada contra la Root CA de la Bóveda`);
      } else {
        addLog(`❌ Error HTTP ${res.status}: ${data.error}`);
      }
    } catch (err: any) {
      addLog(`❌ Error de red: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleTestNoCert = async () => {
    setActiveTest('no_cert');
    setLoading(true);
    setCertInput('');
    addLog('Probando ataque: Enviando petición a /api/pki/operaciones SIN certificado...');
    try {
      const res = await fetch('/api/pki/operaciones', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      setResponseStatus(res.status);
      setResponseBody(data);
      addLog(`🛡️ HTTP ${res.status} BLOQUEADO: ${data.error}`);
    } catch (err: any) {
      addLog(`❌ Error de red: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleTestRogueCert = async () => {
    setActiveTest('rogue');
    setLoading(true);
    setCertInput(ATTACKER_CERT);
    addLog('Probando ataque: Enviando certificado firmado por OTRA CA (Rogue Malicious CA)...');
    try {
      const res = await fetch('/api/pki/operaciones', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientCertificate: ATTACKER_CERT }),
      });
      const data = await res.json();
      setResponseStatus(res.status);
      setResponseBody(data);
      addLog(`🛡️ HTTP ${res.status} RECHAZADO: ${data.error}`);
    } catch (err: any) {
      addLog(`❌ Error de red: ${err.message}`);
    } finally {
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
    addLog('Enviando certificado personalizado al API en la nube...');
    try {
      const res = await fetch('/api/pki/operaciones', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientCertificate: certInput }),
      });
      const data = await res.json();
      setResponseStatus(res.status);
      setResponseBody(data);
      if (res.ok) {
        addLog(`✔ HTTP ${res.status} OK: Certificado válido. Acceso concedido.`);
      } else {
        addLog(`🛡️ HTTP ${res.status} DENEGADO: ${data.error}`);
      }
    } catch (err: any) {
      addLog(`❌ Error: ${err.message}`);
    } finally {
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
              Autenticación mutua (mTLS / X.509) desplegada en <strong>Google Cloud Run</strong>.
              El cliente se identifica mediante criptografía de clave pública, <strong>sin contraseñas ni API Keys</strong>.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-medium text-emerald-300">Google Cloud Run API Activo</span>
          </div>
        </div>

        {/* Panel de las 3 Pruebas de la Rúbrica */}
        <div>
          <h2 className="text-lg font-semibold text-white mb-3">
            🧪 Pruebas de Evaluación (Rúbrica de Seguridad)
          </h2>
          <div className="grid gap-4 sm:grid-cols-3">
            {/* Prueba 1: Certificado Válido */}
            <Card className="hover:border-emerald-500/50 transition-all border-emerald-500/20 bg-[#07241f]/40">
              <div className="flex items-start gap-3">
                <span className="text-3xl">🟢</span>
                <div className="flex-1">
                  <h3 className="font-semibold text-emerald-200">Certificado Válido</h3>
                  <p className="mt-1 text-xs text-emerald-100/60">
                    Firmado por la Root CA propia. Acceso concedido con datos bancarios.
                  </p>
                  <Button
                    variant="primary"
                    size="sm"
                    className="mt-4 w-full !bg-emerald-600 hover:!bg-emerald-500"
                    onClick={handleTestValidCert}
                    isLoading={loading && activeTest === 'valid'}
                  >
                    Probar Acceso Válido
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
              rows={12}
              className="w-full rounded-xl border border-cyan-100/10 bg-[#041622] p-3 text-xs font-mono text-cyan-100 outline-none focus:border-cyan-300/50"
            />
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
                  <span>Validando firma criptográfica en Google Cloud...</span>
                </div>
              ) : responseBody ? (
                <pre className="text-cyan-100/90 whitespace-pre-wrap">
                  {JSON.stringify(responseBody, null, 2)}
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
            <span className="text-[11px] text-cyan-50/40">Terminal en vivo</span>
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
