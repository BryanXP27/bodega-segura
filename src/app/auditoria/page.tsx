'use client';

import React, { useState } from 'react';
import { Card, Button, Spinner } from '@/components/ui';

export default function AuditoriaPage() {
  const [version, setVersion] = useState<'v1' | 'v2'>('v1');
  const [activeTab, setActiveTab] = useState<'sqli' | 'xss' | 'upload' | 'rbac'>('sqli');
  const [loading, setLoading] = useState(false);

  // Estados para búsqueda (SQLi)
  const [searchQuery, setSearchQuery] = useState("' UNION SELECT id, name, email, role, balance FROM users--");
  const [searchResult, setSearchResult] = useState<any>(null);

  // Estados para comentarios (XSS)
  const [commentText, setCommentText] = useState("<img src='x' onerror='alert(\"XSS: Robo de cookie de sesión: \" + document.cookie)'>");
  const [commentsList, setCommentsList] = useState<any[]>([]);
  const [commentResult, setCommentResult] = useState<any>(null);

  // Estados para subida de archivo
  const [uploadResult, setUploadResult] = useState<any>(null);

  // Estados para control de acceso (Admin)
  const [adminRolePayload, setAdminRolePayload] = useState('admin');
  const [adminResult, setAdminResult] = useState<any>(null);

  // Logs en tiempo real
  const [logs, setLogs] = useState<string[]>([
    'Laboratorio del Proyecto 4 inicializado.',
    'Selecciona una superficie de ataque y ejecuta las pruebas dinámicas.',
  ]);

  const addLog = (msg: string) => {
    const time = new Date().toLocaleTimeString();
    setLogs((prev) => [`[${time}] ${msg}`, ...prev.slice(0, 24)]);
  };

  // 1. Ejecutar prueba SQLi
  const handleRunSearch = async () => {
    setLoading(true);
    addLog(`Ejecutando búsqueda en [${version.toUpperCase()}] con query: "${searchQuery}"`);
    try {
      const res = await fetch('/api/auditoria', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'search', version, query: searchQuery }),
      });
      const data = await res.json();
      setSearchResult(data);
      if (data.exploit_successful) {
        addLog(`🚨 EXPLOIT SQLi EXITOSO en V1 (CVSS 9.8): Se extrajeron datos confidenciales.`);
      } else if (data.security_status) {
        addLog(`🛡️ BLOQUEADO en V2: ${data.security_status}`);
      }
    } catch (err: any) {
      addLog(`Error de red: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // 2. Ejecutar prueba XSS
  const handleRunComment = async () => {
    setLoading(true);
    addLog(`Publicando comentario en [${version.toUpperCase()}] con carga útil XSS...`);
    try {
      const res = await fetch('/api/auditoria', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'comment', version, text: commentText, user: 'Atacante_Web' }),
      });
      const data = await res.json();
      setCommentResult(data);
      if (data.comments) setCommentsList(data.comments);
      if (version === 'v1') {
        addLog(`🚨 STORED XSS ALMACENADO en V1 (CVSS 8.0): Script guardado sin sanitizar.`);
      } else {
        addLog(`🛡️ XSS SANITIZADO en V2: ${data.security_status}`);
      }
    } catch (err: any) {
      addLog(`Error de red: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // 3. Ejecutar prueba Upload (SVG con script malicioso)
  const handleRunMaliciousUpload = async () => {
    setLoading(true);
    const maliciousSvg = `<svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS_EN_STORAGE")</script></svg>`;
    const b64Data = btoa(maliciousSvg);
    addLog(`Intentando subir archivo "comprobante_falso.svg" en [${version.toUpperCase()}]...`);
    try {
      const res = await fetch('/api/auditoria', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'upload',
          version,
          fileName: 'comprobante_falso.svg',
          fileData: b64Data,
        }),
      });
      const data = await res.json();
      setUploadResult(data);
      if (data.file_accepted && version === 'v1') {
        addLog(`🚨 SUBIDA INSEGURA en V1 (CVSS 8.8): Archivo malicioso aceptado sin validar Magic Bytes.`);
      } else if (data.blocked) {
        addLog(`🛡️ SUBIDA BLOQUEADA en V2: Firma binaria no coincide con .jpg, .png o .pdf.`);
      }
    } catch (err: any) {
      addLog(`Error de red: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // 4. Ejecutar prueba Broken Access Control (Admin Bypass)
  const handleRunAdminBypass = async () => {
    setLoading(true);
    addLog(`Intentando acceso a panel administrativo en [${version.toUpperCase()}] con role=${adminRolePayload}...`);
    try {
      const res = await fetch('/api/auditoria', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'admin_access',
          version,
          role: adminRolePayload,
        }),
      });
      const data = await res.json();
      setAdminResult(data);
      if (data.access_granted && version === 'v1') {
        addLog(`🚨 BROKEN ACCESS CONTROL en V1 (CVSS 8.8): Acceso administrativo concedido por manipulación de parámetro.`);
      } else if (!data.access_granted) {
        addLog(`🛡️ ACCESO RECHAZADO en V2: RBAC en servidor verificó que la sesión carece de rol admin.`);
      }
    } catch (err: any) {
      addLog(`Error de red: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="platform-grid -mx-6 min-h-[calc(100vh-12rem)] px-4 py-8 sm:px-6">
      <div className="mx-auto max-w-[1280px] space-y-8">
        {/* Cabecera Principal */}
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between border-b border-cyan-100/10 pb-6">
          <div>
            <div className="inline-flex items-center gap-2 rounded-lg bg-purple-400/10 px-3 py-1 text-xs font-semibold text-purple-300">
              <span>PROYECTO 4 — UNDC 2026</span>
              <span>•</span>
              <span>DEVSECOPS & AUDITORÍA DE IA</span>
            </div>
            <h1 className="mt-3 text-3xl font-bold tracking-tight text-white sm:text-4xl">
              Auditoría de Aplicación Generada con IA
            </h1>
            <p className="mt-2 text-sm text-cyan-50/60 max-w-2xl">
              Evaluación comparativa: <strong>Versión 1 (Vulnerable por IA)</strong> vs.{' '}
              <strong>Versión 2 (Remediada con Prompt Defensivo)</strong> bajo el estándar{' '}
              <strong>OWASP Top 10:2025</strong> y métricas <strong>CVSS v3.1</strong>.
            </p>
          </div>

          {/* Selector de Versión (V1 vs V2) */}
          <div className="flex items-center rounded-2xl border border-cyan-100/15 bg-[#071d2a] p-1.5 shadow-lg">
            <button
              onClick={() => {
                setVersion('v1');
                addLog('Cambiado a MODO: Versión 1 (Vulnerable - Código generado por IA sin directivas).');
              }}
              className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold transition-all ${
                version === 'v1'
                  ? 'bg-red-500/20 text-red-200 border border-red-500/40 shadow-glow'
                  : 'text-cyan-50/40 hover:text-white'
              }`}
            >
              <span>🔴</span>
              <span>Versión 1 (Vulnerable IA)</span>
            </button>
            <button
              onClick={() => {
                setVersion('v2');
                addLog('Cambiado a MODO: Versión 2 (Remediada - Prompt de Seguridad Defensivo).');
              }}
              className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold transition-all ${
                version === 'v2'
                  ? 'bg-emerald-500/20 text-emerald-200 border border-emerald-500/40 shadow-glow'
                  : 'text-cyan-50/40 hover:text-white'
              }`}
            >
              <span>🟢</span>
              <span>Versión 2 (Remediada)</span>
            </button>
          </div>
        </div>

        {/* Banner de Estado del Modo Actual */}
        <div
          className={`rounded-2xl border p-4 text-xs flex items-center justify-between gap-4 ${
            version === 'v1'
              ? 'border-red-500/30 bg-[#2b0f16]/60 text-red-200'
              : 'border-emerald-500/30 bg-[#07241f]/60 text-emerald-200'
          }`}
        >
          <div className="flex items-center gap-3">
            <span className="text-2xl">{version === 'v1' ? '⚠️' : '🛡️'}</span>
            <div>
              <p className="font-bold text-sm">
                {version === 'v1'
                  ? 'MODO ACTIVO: Versión 1 — Vulnerabilidades introducidas por la IA sin restricciones'
                  : 'MODO ACTIVO: Versión 2 — Contramedidas implementadas tras la auditoría OWASP ZAP'}
              </p>
              <p className="text-cyan-50/60 mt-0.5">
                {version === 'v1'
                  ? 'Las peticiones demuestran inyección SQL, XSS almacenado, subida sin filtro y bypass de rol.'
                  : 'Consultas preparadas ($1), sanitización DOMPurify, validación de Magic Bytes y RBAC estricto.'}
              </p>
            </div>
          </div>
          <span className="hidden sm:inline-block rounded-lg px-2.5 py-1 text-[11px] font-mono bg-black/30 border border-white/10">
            {version === 'v1' ? 'CVSS MAX: 9.8 (CRÍTICO)' : 'CVSS: 0.0 (SEGURO)'}
          </span>
        </div>

        {/* Pestañas de las 4 Superficies de Ataque */}
        <div className="flex flex-wrap gap-2 border-b border-cyan-100/10 pb-2">
          <button
            onClick={() => setActiveTab('sqli')}
            className={`rounded-xl px-4 py-2 text-xs font-bold transition ${
              activeTab === 'sqli' ? 'bg-cyan-400/20 text-cyan-200 border border-cyan-400/40' : 'text-cyan-50/50 hover:bg-white/5'
            }`}
          >
            💉 1. SQL Injection (Búsqueda)
          </button>
          <button
            onClick={() => setActiveTab('xss')}
            className={`rounded-xl px-4 py-2 text-xs font-bold transition ${
              activeTab === 'xss' ? 'bg-cyan-400/20 text-cyan-200 border border-cyan-400/40' : 'text-cyan-50/50 hover:bg-white/5'
            }`}
          >
            💬 2. Stored XSS (Comentarios)
          </button>
          <button
            onClick={() => setActiveTab('upload')}
            className={`rounded-xl px-4 py-2 text-xs font-bold transition ${
              activeTab === 'upload' ? 'bg-cyan-400/20 text-cyan-200 border border-cyan-400/40' : 'text-cyan-50/50 hover:bg-white/5'
            }`}
          >
            📁 3. File Upload Malicioso
          </button>
          <button
            onClick={() => setActiveTab('rbac')}
            className={`rounded-xl px-4 py-2 text-xs font-bold transition ${
              activeTab === 'rbac' ? 'bg-cyan-400/20 text-cyan-200 border border-cyan-400/40' : 'text-cyan-50/50 hover:bg-white/5'
            }`}
          >
            🔑 4. Broken Access Control (Admin)
          </button>
        </div>

        {/* Contenido de Cada Superficie de Prueba */}
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Panel Izquierdo: Carga Útil y Parámetros */}
          <Card>
            {activeTab === 'sqli' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">Superficie 1: Inyección SQL (OWASP A03:2025)</h3>
                  <span className="text-xs text-red-400 font-mono">CVSS 9.8</span>
                </div>
                <p className="text-xs text-cyan-50/60 leading-5">
                  El motor de búsqueda consulta coincidencias en la base de datos. En V1 la IA concatenó variables en la sentencia SQL.
                </p>
                <div>
                  <label className="text-xs text-cyan-100 font-medium block mb-1">Carga Útil de Búsqueda (Payload SQLi):</label>
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full rounded-xl border border-cyan-100/10 bg-[#041622] p-3 text-xs font-mono text-cyan-200 outline-none focus:border-cyan-300/50"
                  />
                </div>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="primary"
                    onClick={handleRunSearch}
                    isLoading={loading}
                    className="w-full"
                  >
                    Ejecutar Búsqueda en {version.toUpperCase()}
                  </Button>
                </div>
              </div>
            )}

            {activeTab === 'xss' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">Superficie 2: Stored XSS (OWASP A03:2025)</h3>
                  <span className="text-xs text-orange-400 font-mono">CVSS 8.0</span>
                </div>
                <p className="text-xs text-cyan-50/60 leading-5">
                  El formulario de soporte publica mensajes en el muro público. En V1 la IA guardó y renderizó HTML sin escape.
                </p>
                <div>
                  <label className="text-xs text-cyan-100 font-medium block mb-1">Mensaje con Payload XSS:</label>
                  <textarea
                    rows={4}
                    value={commentText}
                    onChange={(e) => setCommentText(e.target.value)}
                    className="w-full rounded-xl border border-cyan-100/10 bg-[#041622] p-3 text-xs font-mono text-cyan-200 outline-none focus:border-cyan-300/50"
                  />
                </div>
                <Button
                  size="sm"
                  variant="primary"
                  onClick={handleRunComment}
                  isLoading={loading}
                  className="w-full"
                >
                  Publicar Comentario en {version.toUpperCase()}
                </Button>
              </div>
            )}

            {activeTab === 'upload' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">Superficie 3: Subida Insegura (OWASP A04:2025)</h3>
                  <span className="text-xs text-red-400 font-mono">CVSS 8.8</span>
                </div>
                <p className="text-xs text-cyan-50/60 leading-5">
                  El módulo recibe comprobantes adjuntos. En V1 la IA solo confió en el nombre del archivo. En V2 se validan los Magic Bytes binarios.
                </p>
                <div className="rounded-xl border border-cyan-100/10 bg-[#041622] p-3 text-xs font-mono text-cyan-100 space-y-1">
                  <p><strong>Archivo simulado:</strong> comprobante_falso.svg</p>
                  <p><strong>Tipo MIME enviado:</strong> image/svg+xml</p>
                  <p><strong>Contenido interno:</strong> &lt;svg&gt;&lt;script&gt;alert(&quot;XSS_EN_STORAGE&quot;)&lt;/script&gt;&lt;/svg&gt;</p>
                </div>
                <Button
                  size="sm"
                  variant="primary"
                  onClick={handleRunMaliciousUpload}
                  isLoading={loading}
                  className="w-full"
                >
                  Subir Archivo Malicioso en {version.toUpperCase()}
                </Button>
              </div>
            )}

            {activeTab === 'rbac' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">Superficie 4: Control de Acceso (OWASP A01:2025)</h3>
                  <span className="text-xs text-orange-400 font-mono">CVSS 8.8</span>
                </div>
                <p className="text-xs text-cyan-50/60 leading-5">
                  El panel de administración contiene registros y fondos. En V1 la IA permitió escalada enviando `role=admin` en el body. En V2 exige RBAC en servidor.
                </p>
                <div>
                  <label className="text-xs text-cyan-100 font-medium block mb-1">Parámetro enviado por cliente:</label>
                  <select
                    value={adminRolePayload}
                    onChange={(e) => setAdminRolePayload(e.target.value)}
                    className="w-full rounded-xl border border-cyan-100/10 bg-[#041622] p-3 text-xs font-mono text-cyan-200 outline-none"
                  >
                    <option value="admin">role = &quot;admin&quot; (Intento de escalada ilícita)</option>
                    <option value="user">role = &quot;user&quot; (Usuario normal)</option>
                  </select>
                </div>
                <Button
                  size="sm"
                  variant="primary"
                  onClick={handleRunAdminBypass}
                  isLoading={loading}
                  className="w-full"
                >
                  Probar Acceso Admin en {version.toUpperCase()}
                </Button>
              </div>
            )}
          </Card>

          {/* Panel Derecho: Respuesta del Servidor y Análisis */}
          <Card>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-white">Respuesta del Servidor y Análisis Dinámico</h3>
              <span
                className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                  version === 'v1'
                    ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                }`}
              >
                {version === 'v1' ? 'Respuesta V1 (Vulnerable)' : 'Respuesta V2 (Defendida)'}
              </span>
            </div>

            <div className="h-[280px] overflow-auto rounded-xl border border-cyan-100/10 bg-[#041622] p-4 text-xs font-mono">
              {loading ? (
                <div className="flex h-full items-center justify-center gap-2 text-cyan-300">
                  <Spinner />
                  <span>Procesando prueba de penetración...</span>
                </div>
              ) : (
                <pre className="text-cyan-100/90 whitespace-pre-wrap">
                  {JSON.stringify(
                    activeTab === 'sqli'
                      ? searchResult
                      : activeTab === 'xss'
                      ? commentResult
                      : activeTab === 'upload'
                      ? uploadResult
                      : adminResult,
                    null,
                    2
                  ) || '// Selecciona una prueba y presiona ejecutar para ver la respuesta técnica.'}
                </pre>
              )}
            </div>
          </Card>
        </div>

        {/* Consola de Auditoría en Tiempo Real */}
        <Card className="!bg-[#041622]/90 border-cyan-500/20">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-cyan-300">
              📋 Registro de Auditoría y Detección de Vulnerabilidades
            </h3>
            <span className="text-[11px] text-cyan-50/40">OWASP ZAP / Pentest Trace</span>
          </div>
          <div className="space-y-1 font-mono text-xs text-cyan-100/80">
            {logs.map((log, i) => (
              <div
                key={i}
                className={
                  log.includes('🚨')
                    ? 'text-red-400 font-semibold'
                    : log.includes('🛡️')
                    ? 'text-emerald-300'
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
