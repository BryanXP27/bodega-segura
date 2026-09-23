'use client';

import React, { useEffect, useState, useRef } from 'react';
import { useAppStore } from '@/lib/session';
import { Button, Alert, Card, Spinner } from '@/components/ui';
import { storageAdapter, databaseAdapter } from '@/lib/config';
import { generateAesKey, exportAesKey, encryptFileWithAes, decryptFileWithAes, importAesKey } from '@/lib/crypto/aes';
import { importPublicKeyJwk, decryptAesKeyWithRsa, decryptPrivateKeyWithPassword, encryptAesKeyWithRsa } from '@/lib/crypto/rsa';
import { deriveHmacKey, calculateHmac, verifyHmac } from '@/lib/crypto/hmac';
import { generateRsaKeyPair, exportPublicKeyJwk } from '@/lib/crypto';
import Link from 'next/link';

export default function DashboardPage() {
  const { user, isAuthenticated, logout: storeLogout, files, loading, message, error, setFiles, setMessage, setError, setLoading } = useAppStore();
  const [downloadPassword, setDownloadPassword] = useState('');
  const [downloadingFileId, setDownloadingFileId] = useState<string | null>(null);
  const [activeFileId, setActiveFileId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isAuthenticated && user) {
      (async () => {
        setLoading(true);
        try {
const allFiles = await storageAdapter.getUserFiles(user.id);
          setFiles(allFiles);
        } catch (err: any) {
          setError(err.message);
        } finally {
          setLoading(false);
        }
      })();
    }
  }, [isAuthenticated, user]);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !user) return;
    setLoading(true);
    setError(null);
    try {
      const fileData = await file.arrayBuffer();
      const aesKey = await generateAesKey();
      const aesKeyRaw = await exportAesKey(aesKey);
      const { encryptedData, iv } = await encryptFileWithAes(fileData, aesKey);
      const hmacKey = await deriveHmacKey(aesKeyRaw);
      const hmac = await calculateHmac(encryptedData, hmacKey);
      const publicKeyJwk = user.publicKeyJwk || (await databaseAdapter.getUserById(user.id))?.publicKeyJwk;
      if (!publicKeyJwk) throw new Error('Clave pública no encontrada');
      const publicKey = await importPublicKeyJwk(publicKeyJwk);
      const encryptedAesKey = await encryptAesKeyWithRsa(aesKeyRaw, publicKey);
      const storageName = `${user.id}/${file.name}_${Date.now()}`;
      await storageAdapter.storeFile(storageName, encryptedData);
      const fileId = `file_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const metadata = { id: fileId, userId: user.id, originalName: file.name, storageName, encryptedAesKey, iv, hmac, originalSize: file.size, createdAt: new Date().toISOString(), version: '1.0' };
      await storageAdapter.storeMetadata(metadata);
      const allFiles = await storageAdapter.getUserFiles(user.id);
      setFiles(allFiles);
      setMessage('Archivo cifrado y almacenado exitosamente');
      if (fileInputRef.current) fileInputRef.current.value = '';
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (fileId: string) => {
    if (!user || !downloadPassword) {
      setError('Debe ingresar su contraseña para descargar');
      return;
    }
    setDownloadingFileId(fileId);
    setError(null);
    try {
      const metadata = await storageAdapter.getMetadata(fileId) as any;
      if (!metadata || metadata.userId !== user.id) throw new Error('Archivo no autorizado');
      const encryptedData = await storageAdapter.getFile(metadata.storageName);
      if (!encryptedData) throw new Error('Archivo cifrado no encontrado');
      const encPrivateKey = await databaseAdapter.getEncryptedPrivateKey(user.id);
      if (!encPrivateKey) throw new Error('Clave privada cifrada no encontrada');
      const privateKey = await decryptPrivateKeyWithPassword(encPrivateKey.ciphertext, encPrivateKey.iv, encPrivateKey.salt, downloadPassword);
      const aesKeyRaw = await decryptAesKeyWithRsa(metadata.encryptedAesKey, privateKey);
      const aesKey = await importAesKey(aesKeyRaw);
      const fileData = await decryptFileWithAes(encryptedData, aesKey, metadata.iv);
      const hmacKey = await deriveHmacKey(aesKeyRaw);
      const isValid = await verifyHmac(encryptedData, hmacKey, metadata.hmac);
      if (!isValid) throw new Error('La integridad del archivo ha sido comprometida');
      const blob = new Blob([fileData], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = metadata.originalName;
      document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
      setMessage('Archivo descargado verificado correctamente');
      setDownloadPassword('');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setDownloadingFileId(null);
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="min-h-[calc(100vh-12rem)] flex items-center justify-center px-6">
        <div className="text-center space-y-6">
          <div className="w-24 h-24 rounded-2xl glass flex items-center justify-center text-5xl mx-auto">
            🔒
          </div>
          <h1 className="text-2xl font-bold text-white">Acceso Requerido</h1>
          <p className="text-gray-400">Debes iniciar sesión para acceder al panel.</p>
          <Link href="/login">
            <Button size="lg">Iniciar Sesión</Button>
          </Link>
        </div>
      </div>
    );
  }

  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('es-ES', {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const filteredFiles = files.filter((file) => file.originalName.toLowerCase().includes(searchQuery.toLowerCase()));

  const focusFiles = (event: React.MouseEvent<HTMLAnchorElement>) => {
    event.preventDefault();
    document.getElementById('archivos')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <div className="platform-grid -mx-6 min-h-[calc(100vh-12rem)] px-4 py-6 sm:px-6 relative">
      <div className="relative z-10 mx-auto flex max-w-[1450px] gap-6">
        <aside className="hidden w-56 shrink-0 lg:block">
          <div className="sticky top-24 rounded-2xl border border-cyan-100/10 bg-[#071d2a]/80 p-3">
            <div className="mb-6 px-3 pt-2 text-sm font-semibold text-white">Bóveda<span className="text-cyan-300">Segura</span></div>
            <nav className="space-y-1 text-sm">
              <a className="flex items-center gap-3 rounded-xl bg-cyan-300/15 px-3 py-3 font-medium text-cyan-100" href="#archivos" onClick={focusFiles}>▦ <span>Mis archivos</span></a>
              <a className="flex items-center gap-3 rounded-xl px-3 py-3 text-cyan-50/55 transition hover:bg-white/5 hover:text-white" href="#archivos" onClick={focusFiles}>◷ <span>Recientes</span></a>
              <a className="flex items-center gap-3 rounded-xl px-3 py-3 text-cyan-50/55 transition hover:bg-white/5 hover:text-white" href="#seguridad">◈ <span>Seguridad</span></a>
            </nav>
            <div className="my-6 border-t border-white/10" />
            <div className="px-3 text-[11px] font-semibold uppercase tracking-wider text-cyan-50/35">Almacenamiento</div>
            <div className="mt-3 px-3"><div className="mb-2 flex justify-between text-xs text-cyan-50/55"><span>Local</span><span>{files.length} archivos</span></div><div className="h-1.5 rounded-full bg-white/10"><div className="h-full w-[18%] rounded-full bg-cyan-300" /></div></div>
            <div className="mt-10 rounded-xl bg-cyan-300/8 p-3 text-xs leading-5 text-cyan-50/55"><span className="text-lg">🛡️</span><br /><strong className="text-cyan-100/80">Bóveda protegida</strong><br />Tus archivos se cifran antes de almacenarse.</div>
          </div>
        </aside>

        <div className="relative min-w-0 flex-1 space-y-7">
        <div className="flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">Mi espacio</p>
            <h1 className="text-3xl font-semibold text-white sm:text-4xl">Mis archivos</h1>
            <p className="mt-2 text-sm text-cyan-50/55">Todo tu contenido cifrado, ordenado y disponible.</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden text-right sm:block"><p className="text-xs text-cyan-50/45">Sesión activa</p><p className="max-w-44 truncate text-sm text-white">{user?.email}</p></div>
            <div className="grid h-10 w-10 place-items-center rounded-full bg-cyan-300/20 text-sm font-semibold text-cyan-100">{user?.email?.slice(0, 1).toUpperCase()}</div>
          </div>
        </div>

        <div className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1"><span className="absolute left-4 top-1/2 -translate-y-1/2 text-cyan-50/35">⌕</span><input value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} placeholder="Buscar archivos..." className="w-full rounded-xl border border-cyan-100/10 bg-[#071c2a]/80 py-3.5 pl-11 pr-4 text-sm text-white outline-none placeholder:text-cyan-50/35 focus:border-cyan-300/50" /></div>
          <label htmlFor="fileInput" className="cursor-pointer"><Button variant="primary" size="md" isLoading={loading}>＋ Subir archivo</Button></label>
          <input ref={fileInputRef} type="file" onChange={handleFileUpload} className="hidden" id="fileInput" />
        </div>

        {message && (
          <Alert type="success">
            <p className="text-sm">{message}</p>
          </Alert>
        )}

        {error && (
          <Alert type="error">
            <p className="text-sm">{error}</p>
          </Alert>
        )}

        <div id="seguridad" className="flex flex-wrap items-center gap-x-5 gap-y-2 rounded-xl border border-cyan-100/10 bg-[#071c2a]/60 px-4 py-3 text-xs text-cyan-50/45"><span className="text-cyan-100/75">Protección activa</span><span>🔒 AES-256-GCM</span><span>🔑 RSA-OAEP-2048</span><span>🛡️ HMAC-SHA256</span></div>

        <div>
          <div id="archivos" className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div><h2 className="text-xl font-semibold text-white">Todos los archivos</h2><p className="mt-1 text-xs text-cyan-50/45">{filteredFiles.length} resultado{filteredFiles.length !== 1 ? 's' : ''}</p></div>
            <div className="flex items-center gap-2"><button onClick={() => setViewMode('grid')} className={`rounded-lg px-3 py-2 text-sm ${viewMode === 'grid' ? 'bg-cyan-300/15 text-cyan-100' : 'text-cyan-50/40'}`} aria-label="Vista de tarjetas">▦</button><button onClick={() => setViewMode('list')} className={`rounded-lg px-3 py-2 text-sm ${viewMode === 'list' ? 'bg-cyan-300/15 text-cyan-100' : 'text-cyan-50/40'}`} aria-label="Vista de lista">☷</button>{loading && <Spinner />}</div>
          </div>

          {files.length === 0 ? (
            <div className="glass rounded-2xl border-glow p-12 text-center">
              <div className="text-6xl mb-4">📁</div>
              <h3 className="text-lg font-semibold text-gray-300 mb-2">Sin archivos aún</h3>
              <p className="text-gray-500 text-sm mb-6">Sube tu primer archivo cifrado para comenzar.</p>
              <label htmlFor="fileInputEmpty" className="cursor-pointer">
                <Button variant="primary" size="md">
                  Subir Primer Archivo
                </Button>
              </label>
              <input type="file" className="hidden" id="fileInputEmpty" onChange={handleFileUpload} />
            </div>
          ) : filteredFiles.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-cyan-100/15 p-12 text-center text-sm text-cyan-50/45">No encontramos archivos con ese nombre.</div>
          ) : (
            <div className={viewMode === 'grid' ? 'grid gap-4 sm:grid-cols-2 xl:grid-cols-3' : 'grid gap-3'}>
              {filteredFiles.map((file) => (
                <div key={file.id} className={`file-card rounded-2xl p-5 ${viewMode === 'list' ? 'flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4' : 'min-h-48 flex flex-col justify-between'}`}>
                  <div className="flex items-start gap-4 flex-1 min-w-0">
                    <div className="grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-cyan-300/12 text-2xl">
                      📄
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="truncate text-sm font-medium text-white">{file.originalName}</p>
                      <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-cyan-50/40">
                        <span>{formatDate(file.createdAt)}</span>
                        <span>•</span>
                        <span>{formatSize(file.originalSize)}</span>
                        <span>•</span>
                        <span className="text-teal-300">🔒 Cifrado</span>
                      </div>
                    </div>
                  </div>
                  <div className="mt-5 flex shrink-0 items-center gap-2">
                    <Button
                      variant="secondary"
                      size="sm"
                      isLoading={downloadingFileId === file.id}
                      onClick={() => setActiveFileId(file.id)}
                    >
                      📥 Descargar
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {activeFileId && (
          <Card className="border-glow">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-lg font-semibold text-white">Descargar Archivo</h3>
                <p className="text-gray-400 text-sm">Ingresa tu contraseña para descifrar</p>
              </div>
              <div className="flex gap-2 w-full sm:w-auto">
                <input
                  type="password"
                  value={downloadPassword}
                  onChange={(e) => setDownloadPassword(e.target.value)}
                  placeholder="Contraseña de descifrado"
                  className="flex-1 rounded-xl border border-cyan-100/10 bg-[#071c2a] px-4 py-3 text-sm text-white outline-none placeholder:text-cyan-50/35 focus:border-cyan-300/50"
                />
                <Button
                  size="md"
                  isLoading={downloadingFileId === activeFileId}
                  onClick={() => handleDownload(activeFileId)}
                >
                  Descifrar
                </Button>
              </div>
            </div>
          </Card>
        )}

        <div className="text-center mt-8 text-sm text-cyan-50/35"><Button variant="ghost" size="sm" onClick={() => storeLogout()}>Cerrar sesión</Button></div>
        </div>
      </div>
    </div>
  );
}
