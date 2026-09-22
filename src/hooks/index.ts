import { useAppStore } from '@/lib/session';

export { useAppStore };

export function useAuth() {
  const store = useAppStore();
  return {
    user: store.user,
    sessionId: store.sessionId,
    isAuthenticated: store.isAuthenticated,
    setUser: store.setUser,
    setSessionId: store.setSessionId,
    setAuthenticated: store.setAuthenticated,
    setFiles: store.setFiles,
    logout: store.logout,
  };
}

export function useFiles() {
  const store = useAppStore();
  return {
    files: store.files,
    loading: store.loading,
    error: store.error,
    message: store.message,
    setFiles: store.setFiles,
    setLoading: store.setLoading,
    setError: store.setError,
    setMessage: store.setMessage,
    activeFileId: store.activeFileId,
    setActiveFileId: store.setActiveFileId,
    downloadLoading: store.downloadLoading,
    setDownloadLoading: store.setDownloadLoading,
  };
}

export function useUI() {
  const store = useAppStore();
  return {
    error: store.error,
    message: store.message,
    loading: store.loading,
    setError: store.setError,
    setMessage: store.setMessage,
    clearError: store.clearError,
    clearMessage: store.clearMessage,
  };
}