interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  isLoading?: boolean;
}

export function Button({ variant = 'primary', size = 'md', isLoading = false, children, className = '', disabled, ...props }: ButtonProps) {
  const baseStyles = 'inline-flex items-center justify-center font-medium rounded-xl transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed';
  const variants = {
    primary: 'gradient-bg text-white hover:opacity-90 shadow-lg hover:shadow-glow-strong focus:ring-purple-500/50 scale-[1.02] active:scale-[0.98]',
    secondary: 'glass text-white hover:bg-white/15 border border-white/10 focus:ring-purple-500/50',
    danger: 'bg-red-500/20 text-red-400 hover:bg-red-500/30 border border-red-500/20 focus:ring-red-500/50',
    ghost: 'bg-transparent text-gray-400 hover:text-white hover:bg-white/5 focus:ring-gray-400/50',
  };
  const sizes = {
    sm: 'px-4 py-2 text-sm',
    md: 'px-5 py-2.5 text-sm',
    lg: 'px-8 py-4 text-base',
  };

  return (
    <button
      className={`${baseStyles} ${variants[variant]} ${sizes[size]} ${className}`}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading && (
        <svg className="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      )}
      {children}
    </button>
  );
}

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

export function Input({ label, error, className = '', ...props }: InputProps) {
  return (
    <div className="flex flex-col gap-2">
      {label && <label className="text-sm font-medium text-gray-300">{label}</label>}
      <input
        className={`w-full px-4 py-3 rounded-xl bg-white/5 border backdrop-blur-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 transition-all ${error ? 'border-red-500/50 focus:ring-red-500/50 focus:border-red-500/50' : 'border-white/10 focus:ring-purple-500/50 focus:border-purple-500/50'}`}
        {...props}
      />
      {error && <p className="text-sm text-red-400">{error}</p>}
    </div>
  );
}

interface CardProps {
  children: React.ReactNode;
  className?: string;
}

export function Card({ children, className = '' }: CardProps) {
  return (
    <div className={`rounded-2xl glass border-glow p-6 ${className}`}>
      {children}
    </div>
  );
}

export function Alert({ children, type = 'info' }: { children: React.ReactNode; type?: 'info' | 'success' | 'error' | 'warning' }) {
  const styles = {
    info: 'bg-blue-500/10 border-blue-500/20 text-blue-300',
    success: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300',
    error: 'bg-red-500/10 border-red-500/20 text-red-300',
    warning: 'bg-yellow-500/10 border-yellow-500/20 text-yellow-300',
  };

  return (
    <div className={`p-4 rounded-xl border ${styles[type]} backdrop-blur-sm`}>
      {children}
    </div>
  );
}

export function Spinner() {
  return (
    <div className="flex items-center justify-center p-8">
      <div className="relative">
        <div className="w-10 h-10 rounded-full border-4 border-white/10 border-t-purple-500 animate-spin"></div>
      </div>
    </div>
  );
}
