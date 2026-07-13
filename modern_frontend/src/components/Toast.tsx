import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from "lucide-react";

type ToastKind = "success" | "error" | "warning" | "info";

interface ToastMessage {
  id: number;
  kind: ToastKind;
  title: string;
  detail?: string;
}

interface ToastContextValue {
  toast: (kind: ToastKind, title: string, detail?: string) => void;
}

const ToastContext = createContext<ToastContextValue>({ toast: () => {} });

export function useToast() {
  return useContext(ToastContext);
}

let nextId = 1;

const iconMap: Record<ToastKind, typeof CheckCircle2> = {
  success: CheckCircle2,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const timersRef = useRef<Map<number, number>>(new Map());

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    const timer = timersRef.current.get(id);
    if (timer) {
      window.clearTimeout(timer);
      timersRef.current.delete(id);
    }
  }, []);

  const toast = useCallback(
    (kind: ToastKind, title: string, detail?: string) => {
      const id = nextId++;
      setToasts((prev) => [...prev.slice(-4), { id, kind, title, detail }]);
      const timer = window.setTimeout(() => dismiss(id), 4200);
      timersRef.current.set(id, timer);
    },
    [dismiss],
  );

  useEffect(() => {
    return () => {
      timersRef.current.forEach((t) => window.clearTimeout(t));
    };
  }, []);

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div className="toast-region" aria-live="polite">
        {toasts.map((t) => {
          const Icon = iconMap[t.kind];
          return (
            <div className={`toast toast-${t.kind}`} key={t.id} role="alert">
              <Icon size={17} className="toast-icon" />
              <div className="toast-body">
                <strong>{t.title}</strong>
                {t.detail && <small>{t.detail}</small>}
              </div>
              <button className="toast-dismiss" type="button" onClick={() => dismiss(t.id)} aria-label="Dismiss">
                <X size={14} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
