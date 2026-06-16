import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

export type ToastTone = "info" | "success" | "warning" | "error";
export type ToastPoliteness = "polite" | "assertive";

export type ToastOptions = {
  title?: string;
  message: string;
  tone?: ToastTone;
  durationMs?: number;
};

type ToastRecord = ToastOptions & {
  id: string;
  createdAt: number;
};

type FeedbackContextValue = {
  pushToast: (options: ToastOptions) => string;
  dismissToast: (toastId: string) => void;
  announce: (message: string, politeness?: ToastPoliteness) => void;
};

const DEFAULT_DURATION_MS = 4600;

const FeedbackContext = createContext<FeedbackContextValue>({
  pushToast: () => "",
  dismissToast: () => undefined,
  announce: () => undefined,
});

function createToastId(counter: number) {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `toast-${Date.now()}-${counter}`;
}

export function FeedbackProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastRecord[]>([]);
  const [liveMessage, setLiveMessage] = useState("");
  const [livePoliteness, setLivePoliteness] = useState<ToastPoliteness>("polite");
  const toastCounterRef = useRef(0);
  const timeoutsRef = useRef<Map<string, number>>(new Map());

  const dismissToast = useCallback((toastId: string) => {
    const timeoutId = timeoutsRef.current.get(toastId);
    if (timeoutId) {
      window.clearTimeout(timeoutId);
      timeoutsRef.current.delete(toastId);
    }
    setToasts((current) => current.filter((item) => item.id !== toastId));
  }, []);

  const announce = useCallback((message: string, politeness: ToastPoliteness = "polite") => {
    const normalized = String(message || "").trim();
    if (!normalized) return;
    setLivePoliteness(politeness);
    setLiveMessage("");
    window.setTimeout(() => {
      setLiveMessage(normalized);
    }, 20);
  }, []);

  const pushToast = useCallback((options: ToastOptions) => {
    const normalizedMessage = String(options.message || "").trim();
    if (!normalizedMessage) return "";
    toastCounterRef.current += 1;
    const id = createToastId(toastCounterRef.current);
    const tone = options.tone || "info";
    const durationMs = Math.max(1800, Number(options.durationMs || DEFAULT_DURATION_MS));
    const nextToast: ToastRecord = {
      id,
      title: options.title ? String(options.title).trim() : "",
      message: normalizedMessage,
      tone,
      durationMs,
      createdAt: Date.now(),
    };
    setToasts((current) => [...current, nextToast]);
    announce(options.title ? `${options.title}. ${normalizedMessage}` : normalizedMessage, tone === "error" ? "assertive" : "polite");
    const timeoutId = window.setTimeout(() => dismissToast(id), durationMs);
    timeoutsRef.current.set(id, timeoutId);
    return id;
  }, [announce, dismissToast]);

  useEffect(() => {
    const activeTimeouts = timeoutsRef.current;
    return () => {
      for (const timeoutId of activeTimeouts.values()) {
        window.clearTimeout(timeoutId);
      }
      activeTimeouts.clear();
    };
  }, []);

  const value = useMemo<FeedbackContextValue>(
    () => ({
      pushToast,
      dismissToast,
      announce,
    }),
    [announce, dismissToast, pushToast],
  );

  return (
    <FeedbackContext.Provider value={value}>
      {children}
      <div className="react-feedback-live react-sr-only" aria-live={livePoliteness} aria-atomic="true">
        {liveMessage}
      </div>
      <div className="react-toast-viewport" aria-label="Notifications">
        {toasts.map((toast) => (
          <section
            key={toast.id}
            className={`react-toast react-toast-${toast.tone}`}
            role={toast.tone === "error" ? "alert" : "status"}
          >
            <div className="react-toast-copy">
              {toast.title ? <strong>{toast.title}</strong> : null}
              <span>{toast.message}</span>
            </div>
            <button
              type="button"
              className="react-toast-dismiss"
              onClick={() => dismissToast(toast.id)}
              aria-label="Dismiss notification"
            >
              x
            </button>
          </section>
        ))}
      </div>
    </FeedbackContext.Provider>
  );
}

export function useFeedback() {
  return useContext(FeedbackContext);
}
