import { Component, type ReactNode } from "react";

const ICON_PATHS = {
  dashboard: "M4 5.5A1.5 1.5 0 0 1 5.5 4h4A1.5 1.5 0 0 1 11 5.5v4A1.5 1.5 0 0 1 9.5 11h-4A1.5 1.5 0 0 1 4 9.5v-4Zm9 0A1.5 1.5 0 0 1 14.5 4h4A1.5 1.5 0 0 1 20 5.5v2A1.5 1.5 0 0 1 18.5 9h-4A1.5 1.5 0 0 1 13 7.5v-2Zm0 7A1.5 1.5 0 0 1 14.5 11h4a1.5 1.5 0 0 1 1.5 1.5v6a1.5 1.5 0 0 1-1.5 1.5h-4a1.5 1.5 0 0 1-1.5-1.5v-6ZM4 14.5A1.5 1.5 0 0 1 5.5 13h4a1.5 1.5 0 0 1 1.5 1.5v4A1.5 1.5 0 0 1 9.5 20h-4A1.5 1.5 0 0 1 4 18.5v-4Z",
  control: "M11.2 4.2h1.6l.35 1.75a6.7 6.7 0 0 1 1.38.57l1.5-.95 1.14 1.13-.96 1.5c.23.43.42.88.56 1.36l1.78.36v1.6l-1.78.36a6.7 6.7 0 0 1-.56 1.36l.96 1.5-1.14 1.13-1.5-.95c-.43.23-.88.42-1.38.57l-.35 1.75h-1.6l-.35-1.75a6.7 6.7 0 0 1-1.38-.57l-1.5.95-1.14-1.13.96-1.5a6.7 6.7 0 0 1-.56-1.36L4 12.55v-1.6l1.78-.36c.14-.48.33-.93.56-1.36l-.96-1.5 1.14-1.13 1.5.95c.43-.23.88-.42 1.38-.57l.35-1.75ZM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z",
  incidents: "M12 4 5 8v5c0 4.1 2.8 7.5 7 8.8 4.2-1.3 7-4.7 7-8.8V8l-7-4Zm0 5.2a1.1 1.1 0 0 1 1.1 1.1v2.7a1.1 1.1 0 1 1-2.2 0v-2.7A1.1 1.1 0 0 1 12 9.2Zm0 7a1.25 1.25 0 1 1 0-2.5 1.25 1.25 0 0 1 0 2.5Z",
  events: "M4 17h3.2l2.1-5.2 2.8 8L15 8.5l1.8 4.5H20M5 6h14M5 20h14",
  assets: "M6 6h12v12H6V6Zm2 2v8h8V8H8Zm-3 2H3v4h2v-4Zm16 0h-2v4h2v-4Z",
  sources: "M6 8a2 2 0 1 1 0 4 2 2 0 0 1 0-4Zm12-3a2 2 0 1 1 0 4 2 2 0 0 1 0-4Zm0 11a2 2 0 1 1 0 4 2 2 0 0 1 0-4ZM8 10h6m2-2.5 1.5-1m-1.5 7 1.5 1M8 14h6",
  collectors: "M6 5h12v4H6V5Zm-1 7h14v7H5v-7Zm3 2v3m4-3v3m4-3v3",
  ingest: "M4 12h5l2.2-4 2.7 8 2.1-4H20M6 5h12M6 19h12",
  connectors: "M8 9V7.8A2.8 2.8 0 0 1 10.8 5h1.4A2.8 2.8 0 0 1 15 7.8V9h1.2A2.8 2.8 0 0 1 19 11.8v.4A2.8 2.8 0 0 1 16.2 15H15v1.2A2.8 2.8 0 0 1 12.2 19h-1.4A2.8 2.8 0 0 1 8 16.2V15H6.8A2.8 2.8 0 0 1 4 12.2v-.4A2.8 2.8 0 0 1 6.8 9H8Z",
  cases: "M7 5h10a2 2 0 0 1 2 2v10.2a1.8 1.8 0 0 1-1.8 1.8H9.8a1.8 1.8 0 0 1-1.27-.53l-3-3A1.8 1.8 0 0 1 5 14.2V7a2 2 0 0 1 2-2Zm1 2h8v1.6H8V7Zm0 3h8v1.6H8V10Zm0 3h5v1.6H8V13Z",
  entities: "M12 4a4 4 0 1 1 0 8 4 4 0 0 1 0-8Zm-6 14a6 6 0 0 1 12 0H6Zm11-1.2a3.8 3.8 0 0 1 3-3.7M5 16.8a3.8 3.8 0 0 0-3-3.7",
  vuln: "M8 5h8l4 4v8a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2Zm4 4a3 3 0 1 0 0 6 3 3 0 0 0 0-6Zm-.9 1.2h1.8v2.2H15v1.8h-2.1V16h-1.8v-1.6H9v-1.8h2.1v-2.2Z",
  intel: "M12 4 4 7.5v5C4 17 7.4 20.7 12 22c4.6-1.3 8-5 8-9.5v-5L12 4Zm0 3.2 5 2v3.3c0 3.1-2 5.9-5 6.9-3-1-5-3.8-5-6.9V9.2l5-2Zm0 2.3a2.2 2.2 0 1 0 0 4.4 2.2 2.2 0 0 0 0-4.4Z",
  builders: "M5 7h6v6H5V7Zm8 0h6v6h-6V7ZM9 15h6v6H9v-6Z",
  docs: "M6 5.5A1.5 1.5 0 0 1 7.5 4h5A1.5 1.5 0 0 1 14 5.5V6h2.5A1.5 1.5 0 0 1 18 7.5v11a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 6 18.5v-13ZM8 8h8m-8 3h8m-8 3h5",
  access: "M12 4 5 7.5v4.7c0 4.3 2.7 7.8 7 9.1 4.3-1.3 7-4.8 7-9.1V7.5L12 4Zm0 5.2a2 2 0 0 1 2 2v.6h.6a1 1 0 0 1 1 1V16a1 1 0 0 1-1 1H9.4a1 1 0 0 1-1-1v-3.2a1 1 0 0 1 1-1H10v-.6a2 2 0 0 1 2-2Zm0 1.5a.7.7 0 0 0-.7.7v.6h1.4v-.6a.7.7 0 0 0-.7-.7Z",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm5.9 8h-3.1a14.6 14.6 0 0 0-1.2-4.6A7.04 7.04 0 0 1 17.9 11Zm-5.9 8a12.9 12.9 0 0 1-1.9-4.5h3.8A12.9 12.9 0 0 1 12 19Zm-2.3-6.2a11.7 11.7 0 0 1 0-1.6h4.6a11.7 11.7 0 0 1 0 1.6H9.7ZM6.1 13h3.1A14.6 14.6 0 0 0 10.4 17.6 7.04 7.04 0 0 1 6.1 13Zm0-2A7.04 7.04 0 0 1 10.4 6.4 14.6 14.6 0 0 0 9.2 11H6.1ZM12 5a12.9 12.9 0 0 1 1.9 4.5h-3.8A12.9 12.9 0 0 1 12 5Z",
  map: "M4 6.5 9.5 4l5 2L20 4v13.5L14.5 20l-5-2L4 20V6.5Zm6 0v10.1l4 1.6V8.1l-4-1.6Z",
} as const;

export type IconName = keyof typeof ICON_PATHS;

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="react-empty" role="status" aria-live="polite">
      {message}
    </div>
  );
}

export function Icon({
  name,
  size = 18,
  className = "",
}: {
  name: IconName;
  size?: number;
  className?: string;
}) {
  return (
    <span className={`react-icon ${className}`.trim()} aria-hidden="true">
      <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round">
        <path d={ICON_PATHS[name]} />
      </svg>
    </span>
  );
}

type ErrorBoundaryProps = {
  title?: string;
  children: ReactNode;
};

type ErrorBoundaryState = {
  hasError: boolean;
  message: string;
};

export class ReactErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, message: "" };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      message: error?.message || "Unknown React render error",
    };
  }

  componentDidCatch(error: Error) {
    console.error("ReactErrorBoundary", error);
  }

  render() {
    if (this.state.hasError) {
      return (
        <section className="react-card react-card-nested react-error-card">
          <div className="react-top-kicker">React error</div>
          <h3>{this.props.title || "UI section failed to render"}</h3>
          <p className="react-muted">{this.state.message}</p>
        </section>
      );
    }
    return this.props.children;
  }
}
