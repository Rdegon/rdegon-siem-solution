import type { ButtonHTMLAttributes, ReactNode } from "react";
import {
  Activity, AlertTriangle, Archive, BarChart3, Boxes, Braces, Check, ChevronLeft, ChevronRight,
  CircleHelp, ClipboardList, Database, FileChartColumn, FileSearch, Filter, Fingerprint, Gauge,
  Globe2, KeyRound, LayoutDashboard, Link2, ListChecks, LockKeyhole, Menu, Network, PanelLeftClose,
  PanelLeftOpen, Play, Plus, RadioTower, RefreshCw, Search, Server, Settings2, Shield, ShieldAlert,
  ShieldCheck, TerminalSquare, Trash2, UserRound, UsersRound, X, Zap,
  type LucideIcon,
} from "lucide-react";

const icons: Record<string, LucideIcon> = {
  overview: LayoutDashboard, alerts: ShieldAlert, incidents: AlertTriangle, events: FileSearch,
  cases: ClipboardList, assets: Boxes, reports: FileChartColumn, resources: Database, sources: RadioTower,
  rules: Braces, runtime: Gauge, access: KeyRound, coverage: ShieldCheck, topology: Network,
  discovery: Search, response: Zap, exposure: AlertTriangle, intel: Globe2, identity: Fingerprint,
  container: Boxes, ngfw: Shield, ndr: Activity, ids: ShieldAlert, dfir: FileSearch, analysis: TerminalSquare,
  pki: LockKeyhole, evidence: Archive, vpn: Link2, search: Search, refresh: RefreshCw, filter: Filter,
  settings: Settings2, close: X, plus: Plus, menu: Menu, collapse: PanelLeftClose, expand: PanelLeftOpen,
  check: Check, play: Play, delete: Trash2, user: UserRound, users: UsersRound, server: Server,
  chart: BarChart3, help: CircleHelp, previous: ChevronLeft, next: ChevronRight, list: ListChecks,
  warning: AlertTriangle,
};

export function Icon({ name, size = 16, className = "" }: { name: string; size?: number; className?: string }) {
  const Component = icons[name] ?? Activity;
  return <Component aria-hidden="true" className={`icon ${className}`} size={size} strokeWidth={1.8} />;
}

export function Button({ children, icon, tone = "default", className = "", ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { icon?: string; tone?: "default" | "primary" | "danger" | "ghost" }) {
  return <button className={`button button-${tone} ${className}`} type="button" {...props}>{icon ? <Icon name={icon} size={15} /> : null}<span>{children}</span></button>;
}

export function IconButton({ icon, label, active = false, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { icon: string; label: string; active?: boolean }) {
  return <button aria-label={label} className={`icon-button ${active ? "active" : ""}`} title={label} type="button" {...props}><Icon name={icon} size={16} /></button>;
}

export function Badge({ children, tone = "info" }: { children: ReactNode; tone?: string }) {
  return <span className={`badge tone-${tone}`}>{children}</span>;
}

export function StatusCell({ value }: { value: string }) {
  const lowered = value.toLowerCase();
  const tone = /healthy|active|enabled|running|online|completed|готов|актив|норма|доступ/.test(lowered)
    ? "healthy" : /critical|failed|error|down|крит|ошиб|недоступ/.test(lowered)
      ? "critical" : /warn|degrad|stale|quiet|ожид|предуп/.test(lowered) ? "warning" : "info";
  return <Badge tone={tone}>{value || "Неизвестно"}</Badge>;
}

export function PageHeader({ title, actions, eyebrow }: { title: string; actions?: ReactNode; eyebrow?: string }) {
  return <header className="native-page-header"><div>{eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}<h1>{title}</h1></div><div>{actions}</div></header>;
}

export function Tabs({ items, value, onChange, label }: { items: Array<{ id: string; label: string; count?: number }>; value: string; onChange: (value: string) => void; label: string }) {
  return <nav aria-label={label} className="native-tabs">{items.map((item) => <button className={value === item.id ? "active" : ""} key={item.id} onClick={() => onChange(item.id)} type="button">{item.label}{typeof item.count === "number" ? <span className="kuma-tab-count">{item.count.toLocaleString("ru-RU")}</span> : null}</button>)}</nav>;
}

export function SearchField({ value, onChange, placeholder = "Поиск..." }: { value: string; onChange: (value: string) => void; placeholder?: string }) {
  return <label className="kuma-search-field"><Icon name="search" /><input aria-label={placeholder} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} value={value} />{value ? <button aria-label="Очистить" onClick={() => onChange("")} type="button"><Icon name="close" size={14} /></button> : null}</label>;
}

export function DetailDrawer({ open, title, eyebrow, actions, onClose, children }: { open: boolean; title: string; eyebrow?: string; actions?: ReactNode; onClose: () => void; children: ReactNode }) {
  if (!open) return null;
  return <><button aria-label="Закрыть окно деталей" className="drawer-scrim" onClick={onClose} type="button" /><aside aria-modal="true" className="detail-drawer open" role="dialog"><header className="detail-drawer-header"><div className="detail-drawer-title">{eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}<h2>{title}</h2></div><button aria-label="Закрыть" className="icon-button" onClick={onClose} type="button"><Icon name="close" /></button></header>{actions ? <div className="detail-drawer-actionbar">{actions}</div> : null}<div className="detail-drawer-body">{children}</div></aside></>;
}

export function Modal({ open, title, onClose, footer, children }: { open: boolean; title: string; onClose: () => void; footer?: ReactNode; children: ReactNode }) {
  if (!open) return null;
  return <div className="modal-backdrop" onMouseDown={onClose} role="presentation"><div aria-modal="true" className="modal" onMouseDown={(event) => event.stopPropagation()} role="dialog"><header><h2>{title}</h2><IconButton icon="close" label="Закрыть" onClick={onClose} /></header><div className="modal-body">{children}</div>{footer ? <footer>{footer}</footer> : null}</div></div>;
}

export function LoadingState({ label = "Загрузка данных..." }: { label?: string }) {
  return <div className="empty-state"><RefreshCw className="sentinel-spin" size={22} /><strong>{label}</strong></div>;
}

export function ErrorState({ error, retry }: { error: Error; retry: () => void }) {
  return <div className="empty-state"><AlertTriangle size={24} /><strong>Не удалось загрузить данные</strong><p>{error.message}</p><Button icon="refresh" onClick={retry}>Повторить</Button></div>;
}

export function EmptyState({ title = "Нет данных", detail }: { title?: string; detail?: string }) {
  return <div className="empty-state"><Database size={24} /><strong>{title}</strong>{detail ? <p>{detail}</p> : null}</div>;
}

export function KeyValue({ rows }: { rows: Array<[string, ReactNode]> }) {
  return <dl className="kuma-kv">{rows.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? "—"}</dd></div>)}</dl>;
}
