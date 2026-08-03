import { useMemo, useState } from "react";
import { api } from "./runtime/api";
import type { ServiceLifecycleAction, ServiceLifecycleInstance } from "./runtime/types";
import { Button, DetailDrawer, EmptyState, ErrorState, IconButton, KeyValue, LoadingState, StatusCell } from "./ui";
import { formatTime, number, text, useQuery } from "./runtime/query";

type Notify = (message: string, tone?: string) => void;

const ACTION_LABELS: Record<ServiceLifecycleAction, string> = {
  start: "Запустить",
  stop: "Остановить",
  restart: "Перезапустить",
  reload: "Перезагрузить конфигурацию",
};

export function canInvokeServiceAction(instance: ServiceLifecycleInstance, action: ServiceLifecycleAction) {
  return instance.management_state === "managed" && instance.capabilities.includes(action);
}

export function serviceActionLabel(action: ServiceLifecycleAction) {
  return ACTION_LABELS[action];
}

function idempotencyKey(instanceId: string, action: ServiceLifecycleAction) {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `sentinel:${instanceId}:${action}:${suffix}`;
}

function metric(value: number | null | undefined) {
  return value === null || value === undefined ? "—" : number(value).toLocaleString("ru-RU");
}

export function ServiceLifecyclePanel({ notify }: { notify: Notify }) {
  const [selected, setSelected] = useState<ServiceLifecycleInstance | null>(null);
  const [busy, setBusy] = useState<ServiceLifecycleAction | null>(null);
  const state = useQuery("service-lifecycle", () => api.serviceLifecycle({ refresh_live: false }), 30_000);
  const rows = useMemo(() => state.data?.items ?? [], [state.data]);

  async function openDetail(item: ServiceLifecycleInstance) {
    setSelected(item);
    try {
      setSelected(await api.serviceLifecycleDetail(item.instance_id, { refresh_live: true }));
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    }
  }

  async function execute(action: ServiceLifecycleAction) {
    if (!selected || !canInvokeServiceAction(selected, action)) return;
    if ((action === "stop" || action === "restart") && !window.confirm(`${ACTION_LABELS[action]} ${selected.title}?`)) return;
    setBusy(action);
    try {
      const result = await api.executeServiceLifecycleAction(selected.instance_id, action, idempotencyKey(selected.instance_id, action));
      notify(`${ACTION_LABELS[action]}: ${result.verified ? "состояние подтверждено" : "проверка не пройдена"}`, result.verified ? "healthy" : "critical");
      state.reload();
      setSelected(await api.serviceLifecycleDetail(selected.instance_id, { refresh_live: true }));
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    } finally {
      setBusy(null);
    }
  }

  const drawerActions = selected ? (["start", "stop", "restart", "reload"] as ServiceLifecycleAction[])
    .filter((action) => canInvokeServiceAction(selected, action))
    .map((action) => <Button
      disabled={busy !== null}
      icon={action === "start" ? "play" : action === "reload" || action === "restart" ? "refresh" : undefined}
      key={action}
      onClick={() => void execute(action)}
      tone={action === "stop" ? "danger" : action === "start" ? "primary" : "default"}
    >{busy === action ? "Выполняется..." : ACTION_LABELS[action]}</Button>) : null;

  return <section className="panel panel-flush">
    <header className="panel-header"><div className="panel-title"><h2>Управляемые SIEM-сервисы</h2><span>Live systemd, runtime health и Proxmox inventory</span></div><IconButton icon="refresh" label="Обновить состояния сервисов" onClick={state.reload} /></header>
    {state.loading && !state.data ? <LoadingState label="Проверка SIEM-сервисов..." /> : null}
    {state.error ? <ErrorState error={state.error} retry={state.reload} /> : null}
    {!state.loading && !state.error && !rows.length ? <EmptyState detail="Управляемые runtime instances не обнаружены" /> : null}
    {rows.length ? <div className="native-grid"><table><thead><tr><th>Статус</th><th>Instance</th><th>Узел</th><th>Тип</th><th>Версия</th><th>Lag</th><th>EPS</th><th>Управление</th></tr></thead><tbody>{rows.map((item) => <tr className="sentinel-clickable-row" key={item.instance_id} onClick={() => void openDetail(item)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") void openDetail(item); }} tabIndex={0}>
      <td><StatusCell value={item.active_state} /></td><td><strong>{item.title}</strong><small>{item.unit}</small></td><td>{item.node}<small>{item.node_ip || `VM ${item.vmid}`}</small></td><td>{item.service_type}</td><td>{item.version || "—"}</td><td>{metric(item.lag)}</td><td>{metric(item.eps)}</td><td><StatusCell value={item.management_state} /></td>
    </tr>)}</tbody></table></div> : null}
    <DetailDrawer actions={drawerActions} eyebrow={selected ? `${selected.service_type} · ${selected.node}` : undefined} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected?.title ?? "SIEM-сервис"}>
      {selected ? <><KeyValue rows={[
        ["Состояние", <StatusCell key="status" value={selected.active_state} />], ["Systemd unit", selected.unit], ["Узел", `${selected.node} (${selected.node_ip || `VM ${selected.vmid}`})`], ["Тип", selected.service_type], ["Версия", selected.version || "—"], ["Источник статуса", selected.status_source], ["Unit file", selected.unit_file_state || "—"], ["Рестарты", number(selected.restarts)], ["Lag", metric(selected.lag)], ["EPS", metric(selected.eps)], ["Последняя телеметрия", formatTime(selected.last_seen_ts)], ["Управление", selected.management_state],
      ]} />
      {selected.unavailable_reason ? <p className="sentinel-callout">{selected.unavailable_reason}</p> : null}
      <section className="detail-section"><h3>Аудит действий</h3>{selected.audit_trail?.length ? <div className="native-grid"><table><thead><tr><th>Время</th><th>Действие</th><th>Оператор</th><th>Результат</th></tr></thead><tbody>{selected.audit_trail.map((entry, index) => <tr key={text(entry.id, String(index))}><td>{formatTime(entry.ts)}</td><td>{text(entry.action)}</td><td>{text(entry.actor)}</td><td>{text(entry.summary)}</td></tr>)}</tbody></table></div> : <EmptyState detail="Действия с этим instance еще не выполнялись" />}</section></> : null}
    </DetailDrawer>
  </section>;
}
