import { useState } from "react";
import { api } from "./runtime/api";
import type { View } from "./model";
import type {
  RemoteAccessStateResponse,
  SecurityServiceDetailResponse,
} from "./runtime/types";
import {
  formatTime,
  number,
  severityTone,
  text,
  useQuery,
} from "./runtime/query";
import {
  Badge,
  Button,
  DetailDrawer,
  EmptyState,
  ErrorState,
  IconButton,
  LoadingState,
  Modal,
  PageHeader,
  StatusCell,
  Tabs,
} from "./ui";

type Notify = (message: string, tone?: string) => void;
type Row = Record<string, unknown>;

const SERVICE_BY_VIEW: Partial<Record<View, string>> = {
  ndr: "ndr",
  container: "runtime",
  vpn: "vpn",
  dfir: "dfir",
  analysis: "analysis",
  evidence: "evidence",
  pki: "pki",
};
const TITLE_BY_VIEW: Partial<Record<View, string>> = {
  ndr: "Network Detection and Response",
  container: "Container Runtime Security",
  vpn: "VPN и защищенный доступ",
  dfir: "Расследование и Endpoint DFIR",
  analysis: "Malware Analysis",
  evidence: "Хранилище доказательств",
  pki: "Доверие и внутренняя PKI",
};

function rows(value: unknown): Row[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is Row => Boolean(item) && typeof item === "object",
      )
    : [];
}

function WorkspaceTable({
  data,
  onOpen,
  empty = "Данные за выбранный период отсутствуют",
}: {
  data: Row[];
  onOpen: (row: Row) => void;
  empty?: string;
}) {
  if (!data.length) return <EmptyState detail={empty} />;
  const preferred = [
    "severity",
    "status",
    "name",
    "title",
    "rule_name",
    "event_name",
    "container_name",
    "host_name",
    "src_ip",
    "dst_ip",
    "protocol",
    "message",
    "ts",
    "updated_ts",
  ];
  const available = new Set(data.flatMap((item) => Object.keys(item)));
  const columns = preferred.filter((key) => available.has(key)).slice(0, 7);
  const labels: Record<string, string> = {
    severity: "Важность",
    status: "Статус",
    name: "Название",
    title: "Название",
    rule_name: "Правило",
    event_name: "Событие",
    container_name: "Контейнер",
    host_name: "Узел",
    src_ip: "Источник IP",
    dst_ip: "Назначение IP",
    protocol: "Протокол",
    message: "Сводка",
    ts: "Время",
    updated_ts: "Обновлено",
  };
  const renderMessage = (value: unknown) => {
    const raw = text(value);
    if (!raw.trim().startsWith("{")) return raw;
    try {
      const payload = JSON.parse(raw) as Row;
      const summary = Object.entries(payload)
        .filter(([, item]) =>
          ["string", "number", "boolean"].includes(typeof item),
        )
        .slice(0, 3)
        .map(([key, item]) => `${key}: ${text(item)}`)
        .join(" · ");
      return summary || "Структурированное событие";
    } catch {
      return "Структурированное событие";
    }
  };
  return (
    <div className="native-grid security-workspace-grid">
      <table>
        <thead>
          <tr>
            {columns.map((key) => (
              <th key={key}>{labels[key] ?? key.replaceAll("_", " ")}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, index) => (
            <tr
              className="sentinel-clickable-row"
              key={text(row.id ?? row.event_id ?? row.ts, String(index))}
              onClick={() => onOpen(row)}
            >
              {columns.map((key) => (
                <td key={key}>
                  {key === "status" ? (
                    <StatusCell value={text(row[key])} />
                  ) : key === "severity" ? (
                    <Badge tone={severityTone(row[key])}>
                      {text(row[key])}
                    </Badge>
                  ) : key.includes("ts") ? (
                    formatTime(row[key])
                  ) : (
                    <span
                      className={key === "message" ? "sentinel-truncate" : ""}
                    >
                      {key === "message"
                        ? renderMessage(row[key])
                        : text(row[key])}
                    </span>
                  )}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ServiceSummary({
  detail,
  remote,
}: {
  detail: SecurityServiceDetailResponse;
  remote?: RemoteAccessStateResponse;
}) {
  const service = detail.service;
  const telemetry = detail.telemetry;
  const activeRemotePlane = remote?.access_planes.find(
    (item) => item.status === "active" && item.role === "remote_ingress",
  );
  return (
    <section className="metric-grid">
      <div className="metric">
        <span>Интеграция</span>
        <strong>
          <StatusCell
            value={
              activeRemotePlane
                ? "active"
                : text(service.integration_state ?? service.telemetry_state)
            }
          />
        </strong>
        <small>
          {activeRemotePlane
            ? `${activeRemotePlane.provider.toUpperCase()} · ${activeRemotePlane.endpoint}`
            : service.product}
        </small>
      </div>
      <div className="metric">
        <span>События 1ч</span>
        <strong>
          {number(telemetry.events_1h ?? service.events_1h).toLocaleString(
            "ru-RU",
          )}
        </strong>
        <small>нормализованный поток</small>
      </div>
      <div className="metric">
        <span>События 24ч</span>
        <strong>
          {number(telemetry.events_24h ?? service.events_24h).toLocaleString(
            "ru-RU",
          )}
        </strong>
        <small>{service.host_name}</small>
      </div>
      <div className="metric">
        <span>Покрытие продукта</span>
        <strong>
          {activeRemotePlane
            ? "100%"
            : `${Math.round(number(service.product_coverage) * 100)}%`}
        </strong>
        <small>
          {activeRemotePlane
            ? "удаленный вход подтвержден runtime-проверкой"
            : (service.matched_products ?? []).join(", ") ||
              "нет подтвержденных продуктов"}
        </small>
      </div>
      <div className="metric">
        <span>Последнее событие</span>
        <strong className="metric-time">
          {formatTime(service.latest_event)}
        </strong>
        <small>{service.address}</small>
      </div>
    </section>
  );
}

function RemoteAccessPlanes({ state }: { state: RemoteAccessStateResponse }) {
  return (
    <section
      className="remote-access-planes"
      aria-label="Контуры удаленного доступа"
    >
      {state.access_planes.map((plane) => (
        <article className="remote-access-plane" key={plane.provider}>
          <div>
            <span>{plane.provider.toUpperCase()}</span>
            <Badge
              tone={
                plane.status === "active"
                  ? "healthy"
                  : plane.status === "degraded"
                    ? "warning"
                    : "neutral"
              }
            >
              {plane.status}
            </Badge>
          </div>
          <strong>{plane.endpoint}</strong>
          <small>
            {plane.role === "remote_ingress"
              ? "Входной удаленный доступ"
              : "Исходящий канал, не VPN-вход"}
          </small>
          <dl>
            <dt>Сервис</dt>
            <dd>{plane.service_state}</dd>
            <dt>Туннель</dt>
            <dd>{plane.tunnel_state}</dd>
            <dt>Адрес</dt>
            <dd>{plane.address || "нет"}</dd>
            <dt>Выпуск профилей</dt>
            <dd>
              {plane.managed_profile_issuance
                ? "подключен"
                : "требуется CA controller"}
            </dd>
          </dl>
        </article>
      ))}
    </section>
  );
}

function VpnProfileModal({
  open,
  state,
  onClose,
  onSaved,
  notify,
}: {
  open: boolean;
  state?: RemoteAccessStateResponse;
  onClose: () => void;
  onSaved: () => void;
  notify: Notify;
}) {
  async function submit(form: HTMLFormElement) {
    const values = new FormData(form);
    try {
      const result = await api.saveRemoteAccessProfile({
        provider: text(values.get("provider")),
        name: text(values.get("name")),
        route_preset: text(values.get("route_preset")),
        endpoint: text(values.get("endpoint")),
        server_name: text(values.get("server_name")),
        transport: text(values.get("transport")),
        credential_ref: text(values.get("credential_ref")),
      });
      notify(
        result.status === "active"
          ? "VPN-профиль создан и активирован"
          : `Профиль подготовлен: ${text((result.activation as Row)?.issue, result.status)}`,
        result.status === "failed" ? "critical" : "healthy",
      );
      onSaved();
      onClose();
    } catch (error) {
      notify(
        error instanceof Error ? error.message : String(error),
        "critical",
      );
    }
  }
  return (
    <Modal
      footer={
        <>
          <Button onClick={onClose}>Отмена</Button>
          <Button form="vpn-profile-form" tone="primary" type="submit">
            Создать профиль
          </Button>
        </>
      }
      onClose={onClose}
      open={open}
      title="Новый профиль удаленного доступа"
    >
      <form
        className="kuma-form-grid"
        id="vpn-profile-form"
        onSubmit={(event) => {
          event.preventDefault();
          void submit(event.currentTarget);
        }}
      >
        <label>
          <span>Название</span>
          <input name="name" required />
        </label>
        <label>
          <span>Провайдер</span>
          <select name="provider">
            <option value="openvpn">OpenVPN</option>
            <option value="vless" disabled>
              VLESS (нет inbound-контроллера)
            </option>
          </select>
        </label>
        <label>
          <span>Маршруты</span>
          <select name="route_preset">
            {state?.route_presets.map((preset) => (
              <option key={preset.id} value={preset.id}>
                {preset.id} · {preset.routes.join(", ")}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Endpoint</span>
          <input name="endpoint" placeholder="vpn.example.net:443" />
        </label>
        <label>
          <span>Server name / SNI</span>
          <input name="server_name" />
        </label>
        <label>
          <span>Транспорт</span>
          <select name="transport">
            <option value="tcp">TCP</option>
            <option value="ws">WebSocket</option>
            <option value="grpc">gRPC</option>
          </select>
        </label>
        <label className="wide">
          <span>Credential reference</span>
          <input
            name="credential_ref"
            placeholder="vault://remote-access/user"
          />
        </label>
        <p className="wide security-form-note">
          Секреты не хранятся в профиле. При настроенном controller профиль
          активируется сразу; иначе сохраняется как подготовленный с точной
          причиной.
        </p>
      </form>
    </Modal>
  );
}

export function SecurityOperationsWorkspace({
  view,
  notify,
}: {
  view: View;
  notify: Notify;
}) {
  const serviceId = SERVICE_BY_VIEW[view] ?? view;
  const [tab, setTab] = useState("events");
  const [selected, setSelected] = useState<Row | null>(null);
  const [profileOpen, setProfileOpen] = useState(false);
  const investigation = ["dfir", "analysis", "evidence", "pki"].includes(view);
  const state = useQuery(
    `security-workspace:${view}`,
    async () => {
      const [detail, cases, remote] = await Promise.all([
        api.securityService(serviceId),
        investigation ? api.cases({ limit: 100 }) : Promise.resolve(null),
        view === "vpn" ? api.remoteAccessState() : Promise.resolve(null),
      ]);
      return { detail, cases, remote };
    },
    30_000,
  );
  const data = state.data;
  const detail = data?.detail;
  const eventRows = rows(detail?.recent_events);
  const alertRows = rows(detail?.recent_alerts);
  const signalRows = rows(detail?.signal_breakdown);
  const caseRows = rows(data?.cases?.items);
  const profileRows = rows(data?.remote?.profiles);
  let visibleRows =
    tab === "alerts"
      ? alertRows
      : tab === "signals"
        ? signalRows
        : tab === "cases"
          ? caseRows
          : tab === "profiles"
            ? profileRows
            : eventRows;
  if (view === "container" && tab === "workloads") {
    const seen = new Map<string, Row>();
    for (const item of eventRows) {
      const key = text(
        item.container_name ?? item.container_id ?? item.host_name,
        "unknown",
      );
      if (!seen.has(key))
        seen.set(key, {
          name: key,
          status: "observed",
          host_name: item.host_name,
          updated_ts: item.ts,
          image: item.container_image ?? item.image,
        });
    }
    visibleRows = [...seen.values()];
  }
  async function revokeSelectedProfile() {
    if (!selected || !text(selected.id)) return;
    try {
      await api.deleteRemoteAccessProfile(text(selected.id));
      notify("VPN-профиль отозван, сертификат добавлен в CRL", "healthy");
      setSelected(null);
      state.reload();
    } catch (error) {
      notify(
        error instanceof Error ? error.message : String(error),
        "critical",
      );
    }
  }
  const tabs =
    view === "vpn"
      ? [
          { id: "profiles", label: "Профили", count: profileRows.length },
          { id: "events", label: "События", count: eventRows.length },
          { id: "alerts", label: "Алерты", count: alertRows.length },
        ]
      : investigation
        ? [
            { id: "cases", label: "Расследования", count: caseRows.length },
            { id: "events", label: "Телеметрия", count: eventRows.length },
            { id: "alerts", label: "Сработки", count: alertRows.length },
          ]
        : view === "container"
          ? [
              {
                id: "workloads",
                label: "Workloads",
                count: new Set(
                  eventRows.map((item) =>
                    text(item.container_name ?? item.host_name),
                  ),
                ).size,
              },
              { id: "events", label: "Falco события", count: eventRows.length },
              { id: "alerts", label: "Сработки", count: alertRows.length },
              { id: "signals", label: "Сигналы", count: signalRows.length },
            ]
          : [
              {
                id: "events",
                label: "Сетевые события",
                count: eventRows.length,
              },
              { id: "alerts", label: "Детекты", count: alertRows.length },
              {
                id: "signals",
                label: "Протоколы и сигналы",
                count: signalRows.length,
              },
            ];
  const external = rows(detail?.service.workspaces).find(
    (item) => item.external && /^https?:/i.test(text(item.href)),
  );
  return (
    <div className="native-page security-operations-page">
      <PageHeader
        eyebrow={
          detail
            ? `${detail.service.product} · ${detail.service.host_name}`
            : undefined
        }
        title={TITLE_BY_VIEW[view] ?? text(view)}
        actions={
          <>
            {view === "vpn" ? (
              <Button
                icon="plus"
                onClick={() => setProfileOpen(true)}
                tone="primary"
              >
                Новый VPN-профиль
              </Button>
            ) : null}
            {external ? (
              <a
                className="button button-default"
                href={text(external.href)}
                rel="noreferrer"
                target="_blank"
              >
                Открыть консоль
              </a>
            ) : null}
            <IconButton
              icon="refresh"
              label="Обновить"
              onClick={state.reload}
            />
          </>
        }
      />
      {state.loading && !data ? (
        <LoadingState />
      ) : state.error ? (
        <ErrorState error={state.error} retry={state.reload} />
      ) : detail ? (
        <>
          <ServiceSummary
            detail={detail}
            remote={view === "vpn" ? (data?.remote ?? undefined) : undefined}
          />
          {view === "vpn" && data?.remote ? (
            <RemoteAccessPlanes state={data.remote} />
          ) : null}
          {view === "vpn" && data?.remote?.issues.length ? (
            <div className="sentinel-partial-warning">
              <Badge tone="warning">Controller</Badge>
              <span>{data.remote.issues.join(" · ")}</span>
            </div>
          ) : null}
          <Tabs
            items={tabs}
            label={TITLE_BY_VIEW[view] ?? "Средство защиты"}
            onChange={setTab}
            value={tab}
          />
          <WorkspaceTable
            data={visibleRows}
            empty={tab === "profiles" ? "Профили еще не созданы" : undefined}
            onOpen={setSelected}
          />
        </>
      ) : (
        <EmptyState />
      )}
      <DetailDrawer
        actions={
          selected && view === "vpn" ? (
            <>
              {text(selected.download_url) ? (
                <a
                  className="button button-primary"
                  href={text(selected.download_url)}
                >
                  Скачать .ovpn
                </a>
              ) : null}
              <Button
                onClick={() => void revokeSelectedProfile()}
                tone="danger"
              >
                Отозвать профиль
              </Button>
            </>
          ) : null
        }
        onClose={() => setSelected(null)}
        open={Boolean(selected)}
        title={
          selected
            ? text(
                selected.name ??
                  selected.title ??
                  selected.rule_name ??
                  selected.event_name,
                "Детали",
              )
            : "Детали"
        }
      >
        {selected ? (
          <div className="security-detail-cards">
            {Object.entries(selected)
              .filter(
                ([, value]) =>
                  value !== null &&
                  value !== "" &&
                  ["string", "number", "boolean"].includes(typeof value),
              )
              .map(([key, value]) => (
                <div key={key}>
                  <span>{key.replaceAll("_", " ")}</span>
                  <strong>
                    {key.includes("ts") ? formatTime(value) : text(value)}
                  </strong>
                </div>
              ))}
          </div>
        ) : null}
      </DetailDrawer>
      <VpnProfileModal
        notify={notify}
        onClose={() => setProfileOpen(false)}
        onSaved={state.reload}
        open={profileOpen}
        state={data?.remote ?? undefined}
      />
    </div>
  );
}
