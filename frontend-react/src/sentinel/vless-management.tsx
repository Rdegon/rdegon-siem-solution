import { useMemo, useState } from "react";
import { api } from "./runtime/api";
import type { XuiClientRecord, XuiInboundRecord } from "./runtime/types";
import { number, text, useQuery } from "./runtime/query";
import { Badge, Button, EmptyState, ErrorState, LoadingState, Modal, StatusCell, Tabs } from "./ui";

type Notify = (message: string, tone?: string) => void;

function bytes(value: unknown): string {
  const amount = Math.max(0, number(value));
  if (amount < 1024) return `${amount} B`;
  if (amount < 1024 ** 2) return `${(amount / 1024).toFixed(1)} KB`;
  if (amount < 1024 ** 3) return `${(amount / 1024 ** 2).toFixed(1)} MB`;
  return `${(amount / 1024 ** 3).toFixed(2)} GB`;
}

function expiry(value: unknown): string {
  const timestamp = number(value);
  return timestamp > 0 ? new Date(timestamp).toLocaleString("ru-RU") : "Без срока";
}

function inboundPayload(form: HTMLFormElement) {
  const data = new FormData(form);
  const network = text(data.get("network"), "tcp");
  const security = text(data.get("security"), "reality");
  const serverName = text(data.get("server_name"), "www.microsoft.com");
  const stream: Record<string, unknown> = { network, security };
  if (security === "reality") {
    stream.realitySettings = {
      show: false,
      xver: 0,
      dest: `${serverName}:443`,
      serverNames: [serverName],
      shortIds: [],
      settings: { publicKey: "", fingerprint: "chrome", serverName: "", spiderX: "/" },
    };
  }
  return {
    remark: text(data.get("remark")),
    enable: true,
    listen: "",
    port: number(data.get("port")),
    protocol: "vless",
    expiryTime: 0,
    settings: { clients: [], decryption: "none", fallbacks: [] },
    stream_settings: stream,
    sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: false },
  };
}

function clientPayload(form: HTMLFormElement, existing?: XuiClientRecord) {
  const data = new FormData(form);
  const expiryValue = text(data.get("expiry_days"), "").trim();
  const expiryDays = Math.max(0, number(expiryValue));
  return {
    email: text(data.get("email"), existing?.email),
    enable: data.get("enable") === "on",
    flow: text(data.get("flow"), existing?.flow || "xtls-rprx-vision"),
    limit_ip: Math.max(0, number(data.get("limit_ip"))),
    total_gb: Math.max(0, number(data.get("total_gb"))),
    expiry_time: expiryValue ? (expiryDays ? Date.now() + expiryDays * 86_400_000 : 0) : number(existing?.expiryTime),
    telegram_id: text(data.get("telegram_id"), text(existing?.tgId)),
  };
}

export function VlessManagement({ notify }: { notify: Notify }) {
  const state = useQuery("xui-management", async () => {
    const me = await api.authMe();
    return me.principal.permissions.includes("vpn:manage")
      ? api.xuiManagementState()
      : api.xuiState();
  }, 20_000);
  const [tab, setTab] = useState("clients");
  const [inboundModal, setInboundModal] = useState(false);
  const [clientModal, setClientModal] = useState(false);
  const [selectedInbound, setSelectedInbound] = useState<XuiInboundRecord | null>(null);
  const [selectedClient, setSelectedClient] = useState<XuiClientRecord | null>(null);
  const data = state.data;
  const inbounds = data?.inbounds ?? [];
  const clients = data?.clients ?? [];
  const online = useMemo(() => new Set(data?.online ?? []), [data?.online]);
  const capabilities = useMemo(() => new Set(data?.capabilities ?? []), [data?.capabilities]);

  async function mutate(action: () => Promise<unknown>, success: string) {
    try {
      await action();
      notify(success, "healthy");
      setSelectedClient(null);
      setSelectedInbound(null);
      state.reload();
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    }
  }

  if (state.loading && !data) return <LoadingState label="Загрузка 3x-ui..." />;
  if (state.error) return <ErrorState error={state.error} retry={state.reload} />;
  if (!data?.configured) {
    return <section className="vless-management" aria-label="Управление 3x-ui"><header className="vless-management-header"><div><span className="eyebrow">3x-ui · localhost management plane</span><h2>VLESS / Reality</h2><p>{data?.issue}</p></div><div className="vless-management-actions"><StatusCell value={data?.status || "unavailable"} /><Button icon="refresh" onClick={state.reload}>Повторить</Button></div></header><EmptyState title="Контроллер 3x-ui не подключен" detail="Публичный порт панели намеренно не используется. Требуется приватный controller transport." /></section>;
  }

  return (
    <section className="vless-management" aria-label="Управление 3x-ui">
      <header className="vless-management-header">
        <div>
          <span className="eyebrow">3x-ui · {text(data.connectivity?.transport, "private transport")}</span>
          <h2>VLESS / Reality</h2>
          <p>{data.issue || "Профили, лимиты и трафик управляются через закрытый контроллер."}</p>
        </div>
        <div className="vless-management-actions">
          <StatusCell value={data.status} />
          {capabilities.has("inbounds.create") ? <Button icon="plus" onClick={() => setInboundModal(true)}>Inbound</Button> : null}
          {capabilities.has("clients.create") ? <Button icon="user" onClick={() => setClientModal(true)} tone="primary" disabled={!inbounds.length}>Профиль</Button> : null}
        </div>
      </header>
      <div className="vless-summary-strip">
        <span><small>Inbounds</small><strong>{inbounds.length}</strong></span>
        <span><small>Профили</small><strong>{number(data.client_count) || clients.length}</strong></span>
        <span><small>Онлайн</small><strong>{number(data.online_count) || online.size}</strong></span>
        <span><small>Принято</small><strong>{bytes(data.traffic?.up)}</strong></span>
        <span><small>Передано</small><strong>{bytes(data.traffic?.down)}</strong></span>
        <span><small>Панель</small><strong>{text(data.connectivity?.panel, "unknown")}</strong></span>
        <span><small>Baseline</small><strong>{number(data.protection?.baseline_count)}</strong></span>
      </div>
      <Tabs
        label="3x-ui"
        value={tab}
        onChange={setTab}
        items={[
          { id: "clients", label: "Профили", count: clients.length },
          { id: "inbounds", label: "Inbounds", count: inbounds.length },
        ]}
      />
      {tab === "clients" ? (
        clients.length ? (
          <div className="native-grid"><table><thead><tr><th>Профиль</th><th>Inbound</th><th>Состояние</th><th>Лимит IP</th><th>Трафик</th><th>Срок</th></tr></thead><tbody>
            {clients.map((client) => <tr className="sentinel-clickable-row" key={`${client.inbound_id}:${client.client_ref}`} onClick={() => setSelectedClient(client)}>
              <td><strong>{client.email}</strong><small className="table-secondary">{client.client_ref}</small></td>
              <td>{client.inbound_remark}</td>
              <td><Badge tone={client.enable ? "healthy" : "neutral"}>{online.has(client.email) ? "online" : client.enable ? "active" : "disabled"}</Badge></td>
              <td>{number(client.limitIp) || "Без лимита"}</td>
              <td>{bytes(number(client.traffic?.up) + number(client.traffic?.down))}</td>
              <td>{expiry(client.expiryTime)}</td>
            </tr>)}
          </tbody></table></div>
        ) : <EmptyState title="Нет VLESS-профилей" />
      ) : (
        inbounds.length ? (
          <div className="native-grid"><table><thead><tr><th>Inbound</th><th>Порт</th><th>Протокол</th><th>Состояние</th><th>Клиенты</th><th>Трафик</th></tr></thead><tbody>
            {inbounds.map((inbound) => <tr className="sentinel-clickable-row" key={inbound.id} onClick={() => setSelectedInbound(inbound)}>
              <td><strong>{inbound.remark}</strong>{inbound.protected ? <Badge tone="healthy">защищенный production inbound</Badge> : null}<small className="table-secondary">ID {inbound.id}</small></td>
              <td>{inbound.port}</td><td>{inbound.protocol}</td>
              <td><StatusCell value={inbound.enable ? "active" : "disabled"} /></td>
              <td>{number(inbound.client_count) || inbound.clients?.length || 0}</td><td>{bytes(number(inbound.up) + number(inbound.down))}</td>
            </tr>)}
          </tbody></table></div>
        ) : <EmptyState title="Нет inbounds" />
      )}

      <Modal open={inboundModal} title="Новый VLESS inbound" onClose={() => setInboundModal(false)} footer={<><Button onClick={() => setInboundModal(false)}>Отмена</Button><Button form="xui-inbound-form" type="submit" tone="primary">Создать</Button></>}>
        <form id="xui-inbound-form" className="kuma-form-grid" onSubmit={(event) => { event.preventDefault(); const payload = inboundPayload(event.currentTarget); void mutate(() => api.createXuiInbound(payload), "Inbound создан").then(() => setInboundModal(false)); }}>
          <label><span>Название</span><input name="remark" required /></label>
          <label><span>Порт</span><input name="port" type="number" min="1" max="65535" required /></label>
          <label><span>Транспорт</span><select name="network"><option value="tcp">TCP</option><option value="ws">WebSocket</option><option value="grpc">gRPC</option></select></label>
          <label><span>Защита</span><select name="security"><option value="reality">Reality</option><option value="tls">TLS</option><option value="none">Без TLS</option></select></label>
          <label className="wide"><span>SNI / маскировочный домен</span><input name="server_name" defaultValue="www.microsoft.com" /></label>
        </form>
      </Modal>

      <Modal open={clientModal} title="Новый VLESS-профиль" onClose={() => setClientModal(false)} footer={<><Button onClick={() => setClientModal(false)}>Отмена</Button><Button form="xui-client-form" type="submit" tone="primary">Создать</Button></>}>
        <form id="xui-client-form" className="kuma-form-grid" onSubmit={(event) => { event.preventDefault(); const values = new FormData(event.currentTarget); const inboundId = number(values.get("inbound_id")); const payload = clientPayload(event.currentTarget); void mutate(() => api.createXuiClient(inboundId, payload), "VLESS-профиль создан").then(() => setClientModal(false)); }}>
          <label><span>Inbound</span><select name="inbound_id">{inbounds.map((item) => <option key={item.id} value={item.id}>{item.remark} · {item.port}</option>)}</select></label>
          <label><span>Имя / email</span><input name="email" required /></label>
          <label><span>Лимит IP</span><input name="limit_ip" type="number" min="0" defaultValue="0" /></label>
          <label><span>Лимит трафика, GB</span><input name="total_gb" type="number" min="0" defaultValue="0" /></label>
          <label><span>Срок, дней</span><input name="expiry_days" type="number" min="0" defaultValue="0" /></label>
          <label><span>Flow</span><select name="flow"><option value="xtls-rprx-vision">XTLS Vision</option><option value="">Без flow</option></select></label>
          <label><span>Telegram ID</span><input name="telegram_id" /></label>
          <label className="check-row"><input name="enable" type="checkbox" defaultChecked /><span>Активен</span></label>
        </form>
      </Modal>

      <Modal open={Boolean(selectedClient)} title={selectedClient?.email || "VLESS-профиль"} onClose={() => setSelectedClient(null)} footer={selectedClient ? <>
        {capabilities.has("traffic.reset") ? <Button onClick={() => void mutate(() => api.resetXuiClientTraffic(number(selectedClient.inbound_id), selectedClient.client_ref), "Счетчик трафика сброшен")}>Сбросить трафик</Button> : null}
        {capabilities.has("clients.profile") ? <Button onClick={() => void mutate(async () => { const result = await api.xuiClientProfile(number(selectedClient.inbound_id), selectedClient.client_ref); if (!result.profile) throw new Error(result.issue || "Ссылка профиля недоступна"); await navigator.clipboard.writeText(result.profile); }, "VLESS-ссылка скопирована")} icon="copy">Скопировать ссылку</Button> : null}
        {capabilities.has("clients.delete") ? <Button tone="danger" onClick={() => { if (window.confirm(`Удалить профиль ${selectedClient.email}?`)) void mutate(() => api.deleteXuiClient(number(selectedClient.inbound_id), selectedClient.client_ref), "VLESS-профиль удален"); }}>Удалить</Button> : null}
        {capabilities.has("clients.update") ? <Button form="xui-client-edit-form" type="submit" tone="primary">Сохранить</Button> : null}
      </> : undefined}>
        {selectedClient ? <form id="xui-client-edit-form" className="kuma-form-grid" onSubmit={(event) => { event.preventDefault(); const payload = clientPayload(event.currentTarget, selectedClient); void mutate(() => api.updateXuiClient(number(selectedClient.inbound_id), selectedClient.client_ref, payload), "VLESS-профиль обновлен"); }}>
          <label><span>Reference</span><input value={selectedClient.client_ref} disabled /></label>
          <label><span>Inbound</span><input value={selectedClient.inbound_remark} disabled /></label>
          <label><span>Имя / email</span><input name="email" defaultValue={selectedClient.email} required /></label>
          <label><span>Лимит IP</span><input name="limit_ip" type="number" min="0" defaultValue={number(selectedClient.limitIp)} /></label>
          <label><span>Лимит трафика, GB</span><input name="total_gb" type="number" min="0" defaultValue={number(selectedClient.totalGB) / 1024 ** 3} /></label>
          <label><span>Продлить на дней</span><input name="expiry_days" type="number" min="0" placeholder="Без изменения" /></label>
          <label><span>Flow</span><select name="flow" defaultValue={text(selectedClient.flow, "xtls-rprx-vision")}><option value="xtls-rprx-vision">XTLS Vision</option><option value="">Без flow</option></select></label>
          <label><span>Telegram ID</span><input name="telegram_id" defaultValue={text(selectedClient.tgId)} /></label>
          <label className="check-row"><input name="enable" type="checkbox" defaultChecked={selectedClient.enable} /><span>Активен</span></label>
          <div className="wide"><small>Текущий срок: {expiry(selectedClient.expiryTime)}</small></div>
        </form> : null}
      </Modal>

      <Modal open={Boolean(selectedInbound)} title={selectedInbound?.remark || "Inbound"} onClose={() => setSelectedInbound(null)} footer={selectedInbound ? <>
        {selectedInbound.managed_by_sentinel && capabilities.has("inbounds.update") ? <Button onClick={() => void mutate(() => api.updateXuiInbound(selectedInbound.id, { enable: !selectedInbound.enable }), selectedInbound.enable ? "Inbound отключен" : "Inbound включен")}>{selectedInbound.enable ? "Отключить" : "Включить"}</Button> : null}
        {selectedInbound.managed_by_sentinel && capabilities.has("traffic.reset") ? <Button onClick={() => void mutate(() => api.resetXuiInboundTraffic(selectedInbound.id), "Трафик inbound сброшен")}>Сбросить трафик</Button> : null}
        {selectedInbound.managed_by_sentinel && capabilities.has("inbounds.delete") ? <Button tone="danger" onClick={() => { if (window.confirm(`Удалить inbound ${selectedInbound.remark}?`)) void mutate(() => api.deleteXuiInbound(selectedInbound.id), "Inbound удален"); }}>Удалить</Button> : null}
      </> : undefined}>
        {selectedInbound ? <><dl className="kuma-kv"><div><dt>ID</dt><dd>{selectedInbound.id}</dd></div><div><dt>Порт</dt><dd>{selectedInbound.port}</dd></div><div><dt>Протокол</dt><dd>{selectedInbound.protocol}</dd></div><div><dt>Клиенты</dt><dd>{number(selectedInbound.client_count) || selectedInbound.clients?.length || 0}</dd></div></dl>{selectedInbound.protected ? <Badge tone="healthy">неизменяемый production baseline</Badge> : selectedInbound.managed_by_sentinel ? <Badge tone="info">управляется Sentinel</Badge> : <Badge tone="warning">внешний inbound, только чтение</Badge>}</> : null}
      </Modal>
    </section>
  );
}
