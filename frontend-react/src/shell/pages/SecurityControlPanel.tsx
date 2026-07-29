import { useCallback, useMemo, useState } from "react";

import { api } from "../api";
import { t, useShellContext } from "../context";
import { usePolledData } from "../hooks";
import type {
  FirewallRuleRecord,
  IdsRulesetRecord,
  SecurityServiceControlResponse,
} from "../types";
import { PanelHeader, StatusBadge } from "../ui";


type FirewallDraft = {
  uuid: string;
  description: string;
  interface: string;
  action: string;
  protocol: string;
  source: string;
  destination: string;
  destination_port: string;
  sequence: number;
  enabled: boolean;
  log: boolean;
};

const EMPTY_FIREWALL_DRAFT: FirewallDraft = {
  uuid: "",
  description: "",
  interface: "opt5",
  action: "block",
  protocol: "any",
  source: "any",
  destination: "any",
  destination_port: "",
  sequence: 100,
  enabled: false,
  log: true,
};

function FirewallControl({
  data,
  refresh,
}: {
  data: SecurityServiceControlResponse;
  refresh: () => void;
}) {
  const { lang } = useShellContext();
  const [draft, setDraft] = useState<FirewallDraft>(EMPTY_FIREWALL_DRAFT);
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState("");
  const [policyView, setPolicyView] = useState<"managed" | "native">("managed");
  const [query, setQuery] = useState("");
  const [editorOpen, setEditorOpen] = useState(false);
  const rules = useMemo(() => data.firewall?.rules || [], [data.firewall?.rules]);
  const visibleRules = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return rules
      .filter((rule) => (policyView === "managed" ? rule.managed : !rule.managed))
      .filter((rule) => !needle || [
        rule.description,
        rule.interface,
        rule.action,
        rule.protocol,
        rule.source,
        rule.destination,
        rule.destination_port,
      ].some((value) => String(value || "").toLowerCase().includes(needle)));
  }, [policyView, query, rules]);

  const runMutation = async (operation: string, body: Record<string, unknown>, label: string) => {
    setBusy(label);
    setResult("");
    try {
      const response = await api.mutateFirewall(operation, body);
      setResult(
        t(lang, {
          en: `${label}: ${String(response.status || "completed")}`,
          ru: `${label}: ${String(response.status || "выполнено")}`,
        }),
      );
      refresh();
      if (operation === "create" || operation === "update") {
        setDraft(EMPTY_FIREWALL_DRAFT);
        setEditorOpen(false);
      }
    } catch (error) {
      setResult(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy("");
    }
  };

  const editRule = (rule: FirewallRuleRecord) => {
    setDraft({
      uuid: rule.uuid,
      description: rule.description,
      interface: rule.interface || "opt5",
      action: String(rule.action || "block").toLowerCase(),
      protocol: rule.protocol || "any",
      source: rule.source || "any",
      destination: rule.destination || "any",
      destination_port: rule.destination_port || "",
      sequence: Number(rule.sort_order || 100),
      enabled: rule.enabled,
      log: Boolean(rule.log),
    });
    setEditorOpen(true);
  };

  const saveRule = () => {
    const operation = draft.uuid ? "update" : "create";
    if (!window.confirm(t(lang, {
      en: `${draft.uuid ? "Apply changes to" : "Create"} firewall rule "${draft.description}" on OPNsense?`,
      ru: `${draft.uuid ? "Применить изменения правила" : "Создать правило"} "${draft.description}" в OPNsense?`,
    }))) return;
    void runMutation(operation, draft, draft.uuid ? "Update rule" : "Create rule");
  };

  const deleteRule = (rule: FirewallRuleRecord) => {
    const confirmation = window.prompt(
      t(lang, {
        en: `Type the rule description to delete it:\n${rule.description}`,
        ru: `Введите описание правила для удаления:\n${rule.description}`,
      }),
    );
    if (confirmation !== rule.description) return;
    void runMutation(
      "delete",
      { uuid: rule.uuid, confirm: confirmation },
      "Delete rule",
    );
  };

  return (
    <>
      <section className="react-card">
        <PanelHeader
          title={t(lang, { en: "Firewall policy", ru: "Политика межсетевого экрана" })}
          subtitle={t(lang, {
            en: `${data.firewall?.managed_rules || 0} SIEM-managed rules out of ${data.firewall?.rules_total || 0}`,
            ru: `${data.firewall?.managed_rules || 0} управляемых SIEM правил из ${data.firewall?.rules_total || 0}`,
          })}
          icon="control"
          actions={
            <div className="react-actions">
              <button
                className="react-primary-button"
                type="button"
                onClick={() => {
                  setDraft(EMPTY_FIREWALL_DRAFT);
                  setEditorOpen(true);
                }}
              >
                {t(lang, { en: "New managed rule", ru: "Новое управляемое правило" })}
              </button>
              <a className="react-link-button" href={data.device_url} target="_blank" rel="noreferrer">
                OPNsense
              </a>
            </div>
          }
        />
        <div className="react-actions react-wrap react-security-control-toolbar">
          <div className="react-segmented react-segmented-compact">
            <button type="button" className={policyView === "managed" ? "active" : ""} onClick={() => setPolicyView("managed")}>
              {t(lang, { en: `SIEM managed (${data.firewall?.managed_rules || 0})`, ru: `Управляются SIEM (${data.firewall?.managed_rules || 0})` })}
            </button>
            <button type="button" className={policyView === "native" ? "active" : ""} onClick={() => setPolicyView("native")}>
              {t(lang, {
                en: `Native read-only (${Math.max(0, Number(data.firewall?.rules_total || 0) - Number(data.firewall?.managed_rules || 0))})`,
                ru: `Системные, только чтение (${Math.max(0, Number(data.firewall?.rules_total || 0) - Number(data.firewall?.managed_rules || 0))})`,
              })}
            </button>
          </div>
          <input
            className="react-input react-input-grow"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t(lang, { en: "Search policy, address, port...", ru: "Поиск правила, адреса, порта..." })}
          />
        </div>
        <div className="react-table-wrap">
          <table className="react-table">
            <thead>
              <tr>
                <th>{t(lang, { en: "State", ru: "Состояние" })}</th>
                <th>{t(lang, { en: "Rule", ru: "Правило" })}</th>
                <th>{t(lang, { en: "Interface", ru: "Интерфейс" })}</th>
                <th>{t(lang, { en: "Policy", ru: "Политика" })}</th>
                <th>{t(lang, { en: "Source", ru: "Источник" })}</th>
                <th>{t(lang, { en: "Destination", ru: "Назначение" })}</th>
                <th>{t(lang, { en: "Actions", ru: "Действия" })}</th>
              </tr>
            </thead>
            <tbody>
              {visibleRules.map((rule) => {
                const mutable = rule.managed && !rule.legacy && !rule.automatic;
                return (
                <tr key={rule.uuid}>
                  <td><StatusBadge value={rule.enabled ? "enabled" : "disabled"} /></td>
                  <td>
                    <strong>{rule.description}</strong>
                    {!mutable ? (
                      <div className="react-muted">
                        {t(lang, { en: "Owned by native OPNsense policy", ru: "Управляется штатной политикой OPNsense" })}
                      </div>
                    ) : null}
                  </td>
                  <td>{rule.interface || "n/a"}</td>
                  <td>{rule.action || "n/a"} / {rule.protocol || "any"}</td>
                  <td>{rule.source || "any"}</td>
                  <td>{rule.destination || "any"}{rule.destination_port ? `:${rule.destination_port}` : ""}</td>
                  <td>
                    {mutable ? <div className="react-actions">
                      <button
                        className="react-link-button"
                        type="button"
                        disabled={Boolean(busy)}
                        onClick={() => void runMutation(
                          "toggle",
                          { uuid: rule.uuid, enabled: !rule.enabled },
                          rule.enabled ? "Disable rule" : "Enable rule",
                        )}
                      >
                        {rule.enabled
                          ? t(lang, { en: "Disable", ru: "Выключить" })
                          : t(lang, { en: "Enable", ru: "Включить" })}
                      </button>
                      <button
                        className="react-link-button"
                        type="button"
                        disabled={Boolean(busy)}
                        onClick={() => editRule(rule)}
                      >
                        {t(lang, { en: "Edit", ru: "Изменить" })}
                      </button>
                      <button
                        className="react-link-button"
                        type="button"
                        disabled={Boolean(busy)}
                        onClick={() => deleteRule(rule)}
                      >
                        {t(lang, { en: "Delete", ru: "Удалить" })}
                      </button>
                    </div> : (
                      <span className="react-muted">{t(lang, { en: "View in OPNsense", ru: "Просмотр в OPNsense" })}</span>
                    )}
                  </td>
                </tr>
              )})}
              {!visibleRules.length ? (
                <tr><td colSpan={7}>{t(lang, { en: "No policy rows match the current filter.", ru: "Нет правил, соответствующих фильтру." })}</td></tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>

      {editorOpen ? <section className="react-card">
        <PanelHeader
          title={draft.uuid
            ? t(lang, { en: "Edit managed rule", ru: "Изменить управляемое правило" })
            : t(lang, { en: "New managed rule", ru: "Новое управляемое правило" })}
          subtitle={t(lang, {
            en: "Every change is verified on-device. OPNsense automatically rolls it back unless SIEM confirms the verified policy.",
            ru: "Каждое изменение проверяется на устройстве. OPNsense автоматически откатит его, пока SIEM не подтвердит проверенную политику.",
          })}
          icon="rules"
        />
        <div className="react-form-grid">
          <label className="react-field react-input-full">
            <span>{t(lang, { en: "Description", ru: "Описание" })}</span>
            <input
              className="react-input"
              value={draft.description}
              onChange={(event) => setDraft((current) => ({ ...current, description: event.target.value }))}
              placeholder="SIEM block untrusted traffic"
            />
          </label>
          <label className="react-field">
            <span>{t(lang, { en: "Interface", ru: "Интерфейс" })}</span>
            <select className="react-select" value={draft.interface} onChange={(event) => setDraft((current) => ({ ...current, interface: event.target.value }))}>
              <option value="opt1">WAN</option>
              <option value="opt2">SEC</option>
              <option value="opt3">SERVERS/GAMES</option>
              <option value="opt4">LAB</option>
              <option value="opt5">USERS</option>
              <option value="lan">LAN</option>
            </select>
          </label>
          <label className="react-field">
            <span>{t(lang, { en: "Action", ru: "Действие" })}</span>
            <select className="react-select" value={draft.action} onChange={(event) => setDraft((current) => ({ ...current, action: event.target.value }))}>
              <option value="block">Block</option>
              <option value="reject">Reject</option>
              <option value="pass">Pass</option>
            </select>
          </label>
          <label className="react-field">
            <span>{t(lang, { en: "Protocol", ru: "Протокол" })}</span>
            <select className="react-select" value={draft.protocol} onChange={(event) => setDraft((current) => ({ ...current, protocol: event.target.value }))}>
              {["any", "TCP", "UDP", "TCP/UDP", "ICMP"].map((value) => <option key={value}>{value}</option>)}
            </select>
          </label>
          <label className="react-field">
            <span>{t(lang, { en: "Order", ru: "Порядок" })}</span>
            <input className="react-input" type="number" min={1} max={999999} value={draft.sequence} onChange={(event) => setDraft((current) => ({ ...current, sequence: Number(event.target.value || 100) }))} />
          </label>
          <label className="react-field">
            <span>{t(lang, { en: "Source", ru: "Источник" })}</span>
            <input className="react-input" value={draft.source} onChange={(event) => setDraft((current) => ({ ...current, source: event.target.value }))} />
          </label>
          <label className="react-field">
            <span>{t(lang, { en: "Destination", ru: "Назначение" })}</span>
            <input className="react-input" value={draft.destination} onChange={(event) => setDraft((current) => ({ ...current, destination: event.target.value }))} />
          </label>
          <label className="react-field">
            <span>{t(lang, { en: "Destination port", ru: "Порт назначения" })}</span>
            <input className="react-input" value={draft.destination_port} onChange={(event) => setDraft((current) => ({ ...current, destination_port: event.target.value }))} />
          </label>
          <label className="react-field">
            <span>{t(lang, { en: "Initial state", ru: "Начальное состояние" })}</span>
            <select className="react-select" value={draft.enabled ? "enabled" : "disabled"} onChange={(event) => setDraft((current) => ({ ...current, enabled: event.target.value === "enabled" }))}>
              <option value="disabled">{t(lang, { en: "Disabled", ru: "Выключено" })}</option>
              <option value="enabled">{t(lang, { en: "Enabled", ru: "Включено" })}</option>
            </select>
          </label>
        </div>
        <div className="react-actions" style={{ marginTop: 16 }}>
          <button className="react-primary-button" type="button" disabled={Boolean(busy) || draft.description.trim().length < 4} onClick={saveRule}>
            {busy || (draft.uuid
              ? t(lang, { en: "Save rule", ru: "Сохранить правило" })
              : t(lang, { en: "Create rule", ru: "Создать правило" }))}
          </button>
          <button className="react-link-button" type="button" disabled={Boolean(busy)} onClick={() => {
            setDraft(EMPTY_FIREWALL_DRAFT);
            setEditorOpen(false);
          }}>
            {t(lang, { en: "Cancel", ru: "Отмена" })}
          </button>
          {result ? <span className="react-muted">{result}</span> : null}
        </div>
      </section> : result ? <div className="react-callout">{result}</div> : null}
    </>
  );
}

function IdsControl({
  data,
  refresh,
}: {
  data: SecurityServiceControlResponse;
  refresh: () => void;
}) {
  const { lang, formatTimestamp } = useShellContext();
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState("");
  const [rulesetView, setRulesetView] = useState<"enabled" | "disabled" | "all">("enabled");
  const [query, setQuery] = useState("");
  const rulesets = useMemo(() => data.ids?.rulesets || [], [data.ids?.rulesets]);
  const alerts = data.ids?.alerts || [];
  const visibleRulesets = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return rulesets
      .filter((ruleset) => rulesetView === "all" || ruleset.enabled === (rulesetView === "enabled"))
      .filter((ruleset) => !needle || `${ruleset.filename} ${ruleset.description}`.toLowerCase().includes(needle))
      .slice(0, 30);
  }, [query, rulesetView, rulesets]);

  const run = async (operation: string, body: Record<string, unknown>, label: string) => {
    setBusy(label);
    setResult("");
    try {
      const response = await api.mutateIds(operation, body);
      setResult(`${label}: ${String(response.status || "completed")}`);
      refresh();
    } catch (error) {
      setResult(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy("");
    }
  };

  const toggleRuleset = (ruleset: IdsRulesetRecord) => {
    const enabled = !ruleset.enabled;
    if (!window.confirm(t(lang, {
      en: `${enabled ? "Enable" : "Disable"} Suricata ruleset "${ruleset.filename}" and reload the active IPS policy?`,
      ru: `${enabled ? "Включить" : "Выключить"} набор "${ruleset.filename}" и перезагрузить действующую политику IPS?`,
    }))) return;
    void run(
      "toggle_ruleset",
      { filename: ruleset.filename, enabled },
      enabled ? "Enable ruleset" : "Disable ruleset",
    );
  };

  return (
    <>
      <section className="react-card">
        <PanelHeader
          title={t(lang, { en: "Suricata rule management", ru: "Управление правилами Suricata" })}
          subtitle={`${data.ids?.rulesets_total || 0} rulesets | ${data.ids?.alerts_total || 0} device alerts`}
          icon="rules"
          actions={
            <div className="react-actions">
              <button className="react-link-button" type="button" disabled={Boolean(busy)} onClick={() => void run("reload", {}, "Reload rules")}>
                {t(lang, { en: "Reload", ru: "Перезагрузить" })}
              </button>
              <button className="react-primary-button" type="button" disabled={Boolean(busy)} onClick={() => {
                if (window.confirm(t(lang, {
                  en: "Download signature updates and reload the active IPS policy?",
                  ru: "Скачать обновления сигнатур и перезагрузить действующую политику IPS?",
                }))) void run("update", {}, "Update signatures");
              }}>
                {t(lang, { en: "Update signatures", ru: "Обновить сигнатуры" })}
              </button>
            </div>
          }
        />
        {result ? <div className="react-callout">{result}</div> : null}
        <div className="react-actions react-wrap react-security-control-toolbar">
          <div className="react-segmented react-segmented-compact">
            <button type="button" className={rulesetView === "enabled" ? "active" : ""} onClick={() => setRulesetView("enabled")}>
              {t(lang, { en: "Enabled", ru: "Включенные" })}
            </button>
            <button type="button" className={rulesetView === "disabled" ? "active" : ""} onClick={() => setRulesetView("disabled")}>
              {t(lang, { en: "Disabled", ru: "Выключенные" })}
            </button>
            <button type="button" className={rulesetView === "all" ? "active" : ""} onClick={() => setRulesetView("all")}>
              {t(lang, { en: "All", ru: "Все" })}
            </button>
          </div>
          <input
            className="react-input react-input-grow"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t(lang, { en: "Search ruleset...", ru: "Поиск набора правил..." })}
          />
          <span className="react-muted">
            {t(lang, {
              en: `Showing ${visibleRulesets.length} of ${rulesets.length}`,
              ru: `Показано ${visibleRulesets.length} из ${rulesets.length}`,
            })}
          </span>
        </div>
        <div className="react-table-wrap">
          <table className="react-table">
            <thead><tr><th>{t(lang, { en: "State", ru: "Состояние" })}</th><th>Ruleset</th><th>{t(lang, { en: "Description", ru: "Описание" })}</th><th>{t(lang, { en: "Action", ru: "Действие" })}</th></tr></thead>
            <tbody>
              {visibleRulesets.map((ruleset: IdsRulesetRecord) => (
                <tr key={ruleset.filename}>
                  <td><StatusBadge value={ruleset.enabled ? "enabled" : "disabled"} /></td>
                  <td>{ruleset.filename}</td>
                  <td>{ruleset.description || "n/a"}</td>
                  <td>
                    <button
                      className="react-link-button"
                      type="button"
                      disabled={Boolean(busy)}
                      onClick={() => toggleRuleset(ruleset)}
                    >
                      {ruleset.enabled
                        ? t(lang, { en: "Disable", ru: "Выключить" })
                        : t(lang, { en: "Enable", ru: "Включить" })}
                    </button>
                  </td>
                </tr>
              ))}
              {!visibleRulesets.length ? (
                <tr><td colSpan={4}>{t(lang, { en: "No rulesets match the current filter.", ru: "Нет наборов, соответствующих фильтру." })}</td></tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className="react-card">
        <PanelHeader
          title={t(lang, { en: "Device alerts", ru: "Сработки устройства" })}
          subtitle={t(lang, { en: "Live OPNsense IDS alert log.", ru: "Живой журнал IDS на OPNsense." })}
          icon="incidents"
        />
        <div className="react-table-wrap">
          <table className="react-table">
            <thead><tr><th>{t(lang, { en: "Time", ru: "Время" })}</th><th>SID</th><th>{t(lang, { en: "Action", ru: "Действие" })}</th><th>{t(lang, { en: "Source", ru: "Источник" })}</th><th>{t(lang, { en: "Destination", ru: "Назначение" })}</th><th>{t(lang, { en: "Alert", ru: "Сработка" })}</th></tr></thead>
            <tbody>
              {alerts.map((alert, index) => (
                <tr key={`${String(alert.flow_id || "")}-${String(alert.filepos || index)}`}>
                  <td>{formatTimestamp(alert.timestamp, "compact")}</td>
                  <td>{String(alert.alert_sid || "n/a")}</td>
                  <td>{String(alert.alert_action || "n/a")}</td>
                  <td>{String(alert.src_ip || "n/a")}:{String(alert.src_port || "")}</td>
                  <td>{String(alert.dest_ip || "n/a")}:{String(alert.dest_port || "")}</td>
                  <td>{String(alert.alert || "n/a")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

export function SecurityControlPanel({ serviceId }: { serviceId: string }) {
  const { lang } = useShellContext();
  const [refreshToken, setRefreshToken] = useState(0);
  const load = useCallback(
    () => {
      void refreshToken;
      return api.securityServiceControl(serviceId);
    },
    [serviceId, refreshToken],
  );
  const state = usePolledData<SecurityServiceControlResponse>(load, 20_000);
  const data = state.data;
  const refresh = () => setRefreshToken((value) => value + 1);
  const status = useMemo(() => {
    if (state.loading && !data) return "loading";
    if (state.error || !data?.available) return "degraded";
    return serviceId === "ips" ? String(data.ids?.status || "unknown") : "connected";
  }, [data, serviceId, state.error, state.loading]);

  if (!data && state.loading) {
    return <section className="react-card"><div className="react-empty">{t(lang, { en: "Loading device state...", ru: "Загрузка состояния устройства..." })}</div></section>;
  }

  if (!data?.available) {
    return (
      <section className="react-card">
        <PanelHeader
          title={t(lang, { en: "Device control", ru: "Управление устройством" })}
          subtitle={data?.error || state.error || t(lang, { en: "Device API is unavailable.", ru: "API устройства недоступен." })}
          icon="control"
          actions={<StatusBadge value={status} />}
        />
      </section>
    );
  }

  return (
    <>
      <section className="react-card">
        <PanelHeader
          title={t(lang, { en: "Device API", ru: "API устройства" })}
          subtitle={`${data.device_url || ""} | ${data.auth_mode || "unknown"}`}
          icon="control"
          actions={<StatusBadge value={status} />}
        />
        {!data.verify_tls ? (
          <div className="react-callout">
            {t(lang, {
              en: "TLS certificate verification is disabled for this internal OPNsense connection.",
              ru: "Проверка TLS-сертификата для внутреннего подключения к OPNsense отключена.",
            })}
          </div>
        ) : null}
      </section>
      {serviceId === "ngfw" ? <FirewallControl data={data} refresh={refresh} /> : <IdsControl data={data} refresh={refresh} />}
    </>
  );
}
