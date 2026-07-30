import { useCallback, useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { t, useShellContext } from "../context";
import { useFeedback } from "../feedback";
import { useAsyncData, useDebouncedValue } from "../hooks";
import { NativeActionBar, NativePageHeader, NativePager } from "../native";
import { DrawerFieldGrid, DrawerOverlay, EmptyState, JsonPreview, KeyValue, SeverityBadge, StatusBadge } from "../ui";
import type {
  BuilderValidationResponse,
  CorrelationBatchRuleRecord,
  CorrelationPackRecord,
  CorrelationPacksResponse,
  CorrelationPackTestResponse,
  CorrelationRuleRecord,
  RuntimeBlob,
} from "../types";

type RuleRow = {
  pack: CorrelationPackRecord;
  engine: "stream" | "batch";
  rule: CorrelationRuleRecord | CorrelationBatchRuleRecord;
};

const RULE_PAGE_SIZE = 25;

export function RulesPage() {
  const { lang, formatTimestamp } = useShellContext();
  const { pushToast } = useFeedback();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [tab, setTab] = useState<"rules" | "packs">("rules");
  const [rulePage, setRulePage] = useState(1);
  const [selectedPackId, setSelectedPackId] = useState("");
  const [selectedRuleKey, setSelectedRuleKey] = useState("");
  const [refreshToken, setRefreshToken] = useState(0);
  const [operation, setOperation] = useState<"validate" | "test" | "publish" | null>(null);
  const [operationOutput, setOperationOutput] = useState<RuntimeBlob | null>(null);
  const debouncedQuery = useDebouncedValue(query, 250);
  const loadPacks = useCallback(() => {
    void refreshToken;
    return api.correlationPacks();
  }, [refreshToken]);
  const state = useAsyncData<CorrelationPacksResponse>(loadPacks);
  const packs = useMemo(() => state.data?.items || [], [state.data?.items]);
  const allRules = useMemo<RuleRow[]>(
    () => packs.flatMap((pack) => [
      ...(pack.stream_rules || []).map((rule) => ({ pack, engine: "stream" as const, rule })),
      ...(pack.batch_rules || []).map((rule) => ({ pack, engine: "batch" as const, rule })),
    ]),
    [packs],
  );
  const filteredPacks = useMemo(() => {
    const token = debouncedQuery.trim().toLowerCase();
    return packs.filter((pack) => {
      if (status !== "all" && String(pack.status || "").toLowerCase() !== status) return false;
      return !token || JSON.stringify(pack).toLowerCase().includes(token);
    });
  }, [debouncedQuery, packs, status]);
  const filteredRules = useMemo(() => {
    const token = debouncedQuery.trim().toLowerCase();
    return allRules.filter((row) => {
      if (status !== "all" && String(row.rule.status || "").toLowerCase() !== status) return false;
      return !token || JSON.stringify(row).toLowerCase().includes(token);
    });
  }, [allRules, debouncedQuery, status]);
  const rulePageCount = Math.max(1, Math.ceil(filteredRules.length / RULE_PAGE_SIZE));
  const visibleRules = useMemo(() => {
    const start = (rulePage - 1) * RULE_PAGE_SIZE;
    return filteredRules.slice(start, start + RULE_PAGE_SIZE);
  }, [filteredRules, rulePage]);

  useEffect(() => {
    setRulePage(1);
  }, [debouncedQuery, status]);

  useEffect(() => {
    if (rulePage > rulePageCount) setRulePage(rulePageCount);
  }, [rulePage, rulePageCount]);
  const selectedPack = packs.find((pack) => pack.pack_id === selectedPackId) || null;
  const selectedRule = allRules.find((row) => `${row.pack.pack_id}:${row.engine}:${row.rule.id}` === selectedRuleKey) || null;

  async function runPackOperation(kind: "validate" | "test" | "publish", pack: CorrelationPackRecord) {
    if (operation) return;
    setSelectedPackId(pack.pack_id);
    setOperation(kind);
    setOperationOutput(null);
    try {
      let result: BuilderValidationResponse | CorrelationPackTestResponse | RuntimeBlob;
      if (kind === "validate") result = await api.validateCorrelationPack(pack.pack_id, pack as unknown as Record<string, unknown>);
      else if (kind === "test") result = await api.testCorrelationPack(pack.pack_id, pack as unknown as Record<string, unknown>);
      else result = await api.publishCorrelationPack(pack.pack_id);
      setOperationOutput(result as RuntimeBlob);
      setRefreshToken((value) => value + 1);
      pushToast({
        title: kind === "publish" ? t(lang, { en: "Pack published", ru: "Пакет опубликован" }) : t(lang, { en: "Operation completed", ru: "Операция завершена" }),
        message: pack.title || pack.pack_id,
        tone: "success",
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      setOperationOutput({ error: message });
      pushToast({ title: t(lang, { en: "Rule operation failed", ru: "Операция с правилами не выполнена" }), message, tone: "error" });
    } finally {
      setOperation(null);
    }
  }

  return (
    <div className="react-page native-page">
      <NativePageHeader
        title={t(lang, { en: "Detection content", ru: "Контент детектирования" })}
        icon="builders"
        actions={(
          <>
            <button type="button" className="react-link-button" onClick={() => setRefreshToken((value) => value + 1)}>{t(lang, { en: "Refresh", ru: "Обновить" })}</button>
            <Link className="react-primary-button" to="/builders">{t(lang, { en: "Open builder", ru: "Открыть конструктор" })}</Link>
          </>
        )}
      />
      <div className="native-list-search">
        <label className="native-search-field">
          <Search size={16} aria-hidden="true" />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t(lang, { en: "Search rules, packs, owners and identifiers", ru: "Поиск по правилам, пакетам, владельцам и идентификаторам" })} />
        </label>
        <select value={status} onChange={(event) => setStatus(event.target.value)}>
          <option value="all">{t(lang, { en: "All states", ru: "Все состояния" })}</option>
          <option value="active">active</option>
          <option value="draft">draft</option>
          <option value="maintenance">maintenance</option>
          <option value="disabled">disabled</option>
        </select>
        <button type="button" className="react-link-button" onClick={() => { setQuery(""); setStatus("all"); }}>{t(lang, { en: "Clear", ru: "Очистить" })}</button>
      </div>
      <div className="native-workspace-tabs">
        <div>
          <button type="button" className={tab === "rules" ? "active" : ""} onClick={() => setTab("rules")}>{t(lang, { en: "Rules", ru: "Правила" })}</button>
          <button type="button" className={tab === "packs" ? "active" : ""} onClick={() => setTab("packs")}>{t(lang, { en: "Packs", ru: "Пакеты" })}</button>
        </div>
        <span>{t(lang, { en: "Runtime rules", ru: "Runtime-правила" })}: <strong>{allRules.length}</strong></span>
      </div>
      <NativeActionBar
        primary={<Link className="react-link-button" to="/resources">{t(lang, { en: "Resource catalog", ru: "Каталог ресурсов" })}</Link>}
        meta={(
          <>
            <span>{t(lang, { en: "Packs", ru: "Пакеты" })}: <strong>{packs.length}</strong></span>
            <span>{t(lang, { en: "Active", ru: "Активно" })}: <strong>{allRules.filter((row) => row.rule.status === "active").length}</strong></span>
            <span>Stream: <strong>{allRules.filter((row) => row.engine === "stream").length}</strong></span>
            <span>Batch: <strong>{allRules.filter((row) => row.engine === "batch").length}</strong></span>
          </>
        )}
      />

      {state.loading ? <EmptyState message={t(lang, { en: "Loading rules...", ru: "Загрузка правил..." })} /> : null}
      {state.error ? <EmptyState message={state.error} /> : null}
      {!state.loading && !state.error && tab === "rules" ? (
        <>
          <section className="native-grid native-rules-grid">
            <div className="react-table-wrap">
              <table className="react-table">
                <thead><tr><th>ID</th><th>{t(lang, { en: "Name", ru: "Название" })}</th><th>{t(lang, { en: "Severity", ru: "Важность" })}</th><th>{t(lang, { en: "Engine", ru: "Движок" })}</th><th>{t(lang, { en: "Pack", ru: "Пакет" })}</th><th>{t(lang, { en: "Window", ru: "Окно" })}</th><th>{t(lang, { en: "Threshold", ru: "Порог" })}</th><th>{t(lang, { en: "State", ru: "Состояние" })}</th></tr></thead>
                <tbody>
                  {visibleRules.map((row) => {
                    const key = `${row.pack.pack_id}:${row.engine}:${row.rule.id}`;
                    const streamRule = row.rule as CorrelationRuleRecord;
                    return (
                      <tr key={key} className={selectedRuleKey === key ? "selected" : ""} onClick={() => setSelectedRuleKey(key)}>
                        <td><code>{row.rule.id}</code></td>
                        <td><button type="button" className="native-primary-cell" onClick={() => setSelectedRuleKey(key)}><strong>{row.rule.title}</strong><small>{streamRule.suppression_key || row.pack.owner || row.pack.pack_id}</small></button></td>
                        <td><SeverityBadge value={row.rule.severity || "info"} /></td>
                        <td>{row.engine}</td>
                        <td><span className="native-secondary-cell"><strong>{row.pack.title || row.pack.pack_id}</strong><small>{row.pack.pack_id}</small></span></td>
                        <td>{streamRule.window_s ? `${streamRule.window_s}s` : "n/a"}</td>
                        <td>{streamRule.threshold || "n/a"}</td>
                        <td><StatusBadge value={row.rule.status || "draft"} /></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
          <div className="react-resource-pagination native-rule-pagination">
            <NativePager shown={visibleRules.length} total={filteredRules.length} lang={lang} />
            <div className="react-actions">
              <button type="button" className="react-inline-action" disabled={rulePage <= 1} onClick={() => setRulePage((value) => Math.max(1, value - 1))}>
                {t(lang, { en: "Previous", ru: "Назад" })}
              </button>
              <strong>{rulePage} / {rulePageCount}</strong>
              <button type="button" className="react-inline-action" disabled={rulePage >= rulePageCount} onClick={() => setRulePage((value) => Math.min(rulePageCount, value + 1))}>
                {t(lang, { en: "Next", ru: "Далее" })}
              </button>
            </div>
          </div>
        </>
      ) : null}
      {!state.loading && !state.error && tab === "packs" ? (
        <>
          <section className="native-grid native-packs-grid">
            <div className="react-table-wrap">
              <table className="react-table">
                <thead><tr><th>{t(lang, { en: "Pack", ru: "Пакет" })}</th><th>{t(lang, { en: "Version", ru: "Версия" })}</th><th>{t(lang, { en: "Owner", ru: "Владелец" })}</th><th>{t(lang, { en: "Rules", ru: "Правила" })}</th><th>{t(lang, { en: "Active", ru: "Активно" })}</th><th>{t(lang, { en: "State", ru: "Состояние" })}</th><th>{t(lang, { en: "Updated", ru: "Обновлено" })}</th><th>{t(lang, { en: "Actions", ru: "Действия" })}</th></tr></thead>
                <tbody>
                  {filteredPacks.map((pack) => (
                    <tr key={pack.pack_id} className={selectedPackId === pack.pack_id ? "selected" : ""} onClick={() => setSelectedPackId(pack.pack_id)}>
                      <td><button type="button" className="native-primary-cell" onClick={() => setSelectedPackId(pack.pack_id)}><strong>{pack.title || pack.pack_id}</strong><small>{pack.pack_id}</small></button></td>
                      <td>{pack.version || "n/a"}</td>
                      <td>{pack.owner || "n/a"}</td>
                      <td>{pack.rule_count || (pack.stream_rules?.length || 0) + (pack.batch_rules?.length || 0)}</td>
                      <td>{pack.active_stream_rules || 0}</td>
                      <td><StatusBadge value={pack.status || "draft"} /></td>
                      <td>{formatTimestamp(pack.updated_ts, "compact")}</td>
                      <td><div className="native-row-actions"><button type="button" disabled={Boolean(operation)} onClick={(event) => { event.stopPropagation(); void runPackOperation("validate", pack); }}>{t(lang, { en: "Validate", ru: "Проверить" })}</button><button type="button" disabled={Boolean(operation)} onClick={(event) => { event.stopPropagation(); void runPackOperation("test", pack); }}>{t(lang, { en: "Test", ru: "Тест" })}</button><button type="button" disabled={Boolean(operation)} onClick={(event) => { event.stopPropagation(); void runPackOperation("publish", pack); }}>{t(lang, { en: "Publish", ru: "Публикация" })}</button></div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <NativePager shown={filteredPacks.length} total={packs.length} lang={lang} />
        </>
      ) : null}

      <DrawerOverlay
        open={Boolean(selectedRule)}
        title={selectedRule?.rule.title || t(lang, { en: "Rule details", ru: "Информация о правиле" })}
        subtitle={selectedRule ? `${selectedRule.engine} / ${selectedRule.pack.pack_id} / ${selectedRule.rule.id}` : ""}
        onClose={() => setSelectedRuleKey("")}
        panelClassName="react-drawer-panel-wide"
      >
        {selectedRule ? (
          <>
            <div className="react-actions react-wrap">
              <Link className="react-primary-button" to={`/builders?pack=${encodeURIComponent(selectedRule.pack.pack_id)}&rule=${selectedRule.rule.id}`}>{t(lang, { en: "Edit in builder", ru: "Изменить в конструкторе" })}</Link>
              <button type="button" className="react-link-button" onClick={() => { setSelectedRuleKey(""); setTab("packs"); setSelectedPackId(selectedRule.pack.pack_id); }}>{t(lang, { en: "Open pack", ru: "Открыть пакет" })}</button>
            </div>
            <section className="react-card react-card-nested">
              <DrawerFieldGrid>
                <KeyValue label="Rule ID" value={selectedRule.rule.id} />
                <KeyValue label={t(lang, { en: "Severity", ru: "Важность" })} value={<SeverityBadge value={selectedRule.rule.severity || "info"} />} />
                <KeyValue label={t(lang, { en: "State", ru: "Состояние" })} value={<StatusBadge value={selectedRule.rule.status || "draft"} />} />
                <KeyValue label={t(lang, { en: "Engine", ru: "Движок" })} value={selectedRule.engine} />
                <KeyValue label={t(lang, { en: "Window", ru: "Окно" })} value={(selectedRule.rule as CorrelationRuleRecord).window_s || "n/a"} />
                <KeyValue label={t(lang, { en: "Threshold", ru: "Порог" })} value={(selectedRule.rule as CorrelationRuleRecord).threshold || "n/a"} />
                <KeyValue label={t(lang, { en: "Entity field", ru: "Поле сущности" })} value={(selectedRule.rule as CorrelationRuleRecord).entity_field || "n/a"} />
                <KeyValue label={t(lang, { en: "Suppression key", ru: "Ключ подавления" })} value={(selectedRule.rule as CorrelationRuleRecord).suppression_key || "n/a"} />
              </DrawerFieldGrid>
            </section>
            <details className="react-details" open>
              <summary>Sigma / JSON</summary>
              <JsonPreview value={selectedRule.rule} />
            </details>
          </>
        ) : null}
      </DrawerOverlay>
      <DrawerOverlay
        open={Boolean(selectedPack && operationOutput)}
        title={selectedPack?.title || t(lang, { en: "Pack operation", ru: "Операция с пакетом" })}
        subtitle={selectedPack?.pack_id || ""}
        onClose={() => setOperationOutput(null)}
        panelClassName="react-drawer-panel-wide"
      >
        {operationOutput ? <JsonPreview value={operationOutput} /> : null}
      </DrawerOverlay>
    </div>
  );
}
