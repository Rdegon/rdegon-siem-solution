import { Plus, RefreshCw, Save, Trash2 } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { api } from "../../api";
import { AsyncGate } from "../../async";
import { t, useShellContext } from "../../context";
import { useFeedback } from "../../feedback";
import { useAsyncData } from "../../hooks";
import type {
  SourceMonitoringPoliciesResponse,
  SourceMonitoringPolicyRecord,
} from "../../types";
import {
  DrawerFieldGrid,
  DrawerOverlay,
  EmptyState,
  KeyValue,
  PanelHeader,
  StatusBadge,
} from "../../ui";

type PolicyDraft = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  source_pattern: string;
  window_hours: number;
  min_events: number;
  max_events: number;
  stale_after_minutes: number;
  severity: string;
  notifications: string;
  owner: string;
};

const EMPTY_DRAFT: PolicyDraft = {
  id: "",
  name: "",
  description: "",
  enabled: true,
  source_pattern: "",
  window_hours: 24,
  min_events: 1,
  max_events: 0,
  stale_after_minutes: 30,
  severity: "high",
  notifications: "",
  owner: "siem-engineering",
};

function toDraft(policy: SourceMonitoringPolicyRecord): PolicyDraft {
  return {
    id: policy.id,
    name: policy.name,
    description: policy.description || "",
    enabled: policy.enabled,
    source_pattern: policy.source_pattern,
    window_hours: policy.window_hours,
    min_events: policy.min_events,
    max_events: policy.max_events,
    stale_after_minutes: policy.stale_after_minutes,
    severity: policy.severity,
    notifications: (policy.notifications || []).join(", "),
    owner: policy.owner,
  };
}

function splitList(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function SourcePoliciesWorkspace() {
  const { lang } = useShellContext();
  const { pushToast } = useFeedback();
  const [refreshToken, setRefreshToken] = useState(0);
  const [draft, setDraft] = useState<PolicyDraft>(EMPTY_DRAFT);
  const [editorOpen, setEditorOpen] = useState(false);
  const [selectedId, setSelectedId] = useState("");
  const [mutationState, setMutationState] = useState("");
  const loadPolicies = useCallback(() => {
    void refreshToken;
    return api.sourcePolicies();
  }, [refreshToken]);
  const state = useAsyncData<SourceMonitoringPoliciesResponse>(loadPolicies);
  const policies = useMemo(() => state.data?.items || [], [state.data?.items]);
  const selected = useMemo(
    () => policies.find((policy) => policy.id === selectedId) || null,
    [policies, selectedId],
  );
  const metrics = useMemo(
    () => ({
      total: policies.length,
      enabled: policies.filter((policy) => policy.enabled).length,
      breached: policies.filter((policy) => policy.evaluation_status === "breached").length,
      violations: policies.reduce((sum, policy) => sum + Number(policy.violation_count || 0), 0),
    }),
    [policies],
  );

  function openNewPolicy() {
    setDraft({ ...EMPTY_DRAFT });
    setEditorOpen(true);
  }

  function openPolicy(policy: SourceMonitoringPolicyRecord) {
    setDraft(toDraft(policy));
    setEditorOpen(true);
  }

  async function savePolicy() {
    if (!draft.name.trim() || !draft.source_pattern.trim()) {
      pushToast({
        tone: "warning",
        title: t(lang, { en: "Policy is incomplete", ru: "Политика не заполнена" }),
        message: t(lang, {
          en: "Name and source match pattern are required.",
          ru: "Укажите название и шаблон сопоставления источников.",
        }),
      });
      return;
    }
    setMutationState("saving");
    try {
      const saved = await api.saveSourcePolicy({
        ...draft,
        id: draft.id || undefined,
        name: draft.name.trim(),
        source_pattern: draft.source_pattern.trim(),
        notifications: splitList(draft.notifications),
      });
      setEditorOpen(false);
      setSelectedId(saved.id);
      setRefreshToken((value) => value + 1);
      pushToast({
        tone: "success",
        message: t(lang, { en: "Source monitoring policy saved.", ru: "Политика мониторинга источников сохранена." }),
      });
    } catch (error) {
      pushToast({ tone: "error", message: error instanceof Error ? error.message : String(error) });
    } finally {
      setMutationState("");
    }
  }

  async function deletePolicy(policy: SourceMonitoringPolicyRecord) {
    if (!window.confirm(t(lang, {
      en: `Delete policy "${policy.name}"?`,
      ru: `Удалить политику «${policy.name}»?`,
    }))) return;
    setMutationState(`delete:${policy.id}`);
    try {
      await api.deleteSourcePolicy(policy.id);
      if (selectedId === policy.id) setSelectedId("");
      setRefreshToken((value) => value + 1);
      pushToast({
        tone: "success",
        message: t(lang, { en: "Policy deleted.", ru: "Политика удалена." }),
      });
    } catch (error) {
      pushToast({ tone: "error", message: error instanceof Error ? error.message : String(error) });
    } finally {
      setMutationState("");
    }
  }

  return (
    <>
      <section className="react-card">
        <PanelHeader
          title={t(lang, { en: "Source monitoring policies", ru: "Политики мониторинга источников" })}
          subtitle={t(lang, {
            en: "Live evaluation of telemetry volume and freshness against the current source inventory.",
            ru: "Проверка объема и свежести телеметрии по фактическому реестру источников.",
          })}
          actions={(
            <div className="react-actions">
              <button
                type="button"
                className="react-link-button"
                onClick={() => setRefreshToken((value) => value + 1)}
                disabled={state.loading}
              >
                <RefreshCw size={16} aria-hidden="true" />
                {t(lang, { en: "Evaluate", ru: "Проверить" })}
              </button>
              <button type="button" className="react-primary-button" onClick={openNewPolicy}>
                <Plus size={16} aria-hidden="true" />
                {t(lang, { en: "New policy", ru: "Новая политика" })}
              </button>
            </div>
          )}
        />
        <div className="native-action-bar source-policy-summary">
          <span>{t(lang, { en: "Policies", ru: "Политики" })}: <strong>{metrics.total}</strong></span>
          <span>{t(lang, { en: "Enabled", ru: "Активны" })}: <strong>{metrics.enabled}</strong></span>
          <span>{t(lang, { en: "Breached", ru: "Нарушены" })}: <strong>{metrics.breached}</strong></span>
          <span>{t(lang, { en: "Affected sources", ru: "Источники с нарушениями" })}: <strong>{metrics.violations}</strong></span>
        </div>
        <AsyncGate
          states={[state]}
          loadingMessage={t(lang, { en: "Evaluating source policies...", ru: "Проверка политик источников..." })}
        >
          <div className="react-table-wrap">
            <table className="react-table">
              <thead>
                <tr>
                  <th>{t(lang, { en: "Policy", ru: "Политика" })}</th>
                  <th>{t(lang, { en: "Source match", ru: "Шаблон источника" })}</th>
                  <th>{t(lang, { en: "Window", ru: "Окно" })}</th>
                  <th>{t(lang, { en: "Thresholds", ru: "Пороги" })}</th>
                  <th>{t(lang, { en: "Coverage", ru: "Покрытие" })}</th>
                  <th>{t(lang, { en: "State", ru: "Состояние" })}</th>
                  <th aria-label={t(lang, { en: "Actions", ru: "Действия" })} />
                </tr>
              </thead>
              <tbody>
                {policies.map((policy) => (
                  <tr key={policy.id}>
                    <td>
                      <button type="button" className="react-table-link" onClick={() => setSelectedId(policy.id)}>
                        {policy.name}
                      </button>
                      <div className="react-muted-line">{policy.owner}</div>
                    </td>
                    <td><code>{policy.source_pattern}</code></td>
                    <td>{policy.window_hours}h / {policy.stale_after_minutes}m stale</td>
                    <td>
                      {policy.min_events || 0} min
                      {policy.max_events ? ` / ${policy.max_events} max` : ""}
                    </td>
                    <td>{Number(policy.matched_sources || 0)} / {Number(policy.violation_count || 0)} breached</td>
                    <td><StatusBadge value={policy.evaluation_status || (policy.enabled ? "pending" : "disabled")} /></td>
                    <td>
                      <div className="react-actions react-actions-compact">
                        <button type="button" className="react-icon-button" title={t(lang, { en: "Edit policy", ru: "Изменить политику" })} onClick={() => openPolicy(policy)}>
                          <Save size={16} aria-hidden="true" />
                        </button>
                        <button
                          type="button"
                          className="react-icon-button react-danger-button"
                          title={t(lang, { en: "Delete policy", ru: "Удалить политику" })}
                          onClick={() => void deletePolicy(policy)}
                          disabled={mutationState === `delete:${policy.id}`}
                        >
                          <Trash2 size={16} aria-hidden="true" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!policies.length ? (
              <EmptyState message={t(lang, {
                en: "No monitoring policies yet. Create a policy to validate real source freshness and event volume.",
                ru: "Политики пока не созданы. Добавьте проверку фактической свежести и объема событий.",
              })} />
            ) : null}
          </div>
        </AsyncGate>
      </section>

      <DrawerOverlay
        open={Boolean(selected)}
        title={selected?.name || ""}
        subtitle={selected?.description || t(lang, { en: "Live policy evaluation", ru: "Текущая оценка политики" })}
        onClose={() => setSelectedId("")}
      >
        {selected ? (
          <>
            <section className="react-card react-card-nested">
              <PanelHeader
                title={t(lang, { en: "Evaluation", ru: "Результат проверки" })}
                subtitle={t(lang, {
                  en: "Current policy state calculated from source inventory.",
                  ru: "Текущее состояние, рассчитанное по реестру источников.",
                })}
                actions={<button type="button" className="react-link-button" onClick={() => openPolicy(selected)}>{t(lang, { en: "Edit", ru: "Изменить" })}</button>}
              />
              <DrawerFieldGrid>
                <KeyValue label={t(lang, { en: "State", ru: "Состояние" })} value={<StatusBadge value={selected.evaluation_status || "pending"} />} />
                <KeyValue label={t(lang, { en: "Matched sources", ru: "Найдено источников" })} value={Number(selected.matched_sources || 0)} />
                <KeyValue label={t(lang, { en: "Violations", ru: "Нарушения" })} value={Number(selected.violation_count || 0)} />
                <KeyValue label={t(lang, { en: "Evaluated", ru: "Проверено" })} value={selected.evaluated_ts || "n/a"} />
                <KeyValue label={t(lang, { en: "Severity", ru: "Важность" })} value={<StatusBadge value={selected.severity} />} />
                <KeyValue label={t(lang, { en: "Notifications", ru: "Уведомления" })} value={(selected.notifications || []).join(", ") || "none"} />
              </DrawerFieldGrid>
            </section>
            <section className="react-card react-card-nested">
              <PanelHeader
                title={t(lang, { en: "Affected sources", ru: "Источники с нарушениями" })}
                subtitle={t(lang, {
                  en: "Actual inventory records that currently violate this policy.",
                  ru: "Фактические источники, которые сейчас нарушают условия политики.",
                })}
              />
              <div className="react-list react-list-compact">
                {(selected.violations || []).map((violation) => (
                  <div key={violation.source_name} className="react-list-item">
                    <strong>{violation.source_name}</strong>
                    <span>{violation.events} events / {violation.last_seen || "last seen unavailable"}</span>
                    <span>{violation.reasons.join(", ")}</span>
                  </div>
                ))}
                {!selected.violations?.length ? (
                  <EmptyState message={t(lang, { en: "No current violations.", ru: "Текущих нарушений нет." })} />
                ) : null}
              </div>
            </section>
          </>
        ) : null}
      </DrawerOverlay>

      <DrawerOverlay
        open={editorOpen}
        title={draft.id
          ? t(lang, { en: "Edit source policy", ru: "Изменение политики источника" })
          : t(lang, { en: "New source policy", ru: "Новая политика источника" })}
        subtitle={t(lang, {
          en: "Persisted policy evaluated against live source telemetry.",
          ru: "Сохраняемая политика, проверяемая по текущей телеметрии.",
        })}
        onClose={() => setEditorOpen(false)}
      >
        <div className="react-form-grid source-policy-form">
          <label className="react-field">
            <span className="react-label">{t(lang, { en: "Name", ru: "Название" })}</span>
            <input className="react-input" value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} />
          </label>
          <label className="react-field">
            <span className="react-label">{t(lang, { en: "Owner", ru: "Владелец" })}</span>
            <input className="react-input" value={draft.owner} onChange={(event) => setDraft({ ...draft, owner: event.target.value })} />
          </label>
          <label className="react-field react-input-full">
            <span className="react-label">{t(lang, { en: "Description", ru: "Описание" })}</span>
            <textarea className="react-input react-textarea" value={draft.description} onChange={(event) => setDraft({ ...draft, description: event.target.value })} />
          </label>
          <label className="react-field react-input-full">
            <span className="react-label">{t(lang, { en: "Source match pattern", ru: "Шаблон сопоставления источников" })}</span>
            <input className="react-input" value={draft.source_pattern} onChange={(event) => setDraft({ ...draft, source_pattern: event.target.value })} placeholder="windows, pve, suricata, collector name..." />
          </label>
          <label className="react-field">
            <span className="react-label">{t(lang, { en: "Window, hours", ru: "Окно, часы" })}</span>
            <input className="react-input" type="number" min={1} max={720} value={draft.window_hours} onChange={(event) => setDraft({ ...draft, window_hours: Number(event.target.value) })} />
          </label>
          <label className="react-field">
            <span className="react-label">{t(lang, { en: "Stale after, minutes", ru: "Порог устаревания, минуты" })}</span>
            <input className="react-input" type="number" min={1} max={43200} value={draft.stale_after_minutes} onChange={(event) => setDraft({ ...draft, stale_after_minutes: Number(event.target.value) })} />
          </label>
          <label className="react-field">
            <span className="react-label">{t(lang, { en: "Minimum events", ru: "Минимум событий" })}</span>
            <input className="react-input" type="number" min={0} value={draft.min_events} onChange={(event) => setDraft({ ...draft, min_events: Number(event.target.value) })} />
          </label>
          <label className="react-field">
            <span className="react-label">{t(lang, { en: "Maximum events (0 = unlimited)", ru: "Максимум событий (0 = без ограничения)" })}</span>
            <input className="react-input" type="number" min={0} value={draft.max_events} onChange={(event) => setDraft({ ...draft, max_events: Number(event.target.value) })} />
          </label>
          <label className="react-field">
            <span className="react-label">{t(lang, { en: "Severity", ru: "Важность" })}</span>
            <select className="react-select" value={draft.severity} onChange={(event) => setDraft({ ...draft, severity: event.target.value })}>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </label>
          <label className="react-field">
            <span className="react-label">{t(lang, { en: "Notification channels", ru: "Каналы уведомлений" })}</span>
            <input className="react-input" value={draft.notifications} onChange={(event) => setDraft({ ...draft, notifications: event.target.value })} placeholder="telegram, email" />
          </label>
          <label className="react-checkbox-row react-input-full">
            <input type="checkbox" checked={draft.enabled} onChange={(event) => setDraft({ ...draft, enabled: event.target.checked })} />
            <span>{t(lang, { en: "Policy enabled", ru: "Политика активна" })}</span>
          </label>
        </div>
        <div className="react-actions">
          <button type="button" className="react-primary-button" onClick={() => void savePolicy()} disabled={mutationState === "saving"}>
            <Save size={16} aria-hidden="true" />
            {mutationState === "saving" ? t(lang, { en: "Saving...", ru: "Сохранение..." }) : t(lang, { en: "Save policy", ru: "Сохранить политику" })}
          </button>
          <button type="button" className="react-link-button" onClick={() => setEditorOpen(false)}>
            {t(lang, { en: "Cancel", ru: "Отмена" })}
          </button>
        </div>
      </DrawerOverlay>
    </>
  );
}
