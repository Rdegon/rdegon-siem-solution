import { useCallback, useState } from "react";
import { api } from "../api";
import { useAsyncData, useDebouncedValue } from "../hooks";
import { AsyncGate } from "../async";
import { DrawerFieldGrid, EmptyState, KeyValue, PanelHeader, SeverityBadge, StatusBadge, StatCard } from "../ui";
import type {
  AssetInventoryResponse,
  AssetRecord,
  CollectorsInventoryResponse,
  CollectorInventoryRecord,
  SourceInventoryRecord,
  SourcesInventoryResponse,
} from "../types";

type InventoryRecord = AssetRecord | SourceInventoryRecord | CollectorInventoryRecord;
type InventoryMeta = {
  title: string;
  subtitle: string;
  primary: (item: InventoryRecord) => string;
  secondary: (item: InventoryRecord) => string;
  pivot: (item: InventoryRecord) => string;
};

function sourceIpSummary(item: InventoryRecord) {
  if (!("source_name" in item)) return "";
  const sourceIps = Array.isArray(item.source_ips) ? item.source_ips : [];
  let values = [item.cmdb_ip, ...sourceIps]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  if (!values.length && Array.isArray(item.observed_ips)) {
    values = item.observed_ips.map((value) => String(value || "").trim()).filter(Boolean);
  }
  return values.length ? Array.from(new Set(values)).join(", ") : "";
}

export function InventoryPage({ view }: { view: "assets" | "sources" | "collectors" }) {
  const loadAssets = useCallback(() => api.assetInventory(), []);
  const loadSources = useCallback(() => api.sourcesInventory(), []);
  const loadCollectors = useCallback(() => api.collectorsInventory(), []);
  const assetsState = useAsyncData<AssetInventoryResponse>(loadAssets);
  const sourcesState = useAsyncData<SourcesInventoryResponse>(loadSources);
  const collectorsState = useAsyncData<CollectorsInventoryResponse>(loadCollectors);
  const state = view === "assets" ? assetsState : view === "sources" ? sourcesState : collectorsState;
  const [query, setQuery] = useState("");
  const debouncedQuery = useDebouncedValue(query, 250);
  const [selected, setSelected] = useState<InventoryRecord | null>(null);

  const items = (state.data?.items || []).filter((item: InventoryRecord) => {
    const haystack = JSON.stringify(item).toLowerCase();
    return haystack.includes(String(debouncedQuery || "").trim().toLowerCase());
  });

  const meta: InventoryMeta =
    view === "assets"
      ? {
          title: "Assets",
          subtitle: "Observed devices enriched with CMDB context and event activity.",
          primary: (item: InventoryRecord) => ("asset" in item ? String(item.asset || "n/a") : "n/a"),
          secondary: (item: InventoryRecord) =>
            `${"events" in item ? Number(item.events || 0) : 0} events | ${"last_seen" in item ? String(item.last_seen || "n/a") : "n/a"}`,
          pivot: (item: InventoryRecord) =>
            `asset_id = '${"cmdb_asset_id" in item ? String(item.cmdb_asset_id || "") : ""}' OR log_source = '${"asset" in item ? String(item.asset || "") : ""}'`,
        }
      : view === "sources"
        ? {
            title: "Sources",
            subtitle: "Source inventory with collector path, freshness and event context.",
            primary: (item: InventoryRecord) => ("source_name" in item ? String(item.source_name || "n/a") : "n/a"),
            secondary: (item: InventoryRecord) => {
              const ip = sourceIpSummary(item);
              return `${ip || "no IP"} | ${"source_type" in item ? String(item.source_type || "n/a") : "n/a"} | ${"events" in item ? Number(item.events || 0) : 0} events`;
            },
            pivot: (item: InventoryRecord) => `log_source = '${"source_name" in item ? String(item.source_name || "") : ""}'`,
          }
        : {
            title: "Collectors",
            subtitle: "Collector pipeline health, source coverage and event throughput.",
            primary: (item: InventoryRecord) => ("name" in item ? String(item.name || "n/a") : "n/a"),
            secondary: (item: InventoryRecord) =>
              `${"sources_count" in item ? Number(item.sources_count || 0) : 0} sources | ${"events" in item ? Number(item.events || 0) : 0} events`,
            pivot: (item: InventoryRecord) => `collector_profile = '${"collector_id" in item ? String(item.collector_id || "") : ""}'`,
          };

  return (
    <AsyncGate states={[state]} loadingMessage={`Loading ${view}...`}>
      <div className="react-page">
        <div className="react-grid react-grid-4">
          <StatCard label={meta.title} value={items.length} hint={meta.subtitle} />
          <StatCard label="Active" value={items.filter((item) => item.status === "active").length} hint="Currently active entities in this inventory view." />
          <StatCard label="Delayed" value={items.filter((item) => item.status === "delayed").length} hint="Entities that reported slower than expected." />
          <StatCard label="Search mode" value="Live" hint="Instant filter across the loaded inventory." />
        </div>

        <div className="react-split">
          <section className="react-card">
            <PanelHeader
              title={meta.title}
              subtitle={meta.subtitle}
              actions={<input className="react-input react-input-grow" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search inventory..." />}
            />
            <div className="react-list">
              {items.map((item, index: number) => (
                <button
                  type="button"
                  className={`react-list-item ${selected === item ? "active" : ""}`}
                  key={`${meta.primary(item)}-${index}`}
                  onClick={() => setSelected(item)}
                >
                  <strong>{meta.primary(item)}</strong>
                  <span>{meta.secondary(item)}</span>
                </button>
              ))}
            </div>
          </section>

          <aside className="react-card react-drawer">
            {selected ? (
              <>
                <PanelHeader
                  title={meta.primary(selected)}
                  subtitle={meta.secondary(selected)}
                  actions={<a className="react-link-button" href={`/app#/events?q=${encodeURIComponent(meta.pivot(selected))}`}>Open in Events</a>}
                />
                <DrawerFieldGrid>
                  {Object.entries(selected).map(([key, value]) => (
                    <KeyValue
                      key={key}
                      label={key}
                      value={
                        key === "status" ? (
                          <StatusBadge value={String(value || "unknown")} />
                        ) : key.toLowerCase().includes("severity") ? (
                          <SeverityBadge value={String(value || "info")} />
                        ) : Array.isArray(value) ? (
                          value.join(", ") || "n/a"
                        ) : (
                          String(value ?? "n/a")
                        )
                      }
                    />
                  ))}
                </DrawerFieldGrid>
              </>
            ) : (
              <EmptyState message={`Select a ${view.slice(0, -1)} from the list.`} />
            )}
          </aside>
        </div>
      </div>
    </AsyncGate>
  );
}
