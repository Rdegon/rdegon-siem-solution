import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  applyNodeChanges,
  type Edge,
  type Node,
  type NodeChange,
  type NodeProps,
  type ReactFlowInstance,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import "./topology-workbench.css";
import type { NetworkTopologyResponse, TopologyLayoutResponse, TopologyNodeRecord } from "./runtime/types";
import { number, text } from "./runtime/query";
import { Badge, Button, Icon, SearchField, StatusCell } from "./ui";

type Mode = "logical" | "traffic" | "risk";
type PositionRecord = { x: number; y: number; segment: string };
type FlowData = Record<string, unknown> & {
  label: string;
  segment?: string;
  status?: string;
  ip?: string;
  role?: string;
  events?: number;
  count?: number;
  isSegment?: boolean;
};

const SEGMENT_ORDER = ["sec", "mgmt", "users", "lab", "servers/games", "internet", "other"];
const SEGMENT_LABELS: Record<string, string> = {
  sec: "SECURITY",
  mgmt: "MANAGEMENT",
  users: "USERS",
  lab: "LAB",
  "servers/games": "SERVERS / GAMES",
  internet: "INTERNET / EXTERNAL",
  other: "OTHER",
};
const ASSET_GROUP_SEGMENTS: Record<string, string> = {
  proxmox: "mgmt",
  siem_core: "sec",
  identity: "sec",
  vuln: "sec",
  edge_gateway: "sec",
  devops: "mgmt",
  windows: "users",
  linux_common: "servers/games",
  public_services: "servers/games",
  game: "servers/games",
  pilot: "servers/games",
};
const ASSET_GROUP_PRIORITY = [
  "siem_core", "identity", "vuln", "edge_gateway",
  "proxmox", "devops", "windows", "pilot",
  "public_services", "game", "linux_common",
];

const NODE_WIDTH = 238;
const NODE_HEIGHT = 92;
const COLUMN_GAP = 20;
const ROW_GAP = 18;
const SEGMENT_PADDING = 24;
const SEGMENT_HEADER = 62;
const BOARD_MAX_WIDTH = 1_720;
const SEGMENT_GAP = 34;
const COLLISION_MARGIN = 8;

function normalizedTokens(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(normalizedTokens);
  return text(value, "")
    .toLowerCase()
    .split(/[\s,;|/]+/)
    .map((token) => token.trim())
    .filter(Boolean);
}

export function topologySegment(node: TopologyNodeRecord): string {
  const explicit = normalizedTokens(node.segment ?? node.network_segment ?? node.layer);
  for (const token of explicit) {
    if (/^(sec|security)$/.test(token)) return "sec";
    if (/^(mgmt|management)$/.test(token)) return "mgmt";
    if (/^(users?|clients?|workstations?)$/.test(token)) return "users";
    if (/^(lab|test)$/.test(token)) return "lab";
    if (/^(servers?|games?)$/.test(token)) return "servers/games";
    if (/^(internet|external|wan)$/.test(token)) return "internet";
  }

  const assetGroups = new Set(normalizedTokens(node.asset_group ?? node.asset_groups));
  for (const group of ASSET_GROUP_PRIORITY) {
    if (assetGroups.has(group)) return ASSET_GROUP_SEGMENTS[group];
  }

  const fallback = normalizedTokens(node.type ?? node.role)[0] ?? "other";
  if (/firewall|gateway|siem|security|ids|ips|ndr/.test(fallback)) return "sec";
  if (/hypervisor|proxmox|management/.test(fallback)) return "mgmt";
  if (/workstation|desktop|laptop|windows/.test(fallback)) return "users";
  if (/server|container|game|database|cache|linux/.test(fallback)) return "servers/games";
  return "other";
}

function statusClass(value: unknown) {
  const status = text(value, "unknown").toLowerCase();
  if (/active|healthy|online|running|connected/.test(status)) return "healthy";
  if (/down|failed|critical|offline|error/.test(status)) return "critical";
  if (/stale|warning|degraded|quiet/.test(status)) return "warning";
  return "unknown";
}

function nodeIcon(role: unknown) {
  const value = text(role).toLowerCase();
  if (/router|firewall|gateway|ngfw|ids|ips/.test(value)) return "ngfw";
  if (/container|docker|pod|lxc/.test(value)) return "container";
  return "server";
}

function SegmentNode({ data }: NodeProps<Node<FlowData>>) {
  return <div className="topology-segment-node">
    <div>
      <span className="topology-segment-kicker">Сетевой сегмент</span>
      <strong>{data.label}</strong>
    </div>
    <Badge tone="info">{number(data.count)} узл.</Badge>
  </div>;
}

function AssetNode({ data, selected }: NodeProps<Node<FlowData>>) {
  const state = statusClass(data.status);
  const status = text(data.status, "unknown");
  const metadata = [data.ip, data.role].map((value) => text(value)).filter(Boolean).join(" · ") || "Узел инфраструктуры";
  return <div className={`topology-asset-node state-${state} ${selected ? "selected" : ""}`}>
    <Handle position={Position.Left} type="target" />
    <div className="topology-asset-icon"><Icon name={nodeIcon(data.role)} size={19} /></div>
    <div className="topology-asset-copy">
      <strong>{data.label}</strong>
      <small title={metadata}>{metadata}</small>
    </div>
    <span aria-label={`Состояние: ${status}`} className="topology-node-status" role="img" title={status} />
    {number(data.events) > 0 ? <span className="topology-event-count">{number(data.events).toLocaleString("ru-RU")} evt</span> : null}
    <Handle position={Position.Right} type="source" />
  </div>;
}

const NODE_TYPES = { asset: AssetNode, segment: SegmentNode };

type Rect = { x: number; y: number; width: number; height: number };

function overlaps(left: Rect, right: Rect, margin = 0) {
  return left.x < right.x + right.width + margin
    && left.x + left.width + margin > right.x
    && left.y < right.y + right.height + margin
    && left.y + left.height + margin > right.y;
}

function preferredColumns(count: number) {
  if (count <= 2) return Math.max(1, count);
  return count <= 6 ? 2 : 3;
}

function autoPosition(index: number, columns: number) {
  return {
    x: SEGMENT_PADDING + (index % columns) * (NODE_WIDTH + COLUMN_GAP),
    y: SEGMENT_HEADER + (Math.floor(index / columns) * (NODE_HEIGHT + ROW_GAP)),
  };
}

function layoutSegment(segment: string, records: TopologyNodeRecord[], saved?: TopologyLayoutResponse) {
  const items = [...records].sort((left, right) => text(left.label, left.id).localeCompare(text(right.label, right.id), "ru"));
  const columns = preferredColumns(items.length);
  const width = (SEGMENT_PADDING * 2) + (columns * NODE_WIDTH) + ((columns - 1) * COLUMN_GAP);
  const baseRows = Math.max(1, Math.ceil(items.length / columns));
  const baseHeight = SEGMENT_HEADER + (baseRows * NODE_HEIGHT) + ((baseRows - 1) * ROW_GAP) + SEGMENT_PADDING;
  const placements = new Map<string, { x: number; y: number }>();
  const occupied: Rect[] = [];

  const ordered = [...items].sort((left, right) => Number(Boolean(saved?.positions?.[right.id])) - Number(Boolean(saved?.positions?.[left.id])));
  for (const item of ordered) {
    const stored = saved?.positions?.[item.id];
    const candidate = stored?.segment === segment && Number.isFinite(stored.x) && Number.isFinite(stored.y)
      ? { x: stored.x, y: stored.y }
      : undefined;
    const candidateRect = candidate ? { ...candidate, width: NODE_WIDTH, height: NODE_HEIGHT } : undefined;
    const candidateIsValid = candidateRect
      && candidateRect.x >= SEGMENT_PADDING
      && candidateRect.y >= SEGMENT_HEADER
      && candidateRect.x + NODE_WIDTH <= width - SEGMENT_PADDING
      && candidateRect.y + NODE_HEIGHT <= baseHeight - SEGMENT_PADDING
      && !occupied.some((rect) => overlaps(candidateRect, rect, COLLISION_MARGIN));

    let position = candidateIsValid ? candidate : undefined;
    for (let slot = 0; !position; slot += 1) {
      const next = autoPosition(slot, columns);
      const nextRect = { ...next, width: NODE_WIDTH, height: NODE_HEIGHT };
      if (!occupied.some((rect) => overlaps(nextRect, rect, COLLISION_MARGIN))) position = next;
    }
    placements.set(item.id, position);
    occupied.push({ ...position, width: NODE_WIDTH, height: NODE_HEIGHT });
  }

  const contentBottom = Math.max(...[...placements.values()].map((position) => position.y + NODE_HEIGHT), SEGMENT_HEADER);
  return { segment, items, columns, width, height: Math.max(baseHeight, contentBottom + SEGMENT_PADDING), placements };
}

export function buildTopologyNodes(data: NetworkTopologyResponse, saved?: TopologyLayoutResponse): Node<FlowData>[] {
  const grouped = new Map<string, TopologyNodeRecord[]>();
  for (const node of data.nodes ?? []) {
    const segment = topologySegment(node);
    grouped.set(segment, [...(grouped.get(segment) ?? []), node]);
  }

  const layouts = [...grouped.entries()]
    .sort(([left], [right]) => {
      const leftOrder = SEGMENT_ORDER.indexOf(left);
      const rightOrder = SEGMENT_ORDER.indexOf(right);
      return (leftOrder < 0 ? 99 : leftOrder) - (rightOrder < 0 ? 99 : rightOrder) || left.localeCompare(right);
    })
    .map(([segment, records]) => layoutSegment(segment, records, saved));

  const result: Node<FlowData>[] = [];
  let rowX = 0;
  let rowY = 0;
  let rowHeight = 0;
  for (const layout of layouts) {
    if (rowX > 0 && rowX + layout.width > BOARD_MAX_WIDTH) {
      rowX = 0;
      rowY += rowHeight + SEGMENT_GAP;
      rowHeight = 0;
    }
    const groupId = `segment:${layout.segment}`;
    result.push({
      id: groupId,
      type: "segment",
      position: { x: rowX, y: rowY },
      data: {
        label: SEGMENT_LABELS[layout.segment] ?? layout.segment.toUpperCase(),
        segment: layout.segment,
        count: layout.items.length,
        isSegment: true,
      },
      style: { width: layout.width, height: layout.height },
      selectable: false,
      draggable: false,
      focusable: false,
      zIndex: 0,
      ariaLabel: `Сегмент ${SEGMENT_LABELS[layout.segment] ?? layout.segment}, ${layout.items.length} узлов`,
    });
    for (const record of layout.items) {
      const label = text(record.label, record.id);
      const status = text(record.status, "unknown");
      result.push({
        id: record.id,
        type: "asset",
        parentId: groupId,
        extent: "parent",
        expandParent: false,
        position: layout.placements.get(record.id) ?? autoPosition(0, layout.columns),
        data: {
          ...record,
          label,
          segment: layout.segment,
          status,
          ip: text(record.ip),
          role: text(record.role ?? record.type),
          events: number(record.events),
        },
        style: { width: NODE_WIDTH, height: NODE_HEIGHT },
        zIndex: 2,
        ariaLabel: `${label}. ${text(record.ip, "IP не указан")}. Состояние: ${status}`,
      });
    }
    rowX += layout.width + SEGMENT_GAP;
    rowHeight = Math.max(rowHeight, layout.height);
  }
  return result;
}

function buildEdges(data: NetworkTopologyResponse, mode: Mode): Edge[] {
  return (data.edges ?? []).map((edge) => {
    const events = number(edge.events);
    const risky = /critical|blocked|malicious|alert/i.test(`${edge.status} ${edge.type} ${edge.label}`);
    return {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      type: "smoothstep",
      label: mode === "traffic" && events ? events.toLocaleString("ru-RU") : text(edge.label, ""),
      animated: mode === "traffic" && events > 0,
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
      style: {
        strokeWidth: mode === "traffic" ? Math.min(5, 1.25 + Math.log10(events + 1)) : 1.5,
        stroke: mode === "risk" && risky ? "#d84d5b" : "#52768b",
        opacity: mode === "risk" && !risky ? 0.18 : 0.68,
      },
      labelStyle: { fontSize: 11, fontWeight: 600, fill: "var(--text)" },
      labelBgStyle: { fill: "var(--surface-raised)", fillOpacity: 0.94 },
      labelBgPadding: [5, 3] as [number, number],
      labelBgBorderRadius: 3,
      ariaLabel: `${text(edge.label, edge.type)}: ${edge.source} — ${edge.target}`,
    };
  });
}

function assetNodesCollide(nodes: Node<FlowData>[], node: Node<FlowData>) {
  if (!node.parentId) return false;
  const current = { ...node.position, width: NODE_WIDTH, height: NODE_HEIGHT };
  return nodes.some((candidate) => candidate.id !== node.id
    && candidate.parentId === node.parentId
    && overlaps(current, { ...candidate.position, width: NODE_WIDTH, height: NODE_HEIGHT }, COLLISION_MARGIN));
}

export function TopologyWorkbench({ data, saved, onSave, onSelect }: {
  data: NetworkTopologyResponse;
  saved?: TopologyLayoutResponse;
  onSave: (positions: Record<string, PositionRecord>) => Promise<void>;
  onSelect: (node: TopologyNodeRecord) => void;
}) {
  const [mode, setMode] = useState<Mode>("logical");
  const [query, setQuery] = useState("");
  const [nodes, setNodes] = useState<Node<FlowData>[]>(() => buildTopologyNodes(data, saved));
  const [saving, setSaving] = useState(false);
  const [savedState, setSavedState] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [flow, setFlow] = useState<ReactFlowInstance<Node<FlowData>, Edge> | null>(null);
  const dragOrigin = useRef(new Map<string, { x: number; y: number }>());

  const fit = useCallback((duration = 300) => {
    void flow?.fitView({ padding: 0.1, duration, minZoom: 0.3, maxZoom: 0.92 });
  }, [flow]);

  useEffect(() => {
    setNodes(buildTopologyNodes(data, saved));
    setSelectedId((current) => data.nodes.some((node) => node.id === current) ? current : "");
  }, [data, saved]);

  const edges = useMemo(() => buildEdges(data, mode), [data, mode]);
  const normalizedQuery = query.trim().toLocaleLowerCase("ru");
  const matchingIds = useMemo(() => new Set(nodes.filter((node) => !node.data.isSegment && (!normalizedQuery || `${node.data.label} ${node.data.ip} ${node.data.role} ${node.data.segment}`.toLocaleLowerCase("ru").includes(normalizedQuery))).map((node) => node.id)), [nodes, normalizedQuery]);
  const visibleSegments = useMemo(() => new Set(nodes.filter((node) => !node.data.isSegment && matchingIds.has(node.id)).map((node) => node.parentId)), [nodes, matchingIds]);
  const visibleNodes = useMemo(() => nodes.map((node) => ({
    ...node,
    selected: node.id === selectedId,
    hidden: normalizedQuery ? (node.data.isSegment ? !visibleSegments.has(node.id) : !matchingIds.has(node.id)) : false,
  })), [matchingIds, nodes, normalizedQuery, selectedId, visibleSegments]);

  useEffect(() => {
    if (!flow || !normalizedQuery || matchingIds.size === 0) return undefined;
    const timer = window.setTimeout(() => {
      const targets = visibleNodes.filter((node) => !node.hidden);
      void flow.fitView({ nodes: targets, padding: 0.2, duration: 250, minZoom: 0.5, maxZoom: 1.15 });
    }, 80);
    return () => window.clearTimeout(timer);
  }, [flow, matchingIds.size, normalizedQuery, visibleNodes]);

  async function save() {
    setSaving(true);
    setSavedState("");
    try {
      const positions = Object.fromEntries(nodes.filter((node) => !node.data.isSegment).map((node) => [node.id, {
        x: node.position.x,
        y: node.position.y,
        segment: text(node.data.segment, "other"),
      }]));
      await onSave(positions);
      setSavedState("Раскладка сохранена");
    } catch (error) {
      setSavedState(error instanceof Error ? error.message : String(error));
    } finally {
      setSaving(false);
    }
  }

  function autoArrange() {
    setNodes(buildTopologyNodes(data));
    setSavedState("Автоматическая раскладка применена");
    window.requestAnimationFrame(() => fit());
  }

  const selected = data.nodes.find((node) => node.id === selectedId);

  return <section aria-label="Интерактивная топология сети" className="topology-workbench topology-workbench--production">
    <header className="topology-toolbar">
      <div aria-label="Режим топологии" className="kuma-view-toggle topology-mode-toggle" role="group">
        {([['logical', 'Логическая'], ['traffic', 'Потоки'], ['risk', 'Риски']] as Array<[Mode, string]>).map(([id, label]) => <button aria-pressed={mode === id} className={mode === id ? "active" : ""} key={id} onClick={() => setMode(id)} type="button">{label}</button>)}
      </div>
      <SearchField onChange={setQuery} placeholder="Узел, IP, роль или сегмент..." value={query} />
      <div className="topology-toolbar-actions">
        <span aria-live="polite" className="topology-save-state">{savedState}</span>
        <Button aria-label="Разместить узлы автоматически" icon="refresh" onClick={autoArrange} tone="ghost">Авто</Button>
        <Button aria-label="Показать всю топологию" icon="topology" onClick={() => fit()} tone="ghost">Вписать</Button>
        <Button disabled={saving} icon="check" onClick={() => void save()}>{saving ? "Сохранение..." : "Сохранить"}</Button>
      </div>
    </header>
    <div aria-label="Схема сегментов и узлов. Используйте колесо мыши для масштабирования и перетаскивание для навигации." className="topology-canvas" role="region">
      <ReactFlow
        colorMode="system"
        defaultViewport={{ x: 24, y: 24, zoom: 0.76 }}
        edges={edges}
        elevateEdgesOnSelect
        maxZoom={1.8}
        minZoom={0.3}
        nodeDragThreshold={3}
        nodeTypes={NODE_TYPES}
        nodes={visibleNodes}
        nodesConnectable={false}
        nodesFocusable
        onInit={setFlow}
        onNodeClick={(_, node) => {
          if (node.data.isSegment) return;
          setSelectedId(node.id);
          onSelect(node.data as unknown as TopologyNodeRecord);
        }}
        onNodeDragStart={(_, node) => dragOrigin.current.set(node.id, { ...node.position })}
        onNodeDragStop={(_, node) => {
          if (!assetNodesCollide(nodes, node)) return;
          const origin = dragOrigin.current.get(node.id);
          if (origin) setNodes((current) => current.map((item) => item.id === node.id ? { ...item, position: origin } : item));
          setSavedState("Узел возвращен: позиции не должны пересекаться");
        }}
        onNodesChange={(changes: NodeChange<Node<FlowData>>[]) => setNodes((current) => applyNodeChanges(changes, current))}
        onPaneClick={() => setSelectedId("")}
        onlyRenderVisibleElements
        panOnDrag
        panOnScroll
        selectionOnDrag={false}
        zoomOnDoubleClick={false}
      >
        <Background color="var(--topology-grid, #78909c)" gap={28} size={1} variant={BackgroundVariant.Dots} />
        <MiniMap ariaLabel="Мини-карта топологии" maskColor="color-mix(in srgb, var(--surface-muted) 74%, transparent)" nodeColor={(node) => node.data.isSegment ? "#2f6171" : statusClass(node.data.status) === "critical" ? "#d84d5b" : statusClass(node.data.status) === "warning" ? "#bd762d" : "#319278"} pannable zoomable />
        <Controls fitViewOptions={{ padding: 0.1, minZoom: 0.3, maxZoom: 0.92 }} position="bottom-right" showInteractive={false} />
      </ReactFlow>
    </div>
    <footer className="topology-legend">
      <span><i className="healthy" />Норма</span>
      <span><i className="warning" />Требует внимания</span>
      <span><i className="critical" />Недоступен / критично</span>
      <span className="topology-legend-summary"><StatusCell value={`${data.nodes.length} узлов`} /><StatusCell value={`${data.edges.length} связей`} /></span>
      <span className="topology-current-selection">{selected ? <>Выбран: <strong>{text(selected.label, selected.id)}</strong></> : "Выберите узел для просмотра деталей"}</span>
    </footer>
  </section>;
}
