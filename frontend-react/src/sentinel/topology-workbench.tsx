import { useEffect, useMemo, useState } from "react";
import {
  Background,
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
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { NetworkTopologyResponse, TopologyLayoutResponse, TopologyNodeRecord } from "./runtime/types";
import { number, text } from "./runtime/query";
import { Badge, Button, Icon, SearchField, StatusCell } from "./ui";

type Mode = "logical" | "traffic" | "risk";
type FlowData = Record<string, unknown> & { label: string; segment?: string; status?: string; ip?: string; role?: string; events?: number; isSegment?: boolean };

const SEGMENT_ORDER = ["sec", "mgmt", "users", "lab", "servers/games", "servers", "games", "internet", "other"];

function segmentName(node: TopologyNodeRecord) {
  const value = text(node.segment ?? node.layer ?? node.network_segment ?? node.type, "other").toLowerCase();
  if (/sec|security/.test(value)) return "sec";
  if (/mgmt|management/.test(value)) return "mgmt";
  if (/user|client|workstation/.test(value)) return "users";
  if (/lab|test/.test(value)) return "lab";
  if (/server|game/.test(value)) return "servers/games";
  if (/internet|external|wan/.test(value)) return "internet";
  return value || "other";
}

function statusClass(value: unknown) {
  const status = text(value, "unknown").toLowerCase();
  if (/active|healthy|online|running|connected/.test(status)) return "healthy";
  if (/down|failed|critical|offline|error/.test(status)) return "critical";
  if (/stale|warning|degraded|quiet/.test(status)) return "warning";
  return "unknown";
}

function SegmentNode({ data }: NodeProps<Node<FlowData>>) {
  return <div className="topology-segment-node"><span>{data.label}</span><Badge tone="info">{number(data.count)}</Badge></div>;
}

function AssetNode({ data, selected }: NodeProps<Node<FlowData>>) {
  return <div className={`topology-asset-node state-${statusClass(data.status)} ${selected ? "selected" : ""}`}>
    <Handle position={Position.Left} type="target" />
    <div className="topology-asset-icon"><Icon name={/router|firewall|gateway/i.test(text(data.role)) ? "ngfw" : /container/i.test(text(data.role)) ? "container" : "server"} size={17} /></div>
    <div><strong title={data.label}>{data.label}</strong><small>{data.ip || text(data.role, "Узел")}</small></div>
    <span className="topology-node-status" title={text(data.status, "unknown")} />
    <Handle position={Position.Right} type="source" />
  </div>;
}

function buildNodes(data: NetworkTopologyResponse, saved?: TopologyLayoutResponse): Node<FlowData>[] {
  const grouped = new Map<string, TopologyNodeRecord[]>();
  for (const node of data.nodes ?? []) {
    const segment = segmentName(node);
    grouped.set(segment, [...(grouped.get(segment) ?? []), node]);
  }
  const segments = [...grouped.entries()].sort(([left], [right]) => {
    const li = SEGMENT_ORDER.indexOf(left); const ri = SEGMENT_ORDER.indexOf(right);
    return (li < 0 ? 99 : li) - (ri < 0 ? 99 : ri) || left.localeCompare(right);
  });
  const result: Node<FlowData>[] = [];
  let rowY = 0;
  for (let start = 0; start < segments.length; start += 2) {
    const pair = segments.slice(start, start + 2);
    const heights = pair.map(([, items]) => Math.max(240, 88 + Math.ceil(items.length / 3) * 98));
    pair.forEach(([segment, items], column) => {
      const groupId = `segment:${segment}`;
      const width = 580; const height = heights[column];
      result.push({ id: groupId, type: "segment", position: { x: column * 590, y: rowY }, data: { label: segment.toUpperCase(), segment, count: items.length, isSegment: true }, style: { width, height }, selectable: false, draggable: false, zIndex: -1 });
      items.forEach((node, index) => {
        const savedPosition = saved?.positions?.[node.id];
        result.push({
          id: node.id,
          type: "asset",
          parentId: groupId,
          extent: "parent",
          position: savedPosition?.segment === segment ? { x: savedPosition.x, y: savedPosition.y } : { x: 18 + (index % 3) * 184, y: 64 + Math.floor(index / 3) * 98 },
          data: { ...node, label: text(node.label, node.id), segment, status: text(node.status), ip: text(node.ip), role: text(node.role ?? node.type), events: number(node.events) },
          style: { width: 168, height: 70 },
        });
      });
    });
    rowY += Math.max(...heights) + 70;
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
      label: mode === "traffic" && events ? events.toLocaleString("ru-RU") : text(edge.label, ""),
      animated: mode === "traffic" && events > 0,
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
      style: { strokeWidth: mode === "traffic" ? Math.min(5, 1 + Math.log10(events + 1)) : 1.4, stroke: mode === "risk" && risky ? "#e44e5c" : "#63809a", opacity: mode === "risk" && !risky ? 0.22 : 0.72 },
      labelStyle: { fontSize: 10 },
    };
  });
}

export function TopologyWorkbench({ data, saved, onSave, onSelect }: { data: NetworkTopologyResponse; saved?: TopologyLayoutResponse; onSave: (positions: Record<string, { x: number; y: number; segment: string }>) => Promise<void>; onSelect: (node: TopologyNodeRecord) => void }) {
  const [mode, setMode] = useState<Mode>("logical");
  const [query, setQuery] = useState("");
  const [nodes, setNodes] = useState<Node<FlowData>[]>(() => buildNodes(data, saved));
  const [saving, setSaving] = useState(false);
  const [savedState, setSavedState] = useState("");
  useEffect(() => setNodes(buildNodes(data, saved)), [data, saved]);
  const edges = useMemo(() => buildEdges(data, mode), [data, mode]);
  const visibleNodes = useMemo(() => nodes.map((node) => node.data.isSegment || !query.trim() || `${node.data.label} ${node.data.ip} ${node.data.role}`.toLowerCase().includes(query.toLowerCase()) ? { ...node, hidden: false } : { ...node, hidden: true }), [nodes, query]);
  async function save() {
    setSaving(true); setSavedState("");
    try {
      const positions = Object.fromEntries(nodes.filter((node) => !node.data.isSegment).map((node) => [node.id, { x: node.position.x, y: node.position.y, segment: text(node.data.segment, "other") }]));
      await onSave(positions); setSavedState("Сохранено");
    } catch (error) { setSavedState(error instanceof Error ? error.message : String(error)); }
    finally { setSaving(false); }
  }
  return <div className="topology-workbench">
    <div className="topology-toolbar"><div className="kuma-view-toggle"><button className={mode === "logical" ? "active" : ""} onClick={() => setMode("logical")} type="button">Логическая</button><button className={mode === "traffic" ? "active" : ""} onClick={() => setMode("traffic")} type="button">Потоки</button><button className={mode === "risk" ? "active" : ""} onClick={() => setMode("risk")} type="button">Риски</button></div><SearchField onChange={setQuery} placeholder="Узел, IP или роль..." value={query} /><div><span>{savedState}</span><Button disabled={saving} icon="check" onClick={() => void save()}>{saving ? "Сохранение..." : "Сохранить раскладку"}</Button></div></div>
    <div className="topology-canvas"><ReactFlow defaultViewport={{ x: 26, y: 24, zoom: 0.72 }} edges={edges} maxZoom={1.8} minZoom={0.3} nodeTypes={{ asset: AssetNode, segment: SegmentNode }} nodes={visibleNodes} nodesConnectable={false} onNodeClick={(_, node) => { if (!node.data.isSegment) onSelect(node.data as unknown as TopologyNodeRecord); }} onNodesChange={(changes: NodeChange<Node<FlowData>>[]) => setNodes((current) => applyNodeChanges(changes, current))} panOnScroll selectionOnDrag><Background color="#8090a0" gap={28} size={1} /><MiniMap nodeColor={(node) => node.data.isSegment ? "#1d5365" : statusClass(node.data.status) === "critical" ? "#dc4e5b" : "#45a59b"} pannable zoomable /><Controls /></ReactFlow></div>
    <div className="topology-legend"><span><i className="healthy" />Норма</span><span><i className="warning" />Требует внимания</span><span><i className="critical" />Недоступен / критично</span><span><StatusCell value={`${data.edges.length} связей`} /></span></div>
  </div>;
}
