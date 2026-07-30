import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ELK from "elkjs/lib/elk.bundled.js";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  type Edge,
  type Node,
  type NodeChange,
  type NodeProps,
  type Viewport,
} from "@xyflow/react";
import {
  Box,
  Cable,
  Cloud,
  Container,
  Database,
  Globe2,
  HardDrive,
  Laptop,
  Layers3,
  LayoutGrid,
  LockKeyhole,
  Maximize2,
  Monitor,
  Network,
  Pencil,
  RadioTower,
  Router,
  Save,
  Server,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import "@xyflow/react/dist/style.css";

import { api } from "../../api";
import { useShellContext } from "../../context";
import type {
  TopologyEdgeRecord,
  TopologyLayoutPosition,
  TopologyNodeRecord,
} from "../../types";

export type TopologySegmentId =
  | "external"
  | "mgmt"
  | "sec"
  | "servers-games"
  | "lab"
  | "users"
  | "legacy"
  | "unassigned";

type SegmentDefinition = {
  id: TopologySegmentId;
  label: string;
  cidr: string;
  color: string;
};

type DeviceNodeData = {
  record: TopologyNodeRecord;
  label: string;
  meta: string;
  kind: string;
  segment: TopologySegmentId;
  segmentColor: string;
  statusTone: "ok" | "warn" | "neutral";
  muted: boolean;
  [key: string]: unknown;
};

type SegmentNodeData = {
  segment: TopologySegmentId;
  label: string;
  cidr: string;
  color: string;
  count: number;
  [key: string]: unknown;
};

type DeviceFlowNode = Node<DeviceNodeData, "device">;
type SegmentFlowNode = Node<SegmentNodeData, "segment">;
type TopologyFlowNode = DeviceFlowNode | SegmentFlowNode;

type Props = {
  nodes: TopologyNodeRecord[];
  edges: TopologyEdgeRecord[];
  selectedNodeId: string;
  searchTerm: string;
  segmentScope: "all" | TopologySegmentId;
  segmentCounts: Record<string, number>;
  layerScope: string;
  layerOptions: Array<{ id: string; label: string }>;
  onSelectNode: (nodeId: string) => void;
  onSegmentScopeChange: (segment: "all" | TopologySegmentId) => void;
  onLayerScopeChange: (layer: string) => void;
};

type LayoutResult = {
  nodes: TopologyFlowNode[];
  edges: Edge[];
};

const elk = new ELK();
const NODE_WIDTH = 232;
const NODE_GAP = 24;
const SEGMENT_HEADER_HEIGHT = 56;
const SEGMENT_PADDING = 22;
const LAYOUT_WORKSPACE = "network-reactflow-v1";

export const TOPOLOGY_SEGMENTS: SegmentDefinition[] = [
  { id: "external", label: "External", cidr: "Observed WAN", color: "#e36a7e" },
  { id: "mgmt", label: "Management", cidr: "192.168.3.0/24", color: "#8b91e8" },
  { id: "sec", label: "Security", cidr: "10.20.10.0/24", color: "#4cc7c0" },
  { id: "servers-games", label: "Servers / games", cidr: "10.20.20.0/24", color: "#dfa54d" },
  { id: "lab", label: "Lab", cidr: "10.20.30.0/24", color: "#70b782" },
  { id: "users", label: "Users", cidr: "10.20.40.0/24", color: "#69a7df" },
  { id: "legacy", label: "Legacy", cidr: "192.168.1.0/24", color: "#8493a4" },
  { id: "unassigned", label: "Unassigned", cidr: "Needs classification", color: "#b87882" },
];

function text(value: unknown, fallback = "") {
  return String(value ?? "").trim() || fallback;
}

function normalize(value: unknown) {
  return text(value).toLowerCase().replace(/[^a-z0-9_-]+/g, "_");
}

export function topologySegmentForNode(node: TopologyNodeRecord): TopologySegmentId {
  const explicit = text(node.network_segment).toLowerCase().replace("_", "-") as TopologySegmentId;
  if (TOPOLOGY_SEGMENTS.some((segment) => segment.id === explicit)) return explicit;
  const ip = text(node.ip).split("/", 1)[0];
  const kind = normalize(node.source_kind || node.type);
  const role = normalize(node.entity_role || node.role);
  if (node.type === "external_ip" || node.type === "zone") return "external";
  if (ip.startsWith("10.20.10.")) return "sec";
  if (ip.startsWith("10.20.20.")) return "servers-games";
  if (ip.startsWith("10.20.30.")) return "lab";
  if (ip.startsWith("10.20.40.")) return "users";
  if (ip.startsWith("192.168.3.")) return "mgmt";
  if (ip.startsWith("192.168.1.")) return "legacy";
  if (node.type === "core_service" || node.type === "collector" || kind === "siem_core") return "sec";
  if (kind === "workstation") return "users";
  if (node.type === "protected_public_ip" || kind.includes("vpn") || kind === "virtual_router" || role === "ngfw") return "mgmt";
  if (ip && !ip.startsWith("10.") && !ip.startsWith("172.16.") && !ip.startsWith("192.168.")) return "external";
  return "unassigned";
}

function nodeLabel(node: TopologyNodeRecord) {
  return text(node.display_label || node.hostname || node.source_name || node.label, node.id);
}

function nodeMeta(node: TopologyNodeRecord) {
  const ip = text(node.ip);
  const role = text(node.source_type_label || node.entity_role || node.role || node.type, "Runtime node");
  return ip && ip !== nodeLabel(node) ? `${ip}  |  ${role}` : role;
}

function nodeKind(node: TopologyNodeRecord) {
  return text(node.source_type_label || node.entity_role || node.role || node.type, "Host");
}

function nodeHeight(node: TopologyNodeRecord) {
  const label = nodeLabel(node);
  const estimatedLines = Math.max(1, Math.ceil(label.length / 25));
  return 82 + Math.min(4, estimatedLines) * 17;
}

function statusTone(node: TopologyNodeRecord): DeviceNodeData["statusTone"] {
  const status = text(node.status).toLowerCase();
  if (/(error|failed|down|stale|delayed|unreachable)/.test(status)) return "warn";
  if (/(active|running|connected|healthy|protected|online)/.test(status)) return "ok";
  return "neutral";
}

function matchesSearch(node: TopologyNodeRecord, query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return true;
  return [
    node.id,
    node.label,
    node.ip,
    node.type,
    node.role,
    node.status,
    node.hostname,
    node.display_label,
    node.source_name,
    node.source_kind,
    node.source_type_label,
    node.entity_role,
  ].some((value) => text(value).toLowerCase().includes(normalized));
}

function deviceIcon(node: TopologyNodeRecord): LucideIcon {
  const kind = normalize(node.source_kind || node.entity_role || node.role || node.type);
  const label = nodeLabel(node).toLowerCase();
  if (kind.includes("router") || kind.includes("firewall") || label.includes("opnsense")) return Router;
  if (kind.includes("ngfw") || kind.includes("ids") || kind.includes("ips") || label.includes("suricata")) return ShieldCheck;
  if (kind.includes("database") || /(clickhouse|postgres|mysql|redis)/.test(label)) return Database;
  if (kind.includes("collector") || node.type === "collector") return RadioTower;
  if (kind.includes("container") || kind.includes("lxc")) return Container;
  if (kind.includes("storage") || label.includes("storage")) return HardDrive;
  if (kind.includes("workstation") || kind.includes("windows") || kind.includes("desktop")) return Monitor;
  if (kind.includes("laptop")) return Laptop;
  if (kind.includes("cloud") || node.type === "zone") return Cloud;
  if (node.type === "external_ip" || node.type === "protected_public_ip") return Globe2;
  if (kind.includes("network") || kind.includes("switch")) return Network;
  if (node.type === "core_service") return Server;
  if (node.type === "source") return Cable;
  return Box;
}

function DeviceNode({ data, selected }: NodeProps<DeviceFlowNode>) {
  const DeviceIcon = deviceIcon(data.record);
  return (
    <div
      className={`react-flow-device tone-${data.statusTone} ${selected ? "is-selected" : ""} ${data.muted ? "is-muted" : ""}`}
      style={{ "--segment-color": data.segmentColor } as React.CSSProperties}
      title={`${data.label}\n${data.meta}\n${text(data.record.status, "observed")}`}
    >
      <Handle type="target" id="target-left" position={Position.Left} className="react-flow-handle side-left" />
      <Handle type="source" id="source-left" position={Position.Left} className="react-flow-handle side-left" />
      <Handle type="target" id="target-right" position={Position.Right} className="react-flow-handle side-right" />
      <Handle type="source" id="source-right" position={Position.Right} className="react-flow-handle side-right" />
      <Handle type="target" id="target-top" position={Position.Top} className="react-flow-handle side-top" />
      <Handle type="source" id="source-top" position={Position.Top} className="react-flow-handle side-top" />
      <Handle type="target" id="target-bottom" position={Position.Bottom} className="react-flow-handle side-bottom" />
      <Handle type="source" id="source-bottom" position={Position.Bottom} className="react-flow-handle side-bottom" />
      <div className="react-flow-device-accent" />
      <div className="react-flow-device-icon"><DeviceIcon size={22} strokeWidth={1.7} /></div>
      <div className="react-flow-device-copy">
        <strong>{data.label}</strong>
        <span>{data.meta}</span>
        <small>{data.kind}</small>
      </div>
      <i className="react-flow-device-status" aria-label={text(data.record.status, "observed")} />
    </div>
  );
}

function SegmentNode({ data }: NodeProps<SegmentFlowNode>) {
  return (
    <div
      className="react-flow-segment"
      style={{ "--segment-color": data.color } as React.CSSProperties}
    >
      <div className="react-flow-segment-head">
        <Layers3 size={16} strokeWidth={1.7} />
        <span>
          <strong>{data.label}</strong>
          <small>{data.cidr}</small>
        </span>
        <b>{data.count}</b>
      </div>
    </div>
  );
}

function rectsOverlap(left: TopologyFlowNode, right: TopologyFlowNode) {
  const leftWidth = Number(left.width || left.measured?.width || NODE_WIDTH);
  const leftHeight = Number(left.height || left.measured?.height || 100);
  const rightWidth = Number(right.width || right.measured?.width || NODE_WIDTH);
  const rightHeight = Number(right.height || right.measured?.height || 100);
  return !(
    left.position.x + leftWidth + NODE_GAP <= right.position.x ||
    right.position.x + rightWidth + NODE_GAP <= left.position.x ||
    left.position.y + leftHeight + NODE_GAP <= right.position.y ||
    right.position.y + rightHeight + NODE_GAP <= left.position.y
  );
}

function resolveCollisions(nodes: DeviceFlowNode[]) {
  const resolved: DeviceFlowNode[] = [];
  for (const node of nodes) {
    let candidate = {
      ...node,
      position: {
        x: Math.max(SEGMENT_PADDING, node.position.x),
        y: Math.max(SEGMENT_HEADER_HEIGHT + SEGMENT_PADDING, node.position.y),
      },
    };
    let guard = 0;
    while (resolved.some((other) => rectsOverlap(candidate, other)) && guard < 200) {
      const collisions = resolved.filter((other) => rectsOverlap(candidate, other));
      candidate = {
        ...candidate,
        position: {
          x: candidate.position.x,
          y: Math.max(...collisions.map((other) => other.position.y + Number(other.height || 100) + NODE_GAP)),
        },
      };
      guard += 1;
    }
    resolved.push(candidate);
  }
  return resolved;
}

function edgeTone(edge: TopologyEdgeRecord) {
  const type = text(edge.type).toLowerCase();
  if (type.includes("attack") || type.includes("threat")) return "attack";
  if (type.includes("onboarding") || type.includes("candidate") || type.includes("gap")) return "attention";
  if (type.includes("pipeline") || type.includes("ingest") || type.includes("binding") || type.includes("telemetry")) return "pipeline";
  return "neutral";
}

function edgeColor(tone: string) {
  if (tone === "attack") return "#e36a7e";
  if (tone === "attention") return "#dfa54d";
  if (tone === "pipeline") return "#4cc7c0";
  return "#53697c";
}

function edgeHandles(source: DeviceFlowNode, target: DeviceFlowNode) {
  const sourceX = source.position.x + Number(source.width || NODE_WIDTH) / 2;
  const sourceY = source.position.y + Number(source.height || 100) / 2;
  const targetX = target.position.x + Number(target.width || NODE_WIDTH) / 2;
  const targetY = target.position.y + Number(target.height || 100) / 2;
  const deltaX = targetX - sourceX;
  const deltaY = targetY - sourceY;
  if (Math.abs(deltaX) >= Math.abs(deltaY)) {
    return deltaX >= 0
      ? { sourceHandle: "source-right", targetHandle: "target-left" }
      : { sourceHandle: "source-left", targetHandle: "target-right" };
  }
  return deltaY >= 0
    ? { sourceHandle: "source-bottom", targetHandle: "target-top" }
    : { sourceHandle: "source-top", targetHandle: "target-bottom" };
}

export async function buildTopologyLayout(
  records: TopologyNodeRecord[],
  recordsEdges: TopologyEdgeRecord[],
  persisted: Record<string, TopologyLayoutPosition>,
  query = "",
): Promise<LayoutResult> {
  const recordById = new Map(records.map((record) => [record.id, record]));
  const segmentByNode = new Map(records.map((record) => [record.id, topologySegmentForNode(record)]));
  const grouped = new Map<TopologySegmentId, TopologyNodeRecord[]>();
  for (const segment of TOPOLOGY_SEGMENTS) grouped.set(segment.id, []);
  for (const record of records) grouped.get(topologySegmentForNode(record))?.push(record);

  const localLayouts = await Promise.all(
    TOPOLOGY_SEGMENTS.map(async (segment) => {
      const segmentRecords = [...(grouped.get(segment.id) || [])]
        .sort((left, right) => nodeLabel(left).localeCompare(nodeLabel(right)));
      if (!segmentRecords.length) return null;
      const local = await elk.layout({
        id: `layout:${segment.id}`,
        layoutOptions: {
          "elk.algorithm": "rectpacking",
          "elk.aspectRatio": segmentRecords.length > 12 ? "1.8" : "1.55",
          "elk.spacing.nodeNode": String(NODE_GAP),
          "elk.padding": `[top=${SEGMENT_HEADER_HEIGHT + SEGMENT_PADDING},left=${SEGMENT_PADDING},bottom=${SEGMENT_PADDING},right=${SEGMENT_PADDING}]`,
          "elk.rectpacking.widthApproximation.targetWidth": String(Math.max(520, Math.ceil(Math.sqrt(segmentRecords.length)) * (NODE_WIDTH + NODE_GAP))),
        },
        children: segmentRecords.map((record) => ({
          id: record.id,
          width: NODE_WIDTH,
          height: nodeHeight(record),
        })),
      });
      const localBounds = local as typeof local & { width?: number; height?: number };

      const initialNodes = segmentRecords.map<DeviceFlowNode>((record) => {
        const localNode = local.children?.find((item) => item.id === record.id);
        const saved = persisted[record.id];
        const savedInSegment = saved?.segment === segment.id;
        return {
          id: record.id,
          type: "device",
          parentId: `segment:${segment.id}`,
          extent: "parent",
          position: savedInSegment
            ? { x: saved.x, y: saved.y }
            : { x: Number(localNode?.x || SEGMENT_PADDING), y: Number(localNode?.y || SEGMENT_HEADER_HEIGHT + SEGMENT_PADDING) },
          width: NODE_WIDTH,
          height: nodeHeight(record),
          initialWidth: NODE_WIDTH,
          initialHeight: nodeHeight(record),
          style: { width: NODE_WIDTH, height: nodeHeight(record) },
          draggable: true,
          selectable: true,
          data: {
            record,
            label: nodeLabel(record),
            meta: nodeMeta(record),
            kind: nodeKind(record),
            segment: segment.id,
            segmentColor: segment.color,
            statusTone: statusTone(record),
            muted: !matchesSearch(record, query),
          },
        };
      });
      const resolved = resolveCollisions(initialNodes);
      const width = Math.max(
        Number(localBounds.width || 0),
        ...resolved.map((node) => node.position.x + Number(node.width || NODE_WIDTH) + SEGMENT_PADDING),
      );
      const height = Math.max(
        Number(localBounds.height || 0),
        ...resolved.map((node) => node.position.y + Number(node.height || 100) + SEGMENT_PADDING),
      );
      return { segment, records: segmentRecords, nodes: resolved, width, height };
    }),
  );

  const visibleLayouts = localLayouts.filter((item): item is NonNullable<typeof item> => Boolean(item));
  const aggregateEdges = new Map<string, { source: string; target: string; weight: number }>();
  for (const edge of recordsEdges) {
    const sourceSegment = segmentByNode.get(edge.source);
    const targetSegment = segmentByNode.get(edge.target);
    if (!sourceSegment || !targetSegment || sourceSegment === targetSegment) continue;
    const key = `${sourceSegment}->${targetSegment}`;
    const existing = aggregateEdges.get(key);
    aggregateEdges.set(key, {
      source: `segment:${sourceSegment}`,
      target: `segment:${targetSegment}`,
      weight: (existing?.weight || 0) + 1,
    });
  }

  const rootLayout = await elk.layout({
    id: "topology-root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "RIGHT",
      "elk.edgeRouting": "ORTHOGONAL",
      "elk.spacing.nodeNode": "100",
      "elk.spacing.componentComponent": "120",
      "elk.layered.spacing.nodeNodeBetweenLayers": "180",
      "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
      "elk.layered.nodePlacement.strategy": "NETWORK_SIMPLEX",
      "elk.layered.highDegreeNodes.treatment": "true",
      "elk.layered.highDegreeNodes.threshold": "10",
      "elk.separateConnectedComponents": "false",
    },
    children: visibleLayouts.map((layout) => ({
      id: `segment:${layout.segment.id}`,
      width: layout.width,
      height: layout.height,
      initialWidth: layout.width,
      initialHeight: layout.height,
    })),
    edges: [...aggregateEdges.entries()].map(([id, edge]) => ({
      id: `segment-edge:${id}`,
      sources: [edge.source],
      targets: [edge.target],
      layoutOptions: { "elk.priority": String(Math.min(100, edge.weight * 10)) },
    })),
  });

  const segmentNodes: SegmentFlowNode[] = [];
  const deviceNodes: DeviceFlowNode[] = [];
  for (const layout of visibleLayouts) {
    const rootNode = rootLayout.children?.find((item) => item.id === `segment:${layout.segment.id}`);
    segmentNodes.push({
      id: `segment:${layout.segment.id}`,
      type: "segment",
      position: { x: Number(rootNode?.x || 0), y: Number(rootNode?.y || 0) },
      width: layout.width,
      height: layout.height,
      draggable: false,
      selectable: false,
      data: {
        segment: layout.segment.id,
        label: layout.segment.label,
        cidr: layout.segment.cidr,
        color: layout.segment.color,
        count: layout.records.length,
      },
      style: { width: layout.width, height: layout.height, zIndex: 0 },
    });
    deviceNodes.push(...layout.nodes);
  }

  const deviceById = new Map(deviceNodes.map((node) => [node.id, node]));
  const flowEdges = recordsEdges.flatMap<Edge>((edge) => {
    const source = deviceById.get(edge.source);
    const target = deviceById.get(edge.target);
    if (!source || !target || !recordById.has(edge.source) || !recordById.has(edge.target)) return [];
    const tone = edgeTone(edge);
    const handles = edgeHandles(source, target);
    return [{
      id: edge.id,
      source: edge.source,
      target: edge.target,
      sourceHandle: handles.sourceHandle,
      targetHandle: handles.targetHandle,
      type: "smoothstep",
      pathOptions: { borderRadius: 8, offset: 28 },
      animated: tone === "attack",
      zIndex: 1,
      style: {
        stroke: edgeColor(tone),
        strokeWidth: tone === "attack" ? 2.2 : 1.35,
        opacity: query && (!matchesSearch(source.data.record, query) || !matchesSearch(target.data.record, query)) ? 0.12 : 0.62,
      },
      data: { tone, record: edge },
    }];
  });

  return { nodes: [...segmentNodes, ...deviceNodes], edges: flowEdges };
}

const nodeTypes = {
  device: DeviceNode,
  segment: SegmentNode,
};

function TopologyCanvas({
  nodes: records,
  edges: recordEdges,
  selectedNodeId,
  searchTerm,
  segmentScope,
  segmentCounts,
  layerScope,
  layerOptions,
  onSelectNode,
  onSegmentScopeChange,
  onLayerScopeChange,
}: Props) {
  const { permissions } = useShellContext();
  const [flowNodes, setFlowNodes, applyNodeChanges] = useNodesState<TopologyFlowNode>([]);
  const [flowEdges, setFlowEdges] = useEdgesState<Edge>([]);
  const [persisted, setPersisted] = useState<Record<string, TopologyLayoutPosition>>({});
  const [layoutLoaded, setLayoutLoaded] = useState(false);
  const [layouting, setLayouting] = useState(true);
  const [editMode, setEditMode] = useState(false);
  const [status, setStatus] = useState("");
  const [viewport, setTopologyViewport] = useState<Viewport>({ x: 0, y: 0, zoom: 1 });
  const canvasRef = useRef<HTMLDivElement | null>(null);
  const canSave = permissions.includes("cmdb:write");

  useEffect(() => {
    let cancelled = false;
    void api.topologyLayout(LAYOUT_WORKSPACE)
      .then((payload) => {
        if (!cancelled) setPersisted(payload.positions || {});
      })
      .catch((error) => {
        if (!cancelled) setStatus(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (!cancelled) setLayoutLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!layoutLoaded) return;
    let cancelled = false;
    setLayouting(true);
    void buildTopologyLayout(records, recordEdges, persisted)
      .then((layout) => {
        if (cancelled) return;
        setFlowNodes(layout.nodes.map((node) => ({
          ...node,
          selected: false,
          draggable: false,
        })));
        setFlowEdges(layout.edges);
      })
      .catch((error) => {
        if (!cancelled) setStatus(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (!cancelled) setLayouting(false);
      });
    return () => {
      cancelled = true;
    };
  }, [
    layoutLoaded,
    persisted,
    recordEdges,
    records,
    segmentScope,
    setFlowEdges,
    setFlowNodes,
  ]);

  const fitTopology = useCallback((wholeMap = false) => {
    const canvas = canvasRef.current;
    const segmentNodes = flowNodes.filter((node) => node.type === "segment");
    if (!canvas || !segmentNodes.length) return;
    const securitySegment = segmentNodes.find((node) => node.data.segment === "sec") || segmentNodes[0];
    if (!wholeMap && segmentScope === "all" && canvas.clientWidth < 720) {
      const securityDevices = flowNodes.filter(
        (node): node is DeviceFlowNode =>
          node.type === "device" && node.parentId === securitySegment.id,
      );
      const anchor = securityDevices.find((node) => /siem-web/i.test(node.data.label))
        || securityDevices.find((node) => /siem/i.test(node.data.label))
        || securityDevices[0];
      if (anchor) {
        const anchorWidth = Number(anchor.width || anchor.initialWidth || NODE_WIDTH);
        const anchorHeight = Number(anchor.height || anchor.initialHeight || nodeHeight(anchor.data.record));
        const absoluteX = securitySegment.position.x + anchor.position.x;
        const absoluteY = securitySegment.position.y + anchor.position.y;
        const zoom = 0.88;
        setTopologyViewport({
          x: canvas.clientWidth / 2 - (absoluteX + anchorWidth / 2) * zoom,
          y: canvas.clientHeight / 2 - (absoluteY + anchorHeight / 2) * zoom,
          zoom,
        });
        return;
      }
    }
    const focusNodes = !wholeMap && segmentScope === "all"
      ? [securitySegment]
      : segmentNodes;
    const left = Math.min(...focusNodes.map((node) => node.position.x));
    const top = Math.min(...focusNodes.map((node) => node.position.y));
    const right = Math.max(...focusNodes.map((node) => node.position.x + Number(node.width || node.initialWidth || 0)));
    const bottom = Math.max(...focusNodes.map((node) => node.position.y + Number(node.height || node.initialHeight || 0)));
    const boundsWidth = Math.max(1, right - left);
    const boundsHeight = Math.max(1, bottom - top);
    const padding = wholeMap ? 64 : 96;
    const maxZoom = wholeMap ? 0.72 : 0.9;
    const zoom = Math.max(
      0.14,
      Math.min(
        maxZoom,
        (canvas.clientWidth - padding * 2) / boundsWidth,
        (canvas.clientHeight - padding * 2) / boundsHeight,
      ),
    );
    const x = (canvas.clientWidth - boundsWidth * zoom) / 2 - left * zoom;
    const y = (canvas.clientHeight - boundsHeight * zoom) / 2 - top * zoom;
    setTopologyViewport({ x, y, zoom });
  }, [flowNodes, segmentScope]);

  useEffect(() => {
    if (!flowNodes.length || layouting) return;
    const frame = window.requestAnimationFrame(() => {
      fitTopology();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [fitTopology, flowNodes.length, layouting]);

  useEffect(() => {
    setFlowNodes((current) => current.map((node) => {
      if (node.type !== "device") return node;
      return {
        ...node,
        selected: node.id === selectedNodeId,
        draggable: editMode,
        data: {
          ...node.data,
          muted: !matchesSearch(node.data.record, searchTerm),
        },
      };
    }));
    setFlowEdges((current) => current.map((edge) => {
      const record = edge.data?.record as TopologyEdgeRecord | undefined;
      const source = records.find((node) => node.id === edge.source);
      const target = records.find((node) => node.id === edge.target);
      const tone = record ? edgeTone(record) : "neutral";
      const searchMuted = Boolean(searchTerm) && (
        !source ||
        !target ||
        (!matchesSearch(source, searchTerm) && !matchesSearch(target, searchTerm))
      );
      const selectionMuted = Boolean(selectedNodeId) && edge.source !== selectedNodeId && edge.target !== selectedNodeId;
      return {
        ...edge,
        style: {
          ...edge.style,
          stroke: edgeColor(tone),
          opacity: searchMuted || selectionMuted ? 0.1 : 0.62,
          strokeWidth: edge.source === selectedNodeId || edge.target === selectedNodeId
            ? 2.6
            : tone === "attack" ? 2.2 : 1.35,
        },
      };
    }));
  }, [editMode, records, searchTerm, selectedNodeId, setFlowEdges, setFlowNodes]);

  const onNodesChange = useCallback((changes: NodeChange<TopologyFlowNode>[]) => {
    const allowedChanges = changes.filter((change) => change.type !== "position" || editMode);
    applyNodeChanges(allowedChanges);
  }, [applyNodeChanges, editMode]);

  const save = useCallback(async () => {
    if (!canSave) return;
    const positions: Record<string, TopologyLayoutPosition> = {};
    for (const node of flowNodes) {
      if (node.type !== "device") continue;
      positions[node.id] = {
        x: node.position.x,
        y: node.position.y,
        segment: node.data.segment,
      };
    }
    setStatus("Saving layout...");
    try {
      const response = await api.saveTopologyLayout({
        workspace: LAYOUT_WORKSPACE,
        positions,
      });
      setPersisted(response.positions || positions);
      setStatus(`Saved ${response.node_count ?? Object.keys(positions).length} positions`);
      setEditMode(false);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    }
  }, [canSave, flowNodes]);

  const reset = useCallback(async () => {
    setStatus("Calculating automatic layout...");
    setPersisted({});
    if (canSave) {
      try {
        await api.saveTopologyLayout({ workspace: LAYOUT_WORKSPACE, positions: {} });
        setStatus("Automatic layout restored");
      } catch (error) {
        setStatus(error instanceof Error ? error.message : String(error));
      }
    }
  }, [canSave]);

  const segmentOptions = useMemo(
    () => TOPOLOGY_SEGMENTS.filter((segment) => Number(segmentCounts[segment.id] || 0) > 0),
    [segmentCounts],
  );

  return (
    <div className={`react-flow-topology-shell ${editMode ? "is-editing" : ""}`}>
      <div className="react-flow-topology-toolbar">
        <div className="react-flow-topology-title">
          <Network size={17} strokeWidth={1.8} />
          <span>
            <strong>Network blueprint</strong>
            <small>{records.length} nodes  |  {recordEdges.length} observed links</small>
          </span>
        </div>
        <div className="react-flow-topology-actions">
          {status ? <span className="react-flow-topology-status">{status}</span> : null}
          <button
            type="button"
            className={editMode ? "react-primary-button" : "react-link-button"}
            disabled={!canSave}
            title={!canSave ? "Requires cmdb:write permission" : editMode ? "Lock node positions" : "Move topology nodes"}
            onClick={() => setEditMode((current) => !current)}
          >
            {editMode ? <LockKeyhole size={14} /> : <Pencil size={14} />}
            {editMode ? "Lock" : "Edit"}
          </button>
          {editMode ? (
            <button type="button" className="react-primary-button" onClick={() => void save()}>
              <Save size={14} />
              Save
            </button>
          ) : null}
          <button type="button" className="react-link-button" onClick={() => void reset()}>
            <LayoutGrid size={14} />
            Auto layout
          </button>
          <button
            type="button"
            className="react-icon-button"
            title="Fit all segments"
            aria-label="Fit all segments"
            onClick={() => fitTopology(true)}
          >
            <Maximize2 size={15} />
          </button>
        </div>
      </div>
      <div ref={canvasRef} className="react-flow-topology-canvas" aria-label="Interactive production network topology">
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          viewport={viewport}
          onViewportChange={setTopologyViewport}
          nodeTypes={nodeTypes}
          onNodesChange={onNodesChange}
          onNodeClick={(_event, node) => {
            if (node.type === "device") onSelectNode(node.id);
          }}
          onPaneClick={() => onSelectNode("")}
          nodesDraggable={editMode}
          nodesConnectable={false}
          elementsSelectable
          panOnDrag
          zoomOnScroll
          zoomOnPinch
          minZoom={0.14}
          maxZoom={1.8}
          proOptions={{ hideAttribution: true }}
          colorMode="dark"
        >
          <Background color="rgba(116, 145, 171, 0.20)" gap={28} size={1} variant={BackgroundVariant.Dots} />
          <Controls position="bottom-left" showFitView={false} showInteractive={false} />
          <MiniMap
            position="bottom-right"
            pannable
            zoomable
            nodeColor={(node) => {
              if (node.type === "segment") return String(node.data?.color || "#42566b");
              return String(node.data?.segmentColor || "#70869a");
            }}
            nodeStrokeWidth={2}
            maskColor="rgba(2, 8, 13, 0.68)"
          />
          <div className="react-flow-segment-filter" role="group" aria-label="Network segment">
            <button
              type="button"
              className={segmentScope === "all" ? "active" : ""}
              onClick={() => onSegmentScopeChange("all")}
            >
              <i className="segment-all" />
              <span>All</span>
              <b>{Object.values(segmentCounts).reduce((sum, count) => sum + Number(count || 0), 0)}</b>
            </button>
            {segmentOptions.map((segment) => (
              <button
                type="button"
                key={segment.id}
                className={segmentScope === segment.id ? "active" : ""}
                onClick={() => onSegmentScopeChange(segment.id)}
                title={`${segment.label} | ${segment.cidr}`}
              >
                <i style={{ background: segment.color }} />
                <span>{segment.label}</span>
                <b>{segmentCounts[segment.id] || 0}</b>
              </button>
            ))}
            <select
              className="react-select"
              value={layerScope}
              aria-label="Topology layer"
              onChange={(event) => onLayerScopeChange(event.target.value)}
            >
              <option value="all">All layers</option>
              {layerOptions.map((layer) => (
                <option key={layer.id} value={layer.id}>{layer.label}</option>
              ))}
            </select>
          </div>
        </ReactFlow>
        {layouting ? (
          <div className="react-flow-layout-state">
            <LayoutGrid size={18} />
            Arranging topology
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function ReactFlowTopologyCanvas(props: Props) {
  return (
    <ReactFlowProvider>
      <TopologyCanvas {...props} />
    </ReactFlowProvider>
  );
}
