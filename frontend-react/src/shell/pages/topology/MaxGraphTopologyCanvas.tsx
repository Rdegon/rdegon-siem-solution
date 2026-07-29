import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Graph, InternalEvent } from "@maxgraph/core";
import type { Cell, CellStyle } from "@maxgraph/core";

import { api } from "../../api";
import { useShellContext } from "../../context";
import type {
  TopologyEdgeRecord,
  TopologyLayoutPosition,
  TopologyNodeRecord,
} from "../../types";


type SegmentId =
  | "external"
  | "mgmt"
  | "sec"
  | "servers-games"
  | "lab"
  | "users"
  | "legacy"
  | "unassigned";

type Props = {
  nodes: TopologyNodeRecord[];
  edges: TopologyEdgeRecord[];
  selectedNodeId: string;
  onSelectNode: (nodeId: string) => void;
};

const SEGMENTS: Array<{
  id: SegmentId;
  label: string;
  cidr: string;
  color: string;
  fill: string;
}> = [
  { id: "external", label: "EXTERNAL", cidr: "Observed WAN", color: "#d45d6e", fill: "#17141d" },
  { id: "mgmt", label: "MGMT", cidr: "192.168.3.0/24", color: "#2f90d0", fill: "#101c27" },
  { id: "sec", label: "SEC", cidr: "10.20.10.0/24", color: "#2fb7a3", fill: "#0e211f" },
  { id: "servers-games", label: "SERVERS / GAMES", cidr: "10.20.20.0/24", color: "#df9d42", fill: "#241c12" },
  { id: "lab", label: "LAB", cidr: "10.20.30.0/24", color: "#8b78d2", fill: "#1a1727" },
  { id: "users", label: "USERS", cidr: "10.20.40.0/24", color: "#58a56b", fill: "#142219" },
  { id: "legacy", label: "LEGACY", cidr: "192.168.1.0/24", color: "#8d98a6", fill: "#181d23" },
  { id: "unassigned", label: "UNASSIGNED", cidr: "Needs classification", color: "#b06d78", fill: "#21171b" },
];

function text(value: unknown, fallback = "") {
  return String(value ?? "").trim() || fallback;
}

function segmentForNode(node: TopologyNodeRecord): SegmentId {
  const explicit = text(node.network_segment).toLowerCase().replace("_", "-") as SegmentId;
  if (SEGMENTS.some((segment) => segment.id === explicit)) return explicit;
  const ip = text(node.ip).split("/", 1)[0];
  if (ip.startsWith("10.20.10.")) return "sec";
  if (ip.startsWith("10.20.20.")) return "servers-games";
  if (ip.startsWith("10.20.30.")) return "lab";
  if (ip.startsWith("10.20.40.")) return "users";
  if (ip.startsWith("192.168.3.")) return "mgmt";
  if (ip.startsWith("192.168.1.")) return "legacy";
  if (node.type === "external_ip" || node.type === "protected_public_ip" || node.type === "zone") return "external";
  if (node.type === "core_service" || node.type === "collector") return "sec";
  return "unassigned";
}

function statusColor(node: TopologyNodeRecord) {
  const status = text(node.status).toLowerCase();
  if (/(error|failed|down|stale|delayed)/.test(status)) return "#d45d6e";
  if (/(active|running|connected|healthy|protected)/.test(status)) return "#2fb7a3";
  if (/(candidate|inventory|prepared|unknown)/.test(status)) return "#df9d42";
  return "#778493";
}

function nodeShape(node: TopologyNodeRecord) {
  const kind = text(node.source_kind || node.type).toLowerCase();
  const label = text(node.label).toLowerCase();
  if (kind.includes("router") || kind.includes("network") || label.includes("opnsense")) return "hexagon";
  if (node.type === "collector") return "rhombus";
  if (node.type === "core_service" && /(storage|clickhouse)/.test(label)) return "cylinder";
  if (node.type === "external_ip" || node.type === "protected_public_ip") return "ellipse";
  if (node.type === "zone") return "cloud";
  return "rectangle";
}

function nodeLabel(node: TopologyNodeRecord) {
  const label = text(node.display_label || node.hostname || node.label, node.id);
  const meta = text(node.ip || node.role || node.source_type_label);
  return meta && meta !== label ? `${label}\n${meta}` : label;
}

function nodeStyle(
  node: TopologyNodeRecord,
  segmentColor: string,
): CellStyle {
  return {
    shape: nodeShape(node),
    rounded: true,
    arcSize: 10,
    fillColor: "#0d1721",
    gradientColor: "none",
    strokeColor: statusColor(node),
    strokeWidth: 2,
    fontColor: "#e9f0f6",
    fontSize: 12,
    fontFamily: "Inter, Segoe UI, sans-serif",
    align: "center",
    verticalAlign: "middle",
    whiteSpace: "wrap",
    overflow: "hidden",
    spacing: 6,
    shadow: false,
    glass: false,
    opacity: 100,
    labelBackgroundColor: "none",
    perimeterSpacing: 4,
    portConstraint: "eastwest",
    resizable: false,
    editable: false,
    rotatable: false,
    movable: true,
    dashed: node.type === "discovery_candidate",
    dashPattern: node.type === "discovery_candidate" ? "5 4" : undefined,
    indicatorColor: segmentColor,
  };
}

function edgeStyle(edge: TopologyEdgeRecord): CellStyle {
  const type = text(edge.type).toLowerCase();
  const attack = type.includes("attack");
  const onboarding = type.includes("onboarding") || type.includes("candidate");
  const pipeline = type.includes("pipeline") || type.includes("ingest") || type.includes("binding");
  return {
    edgeStyle: "orthogonalEdgeStyle",
    rounded: true,
    orthogonalLoop: true,
    jettySize: "auto",
    strokeColor: attack ? "#d45d6e" : onboarding ? "#df9d42" : pipeline ? "#2fb7a3" : "#526578",
    strokeWidth: attack ? 2.4 : 1.4,
    dashed: onboarding,
    dashPattern: onboarding ? "5 4" : undefined,
    endArrow: attack ? "block" : "classic",
    endFill: true,
    fontColor: "#8fa1b2",
    fontSize: 10,
    labelBackgroundColor: "#071019",
    opacity: 82,
    editable: false,
    movable: false,
  };
}

function autoPosition(index: number) {
  const columns = 3;
  return {
    x: 20 + (index % columns) * 126,
    y: 58 + Math.floor(index / columns) * 76,
  };
}

export function MaxGraphTopologyCanvas({
  nodes,
  edges,
  selectedNodeId,
  onSelectNode,
}: Props) {
  const { permissions } = useShellContext();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const graphRef = useRef<Graph | null>(null);
  const nodeCellsRef = useRef<Map<string, Cell>>(new Map());
  const nodeSegments = useMemo(
    () => new Map(nodes.map((node) => [node.id, segmentForNode(node)])),
    [nodes],
  );
  const [positions, setPositions] = useState<Record<string, TopologyLayoutPosition>>({});
  const [layoutLoaded, setLayoutLoaded] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const [status, setStatus] = useState("");
  const canSave = permissions.includes("cmdb:write");

  useEffect(() => {
    let cancelled = false;
    void api.topologyLayout("network")
      .then((payload) => {
        if (!cancelled) setPositions(payload.positions || {});
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

  const fit = useCallback(() => {
    const graph = graphRef.current;
    if (!graph) return;
    const plugin = graph.getPlugin("fit") as { fit?: (options?: Record<string, unknown>) => void } | undefined;
    plugin?.fit?.({ border: 28, maxScale: 1 });
  }, []);

  const collectPositions = useCallback(() => {
    const result: Record<string, TopologyLayoutPosition> = {};
    for (const [nodeId, cell] of nodeCellsRef.current.entries()) {
      const geometry = cell.getGeometry();
      if (!geometry) continue;
      result[nodeId] = {
        x: geometry.x,
        y: geometry.y,
        segment: nodeSegments.get(nodeId) || "unassigned",
      };
    }
    return result;
  }, [nodeSegments]);

  const save = useCallback(async () => {
    if (!canSave) return;
    setStatus("Saving layout...");
    try {
      const next = collectPositions();
      const response = await api.saveTopologyLayout({
        workspace: "network",
        positions: next,
      });
      setPositions(response.positions || next);
      setStatus(`Saved ${response.node_count ?? Object.keys(next).length} node positions`);
      setEditMode(false);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    }
  }, [canSave, collectPositions]);

  const reset = useCallback(async () => {
    setPositions({});
    setStatus("Automatic segment layout restored");
    if (canSave) {
      try {
        await api.saveTopologyLayout({ workspace: "network", positions: {} });
      } catch (error) {
        setStatus(error instanceof Error ? error.message : String(error));
      }
    }
  }, [canSave]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container || !layoutLoaded) return;
    container.innerHTML = "";
    const graph = new Graph(container);
    graphRef.current = graph;
    nodeCellsRef.current = new Map();
    graph.setPanning(true);
    graph.setConnectable(false);
    graph.setCellsEditable(false);
    graph.setCellsResizable(false);
    graph.setCellsCloneable(false);
    graph.setCellsDeletable(false);
    graph.setAllowDanglingEdges(false);
    graph.setTooltips(true);
    graph.isCellMovable = (cell) => editMode && nodeCellsRef.current.has(text(cell.getId()));
    graph.isCellSelectable = (cell) => nodeCellsRef.current.has(text(cell.getId()));
    graph.getTooltipForCell = (cell) => {
      const node = nodes.find((item) => item.id === cell.getId());
      return node
        ? `${nodeLabel(node)}\n${text(node.status, "observed")} | ${Number(node.events || 0).toLocaleString()} events`
        : "";
    };

    const parent = graph.getDefaultParent();
    const cells = new Map<string, Cell>();
    const grouped = new Map<SegmentId, TopologyNodeRecord[]>();
    for (const segment of SEGMENTS) grouped.set(segment.id, []);
    for (const node of nodes) {
      const segment = segmentForNode(node);
      grouped.get(segment)?.push(node);
    }
    const visibleSegments = SEGMENTS
      .map((segment) => {
        const segmentNodes = (grouped.get(segment.id) || [])
          .sort((left, right) => nodeLabel(left).localeCompare(nodeLabel(right)));
        return {
          segment,
          segmentNodes,
          laneHeight: Math.max(224, 88 + Math.ceil(segmentNodes.length / 3) * 76),
        };
      })
      .filter((item) => item.segmentNodes.length > 0);
    const lanePositions = new Map<SegmentId, { x: number; y: number }>();
    let nextRowY = 28;
    for (let rowStart = 0; rowStart < visibleSegments.length; rowStart += 3) {
      const rowSegments = visibleSegments.slice(rowStart, rowStart + 3);
      const rowHeight = Math.max(...rowSegments.map((item) => item.laneHeight));
      rowSegments.forEach((item, column) => {
        lanePositions.set(item.segment.id, {
          x: 24 + column * 448,
          y: nextRowY,
        });
      });
      nextRowY += rowHeight + 28;
    }

    graph.batchUpdate(() => {
      for (const { segment, segmentNodes, laneHeight } of visibleSegments) {
        const lanePosition = lanePositions.get(segment.id) || { x: 24, y: 28 };
        const lane = graph.insertVertex({
          parent,
          id: `segment:${segment.id}`,
          value: `${segment.label}   ${segment.cidr}   ${segmentNodes.length} nodes`,
          position: [lanePosition.x, lanePosition.y],
          size: [416, laneHeight],
          style: {
            shape: "swimlane",
            horizontal: true,
            startSize: 38,
            rounded: true,
            arcSize: 8,
            fillColor: segment.fill,
            swimlaneFillColor: "#081019",
            strokeColor: segment.color,
            strokeWidth: 1.4,
            fontColor: "#dfe8ef",
            fontSize: 12,
            fontStyle: 1,
            align: "left",
            verticalAlign: "middle",
            spacingLeft: 12,
            collapsible: false,
            movable: false,
            resizable: false,
            editable: false,
            recursiveResize: false,
          },
        });
        lane.setConnectable(false);
        segmentNodes
          .sort((left, right) => nodeLabel(left).localeCompare(nodeLabel(right)))
          .forEach((node, index) => {
            const saved = positions[node.id];
            const automatic = autoPosition(index);
            const position = saved?.segment === segment.id ? saved : automatic;
            const cell = graph.insertVertex({
              parent: lane,
              id: node.id,
              value: nodeLabel(node),
              position: [position.x, position.y],
              size: [112, 54],
              style: nodeStyle(node, segment.color),
            });
            cells.set(node.id, cell);
            nodeCellsRef.current.set(node.id, cell);
          });
      }

      for (const edge of edges) {
        const source = cells.get(edge.source);
        const target = cells.get(edge.target);
        if (!source || !target) continue;
        graph.insertEdge({
          parent,
          id: edge.id,
          value: text(edge.label),
          source,
          target,
          style: edgeStyle(edge),
        });
      }
    });

    graph.addListener(InternalEvent.CLICK, (_sender, event) => {
      const cell = event.getProperty("cell") as Cell | null;
      const nodeId = text(cell?.getId());
      if (nodeCellsRef.current.has(nodeId)) onSelectNode(nodeId);
    });

    const handleWheel = (event: WheelEvent) => {
      event.preventDefault();
      if (event.deltaY < 0) graph.zoomIn();
      else graph.zoomOut();
    };
    container.addEventListener("wheel", handleWheel, { passive: false });
    const animation = window.requestAnimationFrame(() => {
      graph.zoomTo(0.72, false);
    });

    return () => {
      window.cancelAnimationFrame(animation);
      container.removeEventListener("wheel", handleWheel);
      graph.destroy();
      if (graphRef.current === graph) graphRef.current = null;
      nodeCellsRef.current = new Map();
    };
  }, [edges, editMode, fit, layoutLoaded, nodes, onSelectNode, positions]);

  useEffect(() => {
    const graph = graphRef.current;
    if (!graph || !selectedNodeId) return;
    const cell = nodeCellsRef.current.get(selectedNodeId);
    if (!cell) return;
    graph.setSelectionCell(cell);
    graph.scrollCellToVisible(cell);
  }, [selectedNodeId]);

  return (
    <div className={`react-maxgraph-shell ${editMode ? "is-editing" : ""}`}>
      <div className="react-maxgraph-toolbar">
        <div>
          <strong>Network blueprint</strong>
          <span>maxGraph editor | runtime inventory | automatic CIDR segmentation</span>
        </div>
        <div className="react-actions">
          <button type="button" className="react-icon-button" title="Zoom out" aria-label="Zoom out" onClick={() => graphRef.current?.zoomOut()}>-</button>
          <button type="button" className="react-icon-button" title="Zoom in" aria-label="Zoom in" onClick={() => graphRef.current?.zoomIn()}>+</button>
          <button type="button" className="react-link-button" onClick={fit}>Fit all</button>
          <button
            type="button"
            className={editMode ? "react-primary-button" : "react-link-button"}
            disabled={!canSave}
            title={!canSave ? "Requires cmdb:write permission" : undefined}
            onClick={() => setEditMode((current) => !current)}
          >
            {editMode ? "Editing layout" : "Edit layout"}
          </button>
          {editMode ? (
            <>
              <button type="button" className="react-primary-button" onClick={() => void save()}>Save</button>
              <button type="button" className="react-link-button" onClick={() => void reset()}>Auto arrange</button>
            </>
          ) : null}
        </div>
      </div>
      {status ? <div className="react-maxgraph-status">{status}</div> : null}
      <div
        ref={containerRef}
        className="react-maxgraph-canvas"
        aria-label="Interactive maxGraph network topology editor"
      />
    </div>
  );
}
