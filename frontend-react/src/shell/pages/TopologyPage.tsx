import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useShellContext } from "../context";
import { useAsyncData } from "../hooks";
import { DrawerFieldGrid, EmptyState, KeyValue, PanelHeader, SectionIntro, StatCard, StatusBadge } from "../ui";
import type { HostAccessProfileRecord, NetworkPacketFlowRecord, NetworkTopologyResponse, TopologyEdgeRecord, TopologyNodeRecord } from "../types";

const TOPOLOGY_LANES: Record<string, { label: string; order: number }> = {
  external: { label: "External activity", order: 0 },
  edge: { label: "Protected edge", order: 1 },
  inventory: { label: "Hosts / inventory", order: 2 },
  source: { label: "Telemetry sources", order: 3 },
  collector: { label: "Collectors", order: 4 },
  core: { label: "SIEM core", order: 5 },
};

const CYTOSCAPE_LANE_LAYOUT: Record<string, { x: number; y: number; columns: number; columnGap: number; rowGap: number }> = {
  external: { x: 110, y: 138, columns: 2, columnGap: 92, rowGap: 92 },
  edge: { x: 360, y: 160, columns: 1, columnGap: 1, rowGap: 140 },
  inventory: { x: 640, y: 128, columns: 3, columnGap: 142, rowGap: 104 },
  source: { x: 1080, y: 128, columns: 2, columnGap: 172, rowGap: 108 },
  collector: { x: 1340, y: 150, columns: 1, columnGap: 1, rowGap: 132 },
  core: { x: 1590, y: 142, columns: 1, columnGap: 1, rowGap: 122 },
};

type TopologyGraphNode = TopologyNodeRecord & {
  degree: number;
  lane: string;
};

type NormalizedTopologyGraph = {
  nodes: TopologyNodeRecord[];
  edges: TopologyEdgeRecord[];
  dedupedNodes: number;
};

type TopologyGraphCommand = {
  kind: "zoom-in" | "zoom-out" | "fit" | "layout";
  nonce: number;
};

type TopologyMapMode = "network" | "telemetry" | "posture" | "force";

type HostAccessForm = {
  profile_id: string;
  host_id: string;
  host_label: string;
  hostname: string;
  ip: string;
  protocol: string;
  port: string;
  username: string;
  auth_method: string;
  credential_label: string;
  credential_ref: string;
  private_key_ref: string;
  certificate_ref: string;
  password: string;
  private_key_pem: string;
  certificate_pem: string;
  passphrase: string;
  jump_host: string;
  allowed_actions: string;
  tags: string;
  notes: string;
  enabled: boolean;
};

function safeText(value: unknown, fallback = "n/a") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function nodeField(node: TopologyNodeRecord | null | undefined, key: string, fallback = "") {
  return safeText(node?.[key], fallback);
}

function normalizeTopologyClass(value: unknown, fallback = "unknown") {
  return safeText(value, fallback).toLowerCase().replace(/[^a-z0-9_-]+/g, "_").replace(/^_+|_+$/g, "") || fallback;
}

function looksLikeIpLabel(value: unknown) {
  const text = safeText(value, "");
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(text) || /^[0-9a-f:]+$/i.test(text);
}

function nodeHostname(node: TopologyNodeRecord | null | undefined) {
  const hostname = nodeField(node, "hostname");
  if (hostname && !looksLikeIpLabel(hostname)) return hostname;
  const displayLabel = nodeField(node, "display_label");
  if (displayLabel && !looksLikeIpLabel(displayLabel)) return displayLabel;
  const label = safeText(node?.label, "");
  if (label && !looksLikeIpLabel(label)) return label;
  return "";
}

function nodeSourceKind(node: TopologyNodeRecord | null | undefined) {
  return normalizeTopologyClass(node?.["source_kind"] || node?.["platform_kind"] || node?.["entity_role"] || node?.role || node?.type, "host");
}

function nodeSourceKindLabel(node: TopologyNodeRecord | null | undefined) {
  return safeText(node?.["source_type_label"] || node?.["entity_role"] || node?.role || node?.type, "Host");
}

function metricValue(data: NetworkTopologyResponse | undefined, key: string) {
  return Number(data?.metrics?.[key] || 0).toLocaleString();
}

function flowTokens(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => safeText(item, "")).filter(Boolean);
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function nodeLane(node: TopologyNodeRecord) {
  const laneHint = normalizeTopologyClass(node["topology_lane"], "");
  if (laneHint && TOPOLOGY_LANES[laneHint]) return laneHint;
  if (node.type === "external_ip" || node.type === "zone") return "external";
  if (node.type === "protected_public_ip") return "edge";
  if (node.type === "source") return "source";
  if (node.type === "collector") return "collector";
  if (node.type === "core_service") return "core";
  return "inventory";
}

function nodeTone(node: TopologyNodeRecord) {
  const status = String(node.status || "").toLowerCase();
  if (status.includes("stale") || status.includes("delayed") || status.includes("error")) return "warn";
  if (status.includes("candidate") || status.includes("inventory") || status.includes("prepared")) return "attention";
  if (status.includes("protected") || status.includes("active") || status.includes("connected")) return "ok";
  return "neutral";
}

function nodeSize(node: TopologyNodeRecord) {
  if (node.type === "core_service") return 58;
  if (node.type === "protected_public_ip") return 46;
  if (node.type === "source" || node.type === "collector") return 42;
  if (node.type === "external_ip") return 34;
  if (Number(node.access_profile_count || 0) > 0) return 42;
  return 36;
}

function nodeMatchesQuery(node: TopologyNodeRecord, query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return true;
  return [node.id, node.label, node.ip, node.type, node.role, node.status, node["hostname"], node["display_label"], node["source_name"], node["source_kind"], node["source_type_label"], node["entity_role"]]
    .map((value) => String(value || "").toLowerCase())
    .some((value) => value.includes(normalized));
}

function topologyIdentityTokens(node: TopologyNodeRecord) {
  const rawTokens = [node.label, node.ip, node.id.replace(/^[^:]+:/, ""), node["hostname"], node["display_label"], node["source_name"], node["connected_source"], node["public_ip"]];
  const identityTokens = String(node["identity_tokens"] || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  return [...rawTokens, ...identityTokens]
    .map((value) => safeText(value, "").toLowerCase())
    .map((value) => value.replace(/[^a-z0-9.:-]+/g, "-").replace(/^-+|-+$/g, ""))
    .filter((value) => value.length > 2 && !["n-a", "unknown", "candidate", "host", "source"].includes(value));
}

function topologyNodeDedupeKey(node: TopologyNodeRecord) {
  if (node.type === "collector") return `${node.type}:${safeText(node.label || node.id, node.id).toLowerCase()}`;
  if (node.type === "core_service") return `${node.type}:${safeText(node.role || node.label, node.id).toLowerCase()}`;
  if (node.type === "protected_public_ip") return `${node.type}:${safeText(node.ip || node.label, node.id).toLowerCase()}`;
  if (node.type === "external_ip") return `${node.type}:${safeText(node.ip || node.label, node.id).toLowerCase()}`;
  return node.id;
}

function topologyNodePriority(node: TopologyNodeRecord) {
  if (node.type === "source") return 60;
  if (node.type === "protected_public_ip") return 55;
  if (node.type === "proxmox_guest") return 50;
  if (node.type === "discovery_candidate") return 40;
  if (node.type === "collector") return 30;
  if (node.type === "core_service") return 20;
  return 10;
}

function mergeTopologyNode(base: TopologyNodeRecord, duplicate: TopologyNodeRecord): TopologyNodeRecord {
  const baseEvents = Number(base.events || 0);
  const duplicateEvents = Number(duplicate.events || 0);
  const baseMergedTypes = Array.isArray(base.merged_types) ? base.merged_types.map(String) : [base.type];
  const mergedTypes = Array.from(new Set([...baseMergedTypes, duplicate.type]));
  return {
    ...base,
    status: safeText(base.status, "") === "active" ? base.status : duplicate.status || base.status,
    role: base.role || duplicate.role,
    label: looksLikeIpLabel(base.label) && !looksLikeIpLabel(duplicate.label) ? duplicate.label : base.label,
    ip: base.ip || duplicate.ip,
    href: base.href || duplicate.href,
    hostname: nodeHostname(base) || nodeHostname(duplicate),
    display_label: base.display_label || duplicate.display_label || nodeHostname(base) || nodeHostname(duplicate),
    source_name: base.source_name || duplicate.source_name,
    source_kind: base.source_kind || duplicate.source_kind,
    source_type_label: base.source_type_label || duplicate.source_type_label,
    entity_role: base.entity_role || duplicate.entity_role,
    platform_kind: base.platform_kind || duplicate.platform_kind,
    topology_lane: base.topology_lane || duplicate.topology_lane,
    identity_tokens: [base.identity_tokens, duplicate.identity_tokens].filter(Boolean).join(","),
    protected_ip: Boolean(base.protected_ip || duplicate.protected_ip),
    events: baseEvents + duplicateEvents,
    access_profile_count: Math.max(Number(base.access_profile_count || 0), Number(duplicate.access_profile_count || 0)),
    access_status: base.access_status || duplicate.access_status,
    merged_count: Number(base.merged_count || 1) + Number(duplicate.merged_count || 1),
    merged_types: mergedTypes,
  };
}

function normalizeTopologyGraph(nodes: TopologyNodeRecord[], edges: TopologyEdgeRecord[]): NormalizedTopologyGraph {
  const mergeableTypes = new Set(["source", "proxmox_guest", "discovery_candidate", "protected_public_ip"]);
  const parent = new Map<string, string>();
  const tokenOwner = new Map<string, string>();

  for (const node of nodes) parent.set(node.id, node.id);

  function find(nodeId: string): string {
    const current = parent.get(nodeId) || nodeId;
    if (current === nodeId) return current;
    const root = find(current);
    parent.set(nodeId, root);
    return root;
  }

  function union(left: string, right: string) {
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot !== rightRoot) parent.set(rightRoot, leftRoot);
  }

  for (const node of nodes) {
    if (!mergeableTypes.has(node.type)) continue;
    for (const token of topologyIdentityTokens(node)) {
      const owner = tokenOwner.get(token);
      if (owner) union(node.id, owner);
      else tokenOwner.set(token, node.id);
    }
  }

  const groupedNodes = new Map<string, TopologyNodeRecord[]>();
  for (const node of nodes) {
    const key = mergeableTypes.has(node.type) ? `entity:${find(node.id)}` : topologyNodeDedupeKey(node);
    const group = groupedNodes.get(key) || [];
    group.push(node);
    groupedNodes.set(key, group);
  }

  const aliasToCanonical = new Map<string, string>();
  const normalizedNodes: TopologyNodeRecord[] = [];

  for (const group of groupedNodes.values()) {
    const ordered = [...group].sort((left, right) => {
      const priorityDelta = topologyNodePriority(right) - topologyNodePriority(left);
      if (priorityDelta !== 0) return priorityDelta;
      return Number(right.events || 0) - Number(left.events || 0);
    });
    let canonical: TopologyNodeRecord = { ...ordered[0], merged_count: 1, merged_types: [ordered[0].type] };
    for (const duplicate of ordered.slice(1)) canonical = mergeTopologyNode(canonical, duplicate);
    for (const node of group) aliasToCanonical.set(node.id, canonical.id);
    normalizedNodes.push(canonical);
  }

  const edgeByKey = new Map<string, TopologyEdgeRecord>();
  for (const edge of edges) {
    const source = aliasToCanonical.get(edge.source) || edge.source;
    const target = aliasToCanonical.get(edge.target) || edge.target;
    if (source === target) continue;
    const key = `${source}->${target}:${edge.type}:${safeText(edge.label, "")}`;
    const existing = edgeByKey.get(key);
    if (!existing) {
      edgeByKey.set(key, { ...edge, id: key, source, target });
      continue;
    }
    edgeByKey.set(key, {
      ...existing,
      events: Number(existing.events || 0) + Number(edge.events || 0),
      status: existing.status || edge.status,
    });
  }

  return {
    nodes: normalizedNodes,
    edges: Array.from(edgeByKey.values()),
    dedupedNodes: Math.max(0, nodes.length - normalizedNodes.length),
  };
}

function shortenTopologyLabel(value: unknown, maxLength = 30) {
  const text = safeText(value, "");
  if (text.length <= maxLength) return text;
  return `${text.slice(0, Math.max(4, maxLength - 3))}...`;
}

function nodeDisplayLabel(node: TopologyNodeRecord) {
  const label = safeText(node["display_label"] || nodeHostname(node) || node.label, node.id);
  const normalized = label.toLowerCase();
  if (node.type === "source") return shortenTopologyLabel(label, 25);
  if (node.type === "collector") return shortenTopologyLabel(label, 27);
  if (node.type === "core_service" && normalized === "storage") return "Storage service";
  if (node.type === "core_service") return shortenTopologyLabel(label, 26);
  return shortenTopologyLabel(label, 28);
}

function nodeDisplayMeta(node: TopologyNodeRecord) {
  if (node.type === "source") {
    const events = Number(node.events || 0);
    const ip = safeText(node.ip, "");
    const kind = nodeSourceKindLabel(node);
    if (ip && events > 0) return `${kind} / ${ip} / ${events.toLocaleString()} ev`;
    if (ip) return `${kind} / ${ip}`;
    return events > 0 ? `${kind} / ${events.toLocaleString()} ev` : safeText(kind || node.status || "telemetry source", "telemetry source");
  }
  if (node.type === "collector") {
    const sources = Number(node.sources_count || 0);
    const events = Number(node.events || 0);
    if (sources > 0 || events > 0) return `${sources.toLocaleString()} src / ${events.toLocaleString()} ev`;
    return safeText(node.role || node.status || "collector");
  }
  if (node.type === "core_service") return "SIEM core";
  if (node.type === "proxmox_guest" || node.type === "discovery_candidate" || node.type === "protected_public_ip") {
    return [nodeSourceKindLabel(node), safeText(node.ip, "")].filter(Boolean).join(" / ") || safeText(node.role || node.status || "host inventory");
  }
  if (node.type === "external_ip") {
    return [safeText(node.country, ""), safeText(node.org, "")].filter(Boolean).join(" / ") || safeText(node.ip || "external IP");
  }
  return [nodeSourceKindLabel(node), safeText(node.ip || node.role || node.status, "")].filter(Boolean).join(" / ") || safeText(node.type);
}

function nodeCardTitle(node: TopologyNodeRecord | null) {
  if (!node) return "Selected node";
  const kind = nodeSourceKind(node);
  if (kind === "proxmox_host") return "Proxmox host card";
  if (kind === "proxmox_guest") return "Proxmox VM/CT card";
  if (kind === "virtual_router") return "Virtual router card";
  if (kind === "vpn_host" || kind === "vpn_gateway") return "VPN host card";
  if (kind === "siem_core") return "SIEM core host card";
  if (node.type === "source") return "Source card";
  if (node.type === "collector") return "Collector card";
  if (node.type === "core_service") return "SIEM service";
  if (node.type === "protected_public_ip") return "Protected edge";
  if (node.type === "external_ip") return "External source";
  return "Host card";
}

function nodeOpenLabel(node: TopologyNodeRecord) {
  if (node.type === "source") return "Open source card";
  if (node.type === "collector") return "Open collector card";
  if (node.type === "proxmox_guest") return "Open fleet card";
  if (node.type === "discovery_candidate") return "Open discovery card";
  return "Open pivot";
}

function nodeGlyph(node: TopologyNodeRecord) {
  const kind = nodeSourceKind(node);
  if (kind === "proxmox_host") return "PVE";
  if (kind === "proxmox_guest") return "VM";
  if (kind === "virtual_router" || kind === "network_device") return "RTR";
  if (kind === "vpn_host" || kind === "vpn_gateway") return "VPN";
  if (kind === "siem_core") return "SIEM";
  if (node.type === "external_ip") return "IP";
  if (node.type === "protected_public_ip") return "EDGE";
  if (node.type === "core_service") return "SIEM";
  if (node.type === "collector") return "COL";
  if (node.type === "source") return "SRC";
  return "HOST";
}

function shouldShowNodeLabel(node: TopologyGraphNode, selected: boolean, matched: boolean, query: string) {
  const kind = nodeSourceKind(node);
  return (
    selected ||
    (Boolean(query.trim()) && matched) ||
    node.type === "core_service" ||
    node.type === "protected_public_ip" ||
    node.type === "collector" ||
    kind === "proxmox_host" ||
    kind === "virtual_router" ||
    kind === "vpn_host" ||
    kind === "vpn_gateway" ||
    kind === "siem_core"
  );
}

function annotateTopologyNodes(nodes: TopologyNodeRecord[], edges: TopologyEdgeRecord[]): TopologyGraphNode[] {
  const degree = new Map<string, number>();
  for (const edge of edges) {
    degree.set(edge.source, (degree.get(edge.source) || 0) + 1);
    degree.set(edge.target, (degree.get(edge.target) || 0) + 1);
  }
  return [...nodes]
    .sort((left, right) => {
      const laneDelta = TOPOLOGY_LANES[nodeLane(left)].order - TOPOLOGY_LANES[nodeLane(right)].order;
      if (laneDelta !== 0) return laneDelta;
      return safeText(left.label, "").localeCompare(safeText(right.label, ""));
    })
    .map((node) => ({
      ...node,
      degree: degree.get(node.id) || 0,
      lane: nodeLane(node),
    }));
}

function profileMatchesNode(profile: HostAccessProfileRecord, node: TopologyNodeRecord) {
  const nodeId = safeText(node.id, "");
  const nodeIp = safeText(node.ip, "");
  const nodeLabel = safeText(node.label, "").toLowerCase();
  const nodeHost = nodeHostname(node).toLowerCase();
  const profileHostId = safeText(profile.host_id, "");
  const profileIp = safeText(profile.ip, "");
  const profileHost = safeText(profile.hostname || profile.host_label, "").toLowerCase();
  return Boolean(
    (profileHostId && profileHostId === nodeId) ||
      (profileIp && nodeIp && profileIp === nodeIp) ||
      (profileHost && (profileHost === nodeLabel || profileHost === nodeHost)),
  );
}

function cytoscapeClassName(value: string) {
  return value.replace(/[^a-zA-Z0-9_-]/g, "_");
}

function edgeTone(edge: TopologyEdgeRecord) {
  if (edge.type === "attack_observation") return "attack";
  if (edge.type === "needs_onboarding") return "attention";
  if (edge.type === "pipeline" || edge.type === "ingest") return "pipeline";
  return "neutral";
}

function edgeWidth(edge: TopologyEdgeRecord) {
  const events = Number(edge.events || 0);
  if (events > 20000) return 4;
  if (events > 1000) return 3;
  if (edge.type === "pipeline" || edge.type === "ingest") return 3;
  return 2;
}

function topologyNodePosition(node: TopologyGraphNode, laneIndex: number) {
  const lane = CYTOSCAPE_LANE_LAYOUT[node.lane] || CYTOSCAPE_LANE_LAYOUT.inventory;
  const column = laneIndex % lane.columns;
  const row = Math.floor(laneIndex / lane.columns);
  const priorityOffset = Math.min(34, Math.max(0, Number(node.degree || 0) * 3));
  return {
    x: lane.x + column * lane.columnGap,
    y: lane.y + row * lane.rowGap + (column % 2) * 22 - priorityOffset,
  };
}

function buildCytoscapeElements(nodes: TopologyGraphNode[], edges: TopologyEdgeRecord[]): cytoscape.ElementDefinition[] {
  const nodeIds = new Set(nodes.map((node) => node.id));
  const laneIndexes = new Map<string, number>();
  const contourNodes: cytoscape.ElementDefinition[] = Object.entries(TOPOLOGY_LANES).map(([laneId, lane]) => ({
    data: {
      id: `contour:${laneId}`,
      label: lane.label.toUpperCase(),
      lane: laneId,
    },
    classes: `topology-contour contour-${laneId}`,
  }));
  const graphNodes: cytoscape.ElementDefinition[] = nodes.map((node) => {
    const laneIndex = laneIndexes.get(node.lane) || 0;
    laneIndexes.set(node.lane, laneIndex + 1);
    const labelVisible = shouldShowNodeLabel(node, false, true, "");
    const kindClass = nodeSourceKind(node);
    const platformClass = normalizeTopologyClass(node["platform_kind"], "");
    const classes = [
      `type-${cytoscapeClassName(node.type)}`,
      `kind-${cytoscapeClassName(kindClass)}`,
      platformClass ? `platform-${cytoscapeClassName(platformClass)}` : "",
      `tone-${nodeTone(node)}`,
      `lane-${node.lane}`,
      labelVisible ? "labelled" : "",
      Number(node.access_profile_count || 0) > 0 ? "has-access" : "",
    ]
      .filter(Boolean)
      .join(" ");
    return {
      data: {
        id: node.id,
        parent: `contour:${node.lane}`,
        label: nodeDisplayLabel(node),
        meta: nodeDisplayMeta(node),
        glyph: nodeGlyph(node),
        size: nodeSize(node),
        degree: node.degree,
        lane: node.lane,
        type: node.type,
        sourceKind: kindClass,
        sourceKindLabel: nodeSourceKindLabel(node),
        hostname: nodeHostname(node),
        ip: safeText(node.ip, ""),
      },
      position: topologyNodePosition(node, laneIndex),
      classes,
    };
  });

  const graphEdges: cytoscape.ElementDefinition[] = edges
    .filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target))
    .map((edge) => {
      return {
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: safeText(edge.label || edge.type, ""),
          width: edgeWidth(edge),
          events: Number(edge.events || 0),
        },
        classes: [`edge-${cytoscapeClassName(edge.type)}`, `edge-tone-${edgeTone(edge)}`].join(" "),
      };
    });

  return [...contourNodes, ...graphNodes, ...graphEdges];
}

function setCytoscapeClass(element: cytoscape.SingularElementArgument, className: string, enabled: boolean) {
  if (enabled) element.addClass(className);
  else element.removeClass(className);
}

function syncCytoscapeInteractionState(
  cy: cytoscape.Core,
  nodes: TopologyGraphNode[],
  edges: TopologyEdgeRecord[],
  selectedNodeId: string,
  hoveredNodeId: string,
  searchTerm: string,
) {
  const nodeIndex = new Map(nodes.map((node) => [node.id, node]));
  const edgeIndex = new Map(edges.map((edge) => [edge.id, edge]));
  const selectedNeighborIds = new Set<string>();
  if (selectedNodeId) {
    for (const edge of edges) {
      if (edge.source === selectedNodeId) selectedNeighborIds.add(edge.target);
      if (edge.target === selectedNodeId) selectedNeighborIds.add(edge.source);
    }
  }
  const queryActive = Boolean(searchTerm.trim());
  cy.batch(() => {
    cy.nodes().forEach((nodeElement) => {
      if (nodeElement.hasClass("topology-contour")) return;
      const node = nodeIndex.get(nodeElement.id());
      if (!node) return;
      const selected = selectedNodeId === node.id;
      const hovered = hoveredNodeId === node.id;
      const matched = nodeMatchesQuery(node, searchTerm);
      const dimmedBySearch = queryActive && !matched;
      const dimmedBySelection = Boolean(selectedNodeId) && !selected && !selectedNeighborIds.has(node.id);
      setCytoscapeClass(nodeElement, "selected-node", selected);
      setCytoscapeClass(nodeElement, "hovered-node", hovered);
      setCytoscapeClass(nodeElement, "dimmed", dimmedBySearch || dimmedBySelection);
      setCytoscapeClass(nodeElement, "labelled", shouldShowNodeLabel(node, selected || hovered, matched, searchTerm));
    });
    cy.edges().forEach((edgeElement) => {
      const edge = edgeIndex.get(edgeElement.id());
      if (!edge) return;
      const sourceNode = nodeIndex.get(edge.source);
      const targetNode = nodeIndex.get(edge.target);
      const selected = selectedNodeId ? edge.source === selectedNodeId || edge.target === selectedNodeId : false;
      const sourceMatched = sourceNode ? nodeMatchesQuery(sourceNode, searchTerm) : false;
      const targetMatched = targetNode ? nodeMatchesQuery(targetNode, searchTerm) : false;
      const dimmed = (queryActive && !sourceMatched && !targetMatched) || (Boolean(selectedNodeId) && !selected);
      setCytoscapeClass(edgeElement, "selected-edge", selected);
      setCytoscapeClass(edgeElement, "dimmed", dimmed);
    });
  });
}

const CYTOSCAPE_STYLES: cytoscape.StylesheetJson = [
  {
    selector: "node.topology-contour",
    style: {
      label: "data(label)",
      shape: "round-rectangle",
      "background-color": "rgba(5, 14, 23, 0.34)",
      "background-opacity": 0.2,
      "border-color": "rgba(141, 167, 198, 0.14)",
      "border-style": "solid",
      "border-width": 1,
      color: "rgba(190, 205, 226, 0.82)",
      "font-family": "var(--font-mono)",
      "font-size": 14,
      "font-weight": 900,
      "min-zoomed-font-size": 1,
      padding: 24,
      "text-halign": "center",
      "text-margin-y": -18,
      "text-outline-color": "#06111c",
      "text-outline-width": 3,
      "text-valign": "top",
      "z-index": 0,
    },
  },
  {
    selector: "node.contour-external",
    style: {
      "background-color": "rgba(255, 108, 130, 0.05)",
      "border-color": "rgba(255, 108, 130, 0.28)",
      color: "rgba(255, 177, 190, 0.86)",
    },
  },
  {
    selector: "node.contour-source",
    style: {
      "background-color": "rgba(129, 255, 218, 0.05)",
      "border-color": "rgba(129, 255, 218, 0.26)",
      color: "rgba(190, 255, 236, 0.86)",
    },
  },
  {
    selector: "node.contour-collector, node.contour-core",
    style: {
      "background-color": "rgba(105, 216, 255, 0.05)",
      "border-color": "rgba(105, 216, 255, 0.28)",
      color: "rgba(206, 242, 255, 0.88)",
    },
  },
  {
    selector: "node",
    style: {
      width: "data(size)",
      height: "data(size)",
      label: "",
      "background-color": "#101d2b",
      "border-color": "rgba(141, 167, 198, 0.48)",
      "border-width": 2,
      color: "#eef7ff",
      "font-family": "var(--font-mono)",
      "font-size": 12,
      "font-weight": 800,
      "min-zoomed-font-size": 1,
      "overlay-opacity": 0,
      "text-background-color": "#06111c",
      "text-background-opacity": 0.74,
      "text-background-padding": 4,
      "text-border-color": "rgba(105, 216, 255, 0.2)",
      "text-border-opacity": 1,
      "text-border-width": 1,
      "text-halign": "center",
      "text-margin-y": 8,
      "text-max-width": 104,
      "text-outline-color": "#06111c",
      "text-outline-width": 2,
      "text-valign": "bottom",
      "text-wrap": "wrap",
    },
  },
  {
    selector: "node.labelled",
    style: {
      label: "data(label)",
    },
  },
  {
    selector: "node.type-core_service",
    style: {
      shape: "round-rectangle",
      width: 82,
      height: 44,
      "background-color": "rgba(63, 205, 246, 0.18)",
      "border-color": "rgba(105, 216, 255, 0.9)",
      color: "#d9f5ff",
      "text-max-width": 128,
    },
  },
  {
    selector: "node.type-protected_public_ip",
    style: {
      "background-color": "rgba(255, 108, 130, 0.12)",
      "border-color": "rgba(255, 108, 130, 0.9)",
      color: "#fff1f4",
    },
  },
  {
    selector: "node.type-external_ip",
    style: {
      "background-color": "rgba(255, 108, 130, 0.08)",
      "border-color": "rgba(255, 108, 130, 0.78)",
    },
  },
  {
    selector: "node.type-source",
    style: {
      "background-color": "rgba(129, 255, 218, 0.12)",
      "border-color": "rgba(129, 255, 218, 0.86)",
      color: "#ddfff6",
      "text-max-width": 116,
    },
  },
  {
    selector: "node.kind-proxmox_host, node.platform-proxmox_guest",
    style: {
      shape: "round-octagon",
      "background-color": "rgba(244, 187, 98, 0.13)",
      "border-color": "rgba(244, 187, 98, 0.92)",
      color: "#fff1d8",
    },
  },
  {
    selector: "node.kind-virtual_router, node.kind-network_device",
    style: {
      shape: "diamond",
      "background-color": "rgba(129, 255, 218, 0.16)",
      "border-color": "rgba(129, 255, 218, 0.96)",
      color: "#e0fff8",
      "text-max-width": 132,
    },
  },
  {
    selector: "node.kind-vpn_host, node.kind-vpn_gateway",
    style: {
      shape: "tag",
      "background-color": "rgba(255, 108, 130, 0.18)",
      "border-color": "rgba(255, 108, 130, 0.96)",
      color: "#fff1f4",
      "text-max-width": 138,
    },
  },
  {
    selector: "node.kind-siem_core",
    style: {
      "background-color": "rgba(105, 216, 255, 0.16)",
      "border-color": "rgba(105, 216, 255, 0.96)",
      color: "#e6f8ff",
    },
  },
  {
    selector: "node.type-collector",
    style: {
      "background-color": "rgba(129, 179, 255, 0.12)",
      "border-color": "rgba(129, 179, 255, 0.86)",
      color: "#e5efff",
      "text-max-width": 124,
    },
  },
  {
    selector: "node.tone-warn, node.tone-attention",
    style: {
      "border-color": "rgba(244, 187, 98, 0.88)",
    },
  },
  {
    selector: "node.has-access",
    style: {
      "border-style": "double",
      "border-width": 4,
    },
  },
  {
    selector: "node.selected-node, node.hovered-node",
    style: {
      "background-color": "rgba(63, 205, 246, 0.34)",
      "border-color": "#78ecff",
      "border-width": 4,
      label: "data(label)",
      "z-index": 20,
    },
  },
  {
    selector: "node.dimmed",
    style: {
      opacity: 0.18,
    },
  },
  {
    selector: "edge",
    style: {
      width: "data(width)",
      "curve-style": "bezier",
      "line-color": "rgba(141, 167, 198, 0.32)",
      opacity: 0.46,
      "target-arrow-color": "rgba(141, 167, 198, 0.5)",
      "target-arrow-shape": "triangle",
    },
  },
  {
    selector: "edge.edge-tone-attack",
    style: {
      "line-color": "rgba(255, 108, 130, 0.58)",
      opacity: 0.4,
      "target-arrow-color": "rgba(255, 108, 130, 0.58)",
    },
  },
  {
    selector: "edge.edge-tone-attention",
    style: {
      "line-color": "rgba(244, 187, 98, 0.58)",
      "line-style": "dashed",
      opacity: 0.38,
      "target-arrow-color": "rgba(244, 187, 98, 0.58)",
    },
  },
  {
    selector: "edge.edge-tone-pipeline",
    style: {
      "line-color": "rgba(105, 216, 255, 0.72)",
      "target-arrow-color": "rgba(105, 216, 255, 0.72)",
    },
  },
  {
    selector: "edge.selected-edge",
    style: {
      opacity: 1,
      width: 4,
      "z-index": 12,
    },
  },
  {
    selector: "edge.dimmed",
    style: {
      opacity: 0.08,
    },
  },
];

function runTopologyLayout(cy: cytoscape.Core, onStop?: () => void) {
  const handleStop = () => {
    fitTopologyViewport(cy);
    onStop?.();
  };
  const layoutElements = cy.elements().not(".topology-contour");
  try {
    layoutElements.layout({
      name: "preset",
      fit: false,
      padding: 56,
      animate: true,
      animationDuration: 620,
      stop: handleStop,
    }).run();
  } catch {
    layoutElements.layout({
      name: "cose",
      animate: true,
      animationDuration: 620,
      refresh: 24,
      fit: false,
      padding: 56,
      nodeRepulsion: 92000,
      nodeOverlap: 14,
      idealEdgeLength: 120,
      edgeElasticity: 110,
      nestingFactor: 1.08,
      gravity: 0.14,
      numIter: 1800,
      randomize: false,
      stop: handleStop,
    }).run();
  }
}

function fitTopologyViewport(cy: cytoscape.Core) {
  cy.fit(undefined, 72);
  if (cy.zoom() < 0.45) {
    cy.zoom({ level: 0.45, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    cy.center();
  }
}

type CytoscapeTopologyCanvasProps = {
  nodes: TopologyGraphNode[];
  edges: TopologyEdgeRecord[];
  selectedNodeId: string;
  hoveredNodeId: string;
  searchTerm: string;
  command: TopologyGraphCommand;
  onSelectNode: (nodeId: string) => void;
  onHoverNode: (nodeId: string) => void;
  onZoomChange: (zoomPercent: number) => void;
};

function CytoscapeTopologyCanvas({
  nodes,
  edges,
  selectedNodeId,
  hoveredNodeId,
  searchTerm,
  command,
  onSelectNode,
  onHoverNode,
  onZoomChange,
}: CytoscapeTopologyCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const graphSignature = useMemo(() => `${nodes.map((node) => node.id).join("|")}::${edges.map((edge) => edge.id).join("|")}`, [edges, nodes]);
  const elements = useMemo(() => buildCytoscapeElements(nodes, edges), [edges, nodes]);

  useEffect(() => {
    if (!containerRef.current) return undefined;
    const cy = cytoscape({
      container: containerRef.current,
      elements: [],
      style: CYTOSCAPE_STYLES,
      minZoom: 0.3,
      maxZoom: 2.6,
      wheelSensitivity: 0.18,
      boxSelectionEnabled: false,
    });
    cyRef.current = cy;
    cy.on("tap", "node", (event) => {
      if (event.target.hasClass("topology-contour")) return;
      onSelectNode(event.target.id());
    });
    cy.on("mouseover", "node", (event) => {
      if (event.target.hasClass("topology-contour")) return;
      onHoverNode(event.target.id());
    });
    cy.on("mouseout", "node", () => onHoverNode(""));
    cy.on("tap", (event) => {
      if (event.target === cy) onSelectNode("");
    });
    cy.on("zoom", () => onZoomChange(Math.round(cy.zoom() * 100)));
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [onHoverNode, onSelectNode, onZoomChange]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().remove();
    cy.add(elements);
    runTopologyLayout(cy, () => {
      onZoomChange(Math.round(cy.zoom() * 100));
    });
  }, [elements, graphSignature, onZoomChange]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    syncCytoscapeInteractionState(cy, nodes, edges, selectedNodeId, hoveredNodeId, searchTerm);
  }, [edges, hoveredNodeId, nodes, searchTerm, selectedNodeId]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || command.nonce === 0) return;
    const center = { x: cy.width() / 2, y: cy.height() / 2 };
    if (command.kind === "zoom-in") {
      cy.zoom({ level: Math.min(2.6, cy.zoom() * 1.18), renderedPosition: center });
    } else if (command.kind === "zoom-out") {
      cy.zoom({ level: Math.max(0.3, cy.zoom() / 1.18), renderedPosition: center });
    } else if (command.kind === "fit") {
      fitTopologyViewport(cy);
    } else {
      runTopologyLayout(cy, () => {
        onZoomChange(Math.round(cy.zoom() * 100));
      });
    }
    onZoomChange(Math.round(cy.zoom() * 100));
  }, [command, onZoomChange]);

  return (
    <div className="react-topology-widget">
      <div className="react-topology-cytoscape" ref={containerRef} aria-label="Interactive Cytoscape network topology widget" />
      <div className="react-topology-widget-hint">
        Cytoscape.js widget: drag nodes, pan canvas, wheel to zoom, click a node for host details and SOAR access card.
      </div>
    </div>
  );
}

function canonicalTopologyKey(node: TopologyGraphNode) {
  const host = nodeHostname(node);
  const ip = safeText(node.ip, "");
  return safeText(host || ip || nodeDisplayLabel(node) || node.id, node.id).toLowerCase();
}

function uniqueTopologyNodes(nodes: TopologyGraphNode[]) {
  const byKey = new Map<string, TopologyGraphNode>();
  for (const node of nodes) {
    const key = canonicalTopologyKey(node);
    const current = byKey.get(key);
    if (!current || Number(node.events || 0) + node.degree > Number(current.events || 0) + current.degree) {
      byKey.set(key, node);
    }
  }
  return Array.from(byKey.values());
}

function findCoreNode(nodes: TopologyGraphNode[], token: string) {
  const normalized = token.toLowerCase();
  return nodes.find((node) => node.type === "core_service" && [node.label, node.role, node.id].some((value) => String(value || "").toLowerCase().includes(normalized)));
}

function packetTracerNode(
  id: string,
  label: string,
  meta: string,
  x: number,
  y: number,
  shape: PacketTracerNodeShape,
  lane: string,
  kind: string,
  node?: TopologyGraphNode,
  width = 152,
  height = 58,
  count?: number,
): PacketTracerVisualNode {
  return {
    id,
    sourceId: node?.id,
    label,
    meta,
    x,
    y,
    width,
    height,
    lane,
    kind,
    shape,
    node,
    count,
  };
}

function packetTracerEdge(source: string, target: string, tone: PacketTracerVisualEdge["tone"], label?: string, dashed = false): PacketTracerVisualEdge {
  return {
    id: `${source}->${target}:${tone}:${label || ""}`,
    source,
    target,
    tone,
    label,
    dashed,
  };
}

function buildPacketTracerModel(nodes: TopologyGraphNode[], packetFlows: NetworkPacketFlowRecord[]) {
  const modelNodes: PacketTracerVisualNode[] = [];
  const modelEdges: PacketTracerVisualEdge[] = [];
  const nodeById = new Map<string, PacketTracerVisualNode>();
  const addNode = (node: PacketTracerVisualNode) => {
    if (nodeById.has(node.id)) return nodeById.get(node.id)!;
    nodeById.set(node.id, node);
    modelNodes.push(node);
    return node;
  };
  const addEdge = (edge: PacketTracerVisualEdge) => {
    if (!nodeById.has(edge.source) || !nodeById.has(edge.target)) return;
    if (modelEdges.some((item) => item.id === edge.id)) return;
    modelEdges.push(edge);
  };

  const externalNodes = uniqueTopologyNodes(nodes.filter((node) => node.type === "external_ip"))
    .sort((left, right) => Number(right.events || 0) - Number(left.events || 0));
  const protectedNodes = uniqueTopologyNodes(nodes.filter((node) => node.type === "protected_public_ip"));
  const collectorNodes = uniqueTopologyNodes(nodes.filter((node) => node.type === "collector"))
    .sort((left, right) => Number(right.events || 0) - Number(left.events || 0));
  const sourceNodes = uniqueTopologyNodes(nodes.filter((node) => node.type === "source"))
    .sort((left, right) => Number(right.events || 0) - Number(left.events || 0));
  const physicalNodes = uniqueTopologyNodes(
    nodes.filter((node) => !["external_ip", "protected_public_ip", "collector", "core_service", "source"].includes(node.type)),
  ).sort((left, right) => Number(right.events || 0) + right.degree - (Number(left.events || 0) + left.degree));
  const networkNodes = physicalNodes.filter((node) => {
    const kind = nodeSourceKind(node);
    const label = nodeDisplayLabel(node).toLowerCase();
    return kind.includes("router") || kind.includes("network") || kind.includes("vpn") || label.includes("opnsense") || label.includes("gateway") || label.includes("edge");
  });
  const hostNodes = physicalNodes.filter((node) => !networkNodes.some((networkNode) => networkNode.id === node.id));
  const coreNodes = nodes.filter((node) => node.type === "core_service");

  const totalExternalEvents = externalNodes.reduce((sum, node) => sum + Number(node.events || 0), 0);
  const totalTelemetryEvents = sourceNodes.reduce((sum, node) => sum + Number(node.events || 0), 0);
  const flowProtocols = Array.from(new Set(packetFlows.flatMap((flow) => flowTokens(flow.protocols)))).slice(0, 4);
  const flowPorts = Array.from(new Set(packetFlows.flatMap((flow) => flowTokens(flow.ports)))).slice(0, 5);
  const externalHub = addNode(packetTracerNode(
    "tracer:internet",
    "Internet sources",
    `${externalNodes.length.toLocaleString()} IP / ${totalExternalEvents.toLocaleString()} events`,
    58,
    170,
    "cloud",
    "internet",
    "external",
    externalNodes[0],
    146,
    72,
    externalNodes.length,
  ));

  const edgeRows = protectedNodes.length ? protectedNodes : [];
  const edgePrimary = edgeRows[0];
  const protectedEdge = addNode(packetTracerNode(
    edgePrimary ? `tracer:edge:${edgePrimary.id}` : "tracer:edge:public",
    edgePrimary ? nodeDisplayLabel(edgePrimary) : "Protected public IP",
    edgePrimary ? nodeDisplayMeta(edgePrimary) : "WAN ingress / VPN listener",
    300,
    166,
    "edge",
    "edge",
    edgePrimary ? nodeSourceKind(edgePrimary) : "vpn_gateway",
    edgePrimary,
    164,
    62,
    edgeRows.length,
  ));
  if (edgeRows.length > 1) {
    const secondary = edgeRows[1];
    const secondaryEdge = addNode(packetTracerNode(
      `tracer:edge:${secondary.id}`,
      nodeDisplayLabel(secondary),
      nodeDisplayMeta(secondary),
      300,
      284,
      "edge",
      "edge",
      nodeSourceKind(secondary),
      secondary,
      164,
      56,
    ));
    addEdge(packetTracerEdge(externalHub.id, secondaryEdge.id, "attack", "WAN", false));
  }

  const routerNode = networkNodes.find((node) => nodeDisplayLabel(node).toLowerCase().includes("opnsense")) || networkNodes[0];
  const router = addNode(packetTracerNode("tracer:router", routerNode ? nodeDisplayLabel(routerNode) : "Virtual router", routerNode ? nodeDisplayMeta(routerNode) : "firewall, NAT, VPN routing", 554, 166, "router", "network", routerNode ? nodeSourceKind(routerNode) : "virtual_router", routerNode, 168, 68));
  const switchNode = addNode(packetTracerNode("tracer:switch", "Core LAN switch", "VLAN / east-west forwarding", 554, 330, "switch", "network", "switch", undefined, 168, 58));

  const proxmoxHosts = hostNodes.filter((node) => ["proxmox_host", "proxmox_guest"].includes(nodeSourceKind(node)));
  const vpnHosts = hostNodes.filter((node) => ["vpn_host", "vpn_gateway"].includes(nodeSourceKind(node)));
  const siemHosts = hostNodes.filter((node) => nodeSourceKind(node) === "siem_core" || safeText(node.label, "").toLowerCase().startsWith("siem-"));
  const otherHosts = hostNodes.filter((node) => !proxmoxHosts.includes(node) && !vpnHosts.includes(node) && !siemHosts.includes(node));
  const hostGroups = [
    { id: "siem", label: "SIEM VMs", meta: `${siemHosts.length || 5} core hosts`, kind: "siem_core", node: siemHosts[0], count: siemHosts.length },
    { id: "proxmox", label: "Proxmox fleet", meta: `${proxmoxHosts.length} host/VM/CT`, kind: "proxmox_host", node: proxmoxHosts[0], count: proxmoxHosts.length },
    { id: "vpn", label: "VPN hosts", meta: `${vpnHosts.length} remote/protected hosts`, kind: "vpn_host", node: vpnHosts[0], count: vpnHosts.length },
    { id: "other", label: "Discovered hosts", meta: `${otherHosts.length} LAN assets`, kind: "host", node: otherHosts[0], count: otherHosts.length },
  ].filter((group) => group.count > 0 || group.id === "siem");
  const hostVisuals: PacketTracerVisualNode[] = hostGroups.map((group, index) => addNode(packetTracerNode(
    `tracer:host-group:${group.id}`,
    group.label,
    group.meta,
    830 + (index % 2) * 160,
    130 + Math.floor(index / 2) * 132,
    group.id === "proxmox" ? "aggregate" : "host",
    "hosts",
    group.kind,
    group.node,
    144,
    64,
    group.count,
  )));

  const telemetrySource = addNode(packetTracerNode(
    "tracer:sources",
    "Telemetry sources",
    `${sourceNodes.length.toLocaleString()} bindings / ${totalTelemetryEvents.toLocaleString()} ev`,
    1200,
    164,
    "source",
    "telemetry",
    "source",
    sourceNodes[0],
    168,
    64,
    sourceNodes.length,
  ));
  const collectors = addNode(packetTracerNode(
    "tracer:collectors",
    "Collectors",
    `${collectorNodes.length.toLocaleString()} collectors / ${flowProtocols.join(", ") || "syslog, API"}`,
    1200,
    332,
    "collector",
    "telemetry",
    "collector",
    collectorNodes[0],
    168,
    64,
    collectorNodes.length,
  ));

  const corePositions = [
    { key: "ingest", label: "Ingest", x: 1512, y: 110 },
    { key: "transport", label: "Transport", x: 1676, y: 110 },
    { key: "processing", label: "Processing", x: 1676, y: 244 },
    { key: "storage", label: "Storage", x: 1512, y: 244 },
    { key: "web", label: "Web UI / API", x: 1512, y: 414 },
    { key: "soar", label: "SOAR / IRP", x: 1676, y: 414 },
  ];
  for (const position of corePositions) {
    const node = findCoreNode(coreNodes, position.key);
    addNode(packetTracerNode(`tracer:core:${position.key}`, node ? nodeDisplayLabel(node) : position.label, node ? nodeDisplayMeta(node) : "SIEM core service", position.x, position.y, "service", "core", "siem_core", node, 142, 62));
  }

  addEdge(packetTracerEdge(externalHub.id, protectedEdge.id, "attack", "WAN", false));
  addEdge(packetTracerEdge(protectedEdge.id, router.id, "edge", "NAT / VPN", false));
  addEdge(packetTracerEdge(router.id, switchNode.id, "lan", "routed LAN", false));
  for (const host of hostVisuals) {
    addEdge(packetTracerEdge(switchNode.id, host.id, "lan", host.kind === "proxmox_host" ? "VM/CT" : "LAN", false));
    addEdge(packetTracerEdge(host.id, telemetrySource.id, "telemetry", "logs", true));
  }
  addEdge(packetTracerEdge(telemetrySource.id, collectors.id, "telemetry", flowPorts.length ? `ports ${flowPorts.join(",")}` : "syslog/API", false));
  addEdge(packetTracerEdge(collectors.id, "tracer:core:ingest", "pipeline", "HTTP/TCP", false));
  addEdge(packetTracerEdge("tracer:core:ingest", "tracer:core:transport", "pipeline", "validated events", false));
  addEdge(packetTracerEdge("tracer:core:transport", "tracer:core:processing", "pipeline", "stream/batch", false));
  addEdge(packetTracerEdge("tracer:core:processing", "tracer:core:storage", "pipeline", "normalized logs", false));
  addEdge(packetTracerEdge("tracer:core:storage", "tracer:core:web", "pipeline", "queries", false));
  addEdge(packetTracerEdge("tracer:core:processing", "tracer:core:soar", "soar", "alerts/playbooks", false));
  addEdge(packetTracerEdge("tracer:core:soar", switchNode.id, "soar", "IR action", true));

  return { nodes: modelNodes, edges: modelEdges };
}

function packetTracerEdgePath(edge: PacketTracerVisualEdge, nodes: Map<string, PacketTracerVisualNode>) {
  const source = nodes.get(edge.source);
  const target = nodes.get(edge.target);
  if (!source || !target) return "";
  const x1 = source.x + source.width / 2;
  const y1 = source.y + source.height / 2;
  const x2 = target.x + target.width / 2;
  const y2 = target.y + target.height / 2;
  const midX = x1 + (x2 - x1) * 0.52;
  return `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
}

type PacketTracerTopologyProps = {
  nodes: TopologyGraphNode[];
  packetFlows: NetworkPacketFlowRecord[];
  selectedNodeId: string;
  searchTerm: string;
  onSelectNode: (nodeId: string) => void;
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function PacketTracerTopology({ nodes, packetFlows, selectedNodeId, searchTerm, onSelectNode }: PacketTracerTopologyProps) {
  const model = useMemo(() => buildPacketTracerModel(nodes, packetFlows), [nodes, packetFlows]);
  const visualIndex = useMemo(() => new Map(model.nodes.map((node) => [node.id, node])), [model.nodes]);
  const selectedVisualId = model.nodes.find((node) => node.sourceId === selectedNodeId)?.id || "";
  return (
    <div className="react-packet-tracer-wrap" aria-label="Network packet path diagram">
      <svg className="react-packet-tracer-map" viewBox="0 0 1860 680" role="img" aria-label="Network packet path diagram from Internet to SIEM pipeline">
        <defs>
          <marker id="packetTracerArrow" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
            <path d="M 0 0 L 8 4 L 0 8 z" className="react-packet-tracer-arrow" />
          </marker>
          <filter id="packetTracerGlow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feColorMatrix in="blur" type="matrix" values="0 0 0 0 0.18 0 0 0 0 0.78 0 0 0 0 0.95 0 0 0 0.42 0" result="glow" />
            <feMerge>
              <feMergeNode in="glow" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <rect x="0" y="0" width="1860" height="680" rx="26" className="react-packet-tracer-bg" />
        {PACKET_TRACER_LANES.map((lane) => (
          <g key={lane.id} className={`react-packet-tracer-lane lane-${lane.id}`}>
            <rect x={lane.x} y={lane.y} width={lane.width} height={lane.height} rx="18" />
            <text x={lane.x + 16} y={lane.y + 28}>{lane.label}</text>
          </g>
        ))}
        {model.edges.map((edge) => {
          const edgePathId = `packet-tracer-${edge.id.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
          return (
            <g key={edge.id} className={`react-packet-tracer-link tone-${edge.tone}${edge.dashed ? " dashed" : ""}`}>
              <path id={edgePathId} d={packetTracerEdgePath(edge, visualIndex)} markerEnd="url(#packetTracerArrow)" />
              {edge.label ? (
                <text>
                  <textPath href={`#${edgePathId}`} startOffset="50%">
                    {edge.label}
                  </textPath>
                </text>
              ) : null}
            </g>
          );
        })}
        {model.nodes.map((node) => {
          const selected = selectedVisualId === node.id || selectedNodeId === node.sourceId;
          const matched = topologySearchMatch(node, searchTerm);
          const className = [
            "react-packet-tracer-device",
            `shape-${node.shape}`,
            `lane-${node.lane}`,
            `kind-${cytoscapeClassName(node.kind)}`,
            selected ? "selected" : "",
            !matched ? "dimmed" : "",
          ].filter(Boolean).join(" ");
          return (
            <g
              key={node.id}
              className={className}
              transform={`translate(${node.x} ${node.y})`}
              tabIndex={node.sourceId ? 0 : -1}
              role={node.sourceId ? "button" : "img"}
              onClick={() => node.sourceId && onSelectNode(node.sourceId)}
              onKeyDown={(event) => {
                if (!node.sourceId) return;
                if (event.key === "Enter" || event.key === " ") onSelectNode(node.sourceId);
              }}
            >
              {node.shape === "cloud" ? (
                <path d={`M 26 ${node.height * 0.62} C 6 ${node.height * 0.56}, 6 ${node.height * 0.28}, 34 ${node.height * 0.3} C 42 5, 80 8, 86 30 C 112 22, 136 38, 128 ${node.height * 0.62} C 126 ${node.height * 0.88}, 38 ${node.height * 0.92}, 26 ${node.height * 0.62} Z`} />
              ) : node.shape === "router" ? (
                <path d={`M ${node.width / 2} 2 L ${node.width - 6} ${node.height / 2} L ${node.width / 2} ${node.height - 2} L 6 ${node.height / 2} Z`} />
              ) : node.shape === "edge" ? (
                <path d={`M 12 2 H ${node.width - 28} L ${node.width - 4} ${node.height / 2} L ${node.width - 28} ${node.height - 2} H 12 Z`} />
              ) : (
                <rect x="0" y="0" width={node.width} height={node.height} rx={node.shape === "service" ? 10 : 16} />
              )}
              <text className="react-packet-tracer-glyph" x={node.width / 2} y={node.shape === "cloud" ? 28 : 18}>{nodeGlyph(node.node || ({ type: node.shape, label: node.label } as TopologyNodeRecord))}</text>
              <text className="react-packet-tracer-label" x={node.width / 2} y={node.height / 2 + 5}>{shortenTopologyLabel(node.label, 24)}</text>
              <text className="react-packet-tracer-meta" x={node.width / 2} y={node.height - 10}>{shortenTopologyLabel(node.meta, 28)}</text>
              {node.count ? <text className="react-packet-tracer-count" x={node.width - 14} y="18">{node.count}</text> : null}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

type OlympusMapNodeShape = "sentinel" | "cloud" | "edge" | "router" | "switch" | "host" | "windows" | "linux" | "proxmox" | "vpn" | "collector" | "service" | "holding";

type OlympusMapNode = {
  id: string;
  sourceId?: string;
  label: string;
  meta: string;
  x: number;
  y: number;
  width: number;
  height: number;
  shape: OlympusMapNodeShape;
  kind: string;
  zone: string;
  node?: TopologyGraphNode;
  count?: number;
  details?: string[];
  status?: "healthy" | "degraded" | "stale" | "error" | "unknown";
};

type OlympusMapEdge = {
  id: string;
  source: string;
  target: string;
  tone: "wan" | "lan" | "telemetry" | "siem" | "response" | "attack" | "management" | "metrics";
  label?: string;
  curved?: boolean;
};

type OlympusMapZone = {
  id: string;
  label: string;
  meta?: string;
  x: number;
  y: number;
  width: number;
  height: number;
  tone: "external" | "edge" | "network" | "hosts" | "telemetry" | "siem" | "holding" | "management" | "storage" | "control";
};

type OlympusMapModel = {
  title: string;
  subtitle: string;
  treeTitle: string;
  treeItems: string[];
  nodes: OlympusMapNode[];
  edges: OlympusMapEdge[];
  zones: OlympusMapZone[];
  legend: Array<{ tone: OlympusMapEdge["tone"]; label: string }>;
};

const OLYMPUS_VIEWBOX_WIDTH = 1740;
const OLYMPUS_VIEWBOX_HEIGHT = 900;

const OLYMPUS_MAP_ZONES: OlympusMapZone[] = [
  { id: "internet", label: "External Observed Threats", meta: "WAN / public IPs / Trust: Untrusted", x: 24, y: 76, width: 230, height: 360, tone: "external" },
  { id: "perimeter", label: "DMZ / Public Edge", meta: "VLAN 10 / public edge / Trust: Low", x: 300, y: 92, width: 230, height: 360, tone: "edge" },
  { id: "lan", label: "Core LAN / Routing", meta: "VLAN 20 / 192.168.1.0/24 / Trust: Medium", x: 570, y: 62, width: 290, height: 450, tone: "network" },
  { id: "hosts", label: "Server / Endpoint VLANs", meta: "VLAN 30 / lab hosts / Trust: Medium", x: 52, y: 500, width: 560, height: 258, tone: "hosts" },
  { id: "collectors", label: "SIEM Ingest Zone", meta: "TCP/6514 + HTTPS/8443 / Trust: High", x: 640, y: 526, width: 270, height: 232, tone: "telemetry" },
  { id: "data", label: "SIEM Data Plane", meta: "VLAN 40 / ingest-processing-storage / Trust: High", x: 930, y: 72, width: 265, height: 408, tone: "siem" },
  { id: "control", label: "SIEM Control Plane", meta: "VLAN 50/99 / SOC admin / Trust: Critical", x: 1215, y: 72, width: 265, height: 408, tone: "control" },
  { id: "holding", label: "Unmanaged / Uncovered Assets", meta: "Discovery queue / confidence + onboarding", x: 930, y: 526, width: 550, height: 232, tone: "holding" },
];

const OLYMPUS_DEFAULT_LEGEND: OlympusMapModel["legend"] = [
  { tone: "telemetry", label: "telemetry / log flow" },
  { tone: "lan", label: "network forwarding" },
  { tone: "management", label: "management / control" },
  { tone: "attack", label: "attack / IOC path" },
  { tone: "response", label: "discovery / response" },
  { tone: "metrics", label: "metrics / healthcheck" },
];

function olympusNode(
  id: string,
  label: string,
  meta: string,
  x: number,
  y: number,
  shape: OlympusMapNodeShape,
  kind: string,
  zone: string,
  node?: TopologyGraphNode,
  width = 128,
  height = 58,
  count?: number,
  details?: string[],
  status: OlympusMapNode["status"] = "unknown",
): OlympusMapNode {
  return { id, sourceId: node?.id, label, meta, x, y, width, height, shape, kind, zone, node, count, details, status };
}

function olympusEdge(source: string, target: string, tone: OlympusMapEdge["tone"], label?: string, curved = true): OlympusMapEdge {
  return { id: `olympus:${source}->${target}:${tone}:${label || ""}`, source, target, tone, label, curved };
}

function olympusHostBucket(node: TopologyGraphNode) {
  const text = `${nodeDisplayLabel(node)} ${nodeDisplayMeta(node)} ${nodeSourceKind(node)} ${safeText(node.role, "")}`.toLowerCase();
  if (text.includes("windows") || text.includes("desktop")) return "windows";
  if (text.includes("linux") || text.includes("ubuntu") || text.includes("debian")) return "linux";
  if (text.includes("proxmox") || text.includes("pve")) return "proxmox";
  if (text.includes("vpn") || text.includes("gateway") || text.includes("edge")) return "vpn";
  if (text.includes("siem-")) return "siem";
  return "host";
}

function olympusNodeIcon(shape: OlympusMapNodeShape, kind: string) {
  if (shape === "sentinel") return "SIEM";
  if (shape === "cloud") return "IP";
  if (shape === "edge") return "VPN";
  if (shape === "router") return "RTR";
  if (shape === "switch") return "SW";
  if (shape === "collector") return "COL";
  if (shape === "service") return "SVC";
  if (shape === "holding") return "NEW";
  if (kind === "windows" || shape === "windows") return "WIN";
  if (kind === "linux" || shape === "linux") return "LNX";
  if (kind === "proxmox" || shape === "proxmox") return "PVE";
  if (kind === "vpn" || shape === "vpn") return "VPN";
  return "HOST";
}

function olympusSampleNames(nodes: TopologyGraphNode[], limit = 3) {
  return Array.from(new Set(nodes.map((node) => nodeDisplayLabel(node)).filter(Boolean))).slice(0, limit);
}

function olympusNodeStatus(node: TopologyGraphNode | undefined, fallback: OlympusMapNode["status"] = "healthy"): OlympusMapNode["status"] {
  const status = safeText(node?.status, "").toLowerCase();
  if (["error", "failed", "down", "critical"].some((token) => status.includes(token))) return "error";
  if (["stale", "silent"].some((token) => status.includes(token))) return "stale";
  if (["warn", "degraded", "partial"].some((token) => status.includes(token))) return "degraded";
  if (["ok", "up", "healthy", "active", "covered"].some((token) => status.includes(token))) return "healthy";
  return fallback;
}

function olympusEventsPerHour(events: number) {
  if (!Number.isFinite(events) || events <= 0) return "EPS n/a";
  const eps = events / 3600;
  if (eps >= 100) return `${Math.round(eps).toLocaleString()}/s est`;
  if (eps >= 10) return `${eps.toFixed(1)}/s est`;
  return `${eps.toFixed(2)}/s est`;
}

function olympusCoverageDetails(nodes: TopologyGraphNode[], extras: string[] = []) {
  const events = nodes.reduce((sum, node) => sum + Number(node.events || 0), 0);
  const stale = nodes.filter((node) => olympusNodeStatus(node) === "stale").length;
  return [
    `status: ${stale ? `${stale} stale` : "healthy"}`,
    `load: ${olympusEventsPerHour(events)} / ${events.toLocaleString()} ev`,
    ...extras,
  ];
}

function olympusSourceGroupKey(node: TopologyGraphNode) {
  const label = `${nodeSourceKindLabel(node)} ${safeText(node.role, "")} ${safeText(node.label, "")}`.toLowerCase();
  if (label.includes("vulnerab") || label.includes("greenbone") || label.includes("edr") || label.includes("ids") || label.includes("suricata")) return "security-sources";
  if (label.includes("windows") || label.includes("powershell") || label.includes("sysmon") || label.includes("linux") || label.includes("audit")) return "host-sources";
  if (label.includes("router") || label.includes("firewall") || label.includes("vpn") || label.includes("syslog")) return "network-sources";
  if (label.includes("proxmox") || label.includes("nginx") || label.includes("postgres") || label.includes("mongo") || label.includes("clickhouse")) return "infrastructure-sources";
  if (label.includes("json") || label.includes("application") || label.includes("web")) return "application-sources";
  return "infrastructure-sources";
}

function olympusSourceGroupLabel(key: string) {
  const labels: Record<string, string> = {
    "network-sources": "Network sources",
    "host-sources": "Host sources",
    "infrastructure-sources": "Infrastructure sources",
    "application-sources": "Application sources",
    "security-sources": "Security sources",
  };
  return labels[key] || key.replace(/[-_]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function olympusSourceGroupMeta(key: string) {
  const labels: Record<string, string> = {
    "network-sources": "firewall / router / VPN / IDS",
    "host-sources": "Windows / Sysmon / Linux audit",
    "infrastructure-sources": "Proxmox / DB / Nginx / CH",
    "application-sources": "business app / API / web logs",
    "security-sources": "EDR / scanner / SIEM alerts",
  };
  return labels[key] || "telemetry class";
}

function olympusSourceGroupOrder(key: string) {
  const order: Record<string, number> = {
    "network-sources": 0,
    "host-sources": 1,
    "infrastructure-sources": 2,
    "application-sources": 3,
    "security-sources": 4,
  };
  return order[key] ?? 99;
}

function olympusDominantSourceGroupKey(nodes: TopologyGraphNode[]) {
  const counts = new Map<string, number>();
  for (const node of nodes) {
    const key = olympusSourceGroupKey(node);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return Array.from(counts.entries())
    .sort(([leftKey, leftCount], [rightKey, rightCount]) => {
      if (rightCount !== leftCount) return rightCount - leftCount;
      return olympusSourceGroupOrder(leftKey) - olympusSourceGroupOrder(rightKey);
    })[0]?.[0] || "infrastructure-sources";
}

function olympusSourceClassSummary(nodes: TopologyGraphNode[]) {
  const counts = new Map<string, number>();
  for (const node of nodes) {
    const key = olympusSourceGroupKey(node);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return Array.from(counts.entries())
    .sort(([leftKey], [rightKey]) => olympusSourceGroupOrder(leftKey) - olympusSourceGroupOrder(rightKey))
    .map(([key, count]) => `${olympusSourceGroupLabel(key).replace(" sources", "")}: ${count}`)
    .join(" / ");
}

function olympusBucketTitle(key: string) {
  const labels: Record<string, string> = {
    proxmox: "Proxmox cluster",
    siem: "SIEM VM fleet",
    windows: "Windows endpoints",
    linux: "Linux servers",
    vpn: "VPN / edge hosts",
    host: "Business hosts",
  };
  return labels[key] || "Hosts";
}

function olympusTopologyStats(nodes: TopologyGraphNode[]) {
  const externalNodes = uniqueTopologyNodes(nodes.filter((node) => node.type === "external_ip"))
    .sort((left, right) => Number(right.events || 0) - Number(left.events || 0));
  const protectedNodes = uniqueTopologyNodes(nodes.filter((node) => node.type === "protected_public_ip"));
  const collectorNodes = uniqueTopologyNodes(nodes.filter((node) => node.type === "collector"))
    .sort((left, right) => Number(right.events || 0) - Number(left.events || 0));
  const sourceNodes = uniqueTopologyNodes(nodes.filter((node) => node.type === "source"))
    .sort((left, right) => Number(right.events || 0) - Number(left.events || 0));
  const coreNodes = nodes.filter((node) => node.type === "core_service");
  const physicalNodes = uniqueTopologyNodes(nodes.filter((node) => !["external_ip", "protected_public_ip", "collector", "core_service", "source"].includes(node.type)))
    .sort((left, right) => Number(right.events || 0) + right.degree - (Number(left.events || 0) + left.degree));
  const networkNode = physicalNodes.find((node) => {
    const text = `${nodeDisplayLabel(node)} ${nodeSourceKind(node)}`.toLowerCase();
    return text.includes("opnsense") || text.includes("router") || text.includes("gateway") || text.includes("edge");
  });
  const hostNodes = physicalNodes.filter((node) => node.id !== networkNode?.id);
  const discoveredNodes = hostNodes.filter((node) => node.type === "discovery_candidate" && Number(node.events || 0) === 0);
  const connectedHosts = hostNodes.filter((node) => !discoveredNodes.some((candidate) => candidate.id === node.id));
  const hostsByBucket = new Map<string, TopologyGraphNode[]>();
  for (const node of connectedHosts) {
    const bucket = olympusHostBucket(node);
    const list = hostsByBucket.get(bucket) || [];
    list.push(node);
    hostsByBucket.set(bucket, list);
  }
  const sourceGroups = new Map<string, TopologyGraphNode[]>();
  for (const node of sourceNodes) {
    const key = olympusSourceGroupKey(node);
    const list = sourceGroups.get(key) || [];
    list.push(node);
    sourceGroups.set(key, list);
  }
  return { externalNodes, protectedNodes, collectorNodes, sourceNodes, coreNodes, physicalNodes, networkNode, hostNodes, discoveredNodes, connectedHosts, hostsByBucket, sourceGroups };
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function buildOlympusNetworkModel(nodes: TopologyGraphNode[], _edges: TopologyEdgeRecord[]) {
  const modelNodes: OlympusMapNode[] = [];
  const modelEdges: OlympusMapEdge[] = [];
  const nodeById = new Map<string, OlympusMapNode>();
  const addNode = (node: OlympusMapNode) => {
    if (nodeById.has(node.id)) return nodeById.get(node.id)!;
    nodeById.set(node.id, node);
    modelNodes.push(node);
    return node;
  };
  const addEdge = (edge: OlympusMapEdge) => {
    if (!nodeById.has(edge.source) || !nodeById.has(edge.target)) return;
    if (modelEdges.some((item) => item.id === edge.id)) return;
    modelEdges.push(edge);
  };

  const { externalNodes, protectedNodes, collectorNodes, coreNodes, networkNode, discoveredNodes, hostsByBucket, sourceGroups } = olympusTopologyStats(nodes);

  const sentinel = addNode(olympusNode("olympus:sentinel", "SOC Control Plane", "operator decision layer", 1238, 414, "sentinel", "siem", "control", undefined, 220, 50, undefined, ["audit log enabled", "case + response control"], "healthy"));
  const internet = addNode(olympusNode("olympus:internet", "Internet / WAN", `${externalNodes.length.toLocaleString()} observed external IPs`, 64, 148, "cloud", "external", "internet", externalNodes[0], 156, 62, externalNodes.length, ["attack geography layer"], olympusNodeStatus(externalNodes[0], "degraded")));
  const edgeFirewall = addNode(olympusNode("olympus:edge-firewall", "Edge Firewall", "FW-DMZ-CORE / IDS", 338, 128, "edge", "firewall", "perimeter", protectedNodes[0], 158, 58, undefined, ["allow: 443/1194", "deny: direct storage"], "healthy"));
  const edgeNode = addNode(olympusNode(
    "olympus:edge",
    "VPN / Reverse Proxy",
    protectedNodes[0] ? nodeDisplayMeta(protectedNodes[0]) : "OpenVPN/WireGuard / HTTPS",
    338,
    246,
    "edge",
    "vpn",
    "perimeter",
    protectedNodes[0],
    158,
    60,
    protectedNodes.length,
  ));
  const bastion = addNode(olympusNode(
    "olympus:bastion",
    "Bastion / Jump Host",
    "MFA admin path / SSH-RDP",
    338,
    354,
    "service",
    "bastion",
    "perimeter",
    undefined,
    158,
    58,
    undefined,
    ["SSH/RDP/MFA only"],
    "healthy",
  ));
  const router = addNode(olympusNode(
    "olympus:router",
    networkNode ? nodeDisplayLabel(networkNode) : "Virtual router",
    networkNode ? nodeDisplayMeta(networkNode) : "firewall / NAT / VPN routing",
    612,
    120,
    "router",
    "router",
    "lan",
    networkNode,
    184,
    64,
    undefined,
    ["routes: VLAN 20/30/40"],
    olympusNodeStatus(networkNode, "healthy"),
  ));
  const fwDmzCore = addNode(olympusNode("olympus:fw-dmz-core", "FW-DMZ-CORE", "VPN -> Core allowlist", 538, 246, "edge", "policy", "lan", undefined, 118, 46, undefined, ["directional ACL"], "healthy"));
  const coreSwitch = addNode(olympusNode("olympus:switch", "Core LAN switch", "VLAN trunk / east-west", 626, 320, "switch", "switch", "lan", undefined, 164, 62, undefined, ["VLAN 20/30 trunk"], "healthy"));
  const fwCoreSiem = addNode(olympusNode("olympus:fw-core-siem", "FW-CORE-SIEM", "6514/8443 only", 804, 248, "edge", "policy", "lan", undefined, 112, 50, undefined, ["collector allowlist"], "healthy"));
  const fwMgmtSiem = addNode(olympusNode("olympus:fw-mgmt-siem", "FW-MGMT-SIEM", "SOC admin ACL", 1110, 488, "edge", "policy", "control", undefined, 126, 46, undefined, ["SSH/RDP/MFA path"], "healthy"));

  const bucketSlots = [
    { key: "proxmox", x: 84, y: 548, shape: "proxmox" as OlympusMapNodeShape },
    { key: "siem", x: 270, y: 548, shape: "service" as OlympusMapNodeShape },
    { key: "windows", x: 454, y: 548, shape: "windows" as OlympusMapNodeShape },
    { key: "linux", x: 84, y: 654, shape: "linux" as OlympusMapNodeShape },
    { key: "vpn", x: 270, y: 654, shape: "vpn" as OlympusMapNodeShape },
    { key: "host", x: 454, y: 654, shape: "host" as OlympusMapNodeShape },
  ];
  for (const slot of bucketSlots) {
    const bucketNodes = hostsByBucket.get(slot.key) || [];
    if (!bucketNodes.length) continue;
    const sample = bucketNodes[0];
    const details = olympusSampleNames(bucketNodes, 3);
    const visual = addNode(olympusNode(
      `olympus:bucket:${slot.key}`,
      olympusBucketTitle(slot.key),
      `${(bucketNodes.length || 0).toLocaleString()} nodes`,
      slot.x,
      slot.y,
      slot.shape,
      slot.key,
      slot.key === "siem" ? "control" : "hosts",
      sample,
      160,
      76,
      bucketNodes.length,
      olympusCoverageDetails(bucketNodes, details),
      olympusNodeStatus(sample, bucketNodes.some((node) => Number(node.events || 0) > 0) ? "healthy" : "stale"),
    ));
    addEdge(olympusEdge(coreSwitch.id, visual.id, "lan", slot.key === "proxmox" ? "VM/CT" : "LAN", true));
  }

  const sourceGroupsCount = Array.from(sourceGroups.values()).reduce((sum, group) => sum + group.length, 0);
  const sourceGroupsEvents = Array.from(sourceGroups.values()).reduce(
    (sum, group) => sum + group.reduce((inner, node) => inner + Number(node.events || 0), 0),
    0,
  );
  const sourceClasses = addNode(olympusNode(
    "olympus:source-classes",
    "Telemetry source classes",
    `${sourceGroups.size.toLocaleString()} classes / ${sourceGroupsCount.toLocaleString()} sources`,
    668,
    578,
    "host",
    "source",
    "collectors",
    Array.from(sourceGroups.values())[0]?.[0],
    208,
    68,
    sourceGroupsCount,
    [olympusEventsPerHour(sourceGroupsEvents)],
    "healthy",
  ));
  addEdge(olympusEdge(coreSwitch.id, sourceClasses.id, "telemetry", "", true));
  addEdge(olympusEdge(sourceClasses.id, fwCoreSiem.id, "telemetry", "", true));
  if (collectorNodes.length) {
    const eventsCount = collectorNodes.reduce((sum, node) => sum + Number(node.events || 0), 0);
    const visual = addNode(olympusNode("olympus:collector:summary", "Collector plane", `${collectorNodes.length.toLocaleString()} collectors / ${eventsCount.toLocaleString()} ev`, 668, 692, "collector", "collector", "collectors", collectorNodes[0], 208, 58, collectorNodes.length, [`${olympusEventsPerHour(eventsCount)}`], olympusNodeStatus(collectorNodes[0], "healthy")));
    addEdge(olympusEdge(visual.id, fwCoreSiem.id, "siem", "collector allow", true));
  }

  const serviceSlots = [
    { key: "ingest", label: "Ingest", x: 966, y: 118, zone: "data", meta: "EPS in/out + 4xx/5xx" },
    { key: "transport", label: "Transport", x: 966, y: 178, zone: "data", meta: "stream lag / pending" },
    { key: "processing", label: "Processing", x: 966, y: 238, zone: "data", meta: "parse latency / drops" },
    { key: "storage", label: "Storage", x: 966, y: 298, zone: "data", meta: "ClickHouse / TTL / disk" },
    { key: "correlation", label: "Correlation", x: 966, y: 358, zone: "data", meta: "rule latency / windows" },
    { key: "alert-agg", label: "Alert Aggregator", x: 966, y: 418, zone: "data", meta: "raw alerts -> incidents" },
    { key: "web", label: "Web UI / API", x: 1238, y: 116, zone: "control", meta: "HTTPS/443 investigation" },
    { key: "auth", label: "Auth / RBAC", x: 1238, y: 176, zone: "control", meta: "Keycloak + local guard" },
    { key: "rules", label: "Rule Management", x: 1238, y: 236, zone: "control", meta: "content lifecycle" },
    { key: "platform", label: "Platform Dependencies", x: 1238, y: 296, zone: "control", meta: "Vault / NTP / Backup / Grafana" },
    { key: "soar", label: "SOAR / IRP", x: 1238, y: 356, zone: "control", meta: "approval-gated actions" },
  ];
  for (const slot of serviceSlots) {
    const node = findCoreNode(coreNodes, slot.key);
    addNode(olympusNode(`olympus:core:${slot.key}`, slot.label, node ? nodeDisplayMeta(node) : slot.meta, slot.x, slot.y, "service", "siem", slot.zone, node, 190, 44, undefined, [slot.meta], olympusNodeStatus(node, "healthy")));
  }

  const discoveryEngine = addNode(olympusNode("olympus:discovery-engine", "Discovery Engine", "ARP/DHCP/DNS/Nmap/Proxmox", 960, 568, "service", "discovery", "holding", undefined, 176, 58, undefined, ["dedupe + confidence", "coverage check"], "healthy"));
  discoveredNodes.slice(0, 2).forEach((node, index) => {
    const visual = addNode(olympusNode(`olympus:holding:${node.id}`, nodeDisplayLabel(node), nodeDisplayMeta(node), 1188, 568 + index * 86, "holding", nodeSourceKind(node), "holding", node, 190, 58, undefined, ["status: uncovered", "confidence < 50%"], "stale"));
    addEdge(olympusEdge(discoveryEngine.id, visual.id, "response", "confidence score", true));
  });
  if (discoveredNodes.length > 2) {
    const remaining = discoveredNodes.length - 2;
    const more = addNode(olympusNode("olympus:holding:more", "More unmanaged assets", `${remaining.toLocaleString()} candidates`, 1188, 724, "holding", "holding", "holding", undefined, 190, 42, remaining, ["open Assets / Unconnected"], "degraded"));
    addEdge(olympusEdge(discoveryEngine.id, more.id, "response", "queue", true));
  }
  if (!discoveredNodes.length) {
    const holding = addNode(olympusNode("olympus:holding:empty", "No queue", "all discovered assets connected", 1210, 610, "holding", "holding", "holding", undefined, 190, 58, undefined, ["coverage queue empty"], "healthy"));
    addEdge(olympusEdge(discoveryEngine.id, holding.id, "response", "scan result", true));
  }

  addEdge(olympusEdge(internet.id, edgeFirewall.id, "attack", "scan/IOC -> 443/1194", true));
  addEdge(olympusEdge(edgeFirewall.id, edgeNode.id, "management", "ACL / NAT", false));
  addEdge(olympusEdge(edgeNode.id, bastion.id, "management", "SSH/22 + MFA", false));
  addEdge(olympusEdge(edgeNode.id, fwDmzCore.id, "management", "VPN route / ACL", true));
  addEdge(olympusEdge(fwDmzCore.id, router.id, "lan", "allowlist", true));
  addEdge(olympusEdge(router.id, coreSwitch.id, "lan", "trunk", false));
  addEdge(olympusEdge(bastion.id, fwMgmtSiem.id, "management", "SSH/RDP/MFA Admin Path", true));
  addEdge(olympusEdge(fwMgmtSiem.id, sentinel.id, "management", "HTTPS/443 admin", true));
  addEdge(olympusEdge(coreSwitch.id, fwCoreSiem.id, "telemetry", "6514/8443", true));
  addEdge(olympusEdge(fwCoreSiem.id, "olympus:core:ingest", "telemetry", "TLS/6514 + HTTPS/8443", true));
  addEdge(olympusEdge(sentinel.id, "olympus:core:web", "management", "OIDC/RBAC", true));
  addEdge(olympusEdge("olympus:core:auth", "olympus:core:web", "management", "", false));
  addEdge(olympusEdge("olympus:core:rules", "olympus:core:correlation", "management", "rules", true));
  addEdge(olympusEdge("olympus:core:platform", "olympus:core:web", "metrics", "health", true));
  addEdge(olympusEdge("olympus:core:ingest", "olympus:core:transport", "siem", "", false));
  addEdge(olympusEdge("olympus:core:transport", "olympus:core:processing", "siem", "", false));
  addEdge(olympusEdge("olympus:core:processing", "olympus:core:storage", "siem", "", false));
  addEdge(olympusEdge("olympus:core:processing", "olympus:core:correlation", "siem", "", false));
  addEdge(olympusEdge("olympus:core:correlation", "olympus:core:alert-agg", "siem", "", false));
  addEdge(olympusEdge("olympus:core:alert-agg", "olympus:core:web", "siem", "incidents", true));
  addEdge(olympusEdge("olympus:core:storage", "olympus:core:web", "metrics", "query", true));
  addEdge(olympusEdge("olympus:core:soar", bastion.id, "response", "approved IR actions", true));
  addEdge(olympusEdge(coreSwitch.id, discoveryEngine.id, "response", "ARP/DHCP/DNS/Proxmox", true));

  return {
    title: "Network Topology",
    subtitle: "Network layer only: WAN, DMZ, firewall policy boundaries, bastion, VLAN groups, separated SIEM data/control planes and discovery queue.",
    treeTitle: "Network layers",
    treeItems: ["External / WAN", "DMZ / Public edge", "Core LAN routing", "SIEM Data Plane", "SIEM Control Plane", "Discovery queue"],
    nodes: modelNodes,
    edges: modelEdges,
    zones: OLYMPUS_MAP_ZONES,
    legend: OLYMPUS_DEFAULT_LEGEND,
  };
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function buildOlympusTelemetryModel(nodes: TopologyGraphNode[]): OlympusMapModel {
  const { sourceNodes, collectorNodes, coreNodes, sourceGroups } = olympusTopologyStats(nodes);
  const modelNodes: OlympusMapNode[] = [];
  const modelEdges: OlympusMapEdge[] = [];
  const nodeById = new Map<string, OlympusMapNode>();
  const addNode = (node: OlympusMapNode) => {
    if (nodeById.has(node.id)) return nodeById.get(node.id)!;
    nodeById.set(node.id, node);
    modelNodes.push(node);
    return node;
  };
  const addEdge = (edge: OlympusMapEdge) => {
    if (!nodeById.has(edge.source) || !nodeById.has(edge.target)) return;
    if (modelEdges.some((item) => item.id === edge.id)) return;
    modelEdges.push(edge);
  };
  const totalSourceEvents = sourceNodes.reduce((sum, node) => sum + Number(node.events || 0), 0);
  const totalCollectorEvents = collectorNodes.reduce((sum, node) => sum + Number(node.events || 0), 0);
  const orderedSourceGroups = ["network-sources", "host-sources", "infrastructure-sources", "application-sources", "security-sources"]
    .map((key) => [key, sourceGroups.get(key) || []] as const)
    .sort(([leftKey], [rightKey]) => olympusSourceGroupOrder(leftKey) - olympusSourceGroupOrder(rightKey));
  const pipelineZones: OlympusMapZone[] = [
    { id: "sources", label: "Telemetry Sources", meta: "first-class source classes / explicit coverage", x: 32, y: 92, width: 292, height: 610, tone: "hosts" },
    { id: "collectors", label: "Collectors", meta: "single fan-in plane", x: 346, y: 92, width: 160, height: 610, tone: "telemetry" },
    { id: "ingest", label: "Ingest", meta: "HTTPS/8443 + Syslog TLS/6514", x: 528, y: 92, width: 130, height: 610, tone: "telemetry" },
    { id: "transport", label: "Transport / Buffer", meta: "stream lag / backpressure", x: 680, y: 92, width: 140, height: 610, tone: "siem" },
    { id: "processing", label: "Processing", meta: "normalize / filter / enrich / correlate", x: 842, y: 92, width: 178, height: 610, tone: "siem" },
    { id: "alerting", label: "Alerting", meta: "raw alerts -> incidents", x: 1042, y: 92, width: 140, height: 610, tone: "control" },
    { id: "evidence", label: "Evidence / Storage", meta: "hot / cold / incident store", x: 1204, y: 92, width: 132, height: 610, tone: "storage" },
    { id: "response", label: "UI / SOAR", meta: "investigation / response", x: 1358, y: 92, width: 122, height: 610, tone: "control" },
  ];
  const sourceSummary = addNode(olympusNode(
    "telemetry:sources",
    "Telemetry Sources",
    `${sourceNodes.length.toLocaleString()} total / ${totalSourceEvents.toLocaleString()} ev`,
    58,
    126,
    "host",
    "source",
    "sources",
    sourceNodes[0],
    238,
    58,
    sourceNodes.length,
    [`${olympusEventsPerHour(totalSourceEvents)}`, "classes are explicit below"],
    olympusNodeStatus(sourceNodes[0], "healthy"),
  ));
  orderedSourceGroups.forEach(([key, group], index) => {
    const eventsCount = group.reduce((sum, node) => sum + Number(node.events || 0), 0);
    const visual = addNode(olympusNode(
      `telemetry:source:${key}`,
      olympusSourceGroupLabel(key),
      `${group.length} src / ${eventsCount.toLocaleString()} ev`,
      58,
      210 + index * 74,
      "host",
      key,
      "sources",
      group[0],
      238,
      58,
      group.length,
      [olympusSourceGroupMeta(key), olympusEventsPerHour(eventsCount)],
      olympusNodeStatus(group[0], group.length ? "healthy" : "unknown"),
    ));
    addEdge(olympusEdge(visual.id, "telemetry:collectors", "telemetry", key.includes("host") ? "WEF/syslog" : "API/syslog", true));
  });
  const collectors = addNode(olympusNode("telemetry:collectors", "Collector plane", `${collectorNodes.length.toLocaleString()} collectors`, 360, 324, "collector", "collector", "collectors", collectorNodes[0], 132, 72, collectorNodes.length, [`${totalCollectorEvents.toLocaleString()} ev`, olympusEventsPerHour(totalCollectorEvents)], olympusNodeStatus(collectorNodes[0], "healthy")));
  const ingest = addNode(olympusNode("telemetry:ingest", "Ingest", "EPS in/out", 540, 258, "service", "ingest", "ingest", findCoreNode(coreNodes, "ingest"), 106, 62, undefined, ["4xx/5xx", "sessions"], "healthy"));
  const ingestDlq = addNode(olympusNode("telemetry:ingest-dlq", "Ingest DLQ", "invalid payload", 540, 444, "holding", "dlq", "ingest", undefined, 106, 54, undefined, ["bad JSON/syslog"], "degraded"));
  const transport = addNode(olympusNode("telemetry:transport", "Transport", "lag / pending", 694, 324, "service", "transport", "transport", findCoreNode(coreNodes, "transport"), 112, 66, undefined, ["oldest unacked"], "healthy"));
  const enrichment = addNode(olympusNode("telemetry:enrichment", "Enrichment", "GeoIP / TI / CMDB", 858, 150, "service", "enrich", "processing", undefined, 136, 56, undefined, ["context only"], "healthy"));
  const processing = addNode(olympusNode("telemetry:processing", "Normalize / Filter", "parser + drops", 858, 280, "service", "processing", "processing", findCoreNode(coreNodes, "processing"), 136, 62, undefined, ["match rate"], "healthy"));
  const processingDlq = addNode(olympusNode("telemetry:processing-dlq", "Processing DLQ", "unmapped/error", 858, 424, "holding", "dlq", "processing", undefined, 136, 54, undefined, ["normalizer"], "degraded"));
  const correlation = addNode(olympusNode("telemetry:correlation", "Correlation", "rule windows", 858, 548, "service", "correlation", "processing", findCoreNode(coreNodes, "correlation") || findCoreNode(coreNodes, "processing"), 136, 62, undefined, ["latency"], "healthy"));
  const correlationDlq = addNode(olympusNode("telemetry:correlation-dlq", "Correlation DLQ", "timeout/syntax", 858, 638, "holding", "dlq", "processing", undefined, 136, 42, undefined, ["rule errors"], "degraded"));
  const alertAgg = addNode(olympusNode("telemetry:alert-aggregator", "Alert Aggregator", "dedupe/group", 1054, 548, "service", "alert", "alerting", undefined, 104, 62, undefined, ["raw -> incident"], "healthy"));
  const storage = addNode(olympusNode("telemetry:storage", "ClickHouse Hot", "insert latency", 1216, 190, "service", "storage", "evidence", findCoreNode(coreNodes, "storage"), 108, 58, undefined, ["HTTP/8123"], "healthy"));
  const alertStore = addNode(olympusNode("telemetry:alert-store", "Incident Store", "alerts/cases", 1216, 350, "service", "storage", "evidence", undefined, 108, 58, undefined, ["operator evidence"], "healthy"));
  const archive = addNode(olympusNode("telemetry:archive", "Archive / Cold", "TTL / backup", 1216, 510, "service", "archive", "evidence", undefined, 108, 58, undefined, ["restore"], "healthy"));
  const web = addNode(olympusNode("telemetry:web", "Web UI / API", "investigate", 1368, 300, "sentinel", "web", "response", findCoreNode(coreNodes, "web"), 96, 58, undefined, ["queries"], "healthy"));
  const soar = addNode(olympusNode("telemetry:soar", "SOAR / IRP", "approved actions", 1368, 444, "service", "soar", "response", findCoreNode(coreNodes, "soar"), 96, 54, undefined, ["playbooks"], "healthy"));

  addEdge(olympusEdge(sourceSummary.id, collectors.id, "telemetry", "logs/events", true));
  addEdge(olympusEdge(collectors.id, ingest.id, "telemetry", "6514/8443", false));
  addEdge(olympusEdge(ingest.id, transport.id, "siem", "stream", true));
  addEdge(olympusEdge(ingest.id, ingestDlq.id, "response", "invalid payload", false));
  addEdge(olympusEdge(transport.id, processing.id, "siem", "consume", true));
  addEdge(olympusEdge(enrichment.id, processing.id, "metrics", "context", false));
  addEdge(olympusEdge(processing.id, storage.id, "siem", "insert", true));
  addEdge(olympusEdge(processing.id, processingDlq.id, "response", "parser errors", false));
  addEdge(olympusEdge(processing.id, correlation.id, "siem", "normalized", false));
  addEdge(olympusEdge(correlation.id, correlationDlq.id, "response", "rule errors", false));
  addEdge(olympusEdge(correlation.id, alertAgg.id, "siem", "alerts", true));
  addEdge(olympusEdge(alertAgg.id, alertStore.id, "siem", "incidents", true));
  addEdge(olympusEdge(storage.id, archive.id, "metrics", "TTL", false));
  addEdge(olympusEdge(storage.id, web.id, "metrics", "query", true));
  addEdge(olympusEdge(alertStore.id, web.id, "siem", "cases", true));
  addEdge(olympusEdge(web.id, soar.id, "management", "approval", false));

  return {
    title: "Telemetry Flow",
    subtitle: "Event pipeline only: sources -> collectors -> ingest -> transport -> normalize/enrich -> correlation -> alert aggregation -> evidence/UI/SOAR, with DLQ at each failure point.",
    treeTitle: "Telemetry path",
    treeItems: ["Explicit source classes", "Collectors", "Ingest + DLQ", "Transport lag", "Processing + DLQ", "Alert aggregation", "Evidence", "UI / SOAR"],
    nodes: modelNodes,
    edges: modelEdges,
    zones: pipelineZones,
    legend: OLYMPUS_DEFAULT_LEGEND,
  };
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function buildOlympusPostureModel(nodes: TopologyGraphNode[]): OlympusMapModel {
  const { externalNodes, protectedNodes, sourceNodes, discoveredNodes, collectorNodes } = olympusTopologyStats(nodes);
  const modelNodes: OlympusMapNode[] = [];
  const modelEdges: OlympusMapEdge[] = [];
  const nodeById = new Map<string, OlympusMapNode>();
  const addNode = (node: OlympusMapNode) => {
    if (nodeById.has(node.id)) return nodeById.get(node.id)!;
    nodeById.set(node.id, node);
    modelNodes.push(node);
    return node;
  };
  const addEdge = (edge: OlympusMapEdge) => {
    if (!nodeById.has(edge.source) || !nodeById.has(edge.target)) return;
    if (modelEdges.some((item) => item.id === edge.id)) return;
    modelEdges.push(edge);
  };
  const zones: OlympusMapZone[] = [
    { id: "threats", label: "External Threats / GeoIP / TI", meta: "IP / ASN / country / reputation / target", x: 36, y: 92, width: 264, height: 620, tone: "external" },
    { id: "edge", label: "Attack Surface / Public Edge", meta: "VPN / IDS / evidence chain", x: 334, y: 92, width: 220, height: 620, tone: "edge" },
    { id: "discovery", label: "Asset Discovery", meta: "ARP + DHCP + DNS + Nmap + Proxmox + SIEM", x: 586, y: 92, width: 220, height: 620, tone: "management" },
    { id: "coverage", label: "Coverage Auditor", meta: "formal status rules + confidence scoring", x: 838, y: 92, width: 250, height: 620, tone: "control" },
    { id: "actions", label: "Action Queues", meta: "recommend -> approve -> execute", x: 1118, y: 92, width: 360, height: 620, tone: "holding" },
  ];
  const topThreat = externalNodes[0];
  const threats = addNode(olympusNode("posture:threats", "Observed external IPs", `${externalNodes.length.toLocaleString()} IPs / GeoIP + ASN`, 72, 130, "cloud", "external", "threats", topThreat, 188, 64, externalNodes.length, ["verdict: suspicious", "target service mapped"], "degraded"));
  externalNodes.slice(0, 5).forEach((node, index) => {
    const visual = addNode(olympusNode(`posture:external:${node.id}`, safeText(node.ip || node.label, "external IP"), safeText(node.country || node.org || "unknown reputation"), 78, 226 + index * 58, "cloud", "external", "threats", node, 176, 42, undefined, [`events: ${Number(node.events || 0).toLocaleString()}`], "degraded"));
    addEdge(olympusEdge(visual.id, threats.id, "attack", "observed", false));
  });
  const edge = addNode(olympusNode("posture:edge", "VPN / Public Edge", protectedNodes[0] ? nodeDisplayMeta(protectedNodes[0]) : "public services / exposed ports", 364, 150, "edge", "vpn", "edge", protectedNodes[0], 160, 58, protectedNodes.length, ["exposed: 443/1194"], "degraded"));
  const ids = addNode(olympusNode("posture:ids", "Firewall / IDS", "ACL + bruteforce evidence", 364, 266, "router", "ids", "edge", undefined, 160, 58, undefined, ["scan evidence"], "healthy"));
  const alert = addNode(olympusNode("posture:alert", "SIEM Alert Surface", "critical/high feed", 364, 382, "service", "alert", "edge", undefined, 160, 58, undefined, ["source + target"], "degraded"));
  const incident = addNode(olympusNode("posture:incident", "Correlated Incident", "evidence chain", 364, 498, "service", "incident", "edge", undefined, 160, 58, undefined, ["affected asset linked"], "degraded"));

  const discovery = addNode(olympusNode("posture:discovery", "Asset Discovery", "ARP/DHCP/DNS/Nmap/Proxmox", 614, 140, "service", "discovery", "discovery", undefined, 166, 64, undefined, ["dedupe + owner lookup"], "healthy"));
  const observedAssets = addNode(olympusNode("posture:observed", "Observed assets", `${sourceNodes.length.toLocaleString()} event sources`, 614, 260, "host", "observed", "discovery", sourceNodes[0], 166, 58, sourceNodes.length, ["SIEM source.ip seen"], "healthy"));
  const inventory = addNode(olympusNode("posture:inventory", "Asset Inventory", "CMDB + Proxmox + catalog", 614, 380, "service", "inventory", "discovery", undefined, 166, 58, undefined, ["known owners"], "healthy"));
  const confidence = addNode(olympusNode("posture:confidence", "Confidence Scoring", "CMDB/DHCP/ARP/DNS/EDR", 614, 520, "service", "confidence", "discovery", undefined, 166, 64, undefined, ["85% = actionable", "<50% = unknown"], "healthy"));
  const auditor = addNode(olympusNode("posture:auditor", "SIEM Coverage Auditor", "inventory vs network vs SIEM", 870, 260, "sentinel", "coverage", "coverage", collectorNodes[0], 188, 88, undefined, ["Covered: inv+events<N", "Silent: inv+last_seen>N"], "healthy"));
  const covered = addNode(olympusNode("posture:covered", "Covered", `${sourceNodes.length.toLocaleString()} monitored`, 1148, 132, "service", "covered", "actions", sourceNodes[0], 142, 42, sourceNodes.length, ["inventory + events"], "healthy"));
  const silent = addNode(olympusNode("posture:silent", "Silent / stale", "last_seen > SLA", 1148, 198, "holding", "silent", "actions", undefined, 142, 42, undefined, ["EPS = 0"], "stale"));
  const uncovered = addNode(olympusNode("posture:uncovered", "Uncovered", `${discoveredNodes.length.toLocaleString()} candidates`, 1148, 264, "holding", "uncovered", "actions", discoveredNodes[0], 142, 42, discoveredNodes.length, ["no SIEM events"], "degraded"));
  const unknown = addNode(olympusNode("posture:unknown", "Unknown observed", "not in inventory", 1148, 330, "holding", "unknown", "actions", undefined, 142, 42, undefined, ["confidence < 50%"], "degraded"));
  const rogue = addNode(olympusNode("posture:rogue", "Rogue", "forbidden VLAN/policy", 1148, 396, "holding", "rogue", "actions", undefined, 142, 42, undefined, ["policy breach"], "error"));
  const quarantine = addNode(olympusNode("posture:quarantine", "Quarantine", "rogue + criticality", 1316, 248, "holding", "quarantine", "actions", undefined, 136, 42, undefined, ["candidate only"], "error"));
  const recommended = addNode(olympusNode("posture:recommended", "Recommended", "ticket / tag / scan", 1316, 330, "service", "recommend", "actions", undefined, 136, 42, undefined, ["low-risk auto"], "healthy"));
  const approval = addNode(olympusNode("posture:approval", "Analyst Approval", "required for isolation", 1316, 436, "service", "approval", "actions", undefined, 136, 42, undefined, ["human gate"], "degraded"));
  const response = addNode(olympusNode("posture:response", "SOAR Execute", "firewall / IAM / EDR", 1316, 542, "service", "soar", "actions", undefined, 136, 48, undefined, ["approval-gated"], "healthy"));

  addEdge(olympusEdge(threats.id, edge.id, "attack", "scan -> 443/1194", true));
  addEdge(olympusEdge(edge.id, ids.id, "attack", "FW/IDS", false));
  addEdge(olympusEdge(ids.id, alert.id, "telemetry", "evidence", false));
  addEdge(olympusEdge(alert.id, incident.id, "siem", "correlate", false));
  addEdge(olympusEdge(discovery.id, observedAssets.id, "response", "scan", false));
  addEdge(olympusEdge(observedAssets.id, confidence.id, "metrics", "observed", false));
  addEdge(olympusEdge(inventory.id, confidence.id, "metrics", "inventory", false));
  addEdge(olympusEdge(confidence.id, auditor.id, "metrics", "score", true));
  addEdge(olympusEdge(incident.id, auditor.id, "attack", "evidence", true));
  addEdge(olympusEdge(auditor.id, covered.id, "metrics", "", true));
  addEdge(olympusEdge(auditor.id, silent.id, "metrics", "stale", true));
  addEdge(olympusEdge(auditor.id, uncovered.id, "response", "gap", true));
  addEdge(olympusEdge(auditor.id, unknown.id, "response", "unknown", true));
  addEdge(olympusEdge(auditor.id, rogue.id, "attack", "rogue", true));
  addEdge(olympusEdge(rogue.id, quarantine.id, "attack", "critical", true));
  addEdge(olympusEdge(uncovered.id, recommended.id, "management", "onboard", true));
  addEdge(olympusEdge(unknown.id, recommended.id, "management", "case", true));
  addEdge(olympusEdge(quarantine.id, approval.id, "management", "approve", true));
  addEdge(olympusEdge(recommended.id, approval.id, "management", "gate", true));
  addEdge(olympusEdge(approval.id, response.id, "response", "SOAR", false));

  return {
    title: "Security Posture / Attack Surface",
    subtitle: "Threat and coverage layer: GeoIP/TI evidence chain, public edge, confidence-scored discovery, coverage rules and approval-gated SOAR actions.",
    treeTitle: "Posture decisions",
    treeItems: ["External threats", "Evidence chain", "Discovery + confidence", "Coverage rules", "Rogue / quarantine", "Approval-gated SOAR"],
    nodes: modelNodes,
    edges: modelEdges,
    zones,
    legend: OLYMPUS_DEFAULT_LEGEND,
  };
}

type ActualLayoutSpec = {
  zone: string;
  x: number;
  y: number;
  width: number;
  height: number;
  columns?: number;
  columnGap?: number;
  rowGap?: number;
  max?: number;
};

const ACTUAL_TOPOLOGY_LEGEND: OlympusMapModel["legend"] = [
  { tone: "telemetry", label: "actual telemetry edge" },
  { tone: "siem", label: "actual SIEM pipeline edge" },
  { tone: "attack", label: "actual external/attack edge" },
  { tone: "response", label: "actual discovery/onboarding edge" },
  { tone: "lan", label: "actual inventory binding" },
];

function actualNodeShape(node: TopologyGraphNode): OlympusMapNodeShape {
  const kind = `${node.type} ${nodeSourceKind(node)} ${nodeSourceKindLabel(node)} ${node.role || ""} ${node.label || ""}`.toLowerCase();
  if (node.type === "external_ip" || kind.includes("external")) return "cloud";
  if (node.type === "protected_public_ip" || kind.includes("vpn") || kind.includes("public")) return "edge";
  if (node.type === "collector") return "collector";
  if (node.type === "core_service") return String(node.role || node.label || "").toLowerCase().includes("web") ? "sentinel" : "service";
  if (kind.includes("router") || kind.includes("gateway") || kind.includes("firewall") || kind.includes("opnsense")) return "router";
  if (kind.includes("switch")) return "switch";
  if (kind.includes("proxmox") || kind.includes("pve")) return "proxmox";
  if (kind.includes("windows") || kind.includes("desktop")) return "windows";
  if (kind.includes("linux") || kind.includes("ubuntu") || kind.includes("debian")) return "linux";
  if (node.type === "discovery_candidate") return "holding";
  return "host";
}

function actualNodeKind(node: TopologyGraphNode) {
  if (node.type === "core_service") return normalizeTopologyClass(node.role || node.label || "core");
  if (node.type === "collector") return "collector";
  if (node.type === "external_ip") return "external";
  if (node.type === "protected_public_ip") return "edge";
  if (node.type === "discovery_candidate") return "discovery";
  return nodeSourceKind(node);
}

function actualNodeMeta(node: TopologyGraphNode) {
  const meta = nodeDisplayMeta(node);
  if (node.type === "external_ip") {
    const events = Number(node.events || 0);
    return `${safeText(node.ip || node.label, "external IP")}${events > 0 ? ` / ${events.toLocaleString()} ev` : ""}`;
  }
  if (node.type === "discovery_candidate") {
    const confidence = safeText(node["confidence"], "");
    const portSummary = safeText(node["port_summary"], "");
    return [safeText(node.ip, ""), confidence ? `conf ${confidence}` : "", portSummary].filter(Boolean).join(" / ") || meta;
  }
  return meta;
}

function actualEdgeTone(edge: TopologyEdgeRecord): OlympusMapEdge["tone"] {
  const type = normalizeTopologyClass(edge.type, "");
  if (type.includes("attack") || type.includes("external")) return "attack";
  if (type.includes("source") || type.includes("ingest")) return "telemetry";
  if (type.includes("pipeline") || type.includes("query")) return "siem";
  if (type.includes("onboarding") || type.includes("discovery") || type.includes("response")) return "response";
  if (type.includes("metric") || type.includes("health")) return "metrics";
  return "lan";
}

function actualEdgeLabel(edge: TopologyEdgeRecord) {
  return shortenTopologyLabel(safeText(edge.label || edge.type, ""), 22);
}

function olympusSvgId(value: string) {
  return value.replace(/[^a-zA-Z0-9_-]/g, "_");
}

function olympusTextLimit(width: number, reserved = 68, characterWidth = 6.6) {
  return Math.max(8, Math.floor((width - reserved) / characterWidth));
}

function actualRankNodes(nodes: TopologyGraphNode[]) {
  return uniqueTopologyNodes(nodes).sort((left, right) => {
    const eventDelta = Number(right.events || 0) - Number(left.events || 0);
    if (eventDelta !== 0) return eventDelta;
    const degreeDelta = right.degree - left.degree;
    if (degreeDelta !== 0) return degreeDelta;
    return nodeDisplayLabel(left).localeCompare(nodeDisplayLabel(right));
  });
}

function actualAddNode(
  modelNodes: OlympusMapNode[],
  visualBySourceId: Map<string, string>,
  node: TopologyGraphNode,
  x: number,
  y: number,
  zone: string,
  width: number,
  height: number,
) {
  const visualId = `actual:${node.id}`;
  if (visualBySourceId.has(node.id)) return visualBySourceId.get(node.id)!;
  modelNodes.push(olympusNode(
    visualId,
    nodeDisplayLabel(node),
    actualNodeMeta(node),
    x,
    y,
    actualNodeShape(node),
    actualNodeKind(node),
    zone,
    node,
    width,
    height,
    undefined,
    [
      `type: ${node.type}`,
      nodeSourceKindLabel(node),
      Number(node.events || 0) > 0 ? `${Number(node.events || 0).toLocaleString()} events` : "",
    ].filter(Boolean),
    olympusNodeStatus(node, node.type === "external_ip" ? "degraded" : "healthy"),
  ));
  visualBySourceId.set(node.id, visualId);
  return visualId;
}

function actualPlaceColumn(
  modelNodes: OlympusMapNode[],
  visualBySourceId: Map<string, string>,
  nodes: TopologyGraphNode[],
  spec: ActualLayoutSpec,
) {
  const ordered = actualRankNodes(nodes);
  const visible = ordered.slice(0, spec.max || ordered.length);
  const hidden = ordered.slice(visible.length);
  const columns = spec.columns || 1;
  const columnGap = spec.columnGap || 14;
  const rowGap = spec.rowGap || spec.height + 14;
  visible.forEach((node, index) => {
    const column = index % columns;
    const row = Math.floor(index / columns);
    actualAddNode(
      modelNodes,
      visualBySourceId,
      node,
      spec.x + column * (spec.width + columnGap),
      spec.y + row * rowGap,
      spec.zone,
      spec.width,
      spec.height,
    );
  });
  if (hidden.length > 0) {
    const aggregateRow = Math.floor(visible.length / columns);
    modelNodes.push(olympusNode(
      `derived:${spec.zone}:more`,
      `+${hidden.length} more actual`,
      `${hidden.reduce((sum, node) => sum + Number(node.events || 0), 0).toLocaleString()} hidden events`,
      spec.x,
      spec.y + aggregateRow * rowGap,
      "holding",
      "aggregate",
      spec.zone,
      undefined,
      spec.width,
      Math.min(spec.height, 48),
      hidden.length,
      olympusSampleNames(hidden, 4),
      "unknown",
    ));
  }
}

function actualAddVisibleEdges(
  modelEdges: OlympusMapEdge[],
  edges: TopologyEdgeRecord[],
  visualBySourceId: Map<string, string>,
  limit = 48,
  allowedTypes?: Set<string>,
) {
  const seen = new Set<string>();
  const visible = edges
    .filter((edge) => visualBySourceId.has(edge.source) && visualBySourceId.has(edge.target))
    .filter((edge) => !allowedTypes || allowedTypes.has(normalizeTopologyClass(edge.type, "")))
    .sort((left, right) => Number(right.events || 0) - Number(left.events || 0))
    .slice(0, limit);
  for (const edge of visible) {
    const source = visualBySourceId.get(edge.source)!;
    const target = visualBySourceId.get(edge.target)!;
    const tone = actualEdgeTone(edge);
    const id = `actual-edge:${edge.id}:${source}->${target}`;
    if (seen.has(id)) continue;
    seen.add(id);
    modelEdges.push({ id, source, target, tone, label: actualEdgeLabel(edge), curved: false });
  }
}

function buildActualNetworkModel(nodes: TopologyGraphNode[], edges: TopologyEdgeRecord[]): OlympusMapModel {
  const modelNodes: OlympusMapNode[] = [];
  const modelEdges: OlympusMapEdge[] = [];
  const visualBySourceId = new Map<string, string>();
  const laneGroups = new Map<string, TopologyGraphNode[]>();
  for (const node of nodes) {
    const lane = nodeLane(node);
    const group = laneGroups.get(lane) || [];
    group.push(node);
    laneGroups.set(lane, group);
  }

  const zones: OlympusMapZone[] = [
    { id: "external", label: "External activity", meta: `${(laneGroups.get("external") || []).length} actual nodes from API`, x: 24, y: 92, width: 244, height: 760, tone: "external" },
    { id: "edge", label: "Protected edge", meta: `${(laneGroups.get("edge") || []).length} public/VPN nodes from API`, x: 300, y: 92, width: 244, height: 760, tone: "edge" },
    { id: "inventory", label: "Hosts / inventory", meta: `${(laneGroups.get("inventory") || []).length} fleet/discovery nodes from API`, x: 576, y: 92, width: 430, height: 760, tone: "hosts" },
    { id: "source", label: "Telemetry sources", meta: `${(laneGroups.get("source") || []).length} source records from API`, x: 1038, y: 92, width: 336, height: 760, tone: "telemetry" },
    { id: "collector", label: "Collectors", meta: `${(laneGroups.get("collector") || []).length} collector records from API`, x: 1406, y: 92, width: 142, height: 760, tone: "management" },
    { id: "core", label: "SIEM core", meta: `${(laneGroups.get("core") || []).length} core services from API`, x: 1580, y: 92, width: 136, height: 760, tone: "siem" },
  ];

  actualPlaceColumn(modelNodes, visualBySourceId, laneGroups.get("external") || [], { zone: "external", x: 56, y: 134, width: 174, height: 52, rowGap: 62, max: 11 });
  actualPlaceColumn(modelNodes, visualBySourceId, laneGroups.get("edge") || [], { zone: "edge", x: 332, y: 150, width: 174, height: 64, rowGap: 88, max: 8 });
  actualPlaceColumn(modelNodes, visualBySourceId, laneGroups.get("inventory") || [], { zone: "inventory", x: 610, y: 128, width: 162, height: 60, columns: 2, columnGap: 34, rowGap: 76, max: 18 });
  actualPlaceColumn(modelNodes, visualBySourceId, laneGroups.get("source") || [], { zone: "source", x: 1074, y: 128, width: 140, height: 58, columns: 2, columnGap: 34, rowGap: 76, max: 14 });
  actualPlaceColumn(modelNodes, visualBySourceId, laneGroups.get("collector") || [], { zone: "collector", x: 1424, y: 140, width: 106, height: 60, rowGap: 88, max: 8 });
  actualPlaceColumn(modelNodes, visualBySourceId, laneGroups.get("core") || [], { zone: "core", x: 1596, y: 132, width: 104, height: 60, rowGap: 90, max: 8 });
  actualAddVisibleEdges(modelEdges, edges, visualBySourceId, 56);

  return {
    title: "Actual Topology API Projection",
    subtitle: "Only real /api/topology/network nodes and edges are drawn. Aggregate cards are marked as '+N more actual'; no conceptual firewall, switch, bastion, DLQ or alert nodes are invented.",
    treeTitle: "Real API lanes",
    treeItems: [
      `${nodes.length.toLocaleString()} actual nodes`,
      `${edges.length.toLocaleString()} actual edges`,
      `${(laneGroups.get("external") || []).length} external`,
      `${(laneGroups.get("edge") || []).length} edge`,
      `${(laneGroups.get("inventory") || []).length} inventory`,
      `${(laneGroups.get("source") || []).length} sources`,
      `${(laneGroups.get("collector") || []).length} collectors`,
      `${(laneGroups.get("core") || []).length} core services`,
    ],
    nodes: modelNodes,
    edges: modelEdges,
    zones,
    legend: ACTUAL_TOPOLOGY_LEGEND,
  };
}

function buildActualTelemetryModel(nodes: TopologyGraphNode[], edges: TopologyEdgeRecord[]): OlympusMapModel {
  const modelNodes: OlympusMapNode[] = [];
  const modelEdges: OlympusMapEdge[] = [];
  const visualBySourceId = new Map<string, string>();
  const nodeIndex = new Map(nodes.map((node) => [node.id, node]));
  const sourceNodes = actualRankNodes(nodes.filter((node) => node.type === "source"));
  const collectorNodes = actualRankNodes(nodes.filter((node) => node.type === "collector"));
  const coreNodes = actualRankNodes(nodes.filter((node) => node.type === "core_service"));
  const sourceGroups = new Map<string, TopologyGraphNode[]>();
  const sourceBindingEdges = edges.filter((item) => normalizeTopologyClass(item.type, "") === "source_binding");
  const sourceBundles = new Map<string, { targetId: string; sources: Map<string, TopologyGraphNode>; events: number; bindings: number }>();
  const boundSourceIds = new Set<string>();

  for (const node of sourceNodes) {
    const key = olympusSourceGroupKey(node);
    const group = sourceGroups.get(key) || [];
    group.push(node);
    sourceGroups.set(key, group);
  }

  const zones: OlympusMapZone[] = [
    { id: "sources", label: "Telemetry Source Bundles", meta: `${sourceNodes.length} actual source records bundled by receiving collector/core`, x: 28, y: 92, width: 424, height: 760, tone: "hosts" },
    { id: "collectors", label: "Collectors", meta: `${collectorNodes.length} actual collector records`, x: 492, y: 92, width: 270, height: 760, tone: "telemetry" },
    { id: "pipeline", label: "SIEM Pipeline", meta: `${coreNodes.length} actual core_service nodes`, x: 804, y: 92, width: 570, height: 760, tone: "siem" },
    { id: "consumers", label: "Investigation / Response", meta: "Actual web/SOAR core nodes only", x: 1416, y: 92, width: 292, height: 760, tone: "control" },
  ];

  actualPlaceColumn(modelNodes, visualBySourceId, collectorNodes, { zone: "collectors", x: 532, y: 136, width: 190, height: 66, rowGap: 98, max: 7 });

  const coreSlots: Record<string, { x: number; y: number; zone: string }> = {
    ingest: { x: 846, y: 214, zone: "pipeline" },
    transport: { x: 1012, y: 214, zone: "pipeline" },
    processing: { x: 1178, y: 214, zone: "pipeline" },
    storage: { x: 1094, y: 444, zone: "pipeline" },
    web: { x: 1456, y: 214, zone: "consumers" },
    soar: { x: 1456, y: 444, zone: "consumers" },
  };
  coreNodes.forEach((node, index) => {
    const key = normalizeTopologyClass(node.role || node.label || node.id, "");
    const slot = Object.entries(coreSlots).find(([token]) => key.includes(token))?.[1] || { x: 846 + (index % 3) * 166, y: 620, zone: "pipeline" };
    actualAddNode(modelNodes, visualBySourceId, node, slot.x, slot.y, slot.zone, 136, 66);
  });

  for (const edge of sourceBindingEdges) {
    const source = nodeIndex.get(edge.source);
    if (!source || source.type !== "source") continue;
    const targetKey = visualBySourceId.has(edge.target) ? edge.target : "unrendered-target";
    const bundle = sourceBundles.get(targetKey) || { targetId: targetKey, sources: new Map<string, TopologyGraphNode>(), events: 0, bindings: 0 };
    bundle.sources.set(source.id, source);
    bundle.events += Number(edge.events || source.events || 0);
    bundle.bindings += 1;
    sourceBundles.set(targetKey, bundle);
    boundSourceIds.add(source.id);
  }

  const unboundSources = sourceNodes.filter((source) => !boundSourceIds.has(source.id));
  if (unboundSources.length > 0) {
    sourceBundles.set("unbound-sources", {
      targetId: "unbound-sources",
      sources: new Map(unboundSources.map((source) => [source.id, source])),
      events: unboundSources.reduce((sum, source) => sum + Number(source.events || 0), 0),
      bindings: 0,
    });
  }

  const targetOrder = (bundle: { targetId: string }) => {
    const visualId = visualBySourceId.get(bundle.targetId);
    const target = visualId ? modelNodes.find((node) => node.id === visualId) : undefined;
    return target ? target.y : 820;
  };
  Array.from(sourceBundles.values())
    .sort((left, right) => targetOrder(left) - targetOrder(right))
    .slice(0, 7)
    .forEach((bundle, index) => {
      const group = actualRankNodes(Array.from(bundle.sources.values()));
      const targetVisualId = visualBySourceId.get(bundle.targetId);
      const targetNode = bundle.targetId !== "unrendered-target" ? nodeIndex.get(bundle.targetId) : undefined;
      const key = olympusDominantSourceGroupKey(group);
      const visualId = `derived:source-bundle:${bundle.targetId}`;
      modelNodes.push(olympusNode(
        visualId,
        targetNode ? `Sources -> ${nodeDisplayLabel(targetNode)}` : bundle.targetId === "unbound-sources" ? "Unbound source records" : "Sources -> unrendered target",
        `${group.length} sources / ${bundle.events.toLocaleString()} ev`,
        64,
        134 + index * 102,
        "host",
        key,
        "sources",
        group[0],
        340,
        82,
        group.length,
        [olympusSourceClassSummary(group), ...olympusSampleNames(group, 2)],
        olympusNodeStatus(group[0], "healthy"),
      ));
      if (targetVisualId) {
        modelEdges.push({
          id: `actual-source-bundle:${visualId}->${targetVisualId}`,
          source: visualId,
          target: targetVisualId,
          tone: "telemetry",
          label: `${bundle.bindings} bindings`,
          curved: false,
        });
      }
    });
  actualAddVisibleEdges(
    modelEdges,
    edges.filter((edge) => {
      const source = nodeIndex.get(edge.source);
      return source?.type !== "source";
    }),
    visualBySourceId,
    32,
    new Set(["ingest", "pipeline", "query", "response"]),
  );

  return {
    title: "Actual Telemetry Flow",
    subtitle: "Sources are first-class and grouped from real source records. Collector and core cards are actual API nodes; source-to-collector/core bindings are aggregated from actual source_binding edges.",
    treeTitle: "Real event path",
    treeItems: [
      `${sourceNodes.length.toLocaleString()} actual sources`,
      `${sourceGroups.size.toLocaleString()} source classes`,
      `${sourceBundles.size.toLocaleString()} receiving bundles`,
      `${collectorNodes.length.toLocaleString()} collectors`,
      `${coreNodes.length.toLocaleString()} core services`,
      `${sourceBindingEdges.length.toLocaleString()} source bindings`,
    ],
    nodes: modelNodes,
    edges: modelEdges,
    zones,
    legend: ACTUAL_TOPOLOGY_LEGEND,
  };
}

function buildActualPostureModel(nodes: TopologyGraphNode[], edges: TopologyEdgeRecord[]): OlympusMapModel {
  const modelNodes: OlympusMapNode[] = [];
  const modelEdges: OlympusMapEdge[] = [];
  const visualBySourceId = new Map<string, string>();
  const externalNodes = actualRankNodes(nodes.filter((node) => node.type === "external_ip"));
  const protectedNodes = actualRankNodes(nodes.filter((node) => node.type === "protected_public_ip" || nodeLane(node) === "edge"));
  const sourceNodes = actualRankNodes(nodes.filter((node) => node.type === "source"));
  const discoveryNodes = actualRankNodes(nodes.filter((node) => node.type === "discovery_candidate" || node.type === "proxmox_guest"));
  const staleSources = sourceNodes.filter((node) => olympusNodeStatus(node) === "stale");
  const activeSources = sourceNodes.filter((node) => olympusNodeStatus(node) === "healthy");
  const onboardingNodes = discoveryNodes.filter((node) => safeText(node.status, "").toLowerCase() !== "connected");

  const zones: OlympusMapZone[] = [
    { id: "threats", label: "Observed External Activity", meta: `${externalNodes.length} actual external_ip nodes`, x: 30, y: 92, width: 306, height: 760, tone: "external" },
    { id: "edge", label: "Protected Targets", meta: `${protectedNodes.length} actual edge/public nodes`, x: 374, y: 92, width: 260, height: 760, tone: "edge" },
    { id: "coverage", label: "Coverage From Real Sources", meta: "Derived cards use only actual source statuses", x: 672, y: 92, width: 318, height: 760, tone: "control" },
    { id: "discovery", label: "Discovery / Onboarding Queue", meta: `${discoveryNodes.length} actual fleet/discovery records`, x: 1028, y: 92, width: 280, height: 760, tone: "holding" },
    { id: "actions", label: "Actual Action Inputs", meta: "Needs-onboarding and attack edges only", x: 1346, y: 92, width: 360, height: 760, tone: "management" },
  ];

  actualPlaceColumn(modelNodes, visualBySourceId, externalNodes, { zone: "threats", x: 76, y: 136, width: 214, height: 52, rowGap: 64, max: 9 });
  actualPlaceColumn(modelNodes, visualBySourceId, protectedNodes, { zone: "edge", x: 414, y: 146, width: 184, height: 66, rowGap: 100, max: 6 });
  actualPlaceColumn(modelNodes, visualBySourceId, discoveryNodes, { zone: "discovery", x: 1064, y: 136, width: 210, height: 62, rowGap: 78, max: 8 });

  const coveredEvents = activeSources.reduce((sum, node) => sum + Number(node.events || 0), 0);
  const staleEvents = staleSources.reduce((sum, node) => sum + Number(node.events || 0), 0);
  modelNodes.push(
    olympusNode("derived:coverage:covered", "Covered sources", `${activeSources.length} active / ${coveredEvents.toLocaleString()} ev`, 716, 154, "service", "covered", "coverage", activeSources[0], 228, 72, activeSources.length, olympusSampleNames(activeSources, 3), "healthy"),
    olympusNode("derived:coverage:stale", "Silent / stale sources", `${staleSources.length} stale / ${staleEvents.toLocaleString()} ev`, 716, 296, "holding", "stale", "coverage", staleSources[0], 228, 72, staleSources.length, olympusSampleNames(staleSources, 3), staleSources.length ? "stale" : "healthy"),
    olympusNode("derived:coverage:onboarding", "Needs onboarding", `${onboardingNodes.length} discovered/fleet records`, 716, 438, "holding", "uncovered", "coverage", onboardingNodes[0], 228, 72, onboardingNodes.length, olympusSampleNames(onboardingNodes, 3), onboardingNodes.length ? "degraded" : "healthy"),
  );

  modelNodes.push(
    olympusNode("derived:actions:attack", "Investigate external IPs", `${externalNodes.length} observed actors`, 1388, 170, "service", "attack", "actions", externalNodes[0], 220, 64, externalNodes.length, ["open event drilldown"], externalNodes.length ? "degraded" : "healthy"),
    olympusNode("derived:actions:onboard", "Connect uncovered assets", `${onboardingNodes.length} candidates`, 1388, 340, "service", "response", "actions", onboardingNodes[0], 220, 64, onboardingNodes.length, ["open asset onboarding"], onboardingNodes.length ? "degraded" : "healthy"),
    olympusNode("derived:actions:watch", "Watch stale sources", `${staleSources.length} sources`, 1388, 510, "service", "watch", "actions", staleSources[0], 220, 64, staleSources.length, ["last_seen/EPS review"], staleSources.length ? "stale" : "healthy"),
  );

  actualAddVisibleEdges(modelEdges, edges, visualBySourceId, 42, new Set(["attack_observation", "external_observation", "needs_onboarding", "discovery_binding", "fleet_source_binding"]));
  if (externalNodes.length) modelEdges.push(olympusEdge("derived:actions:attack", "derived:coverage:covered", "attack", "evidence review", false));
  if (onboardingNodes.length) modelEdges.push(olympusEdge("derived:coverage:onboarding", "derived:actions:onboard", "response", "onboard", false));
  if (staleSources.length) modelEdges.push(olympusEdge("derived:coverage:stale", "derived:actions:watch", "management", "verify", false));

  return {
    title: "Actual Security Posture",
    subtitle: "External activity, protected targets and onboarding gaps are drawn from actual topology nodes/edges. Coverage/action cards are derived from real source statuses, not a fictional network design.",
    treeTitle: "Real posture inputs",
    treeItems: [
      `${externalNodes.length.toLocaleString()} external IP nodes`,
      `${protectedNodes.length.toLocaleString()} protected/edge nodes`,
      `${sourceNodes.length.toLocaleString()} telemetry sources`,
      `${staleSources.length.toLocaleString()} stale sources`,
      `${onboardingNodes.length.toLocaleString()} onboarding candidates`,
      `${edges.filter((edge) => ["attack_observation", "needs_onboarding"].includes(edge.type)).length.toLocaleString()} posture edges`,
    ],
    nodes: modelNodes,
    edges: modelEdges,
    zones,
    legend: ACTUAL_TOPOLOGY_LEGEND,
  };
}

function olympusEdgePath(edge: OlympusMapEdge, nodes: Map<string, OlympusMapNode>) {
  const source = nodes.get(edge.source);
  const target = nodes.get(edge.target);
  if (!source || !target) return "";
  const x1 = source.x + source.width / 2;
  const y1 = source.y + source.height / 2;
  const x2 = target.x + target.width / 2;
  const y2 = target.y + target.height / 2;
  const dx = x2 - x1;
  const dy = y2 - y1;
  const horizontal = Math.abs(dx) >= Math.abs(dy);
  const startX = horizontal ? (dx >= 0 ? source.x + source.width : source.x) : x1;
  const startY = horizontal ? y1 : (dy >= 0 ? source.y + source.height : source.y);
  const endX = horizontal ? (dx >= 0 ? target.x : target.x + target.width) : x2;
  const endY = horizontal ? y2 : (dy >= 0 ? target.y : target.y + target.height);
  if (!edge.curved && (Math.abs(startX - endX) < 2 || Math.abs(startY - endY) < 2)) return `M ${startX} ${startY} L ${endX} ${endY}`;
  if (horizontal) {
    const midX = Math.round((startX + endX) / 2);
    return `M ${startX} ${startY} L ${midX} ${startY} L ${midX} ${endY} L ${endX} ${endY}`;
  }
  const midY = Math.round((startY + endY) / 2);
  return `M ${startX} ${startY} L ${startX} ${midY} L ${endX} ${midY} L ${endX} ${endY}`;
}

function shouldRenderOlympusEdgeLabel(edge: OlympusMapEdge, nodes: Map<string, OlympusMapNode>, mode: Exclude<TopologyMapMode, "force">) {
  if (!edge.label) return false;
  const source = nodes.get(edge.source);
  const target = nodes.get(edge.target);
  if (!source || !target) return false;
  const sx = source.x + source.width / 2;
  const sy = source.y + source.height / 2;
  const tx = target.x + target.width / 2;
  const ty = target.y + target.height / 2;
  if (Math.abs(ty - sy) > Math.abs(tx - sx) * 1.15) return false;
  if (mode === "posture" && ["metrics", "management"].includes(edge.tone)) return false;
  if (mode === "network" && ["metrics", "management"].includes(edge.tone) && edge.label.length > 18) return false;
  return true;
}

type OlympusNetworkTopologyProps = {
  nodes: TopologyGraphNode[];
  edges: TopologyEdgeRecord[];
  mode: Exclude<TopologyMapMode, "force">;
  selectedNodeId: string;
  searchTerm: string;
  onSelectNode: (nodeId: string) => void;
};

function OlympusNetworkTopology({ nodes, edges, mode, selectedNodeId, searchTerm, onSelectNode }: OlympusNetworkTopologyProps) {
  const model = useMemo(() => {
    if (mode === "telemetry") return buildActualTelemetryModel(nodes, edges);
    if (mode === "posture") return buildActualPostureModel(nodes, edges);
    return buildActualNetworkModel(nodes, edges);
  }, [edges, mode, nodes]);
  const visualIndex = useMemo(() => new Map(model.nodes.map((node) => [node.id, node])), [model.nodes]);
  const selectedVisualId = model.nodes.find((node) => node.sourceId === selectedNodeId)?.id || "";
  const query = searchTerm.trim().toLowerCase();
  return (
    <div className={`react-olympus-map-shell mode-${mode}`} aria-label="SIEM topology decision map inspired by Network Olympus monitoring">
      <div className="react-olympus-map-header">
        <div>
          <span>{mode === "network" ? "GENERAL SIEM NETWORK MAP" : mode === "telemetry" ? "SIEM TELEMETRY FLOW" : "SECURITY POSTURE MAP"}</span>
          <strong>{model.title}</strong>
          <small>{model.subtitle}</small>
        </div>
        <div className="react-olympus-map-tabs">
          <span className="active">VIEW</span>
          <span>EDIT</span>
        </div>
      </div>
      <div className="react-olympus-legend" aria-label="Line type legend">
        {model.legend.map((item) => (
          <span key={`${item.tone}:${item.label}`} className={`tone-${item.tone}`}>
            <i />
            {item.label}
          </span>
        ))}
      </div>
      <div className="react-olympus-map-body">
        <aside className="react-olympus-map-tree" aria-label="Network map tree">
          <strong>{model.treeTitle}</strong>
          {model.treeItems.map((item, index) => <span key={`${item}:${index}`}>{item}</span>)}
        </aside>
        <div className="react-olympus-minimap" aria-hidden="true">
          <svg viewBox={`0 0 ${OLYMPUS_VIEWBOX_WIDTH / 8} ${OLYMPUS_VIEWBOX_HEIGHT / 8}`}>
            {model.zones.map((zone) => <rect key={zone.id} x={zone.x / 8} y={zone.y / 8} width={zone.width / 8} height={zone.height / 8} rx="3" />)}
            {model.nodes.map((node) => <circle key={node.id} cx={(node.x + node.width / 2) / 8} cy={(node.y + node.height / 2) / 8} r="2.2" />)}
          </svg>
        </div>
        <svg className="react-olympus-map" viewBox={`0 0 ${OLYMPUS_VIEWBOX_WIDTH} ${OLYMPUS_VIEWBOX_HEIGHT}`} role="img" aria-label="General SIEM network map">
          <defs>
            <marker id="olympusArrow" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
              <path d="M 0 0 L 8 4 L 0 8 z" className="react-olympus-arrow" />
            </marker>
          </defs>
          <rect x="0" y="0" width={OLYMPUS_VIEWBOX_WIDTH} height={OLYMPUS_VIEWBOX_HEIGHT} rx="20" className="react-olympus-bg" />
          {model.zones.map((zone) => (
            <g key={zone.id} className={`react-olympus-zone zone-${zone.tone}`}>
              <rect x={zone.x} y={zone.y} width={zone.width} height={zone.height} rx="12" />
              <text x={zone.x + 16} y={zone.y + 28}>{shortenTopologyLabel(zone.label, olympusTextLimit(zone.width, 34, 7.4))}</text>
              {zone.meta ? <text className="react-olympus-zone-meta" x={zone.x + 16} y={zone.y + 46}>{shortenTopologyLabel(zone.meta, olympusTextLimit(zone.width, 34, 5.8))}</text> : null}
            </g>
          ))}
          {model.edges.map((edge) => {
            const pathId = olympusSvgId(edge.id);
            return (
              <g key={edge.id} className={`react-olympus-edge tone-${edge.tone}`}>
                <path id={pathId} d={olympusEdgePath(edge, visualIndex)} markerEnd="url(#olympusArrow)" />
                {shouldRenderOlympusEdgeLabel(edge, visualIndex, mode) ? (
                  <text>
                    <textPath href={`#${pathId}`} startOffset="50%">
                      {edge.label}
                    </textPath>
                  </text>
                ) : null}
              </g>
            );
          })}
          {model.nodes.map((node) => {
            const selected = selectedVisualId === node.id || selectedNodeId === node.sourceId;
            const matched = !query || [node.label, node.meta, node.kind, node.node?.ip, node.node?.hostname, node.node?.source_name].some((value) => String(value || "").toLowerCase().includes(query));
            const className = [
              "react-olympus-node",
              `shape-${node.shape}`,
              `kind-${cytoscapeClassName(node.kind)}`,
              `zone-${node.zone}`,
              `status-${node.status || "unknown"}`,
              selected ? "selected" : "",
              !matched ? "dimmed" : "",
            ].filter(Boolean).join(" ");
            const compact = node.height <= 42;
            const iconRadius = compact ? 13 : node.shape === "sentinel" ? 22 : 17;
            const labelY = compact ? 18 : 23;
            const metaY = compact ? 31 : 40;
            const maxDetails = node.height >= 76 ? 2 : node.height >= 66 ? 1 : 0;
            const details = (node.details || []).slice(0, maxDetails);
            const clipId = `olympusNodeClip_${olympusSvgId(node.id)}`;
            const labelLimit = olympusTextLimit(node.width, compact ? 68 : 78, 6.6);
            const metaLimit = olympusTextLimit(node.width, compact ? 68 : 78, 5.7);
            const detailLimit = olympusTextLimit(node.width, compact ? 68 : 78, 5.6);
            return (
              <g
                key={node.id}
                className={className}
                transform={`translate(${node.x} ${node.y})`}
                role={node.sourceId ? "button" : "img"}
                tabIndex={node.sourceId ? 0 : -1}
                onClick={() => node.sourceId && onSelectNode(node.sourceId)}
                onKeyDown={(event) => {
                  if (!node.sourceId) return;
                  if (event.key === "Enter" || event.key === " ") onSelectNode(node.sourceId);
                }}
              >
                <clipPath id={clipId}>
                  <rect x="3" y="3" width={Math.max(1, node.width - 6)} height={Math.max(1, node.height - 6)} rx={node.shape === "sentinel" ? 25 : 9} />
                </clipPath>
                <rect x="0" y="0" width={node.width} height={node.height} rx={node.shape === "sentinel" ? 28 : 10} />
                <circle cx="28" cy={node.height / 2} r={iconRadius} />
                <text className="react-olympus-glyph" x="28" y={node.height / 2 + 4}>{olympusNodeIcon(node.shape, node.kind)}</text>
                <g clipPath={`url(#${clipId})`}>
                  <text className="react-olympus-label" x="54" y={labelY}>{shortenTopologyLabel(node.label, labelLimit)}</text>
                  <text className="react-olympus-meta" x="54" y={metaY}>{shortenTopologyLabel(node.meta, metaLimit)}</text>
                  {details.map((detail, index) => (
                    <text key={detail} className="react-olympus-detail" x="54" y={56 + index * 12}>{shortenTopologyLabel(detail, detailLimit)}</text>
                  ))}
                </g>
                {node.count ? <text className="react-olympus-count" x={node.width - 12} y="16">{node.count}</text> : null}
                <circle className={`react-olympus-status-dot status-${node.status || "unknown"}`} cx={node.width - 13} cy={node.height - 13} r="4.5" />
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

function formFromNode(node: TopologyNodeRecord | null): HostAccessForm {
  const hostname = nodeHostname(node) || safeText(node?.label, "");
  return {
    profile_id: "",
    host_id: safeText(node?.id, ""),
    host_label: hostname,
    hostname,
    ip: safeText(node?.ip, ""),
    protocol: node?.type === "proxmox_guest" || node?.type === "source" ? "ssh" : "ssh",
    port: "22",
    username: "",
    auth_method: "password",
    credential_label: "default",
    credential_ref: "",
    private_key_ref: "",
    certificate_ref: "",
    password: "",
    private_key_pem: "",
    certificate_pem: "",
    passphrase: "",
    jump_host: "",
    allowed_actions: "ssh_command, collect_artifacts, isolate_host",
    tags: "",
    notes: "",
    enabled: true,
  };
}

function formFromProfile(profile: HostAccessProfileRecord, fallbackNode: TopologyNodeRecord | null): HostAccessForm {
  return {
    ...formFromNode(fallbackNode),
    profile_id: safeText(profile.profile_id, ""),
    host_id: safeText(profile.host_id || fallbackNode?.id, ""),
    host_label: safeText(profile.host_label || fallbackNode?.label, ""),
    hostname: safeText(profile.hostname || profile.host_label || fallbackNode?.label, ""),
    ip: safeText(profile.ip || fallbackNode?.ip, ""),
    protocol: safeText(profile.protocol, "ssh"),
    port: String(profile.port || ""),
    username: safeText(profile.username, ""),
    auth_method: safeText(profile.auth_method, "password"),
    credential_label: safeText(profile.credential_label, "default"),
    credential_ref: safeText(profile.credential_ref, ""),
    private_key_ref: safeText(profile.private_key_ref, ""),
    certificate_ref: safeText(profile.certificate_ref, ""),
    jump_host: safeText(profile.jump_host, ""),
    allowed_actions: (profile.allowed_actions || []).join(", "),
    tags: (profile.tags || []).join(", "),
    notes: safeText(profile.notes, ""),
    enabled: profile.enabled !== false,
  };
}

function formPayload(form: HostAccessForm) {
  const payload: Record<string, unknown> = {
    profile_id: form.profile_id || undefined,
    host_id: form.host_id,
    host_label: form.host_label,
    hostname: form.hostname,
    ip: form.ip,
    protocol: form.protocol,
    port: form.port,
    username: form.username,
    auth_method: form.auth_method,
    credential_label: form.credential_label,
    credential_ref: form.credential_ref || undefined,
    private_key_ref: form.private_key_ref || undefined,
    certificate_ref: form.certificate_ref || undefined,
    jump_host: form.jump_host || undefined,
    allowed_actions: form.allowed_actions,
    tags: form.tags,
    notes: form.notes,
    enabled: form.enabled,
  };
  if (form.password.trim()) payload.password = form.password;
  if (form.private_key_pem.trim()) payload.private_key_pem = form.private_key_pem;
  if (form.certificate_pem.trim()) payload.certificate_pem = form.certificate_pem;
  if (form.passphrase.trim()) payload.passphrase = form.passphrase;
  return payload;
}

export function TopologyPage() {
  const { formatTimestamp } = useShellContext();
  const [refreshToken, setRefreshToken] = useState(0);
  const [selectedNodeId, setSelectedNodeId] = useState("");
  const [hoveredNodeId, setHoveredNodeId] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [mapMode, setMapMode] = useState<TopologyMapMode>("network");
  const [graphZoom, setGraphZoom] = useState(100);
  const [graphCommand, setGraphCommand] = useState<TopologyGraphCommand>({ kind: "fit", nonce: 0 });
  const [hostForm, setHostForm] = useState<HostAccessForm>(() => formFromNode(null));
  const [savingProfile, setSavingProfile] = useState(false);
  const [formMessage, setFormMessage] = useState("");
  const loadTopology = useCallback(() => {
    void refreshToken;
    return api.networkTopology({ hours: 24, limit: 300 });
  }, [refreshToken]);
  const state = useAsyncData<NetworkTopologyResponse>(loadTopology);

  const normalizedTopology = useMemo(
    () => normalizeTopologyGraph(state.data?.nodes || [], state.data?.edges || []),
    [state.data?.edges, state.data?.nodes],
  );
  const graphNodes = useMemo(() => annotateTopologyNodes(normalizedTopology.nodes, normalizedTopology.edges), [normalizedTopology]);
  const graphIndex = useMemo(() => {
    const index = new Map<string, TopologyGraphNode>();
    for (const node of graphNodes) index.set(node.id, node);
    return index;
  }, [graphNodes]);
  const selectedNode = selectedNodeId ? graphIndex.get(selectedNodeId) || null : null;
  const visibleEdges = useMemo(
    () => normalizedTopology.edges.filter((edge: TopologyEdgeRecord) => graphIndex.has(edge.source) && graphIndex.has(edge.target)),
    [graphIndex, normalizedTopology.edges],
  );
  const selectedProfiles = useMemo(
    () => (selectedNode ? (state.data?.host_access_profiles || []).filter((profile) => profileMatchesNode(profile, selectedNode)) : []),
    [selectedNode, state.data?.host_access_profiles],
  );

  useEffect(() => {
    setHostForm(formFromNode(selectedNode));
    setFormMessage("");
  }, [selectedNode]);

  const data = state.data;
  const protectedIps = data?.protected_public_ips || [];
  const selectedEdges = selectedNode
    ? visibleEdges.filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id)
    : [];
  const sourceNodes = useMemo(
    () => graphNodes.filter((node) => node.type === "source").sort((left, right) => Number(right.events || 0) - Number(left.events || 0)),
    [graphNodes],
  );
  const packetFlows = useMemo(
    () => [...(data?.packet_flows || [])].sort((left, right) => Number(left.order || 0) - Number(right.order || 0)),
    [data?.packet_flows],
  );

  function issueGraphCommand(kind: TopologyGraphCommand["kind"]) {
    setGraphCommand((current) => ({ kind, nonce: current.nonce + 1 }));
  }

  async function saveProfile() {
    if (!selectedNode) return;
    setSavingProfile(true);
    setFormMessage("");
    try {
      const saved = await api.saveHostAccessProfile(formPayload(hostForm));
      setHostForm((current) => ({
        ...current,
        profile_id: safeText(saved.profile_id, current.profile_id),
        password: "",
        private_key_pem: "",
        certificate_pem: "",
        passphrase: "",
      }));
      setFormMessage(`Saved profile ${safeText(saved.profile_id, "new profile")}. Secret material was not returned to the browser.`);
      setRefreshToken((current) => current + 1);
    } catch (error) {
      setFormMessage(error instanceof Error ? error.message : "Host access profile save failed");
    } finally {
      setSavingProfile(false);
    }
  }

  async function deleteProfile(profile: HostAccessProfileRecord) {
    const profileId = safeText(profile.profile_id, "");
    if (!profileId) return;
    if (!window.confirm(`Delete host access profile ${profileId}? Vault secret material is not deleted automatically.`)) return;
    setSavingProfile(true);
    setFormMessage("");
    try {
      await api.deleteHostAccessProfile(profileId);
      setHostForm(formFromNode(selectedNode));
      setFormMessage(`Deleted profile ${profileId}.`);
      setRefreshToken((current) => current + 1);
    } catch (error) {
      setFormMessage(error instanceof Error ? error.message : "Host access profile delete failed");
    } finally {
      setSavingProfile(false);
    }
  }

  if (state.loading) return <EmptyState message="Loading topology..." />;
  if (state.error || !data) return <EmptyState message={state.error || "Topology data is unavailable"} />;

  return (
    <div className="react-page react-page-topology">
      <SectionIntro
        kicker="Topology"
        title="SIEM topology decision map"
        subtitle="Three SOC views: network topology, telemetry flow and security posture/attack surface. Each view uses separate zones and link semantics."
        icon="map"
        actions={
          <div className="react-actions react-wrap">
            <Link className="react-link-button" to="/assets?view=unconnected">
              Unconnected assets
            </Link>
            <Link className="react-link-button" to="/sources?view=fleet">
              Proxmox fleet
            </Link>
            <Link className="react-link-button" to="/dashboards">
              Geo dashboards
            </Link>
          </div>
        }
      />

      <div className="react-grid react-grid-5">
        <StatCard
          label="Nodes"
          value={graphNodes.length.toLocaleString()}
          hint={
            normalizedTopology.dedupedNodes > 0
              ? `${normalizedTopology.dedupedNodes.toLocaleString()} raw host/source duplicates merged for visual topology.`
              : "Entities currently generated from topology data."
          }
        />
        <StatCard label="Sources" value={metricValue(data, "monitored_sources")} hint="Telemetry sources observed in the current window." />
        <StatCard label="External IPs" value={metricValue(data, "external_attack_sources")} hint="Public source IPs seen in attack geography." />
        <StatCard label="Needs onboarding" value={metricValue(data, "unmanaged_candidates")} hint="Discovery candidates without connected telemetry." />
        <StatCard label="Access profiles" value={metricValue(data, "host_access_profiles")} hint="Host cards with SOAR/IRP access metadata or Vault refs." />
      </div>
      {(data.issues || []).length ? (
        <div className="react-inline-note react-inline-note-spaced">
          Topology is rendering partial data: {(data.issues || []).slice(0, 4).join(" / ")}
        </div>
      ) : null}

      <section className="react-topology-shell">
        <div className="react-topology-toolbar">
          <div>
            <div className="react-top-kicker">Generated</div>
            <strong>{formatTimestamp(data.generated_ts, "full")}</strong>
            <div className="react-inline-note">Switch layers to avoid mixing network topology, event pipeline and attack-surface decisions in one operator view.</div>
          </div>
          <div className="react-topology-controls">
            <input
              className="react-input react-input-grow"
              value={searchTerm}
              onChange={(event) => setSearchTerm(event.target.value)}
              placeholder="Search host, IP, source, role..."
            />
            <button type="button" className={`react-link-button${mapMode === "network" ? " active" : ""}`} onClick={() => setMapMode("network")}>
              Network topology
            </button>
            <button type="button" className={`react-link-button${mapMode === "telemetry" ? " active" : ""}`} onClick={() => setMapMode("telemetry")}>
              Telemetry flow
            </button>
            <button type="button" className={`react-link-button${mapMode === "posture" ? " active" : ""}`} onClick={() => setMapMode("posture")}>
              Security posture
            </button>
            <button type="button" className={`react-link-button${mapMode === "force" ? " active" : ""}`} onClick={() => setMapMode("force")}>
              Force graph
            </button>
            {mapMode === "force" ? (
              <>
                <button type="button" className="react-link-button" onClick={() => issueGraphCommand("zoom-out")}>
                  -
                </button>
                <span className="react-badge soft">{graphZoom}%</span>
                <button type="button" className="react-link-button" onClick={() => issueGraphCommand("zoom-in")}>
                  +
                </button>
                <button type="button" className="react-link-button" onClick={() => issueGraphCommand("fit")}>
                  Fit
                </button>
                <button type="button" className="react-link-button" onClick={() => issueGraphCommand("layout")}>
                  Layout
                </button>
              </>
            ) : null}
            <button type="button" className="react-link-button" onClick={() => setRefreshToken((current) => current + 1)}>
              Refresh
            </button>
          </div>
        </div>
        <div className="react-topology-layer-strip react-topology-layer-strip-inline">
          {(data.layers || []).map((layer) => (
            <span key={safeText(layer.id)} className="react-badge soft">
              {safeText(layer.title)}: {Number(layer.count || 0).toLocaleString()}
            </span>
          ))}
          <span className="react-badge soft">Protected: {protectedIps.join(", ") || "n/a"}</span>
          {normalizedTopology.dedupedNodes > 0 ? <span className="react-badge soft">Deduped visual nodes: {normalizedTopology.dedupedNodes}</span> : null}
        </div>
        {sourceNodes.length ? (
          <div className="react-topology-source-strip" aria-label="Telemetry source cards">
            <span>Source cards</span>
            {sourceNodes.slice(0, 18).map((node) => (
              <button
                key={node.id}
                type="button"
                className={`react-topology-source-pill kind-${cytoscapeClassName(nodeSourceKind(node))}${selectedNodeId === node.id ? " active" : ""}`}
                title={`${nodeDisplayLabel(node)} - ${nodeDisplayMeta(node)}`}
                onClick={() => setSelectedNodeId(node.id)}
              >
                <strong>{nodeDisplayLabel(node)}</strong>
                <small>{nodeDisplayMeta(node)}</small>
              </button>
            ))}
          </div>
        ) : null}
        <div className="react-topology-canvas-stage">
          {mapMode !== "force" ? (
            <OlympusNetworkTopology
              nodes={graphNodes}
              edges={visibleEdges}
              mode={mapMode}
              selectedNodeId={selectedNodeId}
              searchTerm={searchTerm}
              onSelectNode={setSelectedNodeId}
            />
          ) : (
            <>
              <CytoscapeTopologyCanvas
                nodes={graphNodes}
                edges={visibleEdges}
                selectedNodeId={selectedNodeId}
                hoveredNodeId={hoveredNodeId}
                searchTerm={searchTerm}
                command={graphCommand}
                onSelectNode={setSelectedNodeId}
                onHoverNode={setHoveredNodeId}
                onZoomChange={setGraphZoom}
              />
              <div className="react-topology-contour-legend" aria-label="Topology contour legend">
                {Object.entries(TOPOLOGY_LANES).map(([laneId, lane]) => (
                  <span key={laneId} className={`contour-${laneId}`}>
                    {lane.label}
                  </span>
                ))}
              </div>
            </>
          )}
          {selectedNode ? (
            <div className={`react-topology-floating-card type-${cytoscapeClassName(selectedNode.type)} kind-${cytoscapeClassName(nodeSourceKind(selectedNode))}`}>
              <div className="react-top-kicker">{nodeCardTitle(selectedNode)}</div>
              <strong>{nodeDisplayLabel(selectedNode)}</strong>
              <span>{nodeDisplayMeta(selectedNode)}</span>
              <div className="react-topology-floating-grid">
                <span>
                  Kind <b>{nodeSourceKindLabel(selectedNode)}</b>
                </span>
                <span>
                  Hostname <b>{nodeHostname(selectedNode) || "n/a"}</b>
                </span>
                <span>
                  IP <b>{safeText(selectedNode.ip)}</b>
                </span>
                <span>
                  Events <b>{Number(selectedNode.events || 0).toLocaleString()}</b>
                </span>
                <span>
                  Edges <b>{selectedEdges.length}</b>
                </span>
                <span>
                  Status <b>{safeText(selectedNode.status, "observed")}</b>
                </span>
              </div>
              <div className="react-actions react-wrap">
                {selectedNode.href ? (
                  <Link className="react-link-button" to={String(selectedNode.href).replace(/^\/app/, "")}>
                    {nodeOpenLabel(selectedNode)}
                  </Link>
                ) : null}
                <button type="button" className="react-link-button" onClick={() => setSelectedNodeId("")}>
                  Close
                </button>
              </div>
            </div>
          ) : null}
        </div>
      </section>

      <section className="react-card react-packet-flow-panel">
        <PanelHeader
          title="Actual packet / telemetry flow records"
          subtitle="API-supplied packet_flows only. This section does not invent switches, routers, VLANs or hosts that are absent from topology data."
          icon="map"
        />
        {packetFlows.length ? (
          <div className="react-table-wrap">
            <table className="react-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Flow</th>
                  <th>From</th>
                  <th>To</th>
                  <th>Protocols</th>
                  <th>Ports</th>
                  <th>Events</th>
                  <th>Nodes</th>
                </tr>
              </thead>
              <tbody>
                {packetFlows.map((flow, index) => (
                  <tr key={safeText(flow.id, `flow-${index}`)}>
                    <td>{Number(flow.order || index + 1)}</td>
                    <td>
                      <strong>{safeText(flow.title, "Flow")}</strong>
                      <div className="react-muted">{safeText(flow.description, "API flow record")}</div>
                    </td>
                    <td>{safeText(flow.from, "n/a")}</td>
                    <td>{safeText(flow.to, "n/a")}</td>
                    <td>{flowTokens(flow.protocols).join(", ") || "n/a"}</td>
                    <td>{flowTokens(flow.ports).join(", ") || "n/a"}</td>
                    <td>{Number(flow.events || 0).toLocaleString()}</td>
                    <td>{Number(flow.nodes || 0).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No packet flow records were returned by /api/topology/network for the current window." />
        )}
      </section>

      <div className="react-split react-split-xl">
        <section className="react-card">
          <PanelHeader
            title="Onboarding queue"
            subtitle="Hosts and guests that the system has discovered but does not yet see as full telemetry sources."
            icon="sources"
          />
          <div className="react-table-wrap">
            <table className="react-table">
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Kind</th>
                  <th>Reason</th>
                  <th>IP</th>
                </tr>
              </thead>
              <tbody>
                {(data.attention || []).map((item, index) => (
                  <tr key={`${safeText(item.id)}-${index}`}>
                    <td>
                      <Link className="react-inline-action" to={safeText(item.href, "/sources?view=discovery").replace(/^\/app/, "")}>
                        {safeText(item.label)}
                      </Link>
                    </td>
                    <td>{safeText(item.kind)}</td>
                    <td>{safeText(item.reason)}</td>
                    <td>{safeText(item.ip)}</td>
                  </tr>
                ))}
                {!(data.attention || []).length ? (
                  <tr>
                    <td colSpan={4}>No unmanaged candidates in the current topology window.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>
        <aside className="react-detail-column">
          <section className="react-card">
            <PanelHeader
              title={selectedNode ? nodeCardTitle(selectedNode) : "Selected node"}
              subtitle={selectedNode ? nodeDisplayLabel(selectedNode) : "Pick a host, source, collector or service in the topology map."}
              icon="map"
            />
            {selectedNode ? (
              <>
                <DrawerFieldGrid>
                  <KeyValue label="Type" value={safeText(selectedNode.type)} />
                  <KeyValue label="Kind" value={nodeSourceKindLabel(selectedNode)} />
                  <KeyValue label="Hostname" value={nodeHostname(selectedNode) || "n/a"} />
                  <KeyValue label="Source name" value={safeText(selectedNode.source_name, "n/a")} />
                  <KeyValue label="Status" value={<StatusBadge value={safeText(selectedNode.status, "observed")} />} />
                  <KeyValue label="Role" value={safeText(selectedNode.role)} />
                  <KeyValue label="IP" value={safeText(selectedNode.ip)} />
                  <KeyValue label="Events" value={Number(selectedNode.events || 0).toLocaleString()} />
                  <KeyValue label="Edges" value={selectedEdges.length} />
                  <KeyValue label="Access profiles" value={Number(selectedNode.access_profile_count || 0).toLocaleString()} />
                  <KeyValue label="Access status" value={safeText(selectedNode.access_status, "not configured")} />
                </DrawerFieldGrid>
                <div className="react-actions react-wrap">
                  {selectedNode.href ? (
                    <Link className="react-link-button" to={String(selectedNode.href).replace(/^\/app/, "")}>
                      {nodeOpenLabel(selectedNode)}
                    </Link>
                  ) : null}
                  <button type="button" className="react-link-button" onClick={() => setHostForm(formFromNode(selectedNode))}>
                    New access profile
                  </button>
                </div>
              </>
            ) : (
              <EmptyState message="Select a node to inspect it and create a SOAR-ready host card." />
            )}
          </section>

          {selectedNode ? (
            <section className="react-card react-card-nested">
              <PanelHeader
                title="Host access card"
                subtitle="Write-only secret material goes to Vault; UI stores and returns only references for future SOAR/IRP actions."
                icon="control"
              />
              <div className="react-inline-note react-topology-secret-note">
                Do not paste shared operator passwords unless they belong to this host. Raw password, key and certificate fields are never returned after save.
              </div>
              <div className="react-form-grid react-topology-host-form">
                <input className="react-input" value={hostForm.host_label} onChange={(event) => setHostForm((current) => ({ ...current, host_label: event.target.value }))} placeholder="Host label" />
                <input className="react-input" value={hostForm.hostname} onChange={(event) => setHostForm((current) => ({ ...current, hostname: event.target.value }))} placeholder="Hostname / FQDN" />
                <input className="react-input" value={hostForm.ip} onChange={(event) => setHostForm((current) => ({ ...current, ip: event.target.value }))} placeholder="Management IP" />
                <select className="react-select" value={hostForm.protocol} onChange={(event) => setHostForm((current) => ({ ...current, protocol: event.target.value }))}>
                  <option value="ssh">SSH</option>
                  <option value="rdp">RDP</option>
                  <option value="winrm">WinRM</option>
                  <option value="https">HTTPS</option>
                  <option value="http">HTTP</option>
                  <option value="snmp">SNMP</option>
                  <option value="custom">Custom</option>
                </select>
                <input className="react-input" value={hostForm.port} onChange={(event) => setHostForm((current) => ({ ...current, port: event.target.value }))} placeholder="Port" />
                <input className="react-input" value={hostForm.username} onChange={(event) => setHostForm((current) => ({ ...current, username: event.target.value }))} placeholder="Username / account" />
                <select className="react-select" value={hostForm.auth_method} onChange={(event) => setHostForm((current) => ({ ...current, auth_method: event.target.value }))}>
                  <option value="password">Password</option>
                  <option value="private_key">Private key</option>
                  <option value="certificate">Certificate</option>
                  <option value="vault_ref">Vault reference</option>
                  <option value="kerberos">Kerberos</option>
                  <option value="none">None</option>
                </select>
                <input className="react-input" value={hostForm.credential_label} onChange={(event) => setHostForm((current) => ({ ...current, credential_label: event.target.value }))} placeholder="Credential label" />
                <input className="react-input react-input-full" value={hostForm.credential_ref} onChange={(event) => setHostForm((current) => ({ ...current, credential_ref: event.target.value }))} placeholder="Password ref, e.g. vault://secret/siem/host-access/host?field=password" />
                <input className="react-input react-input-full" value={hostForm.private_key_ref} onChange={(event) => setHostForm((current) => ({ ...current, private_key_ref: event.target.value }))} placeholder="Private key ref" />
                <input className="react-input react-input-full" value={hostForm.certificate_ref} onChange={(event) => setHostForm((current) => ({ ...current, certificate_ref: event.target.value }))} placeholder="Certificate ref" />
                <input className="react-input react-input-full" type="password" value={hostForm.password} onChange={(event) => setHostForm((current) => ({ ...current, password: event.target.value }))} placeholder="Write-only password to Vault" />
                <textarea className="react-query-editor react-input-full" rows={3} value={hostForm.private_key_pem} onChange={(event) => setHostForm((current) => ({ ...current, private_key_pem: event.target.value }))} placeholder="Write-only private key PEM to Vault" />
                <textarea className="react-query-editor react-input-full" rows={3} value={hostForm.certificate_pem} onChange={(event) => setHostForm((current) => ({ ...current, certificate_pem: event.target.value }))} placeholder="Write-only certificate PEM to Vault" />
                <input className="react-input" type="password" value={hostForm.passphrase} onChange={(event) => setHostForm((current) => ({ ...current, passphrase: event.target.value }))} placeholder="Write-only key passphrase" />
                <input className="react-input" value={hostForm.jump_host} onChange={(event) => setHostForm((current) => ({ ...current, jump_host: event.target.value }))} placeholder="Jump host / bastion" />
                <input className="react-input react-input-full" value={hostForm.allowed_actions} onChange={(event) => setHostForm((current) => ({ ...current, allowed_actions: event.target.value }))} placeholder="Allowed SOAR actions, comma-separated" />
                <input className="react-input react-input-full" value={hostForm.tags} onChange={(event) => setHostForm((current) => ({ ...current, tags: event.target.value }))} placeholder="Tags, comma-separated" />
                <textarea className="react-query-editor react-input-full" rows={3} value={hostForm.notes} onChange={(event) => setHostForm((current) => ({ ...current, notes: event.target.value }))} placeholder="Operator notes / IRP guardrails" />
                <label className="react-toggle">
                  <input type="checkbox" checked={hostForm.enabled} onChange={(event) => setHostForm((current) => ({ ...current, enabled: event.target.checked }))} />
                  <span>Enabled for SOAR/IRP</span>
                </label>
              </div>
              <div className="react-actions react-wrap">
                <button type="button" className="react-primary-button" onClick={() => void saveProfile()} disabled={savingProfile || !hostForm.host_label.trim()}>
                  {savingProfile ? "Saving..." : "Save host card"}
                </button>
                <button type="button" className="react-link-button" onClick={() => setHostForm(formFromNode(selectedNode))}>
                  Clear form
                </button>
              </div>
              {formMessage ? <div className="react-inline-note react-inline-note-spaced">{formMessage}</div> : null}
              <div className="react-list react-list-compact react-topology-profile-list">
                {selectedProfiles.map((profile) => (
                  <div key={safeText(profile.profile_id)} className="react-list-item">
                    <div>
                      <strong>{safeText(profile.credential_label || profile.protocol, "profile")}</strong>
                      <span>
                        {safeText(profile.protocol)}:{safeText(profile.port)} / {safeText(profile.username)} / {safeText(profile.secret_status, "missing")}
                      </span>
                    </div>
                    <div className="react-actions react-wrap">
                      <button type="button" className="react-link-button" onClick={() => setHostForm(formFromProfile(profile, selectedNode))}>
                        Edit
                      </button>
                      <button type="button" className="react-link-button" onClick={() => void deleteProfile(profile)}>
                        Delete
                      </button>
                    </div>
                  </div>
                ))}
                {!selectedProfiles.length ? <div className="react-list-item">No access profile for this host yet.</div> : null}
              </div>
            </section>
          ) : null}

          {data.issues?.length ? (
            <section className="react-card react-card-nested">
              <PanelHeader title="Partial data issues" subtitle="Subsystems that did not return complete topology data." icon="control" />
              <div className="react-list react-list-compact">
                {data.issues.map((issue) => (
                  <div key={issue} className="react-list-item">
                    <span>{issue}</span>
                  </div>
                ))}
              </div>
            </section>
          ) : null}
        </aside>
      </div>
    </div>
  );
}
