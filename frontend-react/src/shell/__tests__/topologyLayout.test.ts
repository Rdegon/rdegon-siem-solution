import { describe, expect, it } from "vitest";

import { buildTopologyLayout } from "../pages/topology/ReactFlowTopologyCanvas";
import type { TopologyEdgeRecord, TopologyLayoutPosition, TopologyNodeRecord } from "../types";

function overlaps(
  left: { position: { x: number; y: number }; width?: number | null; height?: number | null },
  right: { position: { x: number; y: number }; width?: number | null; height?: number | null },
) {
  const gap = 20;
  return !(
    left.position.x + Number(left.width || 0) + gap <= right.position.x ||
    right.position.x + Number(right.width || 0) + gap <= left.position.x ||
    left.position.y + Number(left.height || 0) + gap <= right.position.y ||
    right.position.y + Number(right.height || 0) + gap <= left.position.y
  );
}

describe("production topology layout", () => {
  it("keeps full labels and resolves overlapping persisted positions", async () => {
    const nodes: TopologyNodeRecord[] = [
      { id: "core-1", type: "core_service", label: "SIEM Processing and Stream Correlation", ip: "10.20.10.105", network_segment: "sec" },
      { id: "core-2", type: "core_service", label: "SIEM Storage ClickHouse Cluster", ip: "10.20.10.106", network_segment: "sec" },
      { id: "edge-1", type: "source", label: "OPNsense Virtual Router and NGFW", ip: "192.168.3.102", network_segment: "mgmt" },
      { id: "server-1", type: "source", label: "Minecraft Production Server", ip: "10.20.20.100", network_segment: "servers-games" },
    ];
    const edges: TopologyEdgeRecord[] = [
      { id: "e-1", source: "edge-1", target: "core-1", type: "telemetry_pipeline" },
      { id: "e-2", source: "server-1", target: "core-1", type: "telemetry_pipeline" },
      { id: "e-3", source: "core-1", target: "core-2", type: "runtime_relation" },
    ];
    const persisted: Record<string, TopologyLayoutPosition> = Object.fromEntries(
      nodes.map((node) => [node.id, { x: 22, y: 78, segment: String(node.network_segment) }]),
    );

    const result = await buildTopologyLayout(nodes, edges, persisted);
    const deviceNodes = result.nodes.filter((node) => node.type === "device");
    const segmentNodes = result.nodes.filter((node) => node.type === "segment");

    expect(deviceNodes).toHaveLength(nodes.length);
    expect(segmentNodes).toHaveLength(3);
    expect(result.edges).toHaveLength(edges.length);
    expect(deviceNodes.map((node) => node.data.label).sort()).toEqual(nodes.map((node) => node.label).sort());

    for (const segment of segmentNodes) {
      const children = deviceNodes.filter((node) => node.parentId === segment.id);
      for (let leftIndex = 0; leftIndex < children.length; leftIndex += 1) {
        for (let rightIndex = leftIndex + 1; rightIndex < children.length; rightIndex += 1) {
          expect(overlaps(children[leftIndex], children[rightIndex])).toBe(false);
        }
      }
    }

    for (let leftIndex = 0; leftIndex < segmentNodes.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < segmentNodes.length; rightIndex += 1) {
        expect(overlaps(segmentNodes[leftIndex], segmentNodes[rightIndex])).toBe(false);
      }
    }
  });
});
