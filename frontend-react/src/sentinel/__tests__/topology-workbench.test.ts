import { describe, expect, it } from "vitest";
import type { NetworkTopologyResponse, TopologyLayoutResponse, TopologyNodeRecord } from "../runtime/types";
import { buildTopologyNodes, topologySegment } from "../topology-workbench";

function record(id: string, extra: Partial<TopologyNodeRecord> = {}): TopologyNodeRecord {
  return { id, label: `Node ${id}`, type: "server", ...extra };
}

function topology(nodes: TopologyNodeRecord[]): NetworkTopologyResponse {
  return { nodes, edges: [] };
}

function overlaps(left: { position: { x: number; y: number }; style?: React.CSSProperties }, right: { position: { x: number; y: number }; style?: React.CSSProperties }) {
  const leftWidth = Number(left.style?.width ?? 0);
  const leftHeight = Number(left.style?.height ?? 0);
  const rightWidth = Number(right.style?.width ?? 0);
  const rightHeight = Number(right.style?.height ?? 0);
  return left.position.x < right.position.x + rightWidth
    && left.position.x + leftWidth > right.position.x
    && left.position.y < right.position.y + rightHeight
    && left.position.y + leftHeight > right.position.y;
}

describe("production topology layout", () => {
  it("maps explicit segments and asset groups to the expected zones", () => {
    expect(topologySegment(record("pve", { asset_group: "proxmox" }))).toBe("mgmt");
    expect(topologySegment(record("siem", { asset_group: ["linux_common", "siem_core"] }))).toBe("sec");
    expect(topologySegment(record("edge", { segment: "SEC", asset_group: "linux_common" }))).toBe("sec");
    expect(topologySegment(record("game", { asset_group: "game" }))).toBe("servers/games");
  });

  it("places every source without overlapping nodes or segment frames", () => {
    const nodes = buildTopologyNodes(topology([
      ...Array.from({ length: 11 }, (_, index) => record(`sec-${index}`, { segment: "sec" })),
      ...Array.from({ length: 7 }, (_, index) => record(`lab-${index}`, { segment: "lab" })),
      ...Array.from({ length: 5 }, (_, index) => record(`srv-${index}`, { asset_group: "public_services" })),
    ]));
    const assets = nodes.filter((node) => node.type === "asset");
    const segments = nodes.filter((node) => node.type === "segment");

    for (let left = 0; left < assets.length; left += 1) {
      for (let right = left + 1; right < assets.length; right += 1) {
        if (assets[left].parentId === assets[right].parentId) expect(overlaps(assets[left], assets[right])).toBe(false);
      }
    }
    for (let left = 0; left < segments.length; left += 1) {
      for (let right = left + 1; right < segments.length; right += 1) expect(overlaps(segments[left], segments[right])).toBe(false);
    }
  });

  it("repairs colliding saved positions and auto-places a newly discovered source", () => {
    const saved: TopologyLayoutResponse = {
      workspace: "network",
      version: 1,
      positions: {
        first: { x: 24, y: 62, segment: "lab" },
        second: { x: 24, y: 62, segment: "lab" },
      },
    };
    const nodes = buildTopologyNodes(topology([
      record("first", { segment: "lab" }),
      record("second", { segment: "lab" }),
      record("new-source", { asset_group: "windows" }),
    ]), saved);
    const first = nodes.find((node) => node.id === "first")!;
    const second = nodes.find((node) => node.id === "second")!;
    const discovered = nodes.find((node) => node.id === "new-source")!;

    expect(overlaps(first, second)).toBe(false);
    expect(discovered.parentId).toBe("segment:users");
    expect(discovered.position.x).toBeGreaterThanOrEqual(0);
    expect(discovered.position.y).toBeGreaterThanOrEqual(0);
  });
});
