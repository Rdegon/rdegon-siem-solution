import { describe, expect, it } from "vitest";
import type { ServiceLifecycleInstance } from "../runtime/types";
import { canInvokeServiceAction, serviceActionLabel } from "../service-lifecycle";

function instance(overrides: Partial<ServiceLifecycleInstance> = {}): ServiceLifecycleInstance {
  return {
    instance_id: "writer-primary", title: "Writer", node: "siem-storage", vmid: 106, guest_type: "qemu",
    service_type: "writer", unit: "siem-writer.service", status: "active", active_state: "active",
    status_source: "systemd_live", management_state: "managed", capabilities: ["start", "stop", "restart"], ...overrides,
  };
}

describe("service lifecycle capabilities", () => {
  it("exposes only capabilities returned by the backend", () => {
    expect(canInvokeServiceAction(instance(), "restart")).toBe(true);
    expect(canInvokeServiceAction(instance(), "reload")).toBe(false);
  });

  it("never enables actions for read-only or unavailable adapters", () => {
    expect(canInvokeServiceAction(instance({ management_state: "read_only" }), "restart")).toBe(false);
    expect(canInvokeServiceAction(instance({ management_state: "unavailable" }), "start")).toBe(false);
  });

  it("provides explicit labels for every lifecycle action", () => {
    expect(serviceActionLabel("start")).toBe("Запустить");
    expect(serviceActionLabel("stop")).toBe("Остановить");
    expect(serviceActionLabel("restart")).toBe("Перезапустить");
    expect(serviceActionLabel("reload")).toBe("Перезагрузить конфигурацию");
  });
});
