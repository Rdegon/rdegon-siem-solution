import { describe, expect, it } from "vitest";
import {
  RESOURCE_DEFINITIONS,
  resourceDefaults,
  resourceSteps,
  sanitizeResourceConfig,
} from "../kuma-workspaces";

const BACKEND_RESOURCE_KINDS = [
  "collector",
  "correlator",
  "storage",
  "activeList",
  "aggregationRule",
  "connector",
  "correlationRule",
  "dictionary",
  "enrichmentRule",
  "destination",
  "filter",
  "normalizer",
  "responseRule",
  "search",
  "agent",
  "proxy",
  "secret",
  "segmentationRule",
  "emailTemplate",
  "contextTable",
  "eventRouter",
] as const;

describe("KUMA resource workspace schemas", () => {
  it("matches every backend-supported resource kind exactly once", () => {
    const frontendKinds = RESOURCE_DEFINITIONS.map((item) => item.kind);

    expect(frontendKinds).toEqual(BACKEND_RESOURCE_KINDS);
    expect(new Set(frontendKinds).size).toBe(BACKEND_RESOURCE_KINDS.length);
  });

  it.each(BACKEND_RESOURCE_KINDS)(
    "provides Russian labels and a structured editor for %s",
    (kind) => {
      const definition = RESOURCE_DEFINITIONS.find((item) => item.kind === kind);
      const steps = resourceSteps(kind);

      expect(definition).toBeDefined();
      expect(definition?.label).toMatch(/[А-Яа-яЁё]/);
      expect(definition?.description).toMatch(/[А-Яа-яЁё]/);
      expect(steps.length).toBeGreaterThanOrEqual(2);
      expect(new Set(steps.map((item) => item.id)).size).toBe(steps.length);
      expect(steps[steps.length - 1]).toMatchObject({
        id: "validation",
        editor: "validation",
      });

      for (const step of steps) {
        expect(step.label).toMatch(/[А-Яа-яЁё]/);
        if (step.editor === "validation") continue;
        expect(Boolean(step.editor) || Boolean(step.fields?.length)).toBe(true);
        for (const field of step.fields ?? []) {
          expect(field.key.trim()).not.toBe("");
          expect(field.label.trim()).not.toBe("");
          expect(field.type).not.toBe("json");
        }
      }
    },
  );

  it("keeps secret resources reference-only", () => {
    const secretFields = resourceSteps("secret")
      .flatMap((step) => step.fields ?? [])
      .map((field) => field.key);

    expect(secretFields).toEqual([
      "secret_ref",
      "provider",
      "purpose",
      "rotation_days",
    ]);
    expect(secretFields).not.toContain("value");
    expect(secretFields).not.toContain("password");
    expect(secretFields).not.toContain("token");
  });

  it("materializes schema defaults for persisted config and bindings", () => {
    expect(resourceDefaults("collector", "config")).toMatchObject({
      enabled: true,
      transport: "http",
      workers: 2,
      batch_size: 500,
      topic: "siem.raw",
    });
    expect(resourceDefaults("correlator", "bindings")).toEqual({});
    expect(resourceDefaults("activeList", "config")).toMatchObject({
      list_kind: "watch",
      ttl_seconds: 0,
      key_fields: ["value"],
    });
  });

  it("removes legacy inline secret material before save", () => {
    expect(
      sanitizeResourceConfig("secret", {
        secret_ref: "vault:secret/data/siem/example",
        provider: "vault",
        purpose: "API integration",
        rotation_days: 30,
        value: "must-not-survive",
        password: "must-not-survive",
        token: "must-not-survive",
      }),
    ).toEqual({
      secret_ref: "vault:secret/data/siem/example",
      provider: "vault",
      purpose: "API integration",
      rotation_days: 30,
    });
  });
});
