import { describe, expect, test, vi } from "vitest";
import type { ConfigurationSourceIdentity } from "../src/config/config-source-identity.js";

const sourceIdentity: ConfigurationSourceIdentity = {
  status: "available",
  platform: "posix",
  path: "/configs/owner.json"
};

describe("configuration admin controller", () => {
  test("rejects a mismatched mutation identity before reading a candidate", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    const reloadFromFile = vi.fn(async () => state("c".repeat(64), 4));
    const controller = controllerModule.createConfigurationAdminController({
      serverPid: 51,
      instanceId: "22222222-2222-4222-8222-222222222222",
      sourceIdentity,
      revisionStore: createStore(state("a".repeat(64), 2), reloadFromFile)
    });

    const response = await controller.handle(reloadRequest({ expected_server_pid: 52 }));

    expect(response).toMatchObject({
      outcome: "rejected",
      rejection_code: "IDENTITY_MISMATCH",
      active_effective_generation: 2,
      active_source_sha256: "a".repeat(64)
    });
    expect(reloadFromFile).not.toHaveBeenCalled();
  });

  test("does not accept a client-supplied source path as a reload input", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    const reloadFromFile = vi.fn(async () => state("c".repeat(64), 4));
    const controller = controllerModule.createConfigurationAdminController({
      serverPid: 51,
      instanceId: "22222222-2222-4222-8222-222222222222",
      sourceIdentity,
      revisionStore: createStore(state("a".repeat(64), 2), reloadFromFile)
    });
    const request = { ...reloadRequest(), path: "/attacker/config.json" };

    await expect(controller.handle(request)).rejects.toThrow();
    expect(reloadFromFile).not.toHaveBeenCalled();
  });

  test("acknowledges the exact state returned by its own reload operation", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    const operationState = state("b".repeat(64), 3);
    const laterState = state("c".repeat(64), 4);
    const reloadFromFile = vi.fn(async () => {
      currentState = laterState;
      return operationState;
    });
    let currentState = state("a".repeat(64), 2);
    const controller = controllerModule.createConfigurationAdminController({
      serverPid: 51,
      instanceId: "22222222-2222-4222-8222-222222222222",
      sourceIdentity,
      revisionStore: createStore(() => currentState, reloadFromFile)
    });

    const response = await controller.handle(reloadRequest());

    expect(response).toMatchObject({
      outcome: "published",
      effective_generation: 3,
      accepted_source_sha256: "b".repeat(64)
    });
  });

  test("reports rejection against the state active when the response is built", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    let currentState = state("a".repeat(64), 2);
    const reloadFromFile = vi.fn(async () => {
      currentState = state("b".repeat(64), 3);
      throw new Error("private filesystem detail");
    });
    const controller = controllerModule.createConfigurationAdminController({
      serverPid: 51,
      instanceId: "22222222-2222-4222-8222-222222222222",
      sourceIdentity,
      revisionStore: createStore(() => currentState, reloadFromFile)
    });

    const response = await controller.handle(reloadRequest());

    expect(response).toMatchObject({
      outcome: "rejected",
      rejection_code: "CANDIDATE_REJECTED",
      active_effective_generation: 3,
      active_source_sha256: "b".repeat(64)
    });
    expect(JSON.stringify(response)).not.toContain("private filesystem detail");
  });

  test("reports an unavailable server source before checking request identity", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    const reloadFromFile = vi.fn(async () => state("b".repeat(64), 3));
    const controller = controllerModule.createConfigurationAdminController({
      serverPid: 51,
      instanceId: "22222222-2222-4222-8222-222222222222",
      sourceIdentity: { status: "unavailable", reason: "unsupported-path" },
      revisionStore: createStore(state("a".repeat(64), 2), reloadFromFile)
    });

    const response = await controller.handle(reloadRequest());

    expect(response).toMatchObject({ outcome: "rejected", rejection_code: "SOURCE_UNAVAILABLE" });
    expect(reloadFromFile).not.toHaveBeenCalled();
  });

  test("probes current revision state and includes the native helper PID", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    const controller = controllerModule.createConfigurationAdminController({
      serverPid: 51,
      helperPid: () => 52,
      instanceId: "22222222-2222-4222-8222-222222222222",
      sourceIdentity,
      revisionStore: createStore(state("a".repeat(64), 2), vi.fn())
    });

    const response = await controller.handle({
      protocol_version: 1,
      request_id: "33333333-3333-4333-8333-333333333333",
      operation: "probe"
    });

    expect(response).toMatchObject({
      operation: "probe_result",
      server_pid: 51,
      helper_pid: 52,
      effective_generation: 2,
      accepted_source_sha256: "a".repeat(64)
    });
  });

  test("rejects mutation once shutdown has started", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    const reloadFromFile = vi.fn(async () => state("b".repeat(64), 3));
    const controller = controllerModule.createConfigurationAdminController({
      serverPid: 51,
      instanceId: "22222222-2222-4222-8222-222222222222",
      sourceIdentity,
      revisionStore: createStore(state("a".repeat(64), 2), reloadFromFile),
      isShuttingDown: () => true
    });

    const response = await controller.handle(reloadRequest());

    expect(response).toMatchObject({ outcome: "rejected", rejection_code: "SHUTTING_DOWN" });
    expect(reloadFromFile).not.toHaveBeenCalled();
  });
});

function reloadRequest(overrides: Record<string, unknown> = {}) {
  return {
    protocol_version: 1,
    request_id: "11111111-1111-4111-8111-111111111111",
    operation: "reload",
    expected_server_pid: 51,
    expected_instance_id: "22222222-2222-4222-8222-222222222222",
    expected_source_identity: sourceIdentity,
    ...overrides
  };
}

function state(sourceSha256: string, generation: number) {
  return {
    acceptedCandidate: { sourceSha256 },
    effectiveHotRevision: { generation },
    pendingRestart: undefined
  };
}

function createStore(
  initial: ReturnType<typeof state> | (() => ReturnType<typeof state>),
  reloadFromFile: () => Promise<ReturnType<typeof state>>
) {
  return {
    getState: () => typeof initial === "function" ? initial() : initial,
    reloadFromFile
  };
}
