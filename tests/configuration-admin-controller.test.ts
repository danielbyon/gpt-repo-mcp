import { describe, expect, test, vi } from "vitest";
import type { ConfigurationSourceIdentity } from "../src/config/config-source-identity.js";
import type { ConfigurationRevisionState } from "../src/services/configuration-revision-store.js";

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

  test("does not reject a reload when success response construction fails after publication", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    const publishedState = state("b".repeat(64), 3);
    let currentState = state("a".repeat(64), 2);
    let helperPidCalls = 0;
    const reloadFromFile = vi.fn(async () => {
      currentState = publishedState;
      return publishedState;
    });
    const controller = controllerModule.createConfigurationAdminController({
      serverPid: 51,
      helperPid: () => {
        helperPidCalls += 1;
        if (helperPidCalls === 1) throw new Error("helper PID response unavailable");
        return 52;
      },
      instanceId: "22222222-2222-4222-8222-222222222222",
      sourceIdentity,
      revisionStore: createStore(() => currentState, reloadFromFile)
    });

    await expect(controller.handle(reloadRequest())).rejects.toThrow("helper PID response unavailable");

    expect(reloadFromFile).toHaveBeenCalledOnce();
    expect(helperPidCalls).toBe(1);
    expect(currentState).toMatchObject({
      effectiveHotRevision: { generation: 3 },
      acceptedCandidate: { sourceSha256: "b".repeat(64) }
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

  test("returns one coherent status snapshot without publishing or reloading", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    const statusState = revisionStatusState("a".repeat(64), 4);
    const captureStatus = vi.fn(async () => ({
      state: statusState,
      savedSource: {
        status: "validation-failed" as const,
        category: "repository-filesystem" as const,
        sourceSha256: "b".repeat(64),
        issueCodes: ["ROOT_MISSING"],
        issueCodesTruncated: false
      }
    }));
    const reloadFromFile = vi.fn(async () => state("c".repeat(64), 5));
    const controller = controllerModule.createConfigurationAdminController({
      serverPid: 51,
      helperPid: 52,
      instanceId: "22222222-2222-4222-8222-222222222222",
      sourceIdentity,
      revisionStore: {
        getState: vi.fn(() => statusState),
        captureStatus,
        reloadFromFile
      }
    });

    const response = await controller.handle(statusRequest());

    expect(response).toMatchObject({
      operation: "status_result",
      server_pid: 51,
      helper_pid: 52,
      source_identity: sourceIdentity,
      accepted_candidate: {
        source_status: "available",
        source_sha256: "a".repeat(64),
        repository_count: 2,
        restart_fields: ["executable", "index_timeout_ms", "provider", "query_timeout_ms"]
      },
      saved_source: {
        status: "validation-failed",
        category: "repository-filesystem",
        source_sha256: "b".repeat(64),
        issue_codes: ["ROOT_MISSING"]
      },
      active_hot_revision: { generation: 4, repository_count: 1 },
      initialized_restart_fields: ["executable", "index_timeout_ms", "provider", "query_timeout_ms"],
      pending_restart_fields: ["query_timeout_ms"],
      last_reload_outcome: "rejected"
    });
    expect(captureStatus).toHaveBeenCalledOnce();
    expect(reloadFromFile).not.toHaveBeenCalled();
  });

  test("allows status for an intentionally unconfigured server", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    const noSourceIdentity = { status: "none" } as const;
    const statusState = revisionStatusState("a".repeat(64), 1);
    const captureStatus = vi.fn(async () => ({ state: statusState, savedSource: { status: "no-source" as const } }));
    const controller = controllerModule.createConfigurationAdminController({
      serverPid: 51,
      instanceId: "22222222-2222-4222-8222-222222222222",
      sourceIdentity: noSourceIdentity,
      revisionStore: {
        getState: vi.fn(() => statusState),
        captureStatus,
        reloadFromFile: vi.fn()
      }
    });

    const response = await controller.handle(statusRequest({ expected_source_identity: noSourceIdentity }));

    expect(response).toMatchObject({ operation: "status_result", source_identity: noSourceIdentity, saved_source: { status: "no-source" } });
    expect(response).toMatchObject({
      accepted_candidate: { source_status: "none", repository_count: 2, restart_fields: ["executable", "index_timeout_ms", "provider", "query_timeout_ms"] }
    });
    expect(JSON.stringify(response)).not.toContain("source_sha256");
    expect(JSON.stringify(response)).not.toContain("a".repeat(64));
    expect(captureStatus).toHaveBeenCalledOnce();
  });

  test("projects file-read, JSON, and valid saved-source observations without exposing file details", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    const observations = [
      { status: "read-failed", code: "FILE_READ_FAILED" },
      { status: "invalid-json", sourceSha256: "b".repeat(64) },
      {
        status: "valid",
        sourceSha256: "b".repeat(64),
        matchesAccepted: false,
        repositoryCount: 3,
        restartFields: ["provider"]
      }
    ] as const;

    for (const savedSource of observations) {
      const controller = controllerModule.createConfigurationAdminController({
        serverPid: 51,
        instanceId: "22222222-2222-4222-8222-222222222222",
        sourceIdentity,
        revisionStore: {
          getState: () => state("a".repeat(64), 2),
          captureStatus: async () => ({ state: revisionStatusState("a".repeat(64), 2), savedSource }),
          reloadFromFile: vi.fn()
        }
      });

      const response = await controller.handle(statusRequest());

      expect(response.operation).toBe("status_result");
      if (response.operation === "status_result") {
        expect(response.saved_source).toMatchObject({ status: savedSource.status });
        expect(JSON.stringify(response)).not.toContain("private");
      }
    }
  });

  test("does not observe status when the requested source differs from the bound instance", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    const captureStatus = vi.fn();
    const controller = controllerModule.createConfigurationAdminController({
      serverPid: 51,
      instanceId: "22222222-2222-4222-8222-222222222222",
      sourceIdentity,
      revisionStore: {
        getState: () => state("a".repeat(64), 2),
        captureStatus,
        reloadFromFile: vi.fn()
      }
    });

    await expect(controller.handle(statusRequest({
      expected_source_identity: { ...sourceIdentity, path: "/configs/other.json" }
    }))).rejects.toThrow();
    expect(captureStatus).not.toHaveBeenCalled();
  });

  test("does not read saved configuration after status observes server shutdown", async () => {
    const controllerModule = await import("../src/runtime/configuration-admin-controller.js");
    const captureStatus = vi.fn();
    const controller = controllerModule.createConfigurationAdminController({
      serverPid: 51,
      instanceId: "22222222-2222-4222-8222-222222222222",
      sourceIdentity,
      revisionStore: {
        getState: () => state("a".repeat(64), 2),
        captureStatus,
        reloadFromFile: vi.fn()
      },
      isShuttingDown: () => true
    });

    await expect(controller.handle(statusRequest())).rejects.toThrow("shutting down");
    expect(captureStatus).not.toHaveBeenCalled();
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

function statusRequest(overrides: Record<string, unknown> = {}) {
  return {
    protocol_version: 1,
    request_id: "33333333-3333-4333-8333-333333333333",
    operation: "status",
    expected_server_pid: 51,
    expected_instance_id: "22222222-2222-4222-8222-222222222222",
    expected_source_identity: sourceIdentity,
    ...overrides
  };
}

function revisionStatusState(sourceSha256: string, generation: number): ConfigurationRevisionState {
  const initializedSettings = {
    provider: "codebase_memory",
    executable: "/usr/bin/node",
    query_timeout_ms: 3_000,
    index_timeout_ms: 1_800_000
  };
  const acceptedSettings = { ...initializedSettings, query_timeout_ms: 5_000 };
  const repositories = (count: number) => ({ list: () => Array.from({ length: count }, () => ({ repo_id: "fixture", display_name: "Fixture", root: "/private/repo" })) });
  return {
    acceptedCandidate: {
      sourceSha256,
      registry: repositories(2),
      restartSettings: acceptedSettings
    },
    initializedRestartSettings: initializedSettings,
    effectiveHotRevision: {
      generation,
      runtimeContext: { registry: repositories(1) }
    },
    pendingRestart: { initialized: initializedSettings, accepted: acceptedSettings },
    lastReloadOutcome: "rejected" as const
  } as unknown as ConfigurationRevisionState;
}

function state(sourceSha256: string, generation: number): ConfigurationRevisionState {
  return {
    acceptedCandidate: { sourceSha256 },
    effectiveHotRevision: { generation },
    pendingRestart: undefined
  } as unknown as ConfigurationRevisionState;
}

function createStore(
  initial: ReturnType<typeof state> | (() => ReturnType<typeof state>),
  reloadFromFile: () => Promise<ReturnType<typeof state>>
) {
  return {
    getState: () => typeof initial === "function" ? initial() : initial,
    captureStatus: async () => { throw new Error("Status capture is not configured for this reload test."); },
    reloadFromFile
  };
}
