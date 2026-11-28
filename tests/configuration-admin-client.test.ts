import { describe, expect, test, vi } from "vitest";
import type { ConfigurationSourceIdentity } from "../src/config/config-source-identity.js";
import type { ConfigurationAdminDiscoveryRecord, ConfigurationAdminProbeResult } from "../src/runtime/configuration-admin-client.js";
import { ConfigurationAdminIpcError } from "../src/runtime/configuration-admin-error.js";
import { readConfigurationAdminRecords, sendConfigurationAdminRequest } from "../src/runtime/configuration-admin-host.js";
import type { ConfigurationAdminRequest, ConfigurationAdminResponse } from "../src/runtime/configuration-admin-protocol.js";

vi.mock("../src/runtime/configuration-admin-host.js", () => ({
  readConfigurationAdminRecords: vi.fn(),
  sendConfigurationAdminRequest: vi.fn()
}));

const sourceA: ConfigurationSourceIdentity = {
  status: "available",
  platform: "posix",
  path: "/configs/a.json"
};

describe("configuration admin target selection", () => {
  test("selects the sole reachable instance matching the selected source", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    const records = [record(41, "instance-a"), record(42, "instance-b")];
    const selected = await client.selectConfigurationAdminTarget({
      records,
      selectedSourceIdentity: sourceA,
      probe: async (entry) => probe(entry, entry.server_pid === 41 ? sourceA : source("/configs/b.json"))
    });

    expect(selected.record.server_pid).toBe(41);
  });

  test("requires an explicit PID when several reachable instances match", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");

    await expect(client.selectConfigurationAdminTarget({
      records: [record(41, "instance-a"), record(42, "instance-b")],
      selectedSourceIdentity: sourceA,
      probe: async (entry) => probe(entry, sourceA)
    })).rejects.toMatchObject({ code: "AMBIGUOUS_INSTANCE" });
  });

  test("does not let an explicit PID bypass the source identity guard", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");

    await expect(client.selectConfigurationAdminTarget({
      records: [record(41, "instance-a"), record(42, "instance-b")],
      selectedSourceIdentity: sourceA,
      instancePid: 42,
      probe: async (entry) => probe(entry, entry.server_pid === 41 ? sourceA : source("/configs/b.json"))
    })).rejects.toMatchObject({ code: "SOURCE_MISMATCH" });
  });

  test("does not dispatch reload for a differently cased Windows source during automatic selection", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    const selectedSourceIdentity = {
      status: "available",
      platform: "win32",
      path: String.raw`C:\Workspace\Config.json`
    } as const;
    const reportedSourceIdentity = {
      ...selectedSourceIdentity,
      path: String.raw`c:\workspace\config.JSON`
    } as const;
    vi.mocked(readConfigurationAdminRecords).mockReset().mockResolvedValue([record(41, "instance-a")]);
    vi.mocked(sendConfigurationAdminRequest).mockReset().mockImplementation(async (entry, request) => {
      if (request.operation !== "probe") throw new Error("Reload must not be dispatched after a source mismatch.");
      return probe(entry, reportedSourceIdentity, request.request_id);
    });

    await expect(client.reloadConfigurationAdmin({ selectedSourceIdentity }))
      .rejects.toMatchObject({ code: "NO_MATCHING_INSTANCE" });
    expect(vi.mocked(sendConfigurationAdminRequest).mock.calls.map(([, request]) => request.operation))
      .toEqual(["probe"]);
    vi.mocked(readConfigurationAdminRecords).mockClear();
    vi.mocked(sendConfigurationAdminRequest).mockClear();
  });

  test("does not dispatch reload for a differently cased Windows source with an explicit PID", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    const selectedSourceIdentity = {
      status: "available",
      platform: "win32",
      path: String.raw`C:\Workspace\Config.json`
    } as const;
    const reportedSourceIdentity = {
      ...selectedSourceIdentity,
      path: String.raw`c:\workspace\config.JSON`
    } as const;
    vi.mocked(readConfigurationAdminRecords).mockReset().mockResolvedValue([record(41, "instance-a")]);
    vi.mocked(sendConfigurationAdminRequest).mockReset().mockImplementation(async (entry, request) => {
      if (request.operation !== "probe") throw new Error("Reload must not be dispatched after a source mismatch.");
      return probe(entry, reportedSourceIdentity, request.request_id);
    });

    await expect(client.reloadConfigurationAdmin({ selectedSourceIdentity, instancePid: 41 }))
      .rejects.toMatchObject({ code: "SOURCE_MISMATCH" });
    expect(vi.mocked(sendConfigurationAdminRequest).mock.calls.map(([, request]) => request.operation))
      .toEqual(["probe"]);
    vi.mocked(readConfigurationAdminRecords).mockClear();
    vi.mocked(sendConfigurationAdminRequest).mockClear();
  });

  test("ignores stale endpoint identities and instances without a source", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    const records = [record(41, "stale-instance"), record(42, "no-source"), record(43, "active-instance")];
    const selected = await client.selectConfigurationAdminTarget({
      records,
      selectedSourceIdentity: sourceA,
      probe: async (entry) => entry.server_pid === 41
        ? { ...probe(entry, sourceA), instance_id: "replacement-instance" }
        : probe(entry, entry.server_pid === 42 ? { status: "none" } : sourceA)
    });

    expect(selected.record.server_pid).toBe(43);
  });

  test("reports missing, unavailable, and source-mismatched explicit PIDs", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    const options = {
      records: [record(41, "instance-a")],
      selectedSourceIdentity: sourceA,
      probe: async (entry: ConfigurationAdminDiscoveryRecord) => probe(entry, sourceA)
    };

    await expect(client.selectConfigurationAdminTarget({ ...options, instancePid: 42 }))
      .rejects.toMatchObject({ code: "INSTANCE_NOT_FOUND" });
    await expect(client.selectConfigurationAdminTarget({
      ...options,
      instancePid: 41,
      probe: async () => { throw new Error("endpoint unavailable"); }
    })).rejects.toMatchObject({ code: "INSTANCE_UNAVAILABLE" });
    await expect(client.selectConfigurationAdminTarget({
      ...options,
      instancePid: 41,
      probe: async (entry) => probe(entry, source("/configs/other.json"))
    })).rejects.toMatchObject({ code: "SOURCE_MISMATCH" });
  });

  test("counts default-path and intentional no-source servers together for ambiguity", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");

    await expect(client.selectConfigurationAdminStatusTarget({
      records: [record(41, "instance-a"), record(42, "no-source")],
      selectedSourceIdentity: sourceA,
      allowNoSource: true,
      probe: async (entry) => probe(entry, entry.server_pid === 41 ? sourceA : { status: "none" })
    })).rejects.toMatchObject({ code: "AMBIGUOUS_INSTANCE" });
  });

  test("allows default status to select a sole no-source server and excludes unavailable sources", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");

    const selected = await client.selectConfigurationAdminStatusTarget({
      records: [record(41, "unavailable"), record(42, "no-source")],
      selectedSourceIdentity: sourceA,
      allowNoSource: true,
      probe: async (entry) => probe(entry, entry.server_pid === 41
        ? { status: "unavailable", reason: "unsupported-path" }
        : { status: "none" })
    });

    expect(selected.record.server_pid).toBe(42);
    expect(selected.probe.source_identity).toEqual({ status: "none" });
  });

  test("keeps explicit status source matching strict and prevents PID bypass", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    const records = [record(41, "no-source")];

    await expect(client.selectConfigurationAdminStatusTarget({
      records,
      selectedSourceIdentity: sourceA,
      allowNoSource: false,
      probe: async (entry) => probe(entry, { status: "none" })
    })).rejects.toMatchObject({ code: "NO_MATCHING_INSTANCE" });
    await expect(client.selectConfigurationAdminStatusTarget({
      records,
      selectedSourceIdentity: sourceA,
      allowNoSource: true,
      instancePid: 41,
      probe: async (entry) => probe(entry, { status: "unavailable", reason: "unsupported-path" })
    })).rejects.toMatchObject({ code: "SOURCE_MISMATCH" });
  });

  test("rejects unavailable source identities before probing for reload and status", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    const probeRequest = vi.fn(async () => probe(record(41, "instance-a"), sourceA));
    const options = {
      records: [record(41, "instance-a")],
      selectedSourceIdentity: { status: "unavailable", reason: "empty-path" } as const,
      probe: probeRequest
    };

    await expect(client.selectConfigurationAdminTarget(options))
      .rejects.toMatchObject({ code: "ADMIN_SOURCE_UNAVAILABLE" });
    await expect(client.selectConfigurationAdminStatusTarget({ ...options, allowNoSource: true }))
      .rejects.toMatchObject({ code: "ADMIN_SOURCE_UNAVAILABLE" });
    expect(probeRequest).not.toHaveBeenCalled();
  });

  test("does not select a status target when its probe response operation is wrong", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    vi.mocked(readConfigurationAdminRecords).mockReset();
    vi.mocked(readConfigurationAdminRecords).mockResolvedValue([record(41, "instance-a")]);
    vi.mocked(sendConfigurationAdminRequest).mockReset();
    vi.mocked(sendConfigurationAdminRequest).mockResolvedValue({
      ...probe(record(41, "instance-a"), sourceA),
      operation: "reload_result"
    } as unknown as ConfigurationAdminResponse);

    await expect(client.statusConfigurationAdmin({
      selectedSourceIdentity: sourceA,
      allowNoSource: false
    })).rejects.toMatchObject({ code: "NO_MATCHING_INSTANCE" });
    vi.mocked(readConfigurationAdminRecords).mockReset();
    vi.mocked(sendConfigurationAdminRequest).mockReset();
  });

  test("preserves a pre-dispatch probe error for an explicitly selected PID", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    const denied = new ConfigurationAdminIpcError(
      "WINDOWS_PIPE_ACCESS_DENIED",
      "pre-dispatch",
      "Windows denied access to the owner-local administrative pipe."
    );

    await expect(client.selectConfigurationAdminTarget({
      records: [record(41, "instance-a")],
      selectedSourceIdentity: sourceA,
      instancePid: 41,
      probe: async () => { throw denied; }
    })).rejects.toBe(denied);
  });

  test("reports no matching source when discovery has no verified candidate", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    await expect(client.selectConfigurationAdminTarget({
      records: [record(41, "instance-a")],
      selectedSourceIdentity: sourceA,
      probe: async (entry) => ({ ...probe(entry, sourceA), helper_pid: 999 })
    })).rejects.toMatchObject({ code: "NO_MATCHING_INSTANCE" });
  });

  test("sends one identity-bound reload after a matching probe", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    const target = record(41, "instance-a");
    vi.mocked(readConfigurationAdminRecords).mockResolvedValue([target]);
    vi.mocked(sendConfigurationAdminRequest).mockImplementation(async (entry, request) => {
      if (request.operation === "probe") return probe(entry, sourceA, request.request_id);
      return publishedResponse(entry, request, sourceA);
    });

    const response = await client.reloadConfigurationAdmin({ selectedSourceIdentity: sourceA });

    expect(response).toMatchObject({ outcome: "published", accepted_source_sha256: "c".repeat(64) });
    expect(sendConfigurationAdminRequest).toHaveBeenCalledTimes(2);
    expect(sendConfigurationAdminRequest).toHaveBeenLastCalledWith(target, expect.objectContaining({
      operation: "reload",
      expected_server_pid: target.server_pid,
      expected_instance_id: target.instance_id,
      expected_source_identity: sourceA
    }));
  });

  test("sends status bound to the selected no-source instance and validates the response identity", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    const target = record(41, "instance-a");
    vi.mocked(readConfigurationAdminRecords).mockResolvedValue([target]);
    vi.mocked(sendConfigurationAdminRequest).mockImplementation(async (entry, request) => {
      if (request.operation === "probe") return probe(entry, { status: "none" }, request.request_id);
      if (request.operation !== "status") throw new Error("Expected a status request.");
      return statusResponse(entry, request, { status: "none" });
    });

    const response = await client.statusConfigurationAdmin({
      selectedSourceIdentity: sourceA,
      allowNoSource: true
    });

    expect(response).toMatchObject({ operation: "status_result", source_identity: { status: "none" } });
    expect(sendConfigurationAdminRequest).toHaveBeenLastCalledWith(target, expect.objectContaining({
      operation: "status",
      expected_server_pid: target.server_pid,
      expected_instance_id: target.instance_id,
      expected_source_identity: { status: "none" }
    }));
  });

  test("rejects an uncorrelated status response without reload-specific uncertainty", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    vi.mocked(readConfigurationAdminRecords).mockResolvedValue([record(41, "instance-a")]);
    vi.mocked(sendConfigurationAdminRequest).mockImplementation(async (entry, request) => {
      if (request.operation === "probe") return probe(entry, sourceA, request.request_id);
      if (request.operation !== "status") throw new Error("Expected a status request.");
      return { ...statusResponse(entry, request, sourceA), request_id: "99999999-9999-4999-8999-999999999999" };
    });

    await expect(client.statusConfigurationAdmin({
      selectedSourceIdentity: sourceA,
      allowNoSource: false
    })).rejects.toMatchObject({ code: "IPC_IDENTITY_CHANGED", phase: "pre-dispatch" });
  });

  test("rejects an unavailable selected source before discovery", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    vi.mocked(readConfigurationAdminRecords).mockClear();

    await expect(client.reloadConfigurationAdmin({
      selectedSourceIdentity: { status: "unavailable", reason: "empty-path" }
    })).rejects.toMatchObject({ code: "ADMIN_SOURCE_UNAVAILABLE" });
    expect(readConfigurationAdminRecords).not.toHaveBeenCalled();
  });

  test("classifies a changed server response after reload as indeterminate", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    vi.mocked(readConfigurationAdminRecords).mockResolvedValue([record(41, "instance-a")]);
    vi.mocked(sendConfigurationAdminRequest).mockImplementation(async (entry, request) => {
      if (request.operation === "probe") return probe(entry, sourceA, request.request_id);
      return { ...publishedResponse(entry, request, sourceA), instance_id: "replacement-instance" };
    });

    await expect(client.reloadConfigurationAdmin({ selectedSourceIdentity: sourceA }))
      .rejects.toMatchObject({ code: "IPC_IDENTITY_CHANGED", phase: "indeterminate" });
  });

  test("returns a correlated identity-mismatch rejection from the selected endpoint", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    vi.mocked(readConfigurationAdminRecords).mockResolvedValue([record(41, "instance-a")]);
    vi.mocked(sendConfigurationAdminRequest).mockImplementation(async (entry, request) => {
      if (request.operation === "probe") return probe(entry, sourceA, request.request_id);
      if (request.operation !== "reload") throw new Error("Expected reload request.");
      return {
        protocol_version: 1,
        request_id: request.request_id,
        server_pid: entry.server_pid,
        ...(entry.helper_pid === undefined ? {} : { helper_pid: entry.helper_pid }),
        instance_id: entry.instance_id,
        source_identity: source("/configs/other.json"),
        operation: "reload_result",
        outcome: "rejected",
        rejection_code: "IDENTITY_MISMATCH",
        rejection_message: "The selected server identity no longer matches.",
        active_effective_generation: 3,
        active_source_sha256: "b".repeat(64),
        pending_restart: false
      };
    });

    await expect(client.reloadConfigurationAdmin({ selectedSourceIdentity: sourceA }))
      .resolves.toMatchObject({ outcome: "rejected", rejection_code: "IDENTITY_MISMATCH" });
  });

  test("treats an uncorrelated identity-mismatch response as indeterminate", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    const target = record(41, "instance-a");
    vi.mocked(readConfigurationAdminRecords).mockResolvedValue([target]);
    vi.mocked(sendConfigurationAdminRequest).mockImplementation(async (entry, request) => {
      if (request.operation === "probe") return probe(entry, sourceA, request.request_id);
      return {
        protocol_version: 1,
        request_id: "99999999-9999-4999-8999-999999999999",
        server_pid: entry.server_pid,
        ...(entry.helper_pid === undefined ? {} : { helper_pid: entry.helper_pid }),
        instance_id: entry.instance_id,
        source_identity: source("/configs/other.json"),
        operation: "reload_result",
        outcome: "rejected",
        rejection_code: "IDENTITY_MISMATCH",
        rejection_message: "The selected server identity no longer matches.",
        active_effective_generation: 3,
        active_source_sha256: "b".repeat(64),
        pending_restart: false
      };
    });

    await expect(client.reloadConfigurationAdmin({ selectedSourceIdentity: sourceA }))
      .rejects.toMatchObject({ code: "IPC_IDENTITY_CHANGED", phase: "indeterminate" });
  });

  test("treats an unrelated reload response as indeterminate", async () => {
    const client = await import("../src/runtime/configuration-admin-client.js");
    vi.mocked(readConfigurationAdminRecords).mockResolvedValue([record(41, "instance-a")]);
    vi.mocked(sendConfigurationAdminRequest).mockImplementation(async (entry, request) => {
      return probe(entry, sourceA, request.request_id);
    });

    await expect(client.reloadConfigurationAdmin({ selectedSourceIdentity: sourceA }))
      .rejects.toMatchObject({ code: "IPC_BAD_RESPONSE", phase: "indeterminate" });
  });
});

function source(path: string): ConfigurationSourceIdentity {
  return { status: "available", platform: "posix", path };
}

function record(serverPid: number, instanceId: string): ConfigurationAdminDiscoveryRecord {
  return {
    protocol_version: 1,
    server_pid: serverPid,
    helper_pid: serverPid + 100,
    instance_id: instanceId,
    endpoint: `/tmp/config-admin-${serverPid}.sock`
  } as const;
}

function probe(
  entry: ConfigurationAdminDiscoveryRecord,
  sourceIdentity: ConfigurationSourceIdentity,
  requestId = "11111111-1111-4111-8111-111111111111"
): ConfigurationAdminProbeResult {
  return {
    protocol_version: 1,
    request_id: requestId,
    operation: "probe_result",
    server_pid: entry.server_pid,
    ...(entry.helper_pid === undefined ? {} : { helper_pid: entry.helper_pid }),
    instance_id: entry.instance_id,
    source_identity: sourceIdentity,
    effective_generation: 3,
    accepted_source_sha256: "a".repeat(64),
    pending_restart: false
  };
}

function publishedResponse(
  entry: ConfigurationAdminDiscoveryRecord,
  request: ConfigurationAdminRequest,
  sourceIdentity: ConfigurationSourceIdentity
): Extract<ConfigurationAdminResponse, { operation: "reload_result" }> {
  if (request.operation !== "reload") throw new Error("Expected reload request.");
  return {
    protocol_version: 1,
    request_id: request.request_id,
    server_pid: entry.server_pid,
    ...(entry.helper_pid === undefined ? {} : { helper_pid: entry.helper_pid }),
    instance_id: entry.instance_id,
    source_identity: sourceIdentity,
    operation: "reload_result",
    outcome: "published",
    effective_generation: 4,
    accepted_source_sha256: "c".repeat(64),
    pending_restart: false
  };
}

function statusResponse(
  entry: ConfigurationAdminDiscoveryRecord,
  request: ConfigurationAdminRequest,
  sourceIdentity: ConfigurationSourceIdentity
): Extract<ConfigurationAdminResponse, { operation: "status_result" }> {
  if (request.operation !== "status") throw new Error("Expected status request.");
  return {
    protocol_version: 1,
    request_id: request.request_id,
    server_pid: entry.server_pid,
    ...(entry.helper_pid === undefined ? {} : { helper_pid: entry.helper_pid }),
    instance_id: entry.instance_id,
    source_identity: sourceIdentity,
    operation: "status_result",
    accepted_candidate: {
      source_status: "available",
      source_sha256: "a".repeat(64),
      repository_count: 1,
      restart_fields: ["provider"]
    },
    saved_source: { status: "no-source" },
    active_hot_revision: { generation: 2, repository_count: 1 },
    initialized_restart_fields: ["provider"],
    pending_restart_fields: [],
    last_reload_outcome: "not-run"
  };
}
