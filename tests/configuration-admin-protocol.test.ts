import { describe, expect, test } from "vitest";

describe("configuration admin protocol", () => {
  test("round-trips one bounded UTF-8 JSON frame and rejects invalid frames", async () => {
    const protocol = await import("../src/runtime/configuration-admin-protocol.js").catch(() => undefined);
    expect(protocol).toBeDefined();
    if (!protocol) return;

    const request = {
      protocol_version: 1,
      request_id: "11111111-1111-4111-8111-111111111111",
      operation: "probe"
    };
    const frame = protocol.encodeAdminFrame(request);

    expect(frame.readUInt32BE(0)).toBe(frame.byteLength - 4);
    expect(protocol.decodeAdminFrame(frame)).toEqual(request);
    expect(() => protocol.decodeAdminFrame(frame.subarray(0, frame.byteLength - 1))).toThrow();
    expect(() => protocol.encodeAdminFrame({ value: "x".repeat(16_385) })).toThrow();
  expect(() => protocol.encodeAdminFrame(undefined)).toThrow(/not JSON serializable/);
    expect(() => protocol.decodeAdminFrame(Buffer.from([0, 0, 0, 1, 0xff]))).toThrow();
  expect(() => protocol.decodeAdminFrame(Buffer.from([0, 0, 0, 0]))).toThrow();
  expect(() => protocol.decodeAdminFrame(Buffer.from([0, 0, 0, 1, 0x7b]))).toThrow();
  expect(() => protocol.decodeAdminFrame(Buffer.from([0, 0, 0, 2, 0x7b, 0x7d, 0]))).toThrow();
  });

  test("accepts correlated reload requests and rejects source paths or unknown fields", async () => {
    const protocol = await import("../src/runtime/configuration-admin-protocol.js");
    const request = {
      protocol_version: 1,
      request_id: "11111111-1111-4111-8111-111111111111",
      operation: "reload",
      expected_server_pid: 42,
      expected_instance_id: "22222222-2222-4222-8222-222222222222",
      expected_source_identity: {
        status: "available",
        platform: "posix",
        path: "/tmp/config.json"
      }
    };

    expect(protocol.parseAdminRequest(request)).toEqual(request);
    expect(() => protocol.parseAdminRequest({ ...request, path: "/attacker/config.json" })).toThrow();
    expect(() => protocol.parseAdminRequest({ ...request, expected_source_identity: "/tmp/config.json" })).toThrow();
  });

test("matches reload responses to every selected identity field", async () => {
  const protocol = await import("../src/runtime/configuration-admin-protocol.js");
  const sourceIdentity = { status: "available", platform: "posix", path: "/tmp/config.json" } as const;
  const request = {
    protocol_version: 1,
    request_id: "11111111-1111-4111-8111-111111111111",
    operation: "reload",
    expected_server_pid: 42,
    expected_instance_id: "22222222-2222-4222-8222-222222222222",
    expected_source_identity: sourceIdentity
  } as const;
  const response = {
    protocol_version: 1,
    request_id: request.request_id,
    server_pid: 42,
    helper_pid: 43,
    instance_id: request.expected_instance_id,
    source_identity: sourceIdentity,
    operation: "reload_result",
    outcome: "published",
    effective_generation: 4,
    accepted_source_sha256: "a".repeat(64),
    pending_restart: false
  } as const;
  const identity = {
    serverPid: 42,
    helperPid: 43,
    instanceId: request.expected_instance_id,
    sourceIdentity
  };

  expect(protocol.responseMatchesReloadRequest(response, request, identity)).toBe(true);
  expect(protocol.responseMatchesReloadRequest(response, request, {
    serverPid: identity.serverPid,
    instanceId: identity.instanceId,
    sourceIdentity: identity.sourceIdentity
  })).toBe(true);
  expect(protocol.responseMatchesReloadRequest({ ...response, request_id: "33333333-3333-4333-8333-333333333333" }, request, identity)).toBe(false);
  expect(protocol.responseMatchesReloadRequest(response, request, { ...identity, serverPid: 44 })).toBe(false);
  expect(protocol.responseMatchesReloadRequest(response, request, { ...identity, helperPid: 44 })).toBe(false);
  expect(protocol.responseMatchesReloadRequest(response, request, { ...identity, instanceId: "44444444-4444-4444-8444-444444444444" })).toBe(false);
  expect(protocol.responseMatchesReloadRequest(response, request, {
    ...identity,
    sourceIdentity: { ...sourceIdentity, path: "/tmp/other.json" }
  })).toBe(false);
});

test("rejects Windows reload responses when source path casing differs", async () => {
  const protocol = await import("../src/runtime/configuration-admin-protocol.js");
  const sourceIdentity = {
    status: "available",
    platform: "win32",
    path: String.raw`C:\Workspace\Config.json`
  } as const;
  const request = {
    protocol_version: 1,
    request_id: "11111111-1111-4111-8111-111111111111",
    operation: "reload",
    expected_server_pid: 42,
    expected_instance_id: "22222222-2222-4222-8222-222222222222",
    expected_source_identity: sourceIdentity
  } as const;
  const response = {
    protocol_version: 1,
    request_id: request.request_id,
    server_pid: 42,
    helper_pid: 43,
    instance_id: request.expected_instance_id,
    source_identity: { ...sourceIdentity, path: String.raw`c:\workspace\config.JSON` },
    operation: "reload_result",
    outcome: "published",
    effective_generation: 4,
    accepted_source_sha256: "a".repeat(64),
    pending_restart: false
  } as const;

  expect(protocol.responseMatchesReloadRequest(response, request, {
    serverPid: 42,
    helperPid: 43,
    instanceId: request.expected_instance_id,
    sourceIdentity
  })).toBe(false);
});
});
