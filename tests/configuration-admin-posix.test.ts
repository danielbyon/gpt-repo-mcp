import { chmod, mkdtemp, rm, stat } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { describe, expect, test, vi } from "vitest";

const sourceIdentity = {
  status: "available",
  platform: "posix",
  path: "/configs/disposable.json"
} as const;
const instanceId = "22222222-2222-4222-8222-222222222222";

describe.skipIf(process.platform === "win32")("owner-local POSIX configuration IPC", () => {
  test("publishes a private endpoint and completes a correlated probe", async () => {
    const ipc = await import("../src/runtime/configuration-admin-posix.js");
    const directory = await createPrivateDirectory();
    const handler = vi.fn(async (request: unknown) => probeResponse(request));
    let closeEndpoint: (() => Promise<void>) | undefined;

    try {
      const endpoint = await ipc.startPosixConfigurationAdminServer({
        directory,
        serverPid: process.pid,
        instanceId,
        handle: handler
      });
      closeEndpoint = endpoint.close;
      const [record] = await ipc.readPosixConfigurationAdminRecords(directory);
      const socketInfo = await stat(record.endpoint);
      expect(socketInfo.isSocket()).toBe(true);
      expect(socketInfo.mode & 0o777).toBe(0o600);
      expect(record).toMatchObject({ server_pid: process.pid, instance_id: instanceId });

      const request = {
        protocol_version: 1,
        request_id: "11111111-1111-4111-8111-111111111111",
        operation: "probe"
      } as const;
      const response = await ipc.requestPosixConfigurationAdmin(record, request);

      expect(response).toMatchObject({ request_id: request.request_id, operation: "probe_result" });
      expect(handler).toHaveBeenCalledTimes(1);
    } finally {
      try {
        await closeEndpoint?.();
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  });

  test("rejects an unsafe discovery directory before creating an endpoint", async () => {
    const ipc = await import("../src/runtime/configuration-admin-posix.js");
    const directory = await createPrivateDirectory();
    let unexpectedEndpoint: Awaited<ReturnType<typeof ipc.startPosixConfigurationAdminServer>> | undefined;

    try {
      await chmod(directory, 0o755);
      await expect(ipc.startPosixConfigurationAdminServer({
        directory,
        serverPid: process.pid,
        instanceId,
        handle: async () => probeResponse({ request_id: "11111111-1111-4111-8111-111111111111" })
      }).then((endpoint) => {
        unexpectedEndpoint = endpoint;
        return endpoint;
      })).rejects.toMatchObject({ code: "UNSAFE_DISCOVERY_DIRECTORY" });
    } finally {
      try {
        await unexpectedEndpoint?.close();
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  });

  test("requires an explicit temporary directory for marked test servers", async () => {
    const ipc = await import("../src/runtime/configuration-admin-posix.js");
    const fixtureRoot = await createPrivateDirectory();
    const isolatedDirectory = join(fixtureRoot, "admin-ipc");
    vi.stubEnv("GPT_REPO_TEST_BUILT_SERVER", "1");

    try {
      vi.stubEnv("GPT_REPO_ADMIN_TEST_DIRECTORY", undefined);
      await expect(ipc.getPosixConfigurationAdminDirectory())
        .rejects.toMatchObject({ code: "TEST_DIRECTORY_REQUIRED" });

      vi.stubEnv("GPT_REPO_ADMIN_TEST_DIRECTORY", isolatedDirectory);
      expect(await ipc.getPosixConfigurationAdminDirectory()).toBe(isolatedDirectory);
      expect((await stat(isolatedDirectory)).mode & 0o777).toBe(0o700);
    } finally {
      try {
        vi.unstubAllEnvs();
      } finally {
        await rm(fixtureRoot, { recursive: true, force: true });
      }
    }
  });

  test("rejects a missing endpoint before dispatch", async () => {
    const ipc = await import("../src/runtime/configuration-admin-posix.js");
    const directory = await createPrivateDirectory();
    const request = {
      protocol_version: 1,
      request_id: "11111111-1111-4111-8111-111111111111",
      operation: "reload",
      expected_server_pid: process.pid,
      expected_instance_id: instanceId,
      expected_source_identity: sourceIdentity
    } as const;

    try {
      await expect(ipc.requestPosixConfigurationAdmin({
        protocol_version: 1,
        server_pid: process.pid,
        instance_id: instanceId,
        endpoint: join(directory, `instance-${instanceId}.sock`)
      }, request)).rejects.toMatchObject({ phase: "pre-dispatch" });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("classifies a dropped acknowledgement after a reload write as indeterminate", async () => {
    const ipc = await import("../src/runtime/configuration-admin-posix.js");
    const directory = await createPrivateDirectory();
    const endpointPath = join(directory, `instance-${instanceId}.sock`);
    let dispatchCount = 0;
    const server = createServer((socket) => {
      socket.once("data", () => {
        dispatchCount += 1;
        socket.destroy();
      });
    });
    try {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(endpointPath, resolve);
      });
      await chmod(endpointPath, 0o600);
      await expect(ipc.requestPosixConfigurationAdmin({
        protocol_version: 1,
        server_pid: process.pid,
        instance_id: instanceId,
        endpoint: endpointPath
      }, {
        protocol_version: 1,
        request_id: "33333333-3333-4333-8333-333333333333",
        operation: "reload",
        expected_server_pid: process.pid,
        expected_instance_id: instanceId,
        expected_source_identity: sourceIdentity
      })).rejects.toMatchObject({ phase: "indeterminate" });
      expect(dispatchCount).toBe(1);
    } finally {
      try {
        if (server.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  });
});

async function createPrivateDirectory(): Promise<string> {
  const directory = await mkdtemp(join("/tmp", "gpt-repo-admin-test-"));
  try {
    await chmod(directory, 0o700);
    return directory;
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

function probeResponse(value: unknown) {
  const requestId = typeof value === "object" && value !== null && "request_id" in value
    ? String(value.request_id)
    : "11111111-1111-4111-8111-111111111111";
  return {
    protocol_version: 1,
    request_id: requestId,
    operation: "probe_result",
    server_pid: process.pid,
    instance_id: "22222222-2222-4222-8222-222222222222",
    source_identity: sourceIdentity,
    effective_generation: 2,
    accepted_source_sha256: "a".repeat(64),
    pending_restart: false
  } as const;
}
