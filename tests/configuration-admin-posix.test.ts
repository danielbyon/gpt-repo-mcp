import { chmod, mkdtemp, rm, stat } from "node:fs/promises";
import { createConnection, createServer, type Socket } from "node:net";
import { join } from "node:path";
import { describe, expect, test, vi } from "vitest";
import { encodeAdminFrame } from "../src/runtime/configuration-admin-protocol.js";

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

  test("expires a probe by elapsed time while the endpoint continues sending data", async () => {
    const ipc = await import("../src/runtime/configuration-admin-posix.js");
    const directory = await createPrivateDirectory();
    const endpointPath = join(directory, `instance-${instanceId}.sock`);
    const writeIntervals = new Set<ReturnType<typeof setInterval>>();
    const serverSockets = new Set<Socket>();
    const server = createServer({ allowHalfOpen: true }, (socket) => {
      serverSockets.add(socket);
      const interval = setInterval(() => socket.write(Buffer.from([0])), 100);
      writeIntervals.add(interval);
      socket.once("close", () => {
        clearInterval(interval);
        writeIntervals.delete(interval);
        serverSockets.delete(socket);
      });
      socket.on("error", () => undefined);
    });

    try {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(endpointPath, resolve);
      });
      await chmod(endpointPath, 0o600);
      const startedAt = Date.now();
      const request = ipc.requestPosixConfigurationAdmin({
        protocol_version: 1,
        server_pid: process.pid,
        instance_id: instanceId,
        endpoint: endpointPath
      }, {
        protocol_version: 1,
        request_id: "44444444-4444-4444-8444-444444444444",
        operation: "probe"
      });
      const outcome = request.then(
        (response) => ({ kind: "response" as const, response }),
        (error: unknown) => ({ kind: "error" as const, error })
      );
      let elapsedTimer: ReturnType<typeof setTimeout> | undefined;
      const result = await Promise.race([
        outcome,
        new Promise<{ kind: "elapsed" }>((resolve) => {
          elapsedTimer = setTimeout(() => resolve({ kind: "elapsed" }), 3_000);
        })
      ]);
      if (elapsedTimer) clearTimeout(elapsedTimer);

      expect(result.kind).toBe("error");
      if (result.kind === "error") {
        expect(result.error).toMatchObject({ code: "IPC_TIMEOUT", phase: "pre-dispatch" });
      }
      expect(Date.now() - startedAt).toBeGreaterThanOrEqual(1_800);
      expect(Date.now() - startedAt).toBeLessThan(3_000);
    } finally {
      for (const interval of writeIntervals) clearInterval(interval);
      for (const socket of serverSockets) socket.destroy();
      try {
        if (server.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  }, 4_000);

  test("expires a reload acknowledgement by elapsed time despite response activity", async () => {
    const ipc = await import("../src/runtime/configuration-admin-posix.js");
    const directory = await createPrivateDirectory();
    const endpointPath = join(directory, `instance-${instanceId}.sock`);
    const writeIntervals = new Set<ReturnType<typeof setInterval>>();
    const serverSockets = new Set<Socket>();
    const server = createServer({ allowHalfOpen: true }, (socket) => {
      serverSockets.add(socket);
      socket.on("data", () => {
        const interval = setInterval(() => socket.write(Buffer.from([0])), 40);
        writeIntervals.add(interval);
        socket.once("close", () => {
          clearInterval(interval);
          writeIntervals.delete(interval);
          serverSockets.delete(socket);
        });
      });
      socket.on("error", () => undefined);
    });

    try {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(endpointPath, resolve);
      });
      await chmod(endpointPath, 0o600);
      const request = ipc.requestPosixConfigurationAdmin({
        protocol_version: 1,
        server_pid: process.pid,
        instance_id: instanceId,
        endpoint: endpointPath
      }, {
        protocol_version: 1,
        request_id: "55555555-5555-4555-8555-555555555555",
        operation: "reload",
        expected_server_pid: process.pid,
        expected_instance_id: instanceId,
        expected_source_identity: sourceIdentity
      });
      const startedAt = Date.now();
      const outcome = request.then(
        (response) => ({ kind: "response" as const, response }),
        (error: unknown) => ({ kind: "error" as const, error })
      );
      let elapsedTimer: ReturnType<typeof setTimeout> | undefined;
      const result = await Promise.race([
        outcome,
        new Promise<{ kind: "elapsed" }>((resolve) => {
          elapsedTimer = setTimeout(() => resolve({ kind: "elapsed" }), 33_000);
        })
      ]);
      if (elapsedTimer) clearTimeout(elapsedTimer);

      expect(result.kind).toBe("error");
      if (result.kind === "error") {
        const error = result.error as { code?: string; phase?: string };
        expect(error.code).toBe("IPC_TIMEOUT");
        expect(error.phase).toBe("indeterminate");
      }
      expect(Date.now() - startedAt).toBeGreaterThanOrEqual(29_500);
      expect(Date.now() - startedAt).toBeLessThan(33_000);
    } finally {
      for (const interval of writeIntervals) clearInterval(interval);
      for (const socket of serverSockets) socket.destroy();
      try {
        if (server.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  }, 35_000);

  test("bounds request framing by elapsed time while the client sends data", async () => {
    const ipc = await import("../src/runtime/configuration-admin-posix.js");
    const directory = await createPrivateDirectory();
    const handler = vi.fn(async (request: unknown) => probeResponse(request));
    let closeEndpoint: (() => Promise<void>) | undefined;
    let socket: ReturnType<typeof createConnection> | undefined;
    let progressInterval: ReturnType<typeof setInterval> | undefined;
    const partialFrame = Buffer.concat([Buffer.from([0, 0, 0, 100]), Buffer.alloc(100)]);
    let nextByte = 0;

    try {
      const endpoint = await ipc.startPosixConfigurationAdminServer({
        directory,
        serverPid: process.pid,
        instanceId,
        handle: handler
      });
      closeEndpoint = endpoint.close;
      socket = createConnection({ path: endpoint.record.endpoint });
      const closed = new Promise<void>((resolve) => socket?.once("close", resolve));
      progressInterval = setInterval(() => {
        const byte = partialFrame.subarray(nextByte, nextByte + 1);
        if (byte.byteLength > 0) {
          socket?.write(byte);
          nextByte += 1;
        }
      }, 100);
      const startedAt = Date.now();
      let elapsedTimer: ReturnType<typeof setTimeout> | undefined;
      const result = await Promise.race([
        closed.then(() => "closed" as const),
        new Promise<"elapsed">((resolve) => {
          elapsedTimer = setTimeout(() => resolve("elapsed"), 3_000);
        })
      ]);
      if (elapsedTimer) clearTimeout(elapsedTimer);

      expect(result).toBe("closed");
      expect(Date.now() - startedAt).toBeGreaterThanOrEqual(1_800);
      expect(Date.now() - startedAt).toBeLessThan(3_000);
      expect(handler).not.toHaveBeenCalled();
    } finally {
      if (progressInterval) clearInterval(progressInterval);
      socket?.destroy();
      await closeEndpoint?.();
      await rm(directory, { recursive: true, force: true });
    }
  }, 4_000);

  test("bounds reload handling by its 30-second elapsed deadline", async () => {
    const ipc = await import("../src/runtime/configuration-admin-posix.js");
    const directory = await createPrivateDirectory();
    let closeEndpoint: (() => Promise<void>) | undefined;
    let socket: ReturnType<typeof createConnection> | undefined;
    let markHandled: (() => void) | undefined;
    const handled = new Promise<void>((resolve) => {
      markHandled = resolve;
    });

    try {
      const endpoint = await ipc.startPosixConfigurationAdminServer({
        directory,
        serverPid: process.pid,
        instanceId,
        handle: async () => {
          markHandled?.();
          return await new Promise<never>(() => undefined);
        }
      });
      closeEndpoint = endpoint.close;
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      socket = createConnection({ path: endpoint.record.endpoint });
      const closed = new Promise<void>((resolve) => socket?.once("close", resolve));
      socket.end(encodeAdminFrame({
        protocol_version: 1,
        request_id: "66666666-6666-4666-8666-666666666666",
        operation: "reload",
        expected_server_pid: process.pid,
        expected_instance_id: instanceId,
        expected_source_identity: sourceIdentity
      }));
      await handled;

      await vi.advanceTimersByTimeAsync(29_000);
      expect(socket.destroyed).toBe(false);
      await vi.advanceTimersByTimeAsync(1_000);
      const closedAfterDeadline = await Promise.race([
        closed.then(() => true),
        new Promise<boolean>((resolve) => setImmediate(() => resolve(false)))
      ]);
      expect(closedAfterDeadline).toBe(true);
    } finally {
      vi.useRealTimers();
      socket?.destroy();
      await closeEndpoint?.();
      await rm(directory, { recursive: true, force: true });
    }
  }, 4_000);

  test("bounds probe handling by its two-second elapsed deadline", async () => {
    const ipc = await import("../src/runtime/configuration-admin-posix.js");
    const directory = await createPrivateDirectory();
    let closeEndpoint: (() => Promise<void>) | undefined;
    let socket: ReturnType<typeof createConnection> | undefined;
    let markHandled: (() => void) | undefined;
    const handled = new Promise<void>((resolve) => {
      markHandled = resolve;
    });

    try {
      const endpoint = await ipc.startPosixConfigurationAdminServer({
        directory,
        serverPid: process.pid,
        instanceId,
        handle: async () => {
          markHandled?.();
          return await new Promise<never>(() => undefined);
        }
      });
      closeEndpoint = endpoint.close;
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      socket = createConnection({ path: endpoint.record.endpoint });
      const closed = new Promise<void>((resolve) => socket?.once("close", resolve));
      socket.end(encodeAdminFrame({
        protocol_version: 1,
        request_id: "77777777-7777-4777-8777-777777777777",
        operation: "probe"
      }));
      await handled;

      await vi.advanceTimersByTimeAsync(1_800);
      expect(socket.destroyed).toBe(false);
      await vi.advanceTimersByTimeAsync(300);
      const closedAfterDeadline = await Promise.race([
        closed.then(() => true),
        new Promise<boolean>((resolve) => setImmediate(() => resolve(false)))
      ]);
      expect(closedAfterDeadline).toBe(true);
    } finally {
      vi.useRealTimers();
      socket?.destroy();
      await closeEndpoint?.();
      await rm(directory, { recursive: true, force: true });
    }
  }, 4_000);

  test("clears a pending reload deadline when the server closes", async () => {
    const ipc = await import("../src/runtime/configuration-admin-posix.js");
    const directory = await createPrivateDirectory();
    let closeEndpoint: (() => Promise<void>) | undefined;
    let socket: ReturnType<typeof createConnection> | undefined;
    let markHandled: (() => void) | undefined;
    const handled = new Promise<void>((resolve) => {
      markHandled = resolve;
    });

    try {
      const endpoint = await ipc.startPosixConfigurationAdminServer({
        directory,
        serverPid: process.pid,
        instanceId,
        handle: async () => {
          markHandled?.();
          return await new Promise<never>(() => undefined);
        }
      });
      closeEndpoint = endpoint.close;
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      socket = createConnection({ path: endpoint.record.endpoint });
      const closed = new Promise<void>((resolve) => socket?.once("close", resolve));
      socket.end(encodeAdminFrame({
        protocol_version: 1,
        request_id: "88888888-8888-4888-8888-888888888888",
        operation: "reload",
        expected_server_pid: process.pid,
        expected_instance_id: instanceId,
        expected_source_identity: sourceIdentity
      }));
      await handled;

      await closeEndpoint();
      await closed;
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
      socket?.destroy();
      await closeEndpoint?.();
      await rm(directory, { recursive: true, force: true });
    }
  }, 4_000);
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
