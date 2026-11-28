import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { join, resolve } from "node:path";
import { describe, expect, test, vi } from "vitest";
import type { ConfigurationSourceIdentity } from "../src/config/config-source-identity.js";
import type { ConfigurationRevisionState } from "../src/services/configuration-revision-store.js";
import { createConfigurationAdminController } from "../src/runtime/configuration-admin-controller.js";
import {
  readWindowsConfigurationAdminRecords,
  requestWindowsConfigurationAdmin,
  resolveWindowsConfigurationAdminHostPath,
  startWindowsConfigurationAdminHost
} from "../src/runtime/configuration-admin-windows.js";
import type {
  ConfigurationAdminDiscoveryRecord
} from "../src/runtime/configuration-admin-client.js";
import {
  encodeAdminFrame,
  parseAdminRequest,
  type ConfigurationAdminRequest,
  type ConfigurationAdminResponse
} from "../src/runtime/configuration-admin-protocol.js";

const delayedStartupAcknowledgment = vi.hoisted(() => ({
  delayMs: 0,
  beforeClientSpawn: undefined as (() => void) | undefined
}));

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  const spawnWithDelayedAcknowledgment: typeof actual.spawn = ((...args: Parameters<typeof actual.spawn>) => {
    if (args[1]?.[0] === "client") delayedStartupAcknowledgment.beforeClientSpawn?.();
    const child = actual.spawn(...args);
    const stdin = child.stdin;
    if (!stdin) return child;

    const originalWrite = stdin.write.bind(stdin);
    stdin.write = ((
      chunk: string | Uint8Array,
      encodingOrCallback?: BufferEncoding | ((error?: Error | null) => void),
      callback?: (error?: Error | null) => void
    ) => {
      const writeCallback = typeof encodingOrCallback === "function" ? encodingOrCallback : callback;
      const isStartupAcknowledgment = typeof chunk === "string" && chunk.startsWith("READY_ACCEPTED\t");
      const delayedCallback = writeCallback && isStartupAcknowledgment && delayedStartupAcknowledgment.delayMs > 0
        ? (error?: Error | null) => {
          setTimeout(() => writeCallback(error), delayedStartupAcknowledgment.delayMs);
        }
        : writeCallback;

      return typeof encodingOrCallback === "string"
        ? originalWrite(chunk, encodingOrCallback, delayedCallback)
        : originalWrite(chunk, delayedCallback);
    }) as typeof stdin.write;
    return child;
  }) as typeof actual.spawn;

  return { ...actual, spawn: spawnWithDelayedAcknowledgment };
});

const instanceId = "22222222-2222-4222-8222-222222222222";
const userProfileRoot = process.env.USERPROFILE;

type ReloadAttemptState = {
  outcome: "published" | "rejected";
  generation: number;
  digest: string;
};

const overlappingReloadScenarios: Array<{
  label: string;
  first: ReloadAttemptState;
  second: ReloadAttemptState;
}> = [
  {
    label: "success/success",
    first: { outcome: "published", generation: 8, digest: "b" },
    second: { outcome: "published", generation: 9, digest: "c" }
  },
  {
    label: "success/rejection",
    first: { outcome: "published", generation: 8, digest: "b" },
    second: { outcome: "rejected", generation: 8, digest: "b" }
  },
  {
    label: "rejection/success",
    first: { outcome: "rejected", generation: 7, digest: "a" },
    second: { outcome: "published", generation: 8, digest: "c" }
  }
];

describe("owner-local Windows configuration IPC", () => {
  test.skipIf(process.platform !== "win32")(
    "uses the shared 30-second status budget through the native helper",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-status-deadline-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      let helperPid: number | undefined;
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          onHelperPid: (pid) => { helperPid = pid; },
          handle: async (value) => {
            const request = parseAdminRequest(value);
            await new Promise((resolveDelay) => setTimeout(resolveDelay, 2_250));
            return statusResponse(request.request_id, sourceIdentity, helperPid);
          }
        });

        const response = await requestWindowsConfigurationAdmin(host.record, {
          protocol_version: 1,
          request_id: "34343434-3434-4434-8434-343434343434",
          operation: "status",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        });

        expect(response).toMatchObject({
          operation: "status_result",
          request_id: "34343434-3434-4434-8434-343434343434",
          helper_pid: host.record.helper_pid
        });
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    },
    15_000
  );

  test.skipIf(process.platform !== "win32")(
    "rejects a status response carrying the probe operation",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-status-operation-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          handle: async (value) => probeResponse(parseAdminRequest(value).request_id, sourceIdentity)
        });

        await expect(requestWindowsConfigurationAdmin(host.record, {
          protocol_version: 1,
          request_id: "45454545-4545-4545-8454-454545454545",
          operation: "status",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        })).rejects.toMatchObject({ code: "WINDOWS_HELPER_BAD_RESPONSE" });
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    }
  );

  test.skipIf(process.platform !== "win32")(
    "does not dispatch status when helper launch consumes the transaction deadline",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-status-launch-deadline-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      let now = 0;
      const clock = vi.spyOn(performance, "now").mockImplementation(() => now);
      const handle = vi.fn(async (value: unknown) => statusResponse(parseAdminRequest(value).request_id, sourceIdentity));
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({ serverPid: process.pid, instanceId, handle });
        delayedStartupAcknowledgment.beforeClientSpawn = () => { now = 30_001; };

        let timeoutError: unknown;
        try {
          await requestWindowsConfigurationAdmin(host.record, {
            protocol_version: 1,
            request_id: "67676767-6767-4676-8676-676767676767",
            operation: "status",
            expected_server_pid: process.pid,
            expected_instance_id: instanceId,
            expected_source_identity: sourceIdentity
          });
        } catch (error) {
          timeoutError = error;
        }

        expect(timeoutError).toMatchObject({ code: "WINDOWS_HELPER_TIMEOUT" });
        expect(handle).not.toHaveBeenCalled();
      } finally {
        delayedStartupAcknowledgment.beforeClientSpawn = undefined;
        clock.mockRestore();
        await cleanupWindowsHost(host, localAppData);
      }
    }
  );

  test.skipIf(process.platform !== "win32")(
    "times out one status transaction and rejects its late response",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-status-timeout-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      const requestStarted = deferred<void>();
      const handlerFinished = deferred<void>();
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          handle: async (value): Promise<ConfigurationAdminResponse> => {
            const request = parseAdminRequest(value);
            requestStarted.resolve();
            await new Promise((resolveDelay) => setTimeout(resolveDelay, 30_100));
            handlerFinished.resolve();
            return statusResponse(request.request_id, sourceIdentity);
          }
        });

        const pendingStatus = requestWindowsConfigurationAdmin(host.record, {
          protocol_version: 1,
          request_id: "56565656-5656-4656-8656-565656565656",
          operation: "status",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        });
        await requestStarted.promise;
        let timeoutError: unknown;
        try {
          await pendingStatus;
        } catch (error) {
          timeoutError = error;
        }
        expect(timeoutError).toMatchObject({ code: "WINDOWS_HELPER_TIMEOUT" });
        expect(timeoutError).toHaveProperty("message", expect.stringContaining("status request"));
        expect(String(timeoutError)).not.toContain("probe");

        await handlerFinished.promise;
        await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
        expect(timeoutError).toMatchObject({ code: "WINDOWS_HELPER_TIMEOUT" });
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    },
    40_000
  );

  test.skipIf(process.platform !== "win32")(
    "keeps a confirmed startup publication when the acknowledgment write callback stalls",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-start-ack-delay-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
      delayedStartupAcknowledgment.delayMs = 2_500;

      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          handle: async (value): Promise<ConfigurationAdminResponse> => {
            const request = parseAdminRequest(value);
            return probeResponse(request.request_id, sourceIdentity);
          }
        });

        await new Promise((resolveDelay) => setTimeout(resolveDelay, 2_100));
        const response = await requestWindowsConfigurationAdmin(host.record, {
          protocol_version: 1,
          request_id: "56565656-5656-4656-8656-565656565656",
          operation: "probe"
        });
        expect(response).toMatchObject({
          request_id: "56565656-5656-4656-8656-565656565656",
          operation: "probe_result"
        });
      } finally {
        delayedStartupAcknowledgment.delayMs = 0;
        await cleanupWindowsHost(host, localAppData);
      }
    },
    10_000
  );

  test("refuses a legacy discovery record without helper process creation time before dispatch", async () => {
    const serverPid = process.pid;
    const legacyRecord: ConfigurationAdminDiscoveryRecord = {
      protocol_version: 1,
      server_pid: serverPid,
      helper_pid: serverPid + 1,
      instance_id: instanceId,
      endpoint: `\\\\.\\pipe\\gpt-repo-mcp-${serverPid}-${instanceId}`
    };

    await expect(requestWindowsConfigurationAdmin(legacyRecord, {
      protocol_version: 1,
      request_id: "11111111-1111-4111-8111-111111111111",
      operation: "probe"
    })).rejects.toMatchObject({
      code: "WINDOWS_HELPER_IDENTITY_UNAVAILABLE",
      phase: "pre-dispatch"
    });
  });

  test("rejects a helper creation time outside the native uint64 range before dispatch", async () => {
    const serverPid = process.pid;
    const invalidRecord: ConfigurationAdminDiscoveryRecord = {
      protocol_version: 1,
      server_pid: serverPid,
      helper_pid: serverPid + 1,
      helper_creation_time: "18446744073709551616",
      instance_id: instanceId,
      endpoint: `\\\\.\\pipe\\gpt-repo-mcp-${serverPid}-${instanceId}`
    };

    const platformDescriptor = Object.getOwnPropertyDescriptor(process, "platform");
    if (!platformDescriptor) throw new Error("The process platform property is unavailable.");
    Object.defineProperty(process, "platform", { ...platformDescriptor, value: "win32" });
    try {
      await expect(requestWindowsConfigurationAdmin(invalidRecord, {
        protocol_version: 1,
        request_id: "11111111-1111-4111-8111-111111111111",
        operation: "probe"
      })).rejects.toMatchObject({ name: "ZodError" });
    } finally {
      Object.defineProperty(process, "platform", platformDescriptor);
    }
  });

  test.skipIf(process.platform !== "win32")(
    "preserves a discovery record whose helper creation identity changed before shutdown",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-record-identity-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
      vi.stubEnv("GPT_REPO_ADMIN_TEST_FAULT", "replace-record-before-cleanup");
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          handle: async () => {
            throw new Error("A discovery cleanup test must not dispatch requests.");
          }
        });
        const [record] = await readWindowsConfigurationAdminRecords();
        expect(record?.helper_creation_time).toMatch(/^[1-9][0-9]*$/);
        const recordPath = join(
          localAppData,
          "GPTRepoMCP",
          "admin",
          `server-${record!.server_pid}-${record!.instance_id}.record`
        );
        const replacementCreationTime = (BigInt(record!.helper_creation_time!) + 1n).toString();

        await host.close();
        expect(await readFile(recordPath, "utf8")).toContain(
          `helper_creation_time=${replacementCreationTime}`
        );
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    }
  );

  test.skipIf(process.platform !== "win32")(
    "reports a post-publication response failure as indeterminate across the native helper",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-post-publication-error-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      const beforeState = {
        acceptedCandidate: { sourceSha256: "a".repeat(64) },
        effectiveHotRevision: { generation: 2 }
      } as unknown as ConfigurationRevisionState;
      const publishedState = {
        acceptedCandidate: { sourceSha256: "b".repeat(64) },
        effectiveHotRevision: { generation: 3 }
      } as unknown as ConfigurationRevisionState;
      let currentState = beforeState;
      let helperPid: number | undefined;
      let failHelperPidResolution = true;
      const reloadFromFile = vi.fn(async () => {
        currentState = publishedState;
        return publishedState;
      });
      const controller = createConfigurationAdminController({
        serverPid: process.pid,
        helperPid: () => {
          if (failHelperPidResolution) {
            failHelperPidResolution = false;
            throw new Error("helper PID response unavailable");
          }
          return helperPid;
        },
        instanceId,
        sourceIdentity,
        revisionStore: {
          getState: () => currentState,
          captureStatus: async () => { throw new Error("Status capture is not used by this reload test."); },
          reloadFromFile
        }
      });
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          onHelperPid: (pid) => { helperPid = pid; },
          handle: controller.handle
        });
        const [record] = await readWindowsConfigurationAdminRecords();
        expect(record).toBeDefined();

        await expect(requestWindowsConfigurationAdmin(record!, {
          protocol_version: 1,
          request_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
          operation: "reload",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        })).rejects.toMatchObject({ phase: "indeterminate" });

        expect(reloadFromFile).toHaveBeenCalledOnce();
        expect(currentState).toMatchObject({
          acceptedCandidate: { sourceSha256: "b".repeat(64) },
          effectiveHotRevision: { generation: 3 }
        });

        const probe = await requestWindowsConfigurationAdmin(record!, {
          protocol_version: 1,
          request_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
          operation: "probe"
        });
        expect(probe).toMatchObject({
          operation: "probe_result",
          effective_generation: 3,
          accepted_source_sha256: "b".repeat(64)
        });
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    }
  );

  test.skipIf(process.platform !== "win32")(
    "classifies an early helper exit before endpoint verification",
    async () => {
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");

      try {
        await expect(startWindowsConfigurationAdminHost({
          serverPid: 0,
          instanceId,
          handle: async () => {
            throw new Error("An invalid server PID must stop the helper before dispatch.");
          }
        })).rejects.toMatchObject({ phase: "pre-dispatch" });
      } finally {
        vi.unstubAllEnvs();
      }
    }
  );

  test.skipIf(process.platform !== "win32")(
    "does not write an administrative frame after the absolute connection deadline",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-expired-write-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
      let helperPid: number | undefined;
      let requestCount = 0;
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;
      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: join(localAppData, "configuration.json")
      };

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          onHelperPid: (pid) => { helperPid = pid; },
          handle: async (value): Promise<ConfigurationAdminResponse> => {
            const request = parseAdminRequest(value);
            requestCount += 1;
            return {
              protocol_version: 1,
              request_id: request.request_id,
              server_pid: process.pid,
              helper_pid: helperPid,
              instance_id: instanceId,
              source_identity: sourceIdentity,
              operation: "probe_result",
              effective_generation: 1,
              accepted_source_sha256: "a".repeat(64),
              pending_restart: false
            };
          }
        });
        const helperPath = await resolveWindowsConfigurationAdminHostPath();
        const request: ConfigurationAdminRequest = {
          protocol_version: 1,
          request_id: randomUUID(),
          operation: "probe"
        };
        const result = spawnSync(helperPath, [
          "client",
          host.record.endpoint,
          "2000",
          String(host.record.helper_pid),
          host.record.helper_creation_time!
        ], {
          input: encodeAdminFrame(request),
          encoding: "utf8",
          env: { ...process.env, GPT_REPO_ADMIN_TEST_FAULT: "expire-before-write" },
          timeout: 5000,
          windowsHide: true
        });

        expect(result.error).toBeUndefined();
        expect(result.status, result.stderr).toBe(34);
        expect(result.stdout).toBe("NOT_DISPATCHED\t121\n");
        expect(requestCount).toBe(0);
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    },
    15_000
  );

  test.skipIf(process.platform !== "win32")(
    "classifies an unusable administrative root before endpoint verification",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-root-file-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");

      try {
        await writeFile(join(localAppData, "GPTRepoMCP"), "not a directory");
        await expect(startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          handle: async () => {
            throw new Error("An invalid administrative root must stop helper startup.");
          }
        })).rejects.toMatchObject({ phase: "pre-dispatch" });
      } finally {
        await cleanupWindowsHost(undefined, localAppData);
      }
    }
  );

  test.skipIf(process.platform !== "win32")(
    "discovers the private pipe and returns a correlated reload response",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");

      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      let helperPid: number | undefined;
      const requests: ConfigurationAdminRequest[] = [];
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          onHelperPid: (pid) => { helperPid = pid; },
          handle: async (value): Promise<ConfigurationAdminResponse> => {
            const request = parseAdminRequest(value);
            requests.push(request);
            const identity = {
              protocol_version: 1 as const,
              request_id: request.request_id,
              server_pid: process.pid,
              helper_pid: helperPid,
              instance_id: instanceId,
              source_identity: sourceIdentity
            };
            if (request.operation === "probe") {
              return {
                ...identity,
                operation: "probe_result",
                effective_generation: 7,
                accepted_source_sha256: "a".repeat(64),
                pending_restart: false
              };
            }
            return {
              ...identity,
              operation: "reload_result",
              outcome: "published",
              effective_generation: 8,
              accepted_source_sha256: "b".repeat(64),
              pending_restart: false
            };
          }
        });

        const [record] = await readWindowsConfigurationAdminRecords();
        expect(record).toMatchObject({
          server_pid: process.pid,
          helper_pid: helperPid,
          instance_id: instanceId,
          endpoint: `\\\\.\\pipe\\gpt-repo-mcp-${process.pid}-${instanceId}`
        });

        const probe = await requestWindowsConfigurationAdmin(record!, {
          protocol_version: 1,
          request_id: "11111111-1111-4111-8111-111111111111",
          operation: "probe"
        });
        expect(probe).toMatchObject({
          operation: "probe_result",
          server_pid: process.pid,
          helper_pid: helperPid,
          instance_id: instanceId
        });

        const reload = await requestWindowsConfigurationAdmin(record!, {
          protocol_version: 1,
          request_id: "33333333-3333-4333-8333-333333333333",
          operation: "reload",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        });
        expect(reload).toMatchObject({
          operation: "reload_result",
          outcome: "published",
          accepted_source_sha256: "b".repeat(64)
        });

        vi.stubEnv("GPT_REPO_ADMIN_TEST_FAULT", "before-write");
        await expect(requestWindowsConfigurationAdmin(record!, {
          protocol_version: 1,
          request_id: "44444444-4444-4444-8444-444444444444",
          operation: "reload",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        })).rejects.toMatchObject({ phase: "pre-dispatch" });
        expect(requests).toHaveLength(2);

        vi.stubEnv("GPT_REPO_ADMIN_TEST_FAULT", "silent-before-write");
        await expect(requestWindowsConfigurationAdmin(record!, {
          protocol_version: 1,
          request_id: "77777777-7777-4777-8777-777777777777",
          operation: "reload",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        })).rejects.toMatchObject({ phase: "indeterminate" });
        expect(requests).toHaveLength(2);

        vi.stubEnv("GPT_REPO_ADMIN_TEST_FAULT", "lose-dispatch-notification");
        await expect(requestWindowsConfigurationAdmin(record!, {
          protocol_version: 1,
          request_id: "66666666-6666-4666-8666-666666666666",
          operation: "reload",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        })).rejects.toMatchObject({ phase: "indeterminate" });
        await vi.waitFor(() => expect(requests).toHaveLength(3));
        expect(requests.map(({ operation }) => operation)).toEqual(["probe", "reload", "reload"]);
        if (!host) throw new Error("The Windows configuration admin host did not start.");
        await host.close();
        host = undefined;
        expect(await readWindowsConfigurationAdminRecords()).toEqual([]);
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    }
  );

  test.skipIf(process.platform !== "win32")(
    "fails closed when a helper exits unexpectedly and leaves a stale discovery record",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-stale-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");

      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      let helperPid: number | undefined;
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;
      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          onHelperPid: (pid) => { helperPid = pid; },
          handle: async () => { throw new Error("A terminated helper must not dispatch requests."); }
        });
        if (helperPid === undefined) throw new Error("The Windows helper PID was not reported.");

        const staleRecord = host.record;
        execFileSync("taskkill.exe", ["/PID", String(helperPid), "/F"], {
          windowsHide: true,
          stdio: "ignore"
        });
        host = undefined;

        expect(await readWindowsConfigurationAdminRecords()).toContainEqual(staleRecord);
        await expect(requestWindowsConfigurationAdmin(staleRecord, {
          protocol_version: 1,
          request_id: "77777777-7777-4777-8777-777777777777",
          operation: "reload",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        })).rejects.toMatchObject({ phase: "pre-dispatch" });

        const client = await import("../src/runtime/configuration-admin-client.js");
        await expect(client.reloadConfigurationAdmin({ selectedSourceIdentity: sourceIdentity }))
          .rejects.toMatchObject({ code: "NO_MATCHING_INSTANCE" });
        await expect(client.reloadConfigurationAdmin({
          selectedSourceIdentity: sourceIdentity,
          instancePid: process.pid
        })).rejects.toMatchObject({ code: "WINDOWS_HELPER_TIMEOUT", phase: "pre-dispatch" });
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    },
    15_000
  );

  test.skipIf(process.platform !== "win32")(
    "correlates overlapping native connections while an earlier reload is outstanding",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-overlap-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");

      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      const reloadStarted = deferred<void>();
      const finishReload = deferred<void>();
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          handle: async (value): Promise<ConfigurationAdminResponse> => {
            const request = parseAdminRequest(value);
            if (request.operation === "reload") {
              reloadStarted.resolve();
              await finishReload.promise;
              return reloadResponse(request.request_id, sourceIdentity, "d");
            }
            return probeResponse(request.request_id, sourceIdentity);
          }
        });

        const delayedReload = requestWindowsConfigurationAdmin(host.record, {
          protocol_version: 1,
          request_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
          operation: "reload",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        });
        await reloadStarted.promise;

        const concurrentProbe = await requestWindowsConfigurationAdmin(host.record, {
          protocol_version: 1,
          request_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
          operation: "probe"
        });
        expect(concurrentProbe).toMatchObject({
          request_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
          operation: "probe_result"
        });

        finishReload.resolve();
        await expect(delayedReload).resolves.toMatchObject({
          request_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
          operation: "reload_result",
          outcome: "published"
        });

        const followupProbe = await requestWindowsConfigurationAdmin(host.record, {
          protocol_version: 1,
          request_id: "ffffffff-ffff-4fff-8fff-ffffffffffff",
          operation: "probe"
        });
        expect(followupProbe).toMatchObject({
          request_id: "ffffffff-ffff-4fff-8fff-ffffffffffff",
          operation: "probe_result"
        });
      } finally {
        finishReload.resolve();
        await cleanupWindowsHost(host, localAppData);
      }
    },
    40_000
  );

  test.skipIf(process.platform !== "win32").each(overlappingReloadScenarios)(
    "correlates overlapping reload outcomes and per-attempt state ($label)",
    async (scenario) => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-outcome-overlap-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");

      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      const firstRequestId = "12121212-1212-4212-8212-121212121212";
      const secondRequestId = "34343434-3434-4434-8434-343434343434";
      const bothReloadsStarted = deferred<void>();
      const releaseFirstResponse = deferred<void>();
      const releaseSecondResponse = deferred<void>();
      let reloadCount = 0;
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;
      const requests: Promise<ConfigurationAdminResponse>[] = [];

      const responseFor = (requestId: string, attempt: ReloadAttemptState): ConfigurationAdminResponse => {
        const identity = {
          protocol_version: 1 as const,
          request_id: requestId,
          server_pid: process.pid,
          instance_id: instanceId,
          source_identity: sourceIdentity,
          operation: "reload_result" as const,
          pending_restart: false
        };
        if (attempt.outcome === "published") {
          return {
            ...identity,
            outcome: "published",
            effective_generation: attempt.generation,
            accepted_source_sha256: attempt.digest.repeat(64)
          };
        }
        return {
          ...identity,
          outcome: "rejected",
          rejection_code: "CANDIDATE_REJECTED",
          rejection_message: "The candidate was rejected.",
          active_effective_generation: attempt.generation,
          active_source_sha256: attempt.digest.repeat(64)
        };
      };

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          handle: async (value): Promise<ConfigurationAdminResponse> => {
            const request = parseAdminRequest(value);
            if (request.operation !== "reload") return probeResponse(request.request_id, sourceIdentity);
            reloadCount += 1;
            if (reloadCount === 2) bothReloadsStarted.resolve();
            await (request.request_id === firstRequestId
              ? releaseFirstResponse.promise
              : releaseSecondResponse.promise);
            return responseFor(request.request_id, request.request_id === firstRequestId ? scenario.first : scenario.second);
          }
        });

        const makeReloadRequest = (requestId: string): Promise<ConfigurationAdminResponse> =>
          requestWindowsConfigurationAdmin(host!.record, {
            protocol_version: 1,
            request_id: requestId,
            operation: "reload",
            expected_server_pid: process.pid,
            expected_instance_id: instanceId,
            expected_source_identity: sourceIdentity
          });
        requests.push(makeReloadRequest(firstRequestId), makeReloadRequest(secondRequestId));
        await bothReloadsStarted.promise;

        releaseSecondResponse.resolve();
        const secondResponse = await requests[1]!;
        releaseFirstResponse.resolve();
        const firstResponse = await requests[0]!;

        expect(firstResponse).toMatchObject({
          request_id: firstRequestId,
          operation: "reload_result",
          outcome: scenario.first.outcome,
          ...(scenario.first.outcome === "published"
            ? {
              effective_generation: scenario.first.generation,
              accepted_source_sha256: scenario.first.digest.repeat(64)
            }
            : {
              active_effective_generation: scenario.first.generation,
              active_source_sha256: scenario.first.digest.repeat(64)
            })
        });
        expect(secondResponse).toMatchObject({
          request_id: secondRequestId,
          operation: "reload_result",
          outcome: scenario.second.outcome,
          ...(scenario.second.outcome === "published"
            ? {
              effective_generation: scenario.second.generation,
              accepted_source_sha256: scenario.second.digest.repeat(64)
            }
            : {
              active_effective_generation: scenario.second.generation,
              active_source_sha256: scenario.second.digest.repeat(64)
            })
        });
      } finally {
        releaseFirstResponse.resolve();
        releaseSecondResponse.resolve();
        await Promise.allSettled(requests);
        await cleanupWindowsHost(host, localAppData);
      }
    },
    40_000
  );

  test.skipIf(process.platform !== "win32")(
    "bounds shutdown when a native helper cannot drain an outstanding reload",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-shutdown-bound-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
      vi.stubEnv("GPT_REPO_ADMIN_TEST_FAULT", "hold-shutdown");

      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      const requestStarted = deferred<void>();
      const releaseRequest = deferred<void>();
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;
      let pendingReload: Promise<ConfigurationAdminResponse> | undefined;
      let observedReload: Promise<
        | { ok: true; response: ConfigurationAdminResponse }
        | { ok: false; error: unknown }
      > | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          handle: async (value): Promise<ConfigurationAdminResponse> => {
            const request = parseAdminRequest(value);
            if (request.operation === "reload") {
              requestStarted.resolve();
              await releaseRequest.promise;
              return reloadResponse(request.request_id, sourceIdentity, "d");
            }
            return probeResponse(request.request_id, sourceIdentity);
          }
        });

        pendingReload = requestWindowsConfigurationAdmin(host.record, {
          protocol_version: 1,
          request_id: "abababab-abab-4bab-8bab-abababababab",
          operation: "reload",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        });
        observedReload = pendingReload.then(
          (response) => ({ ok: true as const, response }),
          (error: unknown) => ({ ok: false as const, error })
        );
        await requestStarted.promise;

        const shutdownStartedAt = Date.now();
        await expect(host.close()).rejects.toMatchObject({
          code: "WINDOWS_HELPER_SHUTDOWN_TIMEOUT",
          phase: "pre-dispatch"
        });
        expect(Date.now() - shutdownStartedAt).toBeLessThan(2_750);

        const reloadOutcome = await observedReload;
        if (reloadOutcome?.ok) throw new Error("The interrupted reload unexpectedly received a response.");
        expect(reloadOutcome?.error).toMatchObject({ phase: "indeterminate" });
      } finally {
        releaseRequest.resolve();
        if (pendingReload) await Promise.allSettled([pendingReload]);
        await cleanupWindowsHost(host, localAppData);
      }
    },
    10_000
  );

  test.skipIf(process.platform !== "win32")(
    "expires unmonitored probe waits at the two-second deadline",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-probe-deadline-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
      vi.stubEnv("GPT_REPO_ADMIN_TEST_FAULT", "unmonitored-client");

      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      const bothRequestsStarted = deferred<void>();
      const releaseHandlers = deferred<void>();
      let startedCount = 0;
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          handle: async (value): Promise<ConfigurationAdminResponse> => {
            const request = parseAdminRequest(value);
            if (startedCount < 2) {
              startedCount += 1;
              if (startedCount === 2) bothRequestsStarted.resolve();
              await releaseHandlers.promise;
            }
            return probeResponse(request.request_id, sourceIdentity);
          }
        });

        const startedAt = Date.now();
        const blockedRequests = [
          "12121212-1212-4212-8212-121212121212",
          "34343434-3434-4434-8434-343434343434"
        ].map((requestId) => requestWindowsConfigurationAdmin(host!.record, {
          protocol_version: 1,
          request_id: requestId,
          operation: "probe"
        }));
        await bothRequestsStarted.promise;
        const outcomes = await Promise.all(blockedRequests.map((request) => request.then(
          () => "resolved" as const,
          () => "rejected" as const
        )));

        expect(outcomes).toEqual(["rejected", "rejected"]);
        expect(Date.now() - startedAt).toBeLessThan(5_000);
        await expect(requestWindowsConfigurationAdmin(host.record, {
          protocol_version: 1,
          request_id: "56565656-5656-4656-8656-565656565656",
          operation: "probe"
        })).resolves.toMatchObject({
          request_id: "56565656-5656-4656-8656-565656565656",
          operation: "probe_result"
        });
      } finally {
        releaseHandlers.resolve();
        await cleanupWindowsHost(host, localAppData);
      }
    },
    12_000
  );

  test.skipIf(process.platform !== "win32")(
    "drops a late control response after its client connection has ended",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-late-control-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");

      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      const firstStarted = deferred<void>();
      const firstFinished = deferred<void>();
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          handle: async (value): Promise<ConfigurationAdminResponse> => {
            const request = parseAdminRequest(value);
            if (request.request_id === "11111111-1111-4111-8111-111111111111") {
              firstStarted.resolve();
              await new Promise((resolveDelay) => setTimeout(resolveDelay, 5_000));
              firstFinished.resolve();
            }
            return probeResponse(request.request_id, sourceIdentity);
          }
        });

        const timedOutProbe = requestWindowsConfigurationAdmin(host.record, {
          protocol_version: 1,
          request_id: "11111111-1111-4111-8111-111111111111",
          operation: "probe"
        });
        await firstStarted.promise;
        await expect(timedOutProbe).rejects.toMatchObject({ code: "WINDOWS_HELPER_TIMEOUT" });

        const subsequentProbe = await requestWindowsConfigurationAdmin(host.record, {
          protocol_version: 1,
          request_id: "22222222-2222-4222-8222-222222222222",
          operation: "probe"
        });
        expect(subsequentProbe).toMatchObject({
          request_id: "22222222-2222-4222-8222-222222222222",
          operation: "probe_result"
        });

        await firstFinished.promise;
        const finalProbe = await requestWindowsConfigurationAdmin(host.record, {
          protocol_version: 1,
          request_id: "33333333-3333-4333-8333-333333333333",
          operation: "probe"
        });
        expect(finalProbe).toMatchObject({
          request_id: "33333333-3333-4333-8333-333333333333",
          operation: "probe_result"
        });
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    },
    15_000
  );

  test.skipIf(process.platform !== "win32").each([
    "break-control-input",
    "break-control-output"
  ])("keeps helper channel failures from becoming successful dispatches (%s)", async (fault) => {
    const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-control-fault-");
    vi.stubEnv("LOCALAPPDATA", localAppData);
    vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
    vi.stubEnv("GPT_REPO_ADMIN_TEST_FAULT", fault);
    let dispatched = 0;
    let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

    try {
      host = await startWindowsConfigurationAdminHost({
        serverPid: process.pid,
        instanceId,
        handle: async () => {
          dispatched += 1;
          throw new Error("A broken private control channel must not dispatch a request.");
        }
      });
      const record = host.record;
      await vi.waitFor(async () => {
        const records = await readWindowsConfigurationAdminRecords();
        if (fault === "break-control-input") expect(records).not.toContainEqual(record);
        else expect(records).toContainEqual(record);
      }, { timeout: 4_000, interval: 25 });

      await expect(requestWindowsConfigurationAdmin(record, {
        protocol_version: 1,
        request_id: "44444444-4444-4444-8444-444444444444",
        operation: "probe"
      })).rejects.toMatchObject({ phase: "pre-dispatch" });
      expect(dispatched).toBe(0);
    } finally {
      try {
        await host?.close().catch(() => undefined);
      } finally {
        try {
          await rm(localAppData, { recursive: true, force: true });
        } finally {
          vi.unstubAllEnvs();
        }
      }
    }
  });

  test.skipIf(process.platform !== "win32")(
    "rejects a UNC endpoint before starting the native client",
    async () => {
      const record: ConfigurationAdminDiscoveryRecord = {
        protocol_version: 1,
        server_pid: process.pid,
        helper_pid: process.pid + 1,
        instance_id: "44444444-4444-4444-8444-444444444444",
        endpoint: "\\\\remote-host\\pipe\\gpt-repo-mcp-41-44444444-4444-4444-8444-444444444444"
      };

      await expect(requestWindowsConfigurationAdmin(record, {
        protocol_version: 1,
        request_id: "55555555-5555-4555-8555-555555555555",
        operation: "probe"
      })).rejects.toMatchObject({ code: "INVALID_DISCOVERY_RECORD", phase: "pre-dispatch" });
    }
  );

  test.skipIf(process.platform !== "win32")(
    "does not write a response after shutdown closes the helper control channel",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-shutdown-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");

      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      const requestStarted = deferred<void>();
      const finishHandler = deferred<void>();
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          handle: async (value): Promise<ConfigurationAdminResponse> => {
            const request = parseAdminRequest(value);
            requestStarted.resolve();
            await finishHandler.promise;
            return {
              protocol_version: 1,
              request_id: request.request_id,
              server_pid: process.pid,
              instance_id: instanceId,
              source_identity: sourceIdentity,
              operation: "reload_result",
              outcome: "published",
              effective_generation: 8,
              accepted_source_sha256: "b".repeat(64),
              pending_restart: false
            };
          }
        });

        const [record] = await readWindowsConfigurationAdminRecords();
        const pendingRequest = requestWindowsConfigurationAdmin(record!, {
          protocol_version: 1,
          request_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          operation: "reload",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        });
        const pendingOutcome = pendingRequest.then(
          () => undefined,
          (error: unknown) => error
        );
        await requestStarted.promise;

        const closing = host.close();
        finishHandler.resolve();
        await closing;
        await expect(pendingOutcome).resolves.toMatchObject({ phase: "indeterminate" });
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    }
  );

  test.skipIf(process.platform !== "win32")(
    "keeps the helper available after a reload response arrives after its deadline",
    async () => {
      const localAppData = await createIsolatedLocalAppData("gpt-repo-admin-windows-late-response-");
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");

      const sourceIdentity: ConfigurationSourceIdentity = {
        status: "available",
        platform: "win32",
        path: resolve(localAppData, "config.json")
      };
      const requestStarted = deferred<void>();
      const handlerFinished = deferred<void>();
      let helperPid: number | undefined;
      let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

      try {
        host = await startWindowsConfigurationAdminHost({
          serverPid: process.pid,
          instanceId,
          onHelperPid: (pid) => { helperPid = pid; },
          handle: async (value): Promise<ConfigurationAdminResponse> => {
            const request = parseAdminRequest(value);
            const identity = {
              protocol_version: 1 as const,
              request_id: request.request_id,
              server_pid: process.pid,
              helper_pid: helperPid,
              instance_id: instanceId,
              source_identity: sourceIdentity
            };
            if (request.operation === "probe") {
              return {
                ...identity,
                operation: "probe_result",
                effective_generation: 7,
                accepted_source_sha256: "a".repeat(64),
                pending_restart: false
              };
            }
            requestStarted.resolve();
            await new Promise((resolveDelay) => setTimeout(resolveDelay, 31_000));
            handlerFinished.resolve();
            return {
              ...identity,
              operation: "reload_result",
              outcome: "published",
              effective_generation: 8,
              accepted_source_sha256: "b".repeat(64),
              pending_restart: false
            };
          }
        });

        const [record] = await readWindowsConfigurationAdminRecords();
        const pendingReload = requestWindowsConfigurationAdmin(record!, {
          protocol_version: 1,
          request_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
          operation: "reload",
          expected_server_pid: process.pid,
          expected_instance_id: instanceId,
          expected_source_identity: sourceIdentity
        });
        await requestStarted.promise;
        await expect(pendingReload).rejects.toMatchObject({ phase: "indeterminate" });
        await handlerFinished.promise;
        await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));

        const records = await readWindowsConfigurationAdminRecords();
        expect(records).toContainEqual(record);
        const probeResponse = await requestWindowsConfigurationAdmin(record!, {
          protocol_version: 1,
          request_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
          operation: "probe"
        });
        expect(probeResponse.operation).toBe("probe_result");
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    },
    45_000
  );
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => { resolve = complete; });
  return { promise, resolve };
}

function probeResponse(requestId: string, sourceIdentity: ConfigurationSourceIdentity): ConfigurationAdminResponse {
  return {
    protocol_version: 1,
    request_id: requestId,
    server_pid: process.pid,
    instance_id: instanceId,
    source_identity: sourceIdentity,
    operation: "probe_result",
    effective_generation: 7,
    accepted_source_sha256: "a".repeat(64),
    pending_restart: false
  };
}

function reloadResponse(
  requestId: string,
  sourceIdentity: ConfigurationSourceIdentity,
  digestCharacter: string
): ConfigurationAdminResponse {
  return {
    protocol_version: 1,
    request_id: requestId,
    server_pid: process.pid,
    instance_id: instanceId,
    source_identity: sourceIdentity,
    operation: "reload_result",
    outcome: "published",
    effective_generation: 8,
    accepted_source_sha256: digestCharacter.repeat(64),
    pending_restart: false
  };
}

function statusResponse(
  requestId: string,
  sourceIdentity: ConfigurationSourceIdentity,
  helperPid?: number
): ConfigurationAdminResponse {
  return {
    protocol_version: 1,
    request_id: requestId,
    server_pid: process.pid,
    ...(helperPid === undefined ? {} : { helper_pid: helperPid }),
    instance_id: instanceId,
    source_identity: sourceIdentity,
    operation: "status_result",
    accepted_candidate: {
      source_status: "available",
      source_sha256: "a".repeat(64),
      repository_count: 1,
      restart_fields: []
    },
    saved_source: {
      status: "valid",
      source_sha256: "a".repeat(64),
      matches_accepted: true,
      repository_count: 1,
      restart_fields: []
    },
    active_hot_revision: { generation: 1, repository_count: 1 },
    initialized_restart_fields: [],
    pending_restart_fields: [],
    last_reload_outcome: "not-run"
  };
}

async function cleanupWindowsHost(
  host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined,
  localAppData: string
) {
  try {
    if (host) await host.close();
  } finally {
    try {
      await rm(localAppData, { recursive: true, force: true });
    } finally {
      vi.unstubAllEnvs();
    }
  }
}

async function createIsolatedLocalAppData(prefix: string): Promise<string> {
  if (!userProfileRoot) throw new Error("Windows tests require the current user's profile directory.");
  // The helper rejects reparse-point ancestors. mkdtemp appends a random suffix under the profile root.
  return mkdtemp(join(userProfileRoot, prefix));
}
