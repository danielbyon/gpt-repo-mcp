import { mkdtemp, rm } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, test, vi } from "vitest";
import type { ConfigurationSourceIdentity } from "../src/config/config-source-identity.js";
import {
  readWindowsConfigurationAdminRecords,
  requestWindowsConfigurationAdmin,
  startWindowsConfigurationAdminHost
} from "../src/runtime/configuration-admin-windows.js";
import type {
  ConfigurationAdminDiscoveryRecord
} from "../src/runtime/configuration-admin-client.js";
import {
  parseAdminRequest,
  type ConfigurationAdminRequest,
  type ConfigurationAdminResponse
} from "../src/runtime/configuration-admin-protocol.js";

const instanceId = "22222222-2222-4222-8222-222222222222";

describe("owner-local Windows configuration IPC", () => {
  test.skipIf(process.platform !== "win32")(
    "discovers the private pipe and returns a correlated reload response",
    async () => {
      const localAppData = await mkdtemp(join(tmpdir(), "gpt-repo-admin-windows-"));
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
      const localAppData = await mkdtemp(join(tmpdir(), "gpt-repo-admin-windows-stale-"));
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
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    }
  );

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
      const localAppData = await mkdtemp(join(tmpdir(), "gpt-repo-admin-windows-shutdown-"));
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
        await requestStarted.promise;

        const closing = host.close();
        finishHandler.resolve();
        await closing;
        await expect(pendingRequest).rejects.toMatchObject({ phase: "indeterminate" });
      } finally {
        await cleanupWindowsHost(host, localAppData);
      }
    }
  );

  test.skipIf(process.platform !== "win32")(
    "keeps the helper available after a reload response arrives after its deadline",
    async () => {
      const localAppData = await mkdtemp(join(tmpdir(), "gpt-repo-admin-windows-late-response-"));
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
            await new Promise((resolveDelay) => setTimeout(resolveDelay, 6_000));
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
    }
  );
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => { resolve = complete; });
  return { promise, resolve };
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
