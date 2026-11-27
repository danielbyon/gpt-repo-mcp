import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import process from "node:process";
import { describe, expect, test, vi } from "vitest";
import { requestWindowsConfigurationAdmin, startWindowsConfigurationAdminHost } from "../src/runtime/configuration-admin-windows.js";
import type { ConfigurationSourceIdentity } from "../src/config/config-source-identity.js";
import { parseAdminRequest, type ConfigurationAdminResponse } from "../src/runtime/configuration-admin-protocol.js";

const startupAcknowledgmentCallback = vi.hoisted(() => ({
  delayMs: 0,
  delayed: false,
  completed: false,
  pendingTimers: new Set<ReturnType<typeof setTimeout>>()
}));

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  const spawnWithDelayedAcknowledgment: typeof actual.spawn = ((...args: Parameters<typeof actual.spawn>) => {
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
      const delayMs = startupAcknowledgmentCallback.delayMs;
      const delayedCallback = writeCallback && isStartupAcknowledgment && delayMs > 0
        ? (error?: Error | null) => {
          startupAcknowledgmentCallback.delayed = true;
          const timer = setTimeout(() => {
            startupAcknowledgmentCallback.pendingTimers.delete(timer);
            startupAcknowledgmentCallback.completed = true;
            writeCallback(error);
          }, delayMs);
          startupAcknowledgmentCallback.pendingTimers.add(timer);
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

const repoRoot = resolve(fileURLToPath(new URL("../", import.meta.url)));
const testHelper = join(repoRoot, "dist", "windows-configuration-admin-host.test.exe");
const userProfileRoot = process.env.USERPROFILE;
const instanceId = "78787878-7878-4787-8787-787878787878";

describe.skipIf(process.platform !== "win32")("Windows administrative helper startup", () => {
  test("publishes discovery only after the parent accepts the READY record", async () => {
    const localAppData = await createOwnerLocalAppData();
    const instanceId = randomUUID();
    let helper: ChildProcess | undefined;
    let outputLines: ReturnType<typeof createInterface> | undefined;
    let testError: unknown;

    try {
      helper = spawn(testHelper, ["serve", String(process.pid), instanceId], {
        env: { ...process.env, LOCALAPPDATA: localAppData },
        stdio: ["pipe", "pipe", "ignore"],
        windowsHide: true
      });
      helper.once("error", (error) => { testError = error; });
      if (!helper.stdin || !helper.stdout) throw new Error("The native helper control streams were unavailable.");
      outputLines = createInterface({ input: helper.stdout, crlfDelay: Infinity });
      const lineIterator = outputLines[Symbol.asyncIterator]();

      const readyLine = await readNativeControlLine(lineIterator, 5_000);
      if (testError) throw testError;
      expect(readyLine.startsWith("READY\t")).toBe(true);
      const record = JSON.parse(readyLine.slice("READY\t".length)) as {
        server_pid: number;
        helper_pid: number;
        helper_creation_time: string;
        instance_id: string;
      };
      expect(record).toMatchObject({
        server_pid: process.pid,
        helper_pid: helper.pid,
        instance_id: instanceId
      });
      expect(record.helper_creation_time).toMatch(/^[1-9][0-9]*$/);

      const adminDirectory = join(localAppData, "GPTRepoMCP", "admin");
      const recordPath = join(adminDirectory, `server-${process.pid}-${instanceId}.record`);
      await expect(access(recordPath)).rejects.toMatchObject({ code: "ENOENT" });

      helper.stdin.write(`READY_ACCEPTED\t${instanceId}\n`);
      const publicationLine = await readNativeControlLine(lineIterator, 5_000);
      expect(publicationLine).toBe(`PUBLISHED\t${instanceId}`);
      const recordContents = await readFile(recordPath, "utf8");
      expect(recordContents).toContain(`helper_pid=${helper.pid}`);
      expect(recordContents).toContain(`instance_id=${instanceId}`);

      helper.stdin.write("SHUTDOWN\n");
      helper.stdin.end();
      const [exitCode] = await once(helper, "exit");
      expect(exitCode).toBe(0);
      await expect(access(recordPath)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      try {
        outputLines?.close();
        if (helper && helper.pid !== undefined && helper.exitCode === null && helper.signalCode === null) {
          if (helper.stdin && !helper.stdin.destroyed) {
            helper.stdin.write("SHUTDOWN\n");
            helper.stdin.end();
          }
          try {
            await waitForSignal(once(helper, "exit").then(() => undefined), 5_000, "The startup-order fixture helper did not exit.");
          } catch {
            helper.kill();
            await waitForSignal(once(helper, "exit").then(() => undefined), 2_000, "The startup-order fixture helper could not be stopped.");
          }
        }
      } finally {
        await rm(localAppData, { recursive: true, force: true });
      }
    }
  }, 15_000);

  test("uses helper publication when the acknowledgment write callback arrives after its deadline", async () => {
    const localAppData = await createOwnerLocalAppData();
    vi.stubEnv("LOCALAPPDATA", localAppData);
    vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
    startupAcknowledgmentCallback.delayMs = 2_500;
    startupAcknowledgmentCallback.delayed = false;
    startupAcknowledgmentCallback.completed = false;

    const sourceIdentity: ConfigurationSourceIdentity = {
      status: "available",
      platform: "win32",
      path: join(localAppData, "config.json")
    };
    let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;

    try {
      host = await startWindowsConfigurationAdminHost({
        serverPid: process.pid,
        instanceId,
        handle: async (value): Promise<ConfigurationAdminResponse> => {
          const request = parseAdminRequest(value);
          return {
            protocol_version: 1,
            request_id: request.request_id,
            server_pid: process.pid,
            instance_id: instanceId,
            source_identity: sourceIdentity,
            operation: "probe_result",
            effective_generation: 1,
            accepted_source_sha256: "a".repeat(64),
            pending_restart: false
          };
        }
      });
      expect(startupAcknowledgmentCallback.delayed).toBe(true);
      expect(startupAcknowledgmentCallback.completed).toBe(false);

      await new Promise((resolveDelay) => setTimeout(resolveDelay, 2_100));
      expect(startupAcknowledgmentCallback.completed).toBe(false);
      const response = await requestWindowsConfigurationAdmin(host.record, {
        protocol_version: 1,
        request_id: "56565656-5656-4656-8656-565656565656",
        operation: "probe"
      });
      expect(response).toMatchObject({
        request_id: "56565656-5656-4656-8656-565656565656",
        operation: "probe_result"
      });

      await new Promise((resolveDelay) => setTimeout(resolveDelay, 500));
      expect(startupAcknowledgmentCallback.completed).toBe(true);
    } finally {
      startupAcknowledgmentCallback.delayMs = 0;
      for (const timer of startupAcknowledgmentCallback.pendingTimers) clearTimeout(timer);
      startupAcknowledgmentCallback.pendingTimers.clear();
      try {
        await cleanupHost(host);
      } finally {
        try {
          await rm(localAppData, { recursive: true, force: true });
        } finally {
          vi.unstubAllEnvs();
        }
      }
    }
  }, 10_000);
});

async function createOwnerLocalAppData(): Promise<string> {
  if (!userProfileRoot) throw new Error("The Windows startup test requires a user profile directory.");
  return mkdtemp(join(userProfileRoot, "gpt-repo-admin-startup-owner-"));
}

async function cleanupHost(
  host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined
): Promise<void> {
  if (host) await host.close();
}

async function readNativeControlLine(lines: AsyncIterator<string>, timeoutMs: number): Promise<string> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      lines.next().then((result) => {
        if (result.done) throw new Error("The native helper closed its startup control stream.");
        return result.value;
      }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("The native helper did not send its startup control line.")), timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function waitForSignal(signal: Promise<void>, timeoutMs: number, message: string): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      signal,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(message)), timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
