import { spawn, type ChildProcess } from "node:child_process";
import { join } from "node:path";
import type { Readable } from "node:stream";
import { setTimeout as delay } from "node:timers/promises";
import { describe, expect, test } from "vitest";
import {
  runProcessWithTail,
  superviseSpawnedProcessWithTail
} from "../src/services/process-exec.js";

const baseInput = {
  cwd: process.cwd(),
  env: process.env,
  tail_bytes: 1_024
};

type ReadyMessage = {
  type: "ready";
  grandchild_pid?: number;
};

type PipedChildProcess = ChildProcess & {
  stdout: Readable;
  stderr: Readable;
};

const READY_TIMEOUT_MS = 2_000;
const PROCESS_GONE_TIMEOUT_MS = 2_000;

function isReadyMessage(value: unknown): value is ReadyMessage {
  return typeof value === "object" && value !== null && "type" in value && value.type === "ready";
}

function terminateSpawnedTree(child: ChildProcess): void {
  if (!child.pid) return;
  if (process.platform === "win32") {
    child.kill("SIGKILL");
    return;
  }
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    child.kill("SIGKILL");
  }
}

function waitForReady(child: ChildProcess): Promise<ReadyMessage> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error("Timed out waiting for process readiness.")), READY_TIMEOUT_MS);
    const finish = (error?: Error, message?: ReadyMessage): void => {
      clearTimeout(timer);
      child.off("error", onError);
      child.off("exit", onExit);
      child.off("message", onMessage);
      if (error) reject(error);
      else resolve(message as ReadyMessage);
    };
    const onError = (error: Error): void => finish(error);
    const onExit = (code: number | null, signal: NodeJS.Signals | null): void => {
      finish(new Error(`Process exited before readiness (code=${String(code)}, signal=${String(signal)}).`));
    };
    const onMessage = (message: unknown): void => {
      if (isReadyMessage(message)) finish(undefined, message);
    };
    child.once("error", onError);
    child.once("exit", onExit);
    child.on("message", onMessage);
  });
}

async function spawnReadyProcess(script: string): Promise<{ child: PipedChildProcess; ready: ReadyMessage }> {
  const spawned = spawn(process.execPath, ["-e", script], {
    cwd: process.cwd(),
    env: process.env,
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    detached: process.platform !== "win32"
  });
  if (!spawned.stdout || !spawned.stderr) {
    terminateSpawnedTree(spawned);
    throw new Error("Expected piped stdout and stderr.");
  }
  const child: PipedChildProcess = spawned as PipedChildProcess;
  try {
    return { child, ready: await waitForReady(child) };
  } catch (error) {
    terminateSpawnedTree(child);
    throw error;
  }
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ESRCH") return false;
    throw error;
  }
}

async function expectProcessGone(pid: number | undefined): Promise<void> {
  if (!pid) throw new Error("Expected a process ID.");
  const deadline = Date.now() + PROCESS_GONE_TIMEOUT_MS;
  while (isProcessAlive(pid) && Date.now() < deadline) {
    await delay(20);
  }
  expect(isProcessAlive(pid)).toBe(false);
}

describe("runProcessWithTail", () => {
  test("captures bounded output from a normal exit", async () => {
    const result = await runProcessWithTail({
      ...baseInput,
      executable: process.execPath,
      args: ["-e", "process.stdout.write('before-after'); process.stderr.write('warning');"],
      timeout_ms: 2_000,
      tail_bytes: 5
    });

    expect(result).toMatchObject({
      exit_code: 0,
      timed_out: false,
      stdout_tail: "after",
      stderr_tail: "rning"
    });
  });

  test("returns spawn failures without waiting for the timeout", async () => {
    const result = await runProcessWithTail({
      ...baseInput,
      executable: join(process.cwd(), "__missing_process_executable__"),
      args: [],
      timeout_ms: 2_000
    });

    expect(result.timed_out).toBe(false);
    expect(result.duration_ms).toBeLessThan(1_000);
    expect(result.stderr_tail).toMatch(/ENOENT|not found/i);
  });

  test("starts the timeout at spawn without waiting for process readiness", async () => {
    const result = await runProcessWithTail({
      ...baseInput,
      executable: process.execPath,
      args: [
        "-e",
        "setTimeout(() => process.stdout.write('too-late'), 1_000); setInterval(() => {}, 1_000);"
      ],
      timeout_ms: 100
    });

    expect(result.timed_out).toBe(true);
    expect(result.stdout_tail).not.toContain("too-late");
    expect(result.duration_ms).toBeLessThan(900);
  }, 3_000);

  test("allows a process to exit during the SIGTERM grace period", async () => {
    const fixture = await spawnReadyProcess([
      "process.on('SIGTERM', () => { process.stderr.write('terminated'); process.exit(0); });",
      "process.stdout.write('ready');",
      "setInterval(() => {}, 1_000);",
      "process.send({ type: 'ready' });"
    ].join(" "));
    try {
      const result = await superviseSpawnedProcessWithTail(fixture.child, {
        timeout_ms: 100,
        tail_bytes: baseInput.tail_bytes
      });

      expect(result.timed_out).toBe(true);
      expect(result.exit_code).toBe(0);
      expect(result.stdout_tail).toContain("ready");
      expect(result.stderr_tail).toContain("terminated");
    } finally {
      terminateSpawnedTree(fixture.child);
    }
  });

  test("escalates to a forced kill when SIGTERM is ignored", async () => {
    const fixture = await spawnReadyProcess([
      "process.on('SIGTERM', () => {});",
      "process.stdout.write('ready');",
      "setInterval(() => {}, 1_000);",
      "process.send({ type: 'ready' });"
    ].join(" "));
    try {
      const result = await superviseSpawnedProcessWithTail(fixture.child, {
        timeout_ms: 100,
        tail_bytes: baseInput.tail_bytes
      });

      expect(result.timed_out).toBe(true);
      expect(result.signal).toBe("SIGKILL");
      expect(result.duration_ms).toBeLessThan(900);
      expect(result.stdout_tail).toContain("ready");
    } finally {
      terminateSpawnedTree(fixture.child);
    }
  }, 3_000);

  test("forces an inherited child-process tree to release captured pipes and descendant processes", async () => {
    const grandchildScript =
      "process.on('SIGTERM', () => {}); setInterval(() => {}, 1_000); process.send({ type: 'ready', pid: process.pid });";
    const parentScript = [
      "const { spawn } = require('node:child_process');",
      `const grandchild = spawn(${JSON.stringify(process.execPath)}, ['-e', ${JSON.stringify(grandchildScript)}], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });`,
      "grandchild.on('message', (message) => {",
      "  if (message.type === 'ready') {",
      "    process.stdout.write('tree-ready');",
      "    process.send({ type: 'ready', grandchild_pid: message.pid });",
      "  }",
      "});",
      "process.on('SIGTERM', () => {});",
      "setInterval(() => {}, 1_000);"
    ].join(" ");
    const fixture = await spawnReadyProcess(parentScript);
    try {
      const result = await superviseSpawnedProcessWithTail(fixture.child, {
        timeout_ms: 100,
        tail_bytes: baseInput.tail_bytes
      });

      expect(result.timed_out).toBe(true);
      expect(result.signal).toBe("SIGKILL");
      expect(result.duration_ms).toBeLessThan(900);
      expect(result.stdout_tail).toContain("tree-ready");
      await Promise.all([
        expectProcessGone(fixture.child.pid),
        expectProcessGone(fixture.ready.grandchild_pid)
      ]);
    } finally {
      terminateSpawnedTree(fixture.child);
    }
  }, 3_000);
});
