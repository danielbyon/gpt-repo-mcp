import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { EventEmitter } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, test, vi } from "vitest";
import { runWindowsProcessWithTail } from "../src/services/windows-process-host.js";

const input = {
  executable: process.execPath,
  args: [],
  cwd: process.cwd(),
  env: process.env,
  tail_bytes: 1_024,
  timeout_ms: 2_000
};

describe("runWindowsProcessWithTail", () => {
  test("preserves bounded stdout and stderr plus the completed exit code", async () => {
    const result = await runWindowsProcessWithTail({ ...input, tail_bytes: 5 }, {
      executable: process.execPath,
      args: ["-e", completedHost("before-after", "warning", 7)]
    });

    expect(result).toMatchObject({
      exit_code: 7,
      timed_out: false,
      cancelled: false,
      cleanup_confirmed: true,
      stdout_tail: "after",
      stderr_tail: "rning"
    });
  });

  test("sends cancellation to only the active host and waits for its cleanup result", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-windows-host-cancel-"));
    const readyPath = join(root, "ready");
    const controller = new AbortController();
    const resultPromise = runWindowsProcessWithTail({ ...input, cwd: root, signal: controller.signal }, {
      executable: process.execPath,
      args: ["-e", cancellableHost(readyPath)]
    });

    try {
      await waitForFile(readyPath);
      controller.abort();
      const result = await resultPromise;

      expect(result).toMatchObject({
        cancelled: true,
        timed_out: false,
        cleanup_confirmed: true,
        signal: "SIGKILL"
      });
    } finally {
      controller.abort();
      await resultPromise.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  });

  test("does not confirm cleanup when the host reports an uncertain result", async () => {
    const result = await runWindowsProcessWithTail(input, {
      executable: process.execPath,
      args: ["-e", resultHost(2)]
    });

    expect(result).toMatchObject({ cleanup_confirmed: false, cancelled: false, timed_out: false });
    expect(result.exit_code).toBeUndefined();
  });

  test("does not retroactively cancel completion accepted before the abort", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-windows-host-completion-race-"));
    const releasePath = join(root, "release");
    const controller = new AbortController();
    let accepted!: () => void;
    const terminalAccepted = new Promise<void>((resolve) => { accepted = resolve; });
    const sourceSignal = controller.signal;
    const signal = {
      get aborted() { return sourceSignal.aborted; },
      throwIfAborted: sourceSignal.throwIfAborted.bind(sourceSignal),
      addEventListener: sourceSignal.addEventListener.bind(sourceSignal),
      removeEventListener(type: string, listener: EventListenerOrEventListenerObject, options?: boolean | EventListenerOptions) {
        sourceSignal.removeEventListener(type, listener, options);
        if (type === "abort") accepted();
      }
    } as AbortSignal;
    const resultPromise = runWindowsProcessWithTail({ ...input, cwd: root, signal }, {
      executable: process.execPath,
      args: ["-e", completedHostUntilRelease(releasePath)]
    });

    try {
      await terminalAccepted;
      controller.abort();
      await writeFile(releasePath, "release");
      const result = await resultPromise;

      expect(result).toMatchObject({
        exit_code: 0,
        cancelled: false,
        timed_out: false,
        cleanup_confirmed: true
      });
    } finally {
      controller.abort();
      await writeFile(releasePath, "release").catch(() => undefined);
      await resultPromise.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  });

  test("does not infer cleanup from host exit without a result frame", async () => {
    const result = await runWindowsProcessWithTail(input, {
      executable: process.execPath,
      args: ["-e", "process.stdin.once('data', () => { process.stdin.destroy(); process.stdout.end(); });"]
    });

    expect(result).toMatchObject({ cleanup_confirmed: false, cancelled: false, timed_out: false });
    expect(result.stderr_tail).toContain("exited without cleanup evidence");
  });

  test("does not confirm cleanup when a spawned host reports an error before closing", async () => {
    const child = Object.assign(new EventEmitter(), {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      pid: 42424,
      kill: vi.fn(() => true)
    });
    vi.resetModules();
    vi.doMock("node:child_process", () => ({ spawn: () => child }));

    try {
      const { runWindowsProcessWithTail: runWithFakeHost } = await import("../src/services/windows-process-host.js");
      const resultPromise = runWithFakeHost(input, { executable: "test-host", args: [] });
      child.emit("spawn");
      child.emit("error", new Error("termination failed"));
      child.emit("close", null, "SIGKILL");
      const result = await resultPromise;

      expect(result).toMatchObject({ cleanup_confirmed: false, cancelled: false, timed_out: false });
      expect(result.exit_code).toBeUndefined();
      expect(result.stderr_tail).toContain("termination failed");
    } finally {
      vi.doUnmock("node:child_process");
      vi.resetModules();
    }
  });

  test("confirms there was no process to clean up when the host fails before spawning", async () => {
    const child = Object.assign(new EventEmitter(), {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      pid: undefined,
      kill: vi.fn(() => false)
    });
    vi.resetModules();
    vi.doMock("node:child_process", () => ({ spawn: () => child }));

    try {
      const { runWindowsProcessWithTail: runWithFakeHost } = await import("../src/services/windows-process-host.js");
      const resultPromise = runWithFakeHost(input, { executable: "test-host", args: [] });
      child.emit("error", new Error("host failed to launch"));
      child.emit("close", null, null);
      const result = await resultPromise;

      expect(result).toMatchObject({ cleanup_confirmed: true, cancelled: false, timed_out: false });
      expect(result.stderr_tail).toContain("host failed to launch");
    } finally {
      vi.doUnmock("node:child_process");
      vi.resetModules();
    }
  });
});

function completedHost(stdout: string, stderr: string, exitCode: number): string {
  return [
    "process.stdin.once('data', () => {",
    "process.stdin.destroy();",
    `process.stdout.end(${JSON.stringify(Buffer.concat([
      encodeFrame(1, Buffer.from(stdout)),
      encodeFrame(2, Buffer.from(stderr)),
      encodeResult(0, exitCode, 0)
    ]).toString("base64"))}, 'base64');`,
    "});"
  ].join(" ");
}

function cancellableHost(readyPath: string): string {
  return [
    "const { writeFileSync } = require('node:fs');",
    "process.stdin.once('data', () => {",
    `writeFileSync(${JSON.stringify(readyPath)}, 'ready');`,
    "process.stdin.once('data', () => {",
    "process.stdin.destroy();",
    `process.stdout.end(${JSON.stringify(encodeResult(4, 0, 0).toString("base64"))}, 'base64');`,
    "});",
    "});"
  ].join(" ");
}

function completedHostUntilRelease(releasePath: string): string {
  return [
    "const { existsSync } = require('node:fs');",
    "process.stdin.once('data', () => {",
    `process.stdout.write(${JSON.stringify(encodeResult(0, 0, 0).toString("base64"))}, 'base64');`,
    `const poll = setInterval(() => { if (existsSync(${JSON.stringify(releasePath)})) { clearInterval(poll); process.stdin.destroy(); process.stdout.end(); } }, 5);`,
    "});"
  ].join(" ");
}

function resultHost(status: number): string {
  return [
    "process.stdin.once('data', () => {",
    "process.stdin.destroy();",
    `process.stdout.end(${JSON.stringify(encodeResult(status, 0, 5).toString("base64"))}, 'base64');`,
    "});"
  ].join(" ");
}

function encodeFrame(type: number, payload: Buffer): Buffer {
  const header = Buffer.alloc(5);
  header.writeUInt8(type, 0);
  header.writeUInt32LE(payload.length, 1);
  return Buffer.concat([header, payload]);
}

function encodeResult(status: number, exitCode: number, errorCode: number): Buffer {
  const payload = Buffer.alloc(9);
  payload.writeUInt8(status, 0);
  payload.writeUInt32LE(exitCode, 1);
  payload.writeUInt32LE(errorCode, 5);
  return encodeFrame(3, payload);
}

async function waitForFile(path: string): Promise<string> {
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      return await readFile(path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
  throw new Error(`Timed out waiting for ${path}.`);
}
