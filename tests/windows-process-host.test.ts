import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { EventEmitter } from "node:events";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { describe, expect, test, vi } from "vitest";
import { runWindowsProcessWithTail, windowsHostArgs } from "../src/services/windows-process-host.js";
import { waitForFile } from "./fixtures/file-event-wait.js";

const input = {
  executable: process.execPath,
  args: [],
  cwd: process.cwd(),
  env: process.env,
  tail_bytes: 1_024,
  timeout_ms: 2_000
};

describe("runWindowsProcessWithTail", () => {
  test.skipIf(process.platform !== "win32")(
    "rejects a PATH-only executable instead of searching command shims",
    async () => {
      await expect(runWindowsProcessWithTail({
        ...input,
        executable: "node",
        args: ["-e", "process.stdout.write('must-not-run')"],
        env: { PATH: dirname(process.execPath) }
      })).rejects.toThrow(/absolute native executable path/);
    }
  );

  test("passes spaces and shell metacharacters as literal argument values", () => {
    const executable = join(tmpdir(), "trusted tools bin", "node.exe");
    const args = ["path with spaces/file.js", "& | < > ^ %PATH%", "quote\"and\\slash"];
    expect(windowsHostArgs({ ...input, executable, args })).toEqual(["--", executable, ...args]);
  });

  test.skipIf(process.platform !== "win32")(
    "passes spaces and shell metacharacters literally through the production native helper",
    async () => {
      const values = ["path with spaces", "& | < > ^ %PATH%", "quote\"and\\slash"];
      const result = await runWindowsProcessWithTail({
        ...input,
        executable: process.execPath,
        args: ["-e", "console.log(JSON.stringify(process.argv.slice(1)))", ...values]
      });

      expect(result).toMatchObject({
        exit_code: 0,
        cleanup_confirmed: true,
        stdout_tail: JSON.stringify(values)
      });
    }
  );

  test.each([
    "cmd",
    "cmd.exe",
    "npm.cmd",
    "make.bat",
    "script.ps1",
    "powershell.exe",
    "pwsh.exe",
    "bash.exe",
    "sh.exe",
    "cscript.exe",
    "wscript.exe",
    "unknown.exe"
  ])("rejects unsupported Windows command or shell shim %s without fallback", (name) => {
    const executable = name === "cmd" ? name : join(tmpdir(), name);
    expect(() => windowsHostArgs({ ...input, executable, args: ["must-not-run"] })).toThrow();
  });

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

  test("rejects duplicate terminal result frames as unconfirmed supervision", async () => {
    const frames = Buffer.concat([encodeResult(0, 0, 0), encodeResult(0, 0, 0)]);
    const script = [
      "process.stdin.once('data', () => {",
      "process.stdin.destroy();",
      `process.stdout.end(${JSON.stringify(frames.toString("base64"))}, 'base64');`,
      "});"
    ].join(" ");
    const result = await runWindowsProcessWithTail(input, {
      executable: process.execPath,
      args: ["-e", script]
    });

    expect(result).toMatchObject({ cleanup_confirmed: false, cancelled: false, timed_out: false });
    expect(result).toHaveProperty("host_failure");
    expect(result.host_failure).toMatch(/more than one result frame|wrote data after its result frame/i);
  });

  test("fails closed when a completed frame carries a native error", async () => {
    const frame = encodeResult(0, 0, 5);
    const script = [
      "process.stdin.once('data', () => {",
      "process.stdin.destroy();",
      `process.stdout.end(${JSON.stringify(frame.toString("base64"))}, 'base64');`,
      "});"
    ].join(" ");
    const result = await runWindowsProcessWithTail(input, {
      executable: process.execPath,
      args: ["-e", script]
    });

    expect(result).toMatchObject({ cleanup_confirmed: false, cancelled: false, timed_out: false });
    expect(result).toHaveProperty("host_failure");
    expect(result.host_failure).toMatch(/contradictory terminal result/i);
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

  test("reports a confirmed supervision failure without classifying it as cancellation", async () => {
    const result = await runWindowsProcessWithTail(input, {
      executable: process.execPath,
      args: ["-e", resultHost(5)]
    });

    expect(result).toMatchObject({ cancelled: false, timed_out: false, cleanup_confirmed: true });
    expect(result).toHaveProperty("host_failure");
    expect(result.exit_code).toBeUndefined();
    expect(result.stderr_tail).toContain("fatal supervision error (error 5)");
  });

  test.skipIf(process.platform !== "win32")(
    "reports a native resume failure as a supervision error rather than cancellation",
    async () => {
      const result = await runWindowsProcessWithTail({
        ...input,
        env: { ...input.env, GPT_REPO_PROCESS_HOST_TEST_FAULT: "resume" }
      }, {
        executable: join(process.cwd(), "dist", "windows-process-host.test.exe"),
        args: ["--", process.execPath]
      });

      expect(result).toMatchObject({ cancelled: false, timed_out: false, cleanup_confirmed: true });
      expect(result.exit_code).toBeUndefined();
      expect(result.stderr_tail).toContain("fatal supervision error (error 5)");
    }
  );

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

  test("keeps ENOENT primary when the initial START write also reports EPIPE", async () => {
    const writeError = Object.assign(new Error("broken pipe"), { code: "EPIPE" });
    let startWriteCompleted!: () => void;
    const startWrite = new Promise<void>((resolve) => { startWriteCompleted = resolve; });
    const stdin = new Writable({
      write(_chunk, _encoding, callback) {
        process.nextTick(() => {
          callback(writeError);
          startWriteCompleted();
        });
      }
    });
    const child = Object.assign(new EventEmitter(), {
      stdin,
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      pid: undefined,
      kill: vi.fn(() => false),
      unref: vi.fn()
    });
    vi.resetModules();
    vi.doMock("node:child_process", () => ({ spawn: () => child }));

    try {
      const { runWindowsProcessWithTail: runWithFakeHost } = await import("../src/services/windows-process-host.js");
      const resultPromise = runWithFakeHost(input, { executable: "test-host", args: [] });
      child.emit("error", Object.assign(new Error("spawn ENOENT"), { code: "ENOENT" }));
      await startWrite;
      child.emit("close", null, null);

      const result = await resultPromise;
      expect(result).toMatchObject({ cleanup_confirmed: true, cancelled: false, timed_out: false });
      expect(result).toHaveProperty("host_failure");
      expect(result.stderr_tail).toContain("spawn ENOENT");
      expect(result.stderr_tail).not.toContain("broken pipe");
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
    `process.stdout.end(${JSON.stringify(encodeResult(4, 1_223, 0).toString("base64"))}, 'base64');`,
    "});",
    "});"
  ].join(" ");
}

function completedHostUntilRelease(releasePath: string): string {
  return [
    "const { existsSync, watch } = require('node:fs');",
    "const { basename, dirname } = require('node:path');",
    `const releasePath = ${JSON.stringify(releasePath)};`,
    "function waitForRelease() {",
    "return new Promise((resolve, reject) => {",
    "const releaseName = basename(releasePath);",
    "const watcher = watch(dirname(releasePath), (_event, filename) => {",
    "if (filename && filename.toString() !== releaseName) return;",
    "if (existsSync(releasePath)) { watcher.close(); resolve(); }",
    "});",
    "watcher.once('error', error => { watcher.close(); reject(error); });",
    "if (existsSync(releasePath)) { watcher.close(); resolve(); }",
    "});",
    "}",
    "process.stdin.once('data', async () => {",
    "const released = waitForRelease();",
    `process.stdout.write(${JSON.stringify(encodeResult(0, 0, 0).toString("base64"))}, 'base64');`,
    "await released;",
    "process.stdin.destroy();",
    "process.stdout.end();",
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
