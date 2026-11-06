import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, test, vi } from "vitest";

const input = {
  executable: process.execPath,
  args: [],
  cwd: process.cwd(),
  env: process.env,
  timeout_ms: 5_000,
  tail_bytes: 1_024
};
const posixTest = process.platform === "win32" ? test.skip : test;

describe("POSIX process anchor lifecycle", () => {
  afterEach(() => {
    vi.doUnmock("node:child_process");
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.resetModules();
  });

  posixTest("classifies an anchor spawn failure separately from a command failure", async () => {
    const child = fakeAnchor(undefined);
    const run = await loadRunner(child);
    const execution = run();

    child.emit("error", Object.assign(new Error("anchor missing"), { code: "ENOENT" }));
    child.emit("close", -2, null);

    const result = await execution;
    expect(result).toMatchObject({ cleanup_confirmed: true });
    expect(result).toHaveProperty("host_failure");
    expect(child.stdin.readableLength).toBe(0);
  });

  posixTest("checks the process group after an anchor exits before READY", async () => {
    const child = fakeAnchor(42_424);
    const processKill = vi.spyOn(process, "kill").mockImplementation(((_pid, signal) => {
      if (signal === 0) throw Object.assign(new Error("group absent"), { code: "ESRCH" });
      throw Object.assign(new Error("unexpected signal"), { code: "EPERM" });
    }) as typeof process.kill);
    const run = await loadRunner(child);
    const execution = run();

    child.emit("spawn");
    child.exitCode = 1;
    child.emit("close", 1, null);

    const result = await execution;
    expect(processKill).toHaveBeenCalledWith(-42_424, 0);
    expect(result).toMatchObject({ cleanup_confirmed: true });
    expect(result).toHaveProperty("host_failure");
  });

  posixTest("records a failed pre-START anchor kill and waits for close evidence", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const child = fakeAnchor(42_425);
    child.kill.mockImplementation(() => {
      child.emit("error", Object.assign(new Error("anchor kill failed"), { code: "EPERM" }));
      return false;
    });
    const processKill = vi.spyOn(process, "kill").mockImplementation(((_pid, signal) => {
      if (signal === 0) throw Object.assign(new Error("group absent"), { code: "ESRCH" });
      throw Object.assign(new Error("signal denied"), { code: "EPERM" });
    }) as typeof process.kill);
    const run = await loadRunner(child);
    const execution = run(controller.signal);

    child.emit("spawn");
    controller.abort();
    await vi.advanceTimersToNextTimerAsync();
    expect(child.kill).toHaveBeenCalledWith("SIGKILL");

    child.exitCode = null;
    child.emit("close", null, null);
    const result = await execution;

    expect(processKill).toHaveBeenCalledWith(-42_425, 0);
    expect(result).toMatchObject({ cancelled: true, cleanup_confirmed: true });
    expect(result).toHaveProperty("host_failure");
    expect(result.host_failure).toContain("anchor kill failed");
  });

  posixTest("starts pre-READY cleanup when cancellation precedes anchor spawn", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const child = fakeAnchor(42_428);
    vi.spyOn(process, "kill").mockImplementation(((_pid, signal) => {
      if (signal === 0) throw Object.assign(new Error("group absent"), { code: "ESRCH" });
      throw Object.assign(new Error("unexpected signal"), { code: "EPERM" });
    }) as typeof process.kill);
    const run = await loadRunner(child);
    const execution = run(controller.signal);

    controller.abort();
    child.emit("spawn");
    await vi.advanceTimersToNextTimerAsync();

    expect(child.kill).toHaveBeenCalledWith("SIGKILL");
    child.emit("close", null, "SIGKILL");
    const result = await execution;
    expect(result).toMatchObject({ cancelled: true, cleanup_confirmed: true });
    expect(result).toHaveProperty("host_failure");
  });

  posixTest("records a failed post-START termination and verifies the group after close", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const child = fakeAnchor(42_426);
    const processKill = vi.spyOn(process, "kill").mockImplementation(((_pid, signal) => {
      if (signal === 0) throw Object.assign(new Error("group absent"), { code: "ESRCH" });
      throw Object.assign(new Error("signal denied"), { code: "EPERM" });
    }) as typeof process.kill);
    const commandStarted = new Promise<void>((resolve) => child.stdin.once("data", () => resolve()));
    const run = await loadRunner(child);
    const execution = run(controller.signal);

    child.emit("spawn");
    child.stdio[3]!.write('{"type":"ready"}\n');
    await commandStarted;
    controller.abort();
    child.exitCode = null;
    child.emit("close", null, "SIGTERM");
    await vi.advanceTimersToNextTimerAsync();

    const result = await execution;
    expect(processKill).toHaveBeenCalledWith(-42_426, "SIGTERM");
    expect(processKill).toHaveBeenCalledWith(-42_426, 0);
    expect(result).toMatchObject({ cancelled: true, cleanup_confirmed: true });
    expect(result).toHaveProperty("host_failure");
  });

  posixTest("does not confirm cleanup when an unstarted anchor remains alive", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const child = fakeAnchor(42_427);
    let anchorClosed = false;
    child.once("close", () => { anchorClosed = true; });
    let inputWrites = "";
    child.stdin.setEncoding("utf8");
    child.stdin.on("data", (chunk: string) => { inputWrites += chunk; });
    vi.spyOn(process, "kill").mockImplementation(((_pid, signal) => {
      if (signal === 0) return true;
      throw Object.assign(new Error("signal denied"), { code: "EPERM" });
    }) as typeof process.kill);
    const run = await loadRunner(child);
    const execution = run(controller.signal);

    child.emit("spawn");
    controller.abort();
    await vi.runAllTimersAsync();

    const result = await execution;
    expect(child.listenerCount("close")).toBeGreaterThan(0);
    expect(anchorClosed).toBe(false);
    expect(inputWrites).not.toContain("start\n");
    expect(result).toMatchObject({ cleanup_confirmed: false });
    expect(result).toHaveProperty("host_failure");
  });
});

function fakeAnchor(pid: number | undefined) {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const control = new PassThrough();
  return Object.assign(new EventEmitter(), {
    pid,
    exitCode: null as number | null,
    signalCode: null as NodeJS.Signals | null,
    stdin,
    stdout,
    stderr,
    stdio: [stdin, stdout, stderr, control],
    kill: vi.fn(() => false),
    unref: vi.fn()
  });
}

async function loadRunner(child: ReturnType<typeof fakeAnchor>) {
  vi.resetModules();
  vi.doMock("node:child_process", () => ({ spawn: () => child }));
  const { runProcessWithTail } = await import("../src/services/process-exec.js");
  return (signal?: AbortSignal) => runProcessWithTail({ ...input, signal });
}
