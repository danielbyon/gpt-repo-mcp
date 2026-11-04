import { EventEmitter, once } from "node:events";
import process from "node:process";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { watch } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, test, vi } from "vitest";
import { createConnectorRuntime, getManagedProcessTreeStatus, isManagedProcessTreeAlive, signalManagedProcessTree } from "../scripts/connector-runtime.mjs";
import { getSupervisedProcessTreeStatus, spawnSupervisedProcess, waitForManagedTarget } from "../scripts/secure-process-supervisor.mjs";

describe("connector runtime", () => {
  test("prefixes complete and trailing output lines and exposes each line", async () => {
    const output = new PassThrough();
    let rendered = "";
    output.on("data", (chunk) => {
      rendered += chunk.toString();
    });
    const lines = [];
    const runtime = createConnectorRuntime({
      output,
      reportError: () => undefined,
      exit: () => undefined,
      schedule: () => undefined
    });
    const child = fakeChild();

    runtime.track(child, "mcp", { onLine: (line) => lines.push(line) });
    child.stdout.write("first\npart");
    child.stdout.end("ial");
    await once(child.stdout, "end");

    expect(rendered).toBe("[mcp] first\n[mcp] partial\n");
    expect(lines).toEqual(["first", "partial"]);
  });

  test("an unexpected child exit keeps the ordinary connector shutdown bounded", () => {
    const errors = [];
    const exits = [];
    const scheduled = [];
    const runtime = createConnectorRuntime({
      output: new PassThrough(),
      reportError: (message) => errors.push(message),
      exit: (code) => exits.push(code),
      schedule: (callback, delay) => {
        scheduled.push({ callback, delay });
        return scheduled.length;
      },
      cancelSchedule: () => undefined
    });
    const mcp = fakeChild();
    const tunnel = fakeChild();
    runtime.track(mcp, "mcp");
    runtime.track(tunnel, "tunnel");

    mcp.emit("exit", 7, null);

    expect(mcp.kills).toEqual([]);
    expect(tunnel.kills).toEqual(["SIGTERM"]);
    expect(errors).toEqual(["[mcp] exited (code=7, signal=null). Stopping other process."]);
    expect(scheduled.map(({ delay }) => delay)).toEqual([1500, 1700]);
    expect(exits).toEqual([]);

    scheduled[0].callback();
    expect(tunnel.kills).toEqual(["SIGTERM", "SIGKILL"]);
    expect(exits).toEqual([]);
    scheduled[1].callback();

    expect(exits).toEqual([7]);
  });

  test("secure startup treats a clean unexpected child exit as failure", () => {
    const exits = [];
    const scheduled = [];
    const runtime = createConnectorRuntime({
      output: new PassThrough(),
      reportError: () => undefined,
      exit: (code) => exits.push(code),
      schedule: (callback, delay) => {
        scheduled.push({ callback, delay });
        return scheduled.length;
      },
      cancelSchedule: () => undefined,
      failOnUnexpectedCleanExit: true
    });
    const mcp = fakeChild();
    const tunnel = fakeChild();
    runtime.track(mcp, "mcp");
    runtime.track(tunnel, "tunnel");

    mcp.emit("exit", 0, null);

    expect(tunnel.kills).toEqual(["SIGTERM"]);
    scheduled[0].callback();
    scheduled[1].callback();
    expect(exits).toEqual([1]);
  });

  test("ordinary connectors keep the prior clean-exit result", () => {
    const exits = [];
    const scheduled = [];
    const runtime = createConnectorRuntime({
      output: new PassThrough(),
      reportError: () => undefined,
      exit: (code) => exits.push(code),
      schedule: (callback, delay) => {
        scheduled.push({ callback, delay });
        return scheduled.length;
      },
      cancelSchedule: () => undefined
    });
    const mcp = fakeChild();
    const tunnel = fakeChild();
    runtime.track(mcp, "mcp");
    runtime.track(tunnel, "tunnel");

    mcp.emit("exit", 0, null);
    scheduled[0].callback();
    scheduled[1].callback();

    expect(tunnel.kills).toEqual(["SIGTERM", "SIGKILL"]);
    expect(exits).toEqual([0]);
  });

  test("retires a completed helper before its process-group identifier can be reused", () => {
    const exits = [];
    const signals = [];
    let aliveChecks = 0;
    const scheduled = [];
    const runtime = createConnectorRuntime({
      output: new PassThrough(),
      reportError: () => undefined,
      exit: (code) => exits.push(code),
      schedule: (callback, delay) => {
        scheduled.push({ callback, delay });
        return scheduled.length;
      },
      cancelSchedule: () => undefined,
      processTreeCleanup: true,
      signalExitedChildren: true,
      isProcessTreeAlive: () => ++aliveChecks > 1,
      signalChild: (child, signal) => signals.push({ pid: child.pid, signal })
    });
    const helper = fakeChild();
    helper.pid = 4242;
    runtime.track(helper, "startup helper", { expectedExit: true });

    helper.emit("exit", 0, null);
    helper.emit("close", 0, null);
    runtime.shutdown("SIGTERM", "Stop the managed process tree.");
    scheduled[0]?.callback();

    expect(signals).toEqual([]);
    expect(exits).toEqual([0]);
  });

  test("shutdown is idempotent and ordinary connectors exit on the bounded deadline", () => {
    const exits = [];
    const scheduled = [];
    const runtime = createConnectorRuntime({
      output: new PassThrough(),
      reportError: () => undefined,
      exit: (code) => exits.push(code),
      schedule: (callback, delay) => {
        scheduled.push({ callback, delay });
        return scheduled.length;
      },
      cancelSchedule: () => undefined
    });
    const child = fakeChild();
    runtime.track(child, "mcp");

    runtime.shutdown("SIGINT", "Shutting down connector.");
    runtime.shutdown("SIGTERM", "Ignored duplicate.");

    expect(child.kills).toEqual(["SIGTERM"]);
    expect(scheduled.map(({ delay }) => delay)).toEqual([1500, 1700]);
    scheduled[1].callback();
    expect(exits).toEqual([0]);
  });

  test("secure shutdown reports descendants still observable after SIGKILL", () => {
    const errors = [];
    const exits = [];
    const scheduled = [];
    const runtime = createConnectorRuntime({
      output: new PassThrough(),
      reportError: (message) => errors.push(message),
      exit: (code) => exits.push(code),
      schedule: (callback, delay) => {
        scheduled.push({ callback, delay });
        return scheduled.length;
      },
      cancelSchedule: () => undefined,
      processTreeCleanup: true,
      processTreeCleanupTimeoutMs: 10,
      isProcessTreeAlive: () => true,
      signalChild: (child, signal) => child.kill(signal),
      signalExitedChildren: true
    });
    const child = fakeChild();
    runtime.track(child, "secure-tunnel");

    runtime.shutdown("SIGTERM", "Stop the managed process tree.");
    runtime.shutdown("SIGINT", "Duplicate shutdown.");
    expect(child.kills).toEqual(["SIGTERM"]);
    expect(scheduled.map(({ delay }) => delay)).toEqual([1500]);

    scheduled[0].callback();
    expect(child.kills).toEqual(["SIGTERM", "SIGKILL"]);
    expect(scheduled.map(({ delay }) => delay)).toEqual([1500, 10]);
    scheduled[1].callback();

    expect(errors).toContainEqual(expect.stringContaining("process-tree completion could not be verified after SIGKILL"));
    expect(exits).toEqual([1]);
  });

  test("secure shutdown waits for the startup helper owner to finish cancellation", async () => {
    const exits = [];
    let finishHelperCleanup;
    const helperCleanup = new Promise((resolve) => { finishHelperCleanup = resolve; });
    const runtime = createConnectorRuntime({
      output: new PassThrough(),
      reportError: () => undefined,
      exit: (code) => exits.push(code),
      schedule: () => 1,
      cancelSchedule: () => undefined,
      processTreeCleanup: true,
      isProcessTreeAlive: () => false,
      onShutdown: () => helperCleanup
    });

    runtime.shutdown("SIGTERM", "Cancel startup helpers.");
    expect(exits).toEqual([]);

    finishHelperCleanup();
    await Promise.resolve();

    expect(exits).toEqual([0]);
  });

  test("secure shutdown turns an incomplete startup helper cleanup into a failure", async () => {
    const errors = [];
    const exits = [];
    const runtime = createConnectorRuntime({
      output: new PassThrough(),
      reportError: (message) => errors.push(message),
      exit: (code) => exits.push(code),
      schedule: () => 1,
      cancelSchedule: () => undefined,
      processTreeCleanup: true,
      isProcessTreeAlive: () => false,
      onShutdown: () => Promise.reject(Object.assign(new Error("helper tree remains unknown"), {
        code: "ERR_PROCESS_TREE_CLEANUP"
      }))
    });

    runtime.shutdown("SIGTERM", "Cancel startup helpers.");
    await Promise.resolve();

    expect(errors).toEqual(["Secure startup cleanup failed: helper tree remains unknown"]);
    expect(exits).toEqual([1]);
  });

  test("does not treat an unverified process tree as stopped", () => {
    expect(isManagedProcessTreeAlive({ pid: 123, exitCode: 0, signalCode: null }, "win32")).toBe(true);
    expect(isManagedProcessTreeAlive({ pid: undefined, exitCode: 0, signalCode: null }, "linux")).toBe(true);
  });

  test("runs Windows process-tree termination asynchronously and requires force-kill evidence", () => {
    const child = fakeChild();
    child.pid = 123;
    child.exitCode = null;
    child.signalCode = null;
    const commands = [];
    const spawnImpl = vi.fn((command, args, options) => {
      const taskkill = new EventEmitter();
      taskkill.kill = vi.fn();
      commands.push({ command, args, options, taskkill });
      return taskkill;
    });

    const gracefulTermination = signalManagedProcessTree(child, "SIGTERM", "win32", spawnImpl);
    expect(gracefulTermination).toBe(commands[0].taskkill);
    expect(spawnImpl).toHaveBeenCalledWith("taskkill.exe", ["/PID", "123", "/T"], {
      stdio: "ignore",
      windowsHide: true
    });
    gracefulTermination.emit("close", 0, null);
    expect(isManagedProcessTreeAlive(child, "win32")).toBe(true);

    const forcedTermination = signalManagedProcessTree(child, "SIGKILL", "win32", spawnImpl);
    expect(commands[1].args).toEqual(["/PID", "123", "/T", "/F"]);
    forcedTermination.emit("close", 0, null);
  expect(getManagedProcessTreeStatus(child, "win32")).toBe("active");
  child.exitCode = 0;
  expect(getManagedProcessTreeStatus(child, "win32")).toBe("verified-complete");
    expect(isManagedProcessTreeAlive(child, "win32")).toBe(false);
  });

  test("does not taskkill a completed Windows helper PID that may have been reused", () => {
    const child = fakeChild();
    child.pid = 123;
    child.exitCode = 0;
    child.signalCode = null;
    let taskkill;
    const spawnImpl = vi.fn(() => {
      taskkill = new EventEmitter();
      taskkill.kill = vi.fn();
      return taskkill;
    });

    const result = signalManagedProcessTree(child, "SIGKILL", "win32", spawnImpl);
    taskkill?.emit("close", 0, null);

    expect(result).toBeUndefined();
    expect(spawnImpl).not.toHaveBeenCalled();
    expect(getManagedProcessTreeStatus(child, "win32")).toBe("unknown");
    expect(isManagedProcessTreeAlive(child, "win32")).toBe(true);
  });

  test("keeps a failed Windows tree termination active until exit is observed", () => {
    const child = fakeChild();
    child.pid = 123;
    const taskkill = new EventEmitter();
    taskkill.kill = vi.fn();
    const spawnImpl = vi.fn(() => taskkill);

    signalManagedProcessTree(child, "SIGKILL", "win32", spawnImpl);
    taskkill.emit("close", 1, null);

    expect(getManagedProcessTreeStatus(child, "win32")).toBe("active");
    expect(child.kills).toEqual(["SIGKILL"]);
  });

  test("fails closed when an exited leader's process-group ID may have been reused", () => {
    const child = fakeChild();
    child.pid = 123;
    child.exitCode = 0;
    const calls = [];
    const kill = vi.spyOn(process, "kill").mockImplementation((pid, signal) => {
      calls.push({ pid, signal });
      return 0;
    });

    try {
      expect(getManagedProcessTreeStatus(child, "darwin")).toBe("unknown");
      signalManagedProcessTree(child, "SIGTERM", "darwin");
      expect(calls.some(({ pid, signal }) => pid === -123 && signal !== 0)).toBe(false);
    } finally {
      kill.mockRestore();
    }
  });

  test.skipIf(process.platform === "win32")("reports verified completion for a normally completed supervised target", async () => {
    const child = spawnSupervisedProcess(process.execPath, ["-e", "process.stdout.write('ready\\n')"]);
    let output = "";
    child.stdout.on("data", (chunk) => { output += chunk.toString(); });
    const targetPid = await waitForManagedTarget(child, { timeoutMs: 2_000 });
    const [code, signal] = await once(child, "close");

    expect(targetPid).toBeGreaterThan(0);
    expect(child.targetPid).toBe(targetPid);
    expect(code).toBe(0);
    expect(signal).toBeNull();
    expect(output).toBe("ready\n");
    expect(getSupervisedProcessTreeStatus(child)).toBe("verified-complete");
  });

  test.skipIf(process.platform === "win32")("cleans a target descendant before reporting normal completion", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "connector-supervised-tree-"));
    const marker = join(fixture, "descendant-stopped");
    const grandchildSource = `
      const fs = require("node:fs");
      process.on("SIGTERM", () => { fs.writeFileSync(${JSON.stringify(marker)}, "stopped"); process.exit(0); });
      process.stdout.write("ready\\n");
      setInterval(() => {}, 1000);
    `;
    const parentSource = `
      const { spawn } = require("node:child_process");
      const grandchild = spawn(process.execPath, ["-e", ${JSON.stringify(grandchildSource)}], { stdio: ["ignore", "pipe", "ignore"] });
      grandchild.stdout.once("data", () => process.exit(0));
    `;
    const child = spawnSupervisedProcess(process.execPath, ["-e", parentSource]);
    const close = once(child, "close");
    try {
      await waitForManagedTarget(child, { timeoutMs: 2_000 });
      const [code, signal] = await close;
      expect(code).toBe(0);
      expect(signal).toBeNull();
      expect(readFileSync(marker, "utf8")).toBe("stopped");
      expect(getSupervisedProcessTreeStatus(child)).toBe("verified-complete");
    } finally {
      if (isManagedProcessTreeAlive(child)) signalManagedProcessTree(child, "SIGKILL");
      await rm(fixture, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")("verifies forced termination of a lone target before retiring its group", async () => {
    const child = spawnSupervisedProcess(process.execPath, [
      "-e",
      "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)"
    ]);
    await waitForManagedTarget(child, { timeoutMs: 2_000 });
    signalManagedProcessTree(child, "SIGTERM");
    signalManagedProcessTree(child, "SIGKILL");
    await once(child, "close");

    expect(getManagedProcessTreeStatus(child, process.platform)).toBe("verified-complete");
    const send = vi.spyOn(child, "send");
    signalManagedProcessTree(child, "SIGTERM");
    expect(send).not.toHaveBeenCalled();
    send.mockRestore();
  });

  test.skipIf(process.platform === "win32")("keeps cleanup unknown when forced termination includes descendants", async () => {
    const grandchildSource = `
      process.on("SIGTERM", () => {});
      process.stdout.write("descendant-ready\\n");
      setInterval(() => {}, 1000);
    `;
    const parentSource = `
      const { spawn } = require("node:child_process");
      const grandchild = spawn(process.execPath, ["-e", ${JSON.stringify(grandchildSource)}], { stdio: ["ignore", "pipe", "ignore"] });
      grandchild.stdout.once("data", () => process.stdout.write("ready\\n"));
      process.on("SIGTERM", () => {});
      setInterval(() => {}, 1000);
    `;
    const child = spawnSupervisedProcess(process.execPath, ["-e", parentSource]);
    const targetReady = once(child.stdout, "data");
    try {
      await waitForManagedTarget(child, { timeoutMs: 2_000 });
      await targetReady;
      signalManagedProcessTree(child, "SIGTERM");
      signalManagedProcessTree(child, "SIGKILL");
      await once(child, "close");

      expect(getManagedProcessTreeStatus(child, process.platform)).toBe("unknown");
      const send = vi.spyOn(child, "send");
      signalManagedProcessTree(child, "SIGTERM");
      expect(send).not.toHaveBeenCalled();
      send.mockRestore();
    } finally {
      if (isManagedProcessTreeAlive(child)) signalManagedProcessTree(child, "SIGKILL");
    }
  });

  test.skipIf(process.platform === "win32")("signals descendants in the managed process group during owner shutdown", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "connector-process-tree-"));
    const marker = join(fixture, "grandchild-stopped");
    let resolveRuntimeExit;
    const runtimeExit = new Promise((resolveExit) => { resolveRuntimeExit = resolveExit; });
    const grandchildSource = `
      const fs = require("node:fs");
      process.on("SIGTERM", () => { fs.writeFileSync(${JSON.stringify(marker)}, "stopped"); process.exit(0); });
      process.stdout.write("ready\\n");
      setInterval(() => {}, 1000);
    `;
    const parentSource = `
      const { spawn } = require("node:child_process");
      const grandchild = spawn(process.execPath, ["-e", ${JSON.stringify(grandchildSource)}], { stdio: ["ignore", "pipe", "ignore"] });
      grandchild.stdout.once("data", () => process.stdout.write("ready\\n"));
      setInterval(() => {}, 1000);
    `;
    const child = spawnSupervisedProcess(process.execPath, ["-e", parentSource]);
    const exitPromise = once(child, "exit");
    const readyPromise = once(child.stdout, "data");
    const runtime = createConnectorRuntime({
      output: new PassThrough(),
      reportError: () => undefined,
      exit: (code) => resolveRuntimeExit({
        code,
        descendantMarker: existsSync(marker) ? readFileSync(marker, "utf8") : "missing"
      }),
      signalChild: signalManagedProcessTree,
      signalExitedChildren: true,
      isProcessTreeAlive: isManagedProcessTreeAlive
    });
    runtime.track(child, "managed-wrapper");
    try {
      await readyPromise;
      await waitForManagedTarget(child, { timeoutMs: 2_000 });
      const markerPromise = waitForFile(marker);
      runtime.shutdown("SIGTERM", "Stop the isolated process tree.");
      await expect(Promise.all([exitPromise, markerPromise, runtimeExit])).resolves.toEqual([
        expect.any(Array),
        "stopped",
        { code: 0, descendantMarker: "stopped" }
      ]);
    } finally {
      if (isManagedProcessTreeAlive(child)) signalManagedProcessTree(child, "SIGKILL");
      await rm(fixture, { recursive: true, force: true });
    }
  });
});

async function waitForFile(path) {
  try {
    return await readFile(path, "utf8");
  } catch {
    // Install the watcher before checking again so the signal marker cannot race the wait.
  }
  return new Promise((resolve, reject) => {
    const watcher = watch(dirname(path), async () => {
      try {
        const content = await readFile(path, "utf8");
        watcher.close();
        resolve(content);
      } catch (error) {
        if (error?.code !== "ENOENT") {
          watcher.close();
          reject(error);
        }
      }
    });
    void readFile(path, "utf8").then((content) => {
      watcher.close();
      resolve(content);
    }).catch((error) => {
      if (error?.code !== "ENOENT") {
        watcher.close();
        reject(error);
      }
    });
  });
}

function fakeChild() {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killed = false;
  child.kills = [];
  child.kill = (signal) => {
    child.kills.push(signal);
  };
  return child;
}
