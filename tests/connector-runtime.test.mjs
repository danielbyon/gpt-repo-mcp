import { EventEmitter, once } from "node:events";
import { execFileSync, fork } from "node:child_process";
import process from "node:process";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { watch } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PassThrough } from "node:stream";
import { clearTimeout, setTimeout } from "node:timers";
import { setImmediate } from "node:timers/promises";
import { fileURLToPath, URL } from "node:url";
import { describe, expect, test, vi } from "vitest";
import { createConnectorRuntime, getManagedProcessTreeStatus, isManagedProcessTreeAlive, signalManagedProcessTree } from "../scripts/connector-runtime.mjs";
import { getSupervisedProcessTreeStatus, registerSupervisedProcess, spawnSupervisedProcess, waitForManagedTarget } from "../scripts/secure-process-supervisor.mjs";

const PROCESS_TABLE_SCAN_TIMEOUT_MS = 150;
const supervisorTestEntryPath = fileURLToPath(new URL("./fixtures/supervisor-test-entry.mjs", import.meta.url));

function createProcessGroupProbe(fixture) {
  return { fixture, responsePath: join(fixture, "process-table.json") };
}

async function writeProcessGroupProbe(probe, supervisorPid, rows = [], response = {}) {
  await writeFile(probe.responsePath, JSON.stringify({
    rows: [{ pid: supervisorPid, pgid: supervisorPid }, ...rows],
    livePids: [],
    expectedTimeoutMs: PROCESS_TABLE_SCAN_TIMEOUT_MS,
    status: 0,
    ...response
  }));
}

async function spawnWithProcessGroupProbe(probe, args, { withholdTargetIdentity = false } = {}) {
  const child = fork(supervisorTestEntryPath, [], {
    cwd: probe.fixture,
    detached: true,
    execArgv: [],
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    windowsHide: true
  });
  const closed = once(child, "close");
  if (withholdTargetIdentity) {
    const emit = child.emit;
    child.emit = function (event, ...args) {
      if (event === "message" && args[0]?.type === "target-started") return true;
      return emit.call(this, event, ...args);
    };
  }
  try {
    await writeProcessGroupProbe(probe, child.pid, [], { status: 1 });
    return registerSupervisedProcess(child, process.execPath, args, { cwd: probe.fixture });
  } catch (error) {
    child.kill("SIGKILL");
    await closed.catch(() => undefined);
    throw error;
  }
}

/** Waits for one supervisor message and removes its listener when the deadline expires. */
function waitForSupervisorMessage(child, type, timeoutMs = 2_000) {
  return new Promise((resolve, reject) => {
    let timer;
    const onMessage = (message) => {
      if (message?.type !== type) return;
      child.off("message", onMessage);
      clearTimeout(timer);
      resolve(message);
    };
    child.on("message", onMessage);
    timer = setTimeout(() => {
      child.off("message", onMessage);
      reject(new Error(`Timed out waiting for supervisor message ${type}.`));
    }, timeoutMs);
  });
}

/** Rejects when a supervised child does not finish closing within the test bound. */
function waitForChildClose(child, closed, timeoutMs = 2_000) {
  let timer;
  return Promise.race([
    closed,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Test supervisor ${child?.pid ?? "unknown"} did not close after cleanup.`)), timeoutMs);
    })
  ]).finally(() => clearTimeout(timer));
}

/** Waits for the managed target's exit tuple without leaving a listener after timeout. */
function waitForManagedTargetExit(child, timeoutMs = 2_000) {
  return new Promise((resolve, reject) => {
    let timer;
    const finish = (error, result) => {
      clearTimeout(timer);
      child.off("managedTargetExit", onExit);
      child.off("error", onError);
      if (error) reject(error);
      else resolve(result);
    };
    const onExit = (code, signal) => finish(undefined, [code, signal]);
    const onError = (error) => finish(error);
    child.once("managedTargetExit", onExit);
    child.once("error", onError);
    timer = setTimeout(() => finish(new Error("Timed out waiting for the managed target to exit.")), timeoutMs);
  });
}

/** Stops and verifies the isolated test process group before removing its fixture. */
async function cleanupProcessGroupProbeChild(child, targetPid, closed, fixture, readGroupRows = readTestProcessGroupRows) {
  const cleanupErrors = [];
  let groupSettled = false;
  let childClosed = false;
  if (Number.isSafeInteger(child?.pid) && child.pid > 1) {
    try {
      stopOwnedTestProcessGroup(child, readGroupRows(child.pid));
    } catch (error) {
      cleanupErrors.push(error);
      if (getSupervisedProcessTreeStatus(child) === "active") {
        try {
          signalManagedProcessTree(child, "SIGKILL");
        } catch (signalError) {
          cleanupErrors.push(signalError);
        }
      }
    }
  }
  const cleanupTargetPid = targetPid ?? child.targetPid;
  if (Number.isSafeInteger(cleanupTargetPid) && cleanupTargetPid > 1) {
    let stage = "target-exit-check";
    try {
      if (!await waitForProcessExit(cleanupTargetPid, 0)) {
        stage = "target-identity-read";
        const rows = readTestProcessRows(cleanupTargetPid);
        stage = "target-pid-signal";
        signalTestTargetIfOwned(child, cleanupTargetPid, rows);
      }
      stage = "target-exit-confirmation";
      if (!await waitForProcessExit(cleanupTargetPid)) {
        throw new Error("Managed test target did not exit after cleanup.");
      }
    } catch (error) {
      cleanupErrors.push(new Error(`Process-group cleanup failed during ${stage}.`, { cause: error }));
    }
  }
  try {
    await waitForChildClose(child, closed);
    childClosed = true;
  } catch (error) {
    cleanupErrors.push(error);
  }
  if (Number.isSafeInteger(child?.pid) && child.pid > 1) {
    try {
      groupSettled = await waitForTestProcessGroupExit(child.pid);
      if (!groupSettled) {
        throw new Error("Test process group still has live members after cleanup.");
      }
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  if (fixture && childClosed && groupSettled) {
    try {
      await rm(fixture, { recursive: true, force: true });
    } catch (error) {
      cleanupErrors.push(error);
    }
  } else if (fixture) {
    cleanupErrors.push(new Error(`Preserved test fixture because process cleanup was not verified: ${fixture}`));
  }
  return cleanupErrors;
}

/** Preserves both a test failure and any failure while cleaning up its child processes. */
async function finishTestWithCleanup(label, run, cleanup) {
  let testError;
  try {
    await run();
  } catch (error) {
    testError = error;
  }
  let cleanupErrors = [];
  try {
    cleanupErrors = await cleanup();
  } catch (error) {
    cleanupErrors = [error];
  }
  if (testError && cleanupErrors.length > 0) {
    throw new AggregateError([testError, ...cleanupErrors], `${label} and cleanup both failed.`);
  }
  if (testError) throw testError;
  if (cleanupErrors.length > 0) {
    throw new AggregateError(cleanupErrors, `${label} cleanup failed.`);
  }
}

/** Resolves when a supervised child writes a marker, with a finite timeout. */
function waitForOutput(stream, marker, timeoutMs = 2_000) {
  return new Promise((resolve, reject) => {
    let output = "";
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      stream.off("data", onData);
      stream.off("end", onEnd);
      stream.off("error", onError);
      if (error) reject(error);
      else resolve(output);
    };
    const onData = (chunk) => {
      output += chunk.toString();
      if (output.includes(marker)) finish();
    };
    const onEnd = () => finish(new Error(`Child output ended before marker ${marker}.`));
    const onError = (error) => finish(error);
    const timeout = setTimeout(() => finish(new Error(`Timed out waiting for child output marker ${marker}.`)), timeoutMs);
    stream.on("data", onData);
    stream.once("end", onEnd);
    stream.once("error", onError);
  });
}

/** Wait until a known test-owned PID disappears, without sending a group signal. */
async function waitForProcessExit(pid, timeoutMs = 2_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if (error?.code === "ESRCH") return true;
      throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  try {
    process.kill(pid, 0);
  } catch (error) {
    if (error?.code === "ESRCH") return true;
    throw error;
  }
  return processRowsIndicateStopped(readTestProcessRows(pid));
}

/** Treats empty and zombie-only process observations as stopped. */
function processRowsIndicateStopped(rows) {
  return rows.length === 0 || rows.every((row) => row.state.toUpperCase().startsWith("Z"));
}

/** Read the current identity row for a test-owned process without capturing command text. */
function readTestProcessRows(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 1) throw new TypeError("Refusing to inspect a special or invalid test PID.");
  let output;
  try {
    output = execFileSync("ps", ["-o", "pid=", "-o", "ppid=", "-o", "pgid=", "-o", "stat=", "-p", String(pid)], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: PROCESS_TABLE_SCAN_TIMEOUT_MS
    });
  } catch (error) {
    if (error?.status === 1 && error?.signal === null && error?.stdout === "") return [];
    throw error;
  }
  return parseTestProcessRows(output);
}

/** Reads PID, parent PID, group ID and state fields for the isolated process group. */
function readTestProcessGroupRows(groupId) {
  if (!Number.isSafeInteger(groupId) || groupId <= 1) throw new TypeError("Refusing to inspect a special or invalid test process group.");
  let processIds;
  try {
    processIds = execFileSync("pgrep", ["-g", String(groupId), "."], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: PROCESS_TABLE_SCAN_TIMEOUT_MS
    }).trim();
  } catch (error) {
    if (error?.status === 1 && error?.signal === null && error?.stdout === "") return [];
    throw error;
  }
  if (!processIds) return [];
  const pids = processIds.split(/\s+/).map(Number);
  if (pids.some((pid) => !Number.isSafeInteger(pid) || pid <= 1)) {
    throw new Error("Test process-group probe returned an invalid PID.");
  }
  let output;
  try {
    output = execFileSync("ps", ["-o", "pid=", "-o", "ppid=", "-o", "pgid=", "-o", "stat=", "-p", pids.join(",")], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: PROCESS_TABLE_SCAN_TIMEOUT_MS
    });
  } catch (error) {
    if (error?.status === 1 && error?.signal === null && error?.stdout === "") return [];
    throw error;
  }
  return parseTestProcessRows(output).filter((row) => row.pgid === groupId);
}

/** Parses process identity fields without retaining command or environment text. */
function parseTestProcessRows(output) {
  return output.split(/\r?\n/).filter((line) => line.trim() !== "").map((line) => {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$/);
    if (!match) throw new Error("Test process identity probe returned an invalid row.");
    const row = { pid: Number(match[1]), ppid: Number(match[2]), pgid: Number(match[3]), state: match[4] };
    if (!Number.isSafeInteger(row.pid) || row.pid <= 0 || !Number.isSafeInteger(row.ppid) || row.ppid < 0
      || !Number.isSafeInteger(row.pgid) || row.pgid < 0) {
      throw new Error("Test process identity probe returned an invalid identity.");
    }
    return row;
  });
}

/** Sends SIGKILL only while a known supervisor or target PID still belongs to the group. */
function stopOwnedTestProcessGroup(child, rows) {
  const liveRows = rows.filter((row) => !row.state.toUpperCase().startsWith("Z"));
  if (liveRows.length === 0) return;
  const supervisorOwnsGroup = liveRows.some((row) => row.pid === child.pid && row.pgid === child.pid);
  const targetOwnsGroup = Number.isSafeInteger(child.targetPid) && liveRows.some((row) => row.pid === child.targetPid && row.pgid === child.pid);
  if (!supervisorOwnsGroup && !targetOwnsGroup) {
    throw new Error("Refusing to signal a test process group without a matching owned process identity.");
  }
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch (error) {
    if (error?.code !== "ESRCH" || readTestProcessGroupRows(child.pid).some((row) => !row.state.toUpperCase().startsWith("Z"))) {
      throw error;
    }
  }
}

/** Waits for a test-owned process group to contain no live members, within a fixed bound. */
async function waitForTestProcessGroupExit(groupId, timeoutMs = 2_000) {
  const deadline = Date.now() + timeoutMs;
  let rows = readTestProcessGroupRows(groupId);
  while (!processRowsIndicateStopped(rows) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 20));
    rows = readTestProcessGroupRows(groupId);
  }
  return processRowsIndicateStopped(rows);
}

/** Signal a target only while its current PID remains in the test-owned group. */
function signalTestTargetIfOwned(child, targetPid, processRows, sendSignal = (pid, signal) => process.kill(pid, signal)) {
  if (!Number.isSafeInteger(child?.pid) || child.pid <= 1 || !Number.isSafeInteger(targetPid) || targetPid <= 1
    || child.targetPid !== targetPid) {
    throw new TypeError("Refusing to signal a target without its recorded supervisor identity.");
  }
  const targets = processRows.filter((row) => row.pid === targetPid && !row.state.toUpperCase().startsWith("Z"));
  if (targets.length === 0) return false;
  if (targets.length !== 1 || targets[0].pgid !== child.pid) {
    throw new Error("The recorded target PID no longer belongs to its managed process group.");
  }
  const supervisors = processRows.filter((row) => row.pid === child.pid && !row.state.toUpperCase().startsWith("Z"));
  if (supervisors.length > 1 || supervisors.length === 1
    && (supervisors[0].pgid !== child.pid || targets[0].ppid !== child.pid)) {
    throw new Error("The current supervisor and target identities do not match the managed process group.");
  }
  sendSignal(targetPid, "SIGKILL");
  return true;
}

/** Keep a late stream failure handled when supervised startup fails first. */
function waitForTargetReadiness(child) {
  const readiness = waitForOutput(child.stdout, "TARGET_READY");
  void readiness.catch(() => undefined);
  return readiness;
}

describe("connector runtime", () => {
  test("treats zombie-only test process observations as exited", () => {
    expect(processRowsIndicateStopped([])).toBe(true);
    expect(processRowsIndicateStopped([{ state: "Z" }])).toBe(true);
    expect(processRowsIndicateStopped([{ state: "Z+" }])).toBe(true);
    expect(processRowsIndicateStopped([{ state: "S" }])).toBe(false);
    expect(processRowsIndicateStopped([{ state: "Z" }, { state: "S" }])).toBe(false);
  });

  test("runs cleanup when a supervisor close wait reaches its bound", async () => {
    const child = new EventEmitter();
    const closed = new Promise(() => {});
    let cleanupCalled = false;

    await expect(finishTestWithCleanup(
      "Close-timeout supervision",
      () => waitForChildClose(child, closed, 10),
      async () => {
        cleanupCalled = true;
        return [];
      }
    )).rejects.toThrow(/did not close after cleanup/);

    expect(cleanupCalled).toBe(true);
  });

  test.skipIf(process.platform === "win32")("provides shared internal hooks for isolated supervisor execution", async () => {
    const supervisor = await import("../scripts/secure-process-supervisor.mjs");

    expect(supervisor.registerSupervisedProcess).toBeTypeOf("function");
    expect(supervisor.runSupervisorWithScanner).toBeTypeOf("function");
  });

  test.skipIf(process.platform === "win32")("cleans up the owned process group before target identity is delivered", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "connector-unreported-target-"));
    const probe = createProcessGroupProbe(fixture);
    const child = await spawnWithProcessGroupProbe(probe, [
      "-e",
      "process.stdout.write('TARGET_READY\\n'); setInterval(() => {}, 1000)"
    ], { withholdTargetIdentity: true });
    const closed = once(child, "close");
    const targetReady = waitForTargetReadiness(child);

    await finishTestWithCleanup("Unreported-target supervision", async () => {
      expect(await targetReady).toContain("TARGET_READY");
      expect(child.targetPid).toBeUndefined();
      const liveMembers = readTestProcessGroupRows(child.pid)
        .filter((row) => !row.state.toUpperCase().startsWith("Z"));
      expect(liveMembers.some((row) => row.pid === child.pid && row.pgid === child.pid)).toBe(true);
      expect(liveMembers.some((row) => row.pid !== child.pid)).toBe(true);
    }, async () => cleanupProcessGroupProbeChild(child, undefined, closed, fixture));
  });

  test.skipIf(process.platform === "win32")("asks the live supervisor to clean up when the host group probe fails", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "connector-unreported-target-probe-failure-"));
    const probe = createProcessGroupProbe(fixture);
    const child = await spawnWithProcessGroupProbe(probe, [
      "-e",
      "process.stdout.write('TARGET_READY\\n'); setInterval(() => {}, 1000)"
    ], { withholdTargetIdentity: true });
    const closed = once(child, "close");
    const targetReady = waitForTargetReadiness(child);
    const probeFailure = new Error("Synthetic host process-group probe failure.");
    let cleanupErrors;

    await finishTestWithCleanup("Probe-failure supervision", async () => {
      expect(await targetReady).toContain("TARGET_READY");
      expect(child.targetPid).toBeUndefined();
      const liveTargets = readTestProcessGroupRows(child.pid)
        .filter((row) => row.pid !== child.pid && !row.state.toUpperCase().startsWith("Z"));
      expect(liveTargets).toHaveLength(1);
      await writeProcessGroupProbe(probe, child.pid, liveTargets.map(({ pid, pgid }) => ({ pid, pgid })), {
        livePids: liveTargets.map((row) => row.pid)
      });
    }, async () => {
      cleanupErrors = await cleanupProcessGroupProbeChild(
        child,
        undefined,
        closed,
        fixture,
        () => { throw probeFailure; }
      );
      return cleanupErrors.filter((error) => error !== probeFailure);
    });

    expect(cleanupErrors).toEqual([probeFailure]);
    expect(getSupervisedProcessTreeStatus(child)).toBe("verified-complete");
    expect(readTestProcessGroupRows(child.pid).filter((row) => !row.state.toUpperCase().startsWith("Z"))).toEqual([]);
  });

  test.skipIf(process.platform === "win32")("does not treat an uninitialized test process table as an empty group", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "connector-uninitialized-group-probe-"));
    const probe = createProcessGroupProbe(fixture);
    const child = await spawnWithProcessGroupProbe(probe, [
      "-e",
      "process.stdout.write('TARGET_READY\\n'); setInterval(() => {}, 1000)"
    ], { withholdTargetIdentity: true });
    const closed = once(child, "close");
    const targetReady = waitForTargetReadiness(child);
    const probeFailure = new Error("Synthetic host process-group probe failure.");
    let cleanupErrors;

    await finishTestWithCleanup("Uninitialized-probe supervision", async () => {
      expect(await targetReady).toContain("TARGET_READY");
      expect(child.targetPid).toBeUndefined();
      cleanupErrors = await cleanupProcessGroupProbeChild(
        child,
        undefined,
        closed,
        fixture,
        () => { throw probeFailure; }
      );

      expect(cleanupErrors).toEqual([probeFailure]);
      expect(child.signalCode).toBe("SIGKILL");
      expect(getSupervisedProcessTreeStatus(child)).toBe("unknown");
      expect(readTestProcessGroupRows(child.pid).filter((row) => !row.state.toUpperCase().startsWith("Z"))).toEqual([]);
    }, async () => cleanupProcessGroupProbeChild(child, undefined, closed, fixture));
  });

  test("handles a late target-readiness rejection when the output stream closes", async () => {
    const output = new PassThrough();
    const readiness = waitForTargetReadiness({ stdout: output });
    const unhandledRejections = [];
    const recordUnhandled = (reason) => unhandledRejections.push(reason);
    process.on("unhandledRejection", recordUnhandled);

    try {
      output.end();
      await setImmediate();
      expect(unhandledRejections).toEqual([]);
      await expect(readiness).rejects.toThrow("Child output ended before marker TARGET_READY.");
    } finally {
      process.off("unhandledRejection", recordUnhandled);
      await readiness.catch(() => undefined);
    }
  });
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
    const fixture = await mkdtemp(join(tmpdir(), "connector-lone-target-"));
    const probe = createProcessGroupProbe(fixture);
    const child = await spawnWithProcessGroupProbe(probe, [
      "-e",
      "process.on('SIGTERM', () => process.stdout.write('TERM_RECEIVED\\\\n')); process.stdout.write('TARGET_READY\\\\n'); setInterval(() => {}, 1000)"
    ]);
    const closed = once(child, "close");
    const targetReady = waitForTargetReadiness(child);
    const supervisorMessages = [];
    child.on("message", (message) => supervisorMessages.push(message?.type));
    let termAcknowledged = false;
    const prematureKills = [];
    const sendOriginal = child.send.bind(child);
    const send = vi.spyOn(child, "send").mockImplementation((message, ...args) => {
      if (message?.type === "signal" && message.signal === "SIGKILL" && !termAcknowledged) {
        prematureKills.push(message.signal);
      }
      return sendOriginal(message, ...args);
    });
    let targetPid;

    await finishTestWithCleanup("Lone-target supervision", async () => {
      targetPid = await waitForManagedTarget(child, { timeoutMs: 2_000 });
      expect(await targetReady).toContain("TARGET_READY");
      await writeProcessGroupProbe(probe, child.pid, [{ pid: targetPid, pgid: child.pid }], { livePids: [targetPid] });

      const termOutput = waitForOutput(child.stdout, "TERM_RECEIVED").then((output) => {
        termAcknowledged = true;
        return output;
      });
      signalManagedProcessTree(child, "SIGTERM");
      expect(await termOutput).toContain("TERM_RECEIVED");
      signalManagedProcessTree(child, "SIGKILL");
      await waitForChildClose(child, closed);

      expect(prematureKills).toEqual([]);
      expect(child.targetExited).toBe(true);
      expect(child.targetExitCode).toBeNull();
      expect(child.targetSignal).toBe("SIGKILL");
      expect(supervisorMessages).toContain("tree-complete-candidate");
      expect(supervisorMessages).toContain("tree-complete");
      expect(getManagedProcessTreeStatus(child, process.platform)).toBe("verified-complete");

      const sendCountBeforeRetiredSignal = send.mock.calls.length;
      signalManagedProcessTree(child, "SIGTERM");
      expect(send).toHaveBeenCalledTimes(sendCountBeforeRetiredSignal);
    }, async () => {
      send.mockRestore();
      return cleanupProcessGroupProbeChild(child, targetPid, closed, fixture);
    });
  });

  test.skipIf(process.platform === "win32")("requires empty-group completion evidence before acknowledging completion", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "connector-empty-owned-group-"));
    const probe = createProcessGroupProbe(fixture);
    const child = await spawnWithProcessGroupProbe(probe, [
      "-e",
      "process.on('SIGTERM', () => { process.stdout.write('TERM_RECEIVED\\\\n'); process.exit(0); }); process.stdout.write('TARGET_READY\\\\n'); setInterval(() => {}, 1000)"
    ]);
    const closed = once(child, "close");
    const targetReady = waitForTargetReadiness(child);
    let targetExit;
    let completionCandidate;
    const messages = [];
    child.on("message", (message) => messages.push(message?.type));
    const sendOriginal = child.send.bind(child);
    let heldAcknowledgment;
    let acknowledgmentReleased = false;
    const send = vi.spyOn(child, "send").mockImplementation((message, ...args) => {
      if (message?.type === "tree-complete-ack") {
        heldAcknowledgment = { message, args };
        return true;
      }
      return sendOriginal(message, ...args);
    });
    let targetPid;

    await finishTestWithCleanup("Empty-group supervision", async () => {
      targetPid = await waitForManagedTarget(child, { timeoutMs: 2_000 });
      expect(await targetReady).toContain("TARGET_READY");
      await writeProcessGroupProbe(probe, child.pid, [{ pid: targetPid, pgid: child.pid }], { livePids: [targetPid] });

      targetExit = waitForManagedTargetExit(child);
      void targetExit.catch(() => undefined);
      completionCandidate = waitForSupervisorMessage(child, "tree-complete-candidate");
      void completionCandidate.catch(() => undefined);
      const termOutput = waitForOutput(child.stdout, "TERM_RECEIVED");
      signalManagedProcessTree(child, "SIGTERM");
      expect(await termOutput).toContain("TERM_RECEIVED");
      const [targetCode, targetSignal] = await targetExit;
      expect(targetCode).toBe(0);
      expect(targetSignal).toBeNull();

      await completionCandidate;
      expect(heldAcknowledgment).toBeDefined();
      expect(child.targetExited).toBe(true);
      expect(getSupervisedProcessTreeStatus(child)).toBe("active");
      expect(messages).not.toContain("tree-complete");

      send.mockRestore();
      sendOriginal(heldAcknowledgment.message, ...heldAcknowledgment.args);
      acknowledgmentReleased = true;
      await waitForChildClose(child, closed);
      expect(getManagedProcessTreeStatus(child, process.platform)).toBe("verified-complete");
    }, async () => {
      send.mockRestore();
      const cleanupErrors = [];
      if (heldAcknowledgment && !acknowledgmentReleased && getSupervisedProcessTreeStatus(child) === "active") {
        try {
          sendOriginal(heldAcknowledgment.message, ...heldAcknowledgment.args);
          acknowledgmentReleased = true;
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
      cleanupErrors.push(...await cleanupProcessGroupProbeChild(child, targetPid, closed, fixture));
      return cleanupErrors;
    });
  });

  test.skipIf(process.platform === "win32")("uses the group fallback when the scan reports an additional member", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "connector-extra-group-member-"));
    const probe = createProcessGroupProbe(fixture);
    const child = await spawnWithProcessGroupProbe(probe, [
      "-e",
      "process.on('SIGTERM', () => process.stdout.write('TERM_RECEIVED\\\\n')); process.stdout.write('TARGET_READY\\\\n'); setInterval(() => {}, 1000)"
    ]);
    const closed = once(child, "close");
    const targetReady = waitForTargetReadiness(child);
    const messages = [];
    child.on("message", (message) => messages.push(message?.type));
    let targetPid;

    await finishTestWithCleanup("Additional-member supervision", async () => {
      targetPid = await waitForManagedTarget(child, { timeoutMs: 2_000 });
      expect(await targetReady).toContain("TARGET_READY");
      await writeProcessGroupProbe(probe, child.pid, [
        { pid: targetPid, pgid: child.pid },
        { pid: 2_147_483_646, pgid: child.pid }
      ], { livePids: [targetPid] });

      const termOutput = waitForOutput(child.stdout, "TERM_RECEIVED");
      signalManagedProcessTree(child, "SIGTERM");
      expect(await termOutput).toContain("TERM_RECEIVED");
      signalManagedProcessTree(child, "SIGKILL");
      await waitForChildClose(child, closed);

      expect(child.signalCode).toBe("SIGKILL");
      expect(messages).not.toContain("tree-complete");
      expect(getManagedProcessTreeStatus(child, process.platform)).toBe("unknown");
    }, async () => cleanupProcessGroupProbeChild(child, targetPid, closed, fixture));
  });

  test.skipIf(process.platform === "win32")("does not treat a mismatched target row as an owned group member", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "connector-mismatched-group-member-"));
    const probe = createProcessGroupProbe(fixture);
    const child = await spawnWithProcessGroupProbe(probe, [
      "-e",
      "let termCount = 0; process.on('SIGTERM', () => process.stdout.write('TERM_RECEIVED_' + (++termCount) + '\\\\n')); process.stdout.write('TARGET_READY\\\\n'); setInterval(() => {}, 1000)"
    ]);
    const closed = once(child, "close");
    const targetReady = waitForTargetReadiness(child);
    let targetPid;

    await finishTestWithCleanup("Mismatched-row supervision", async () => {
      targetPid = await waitForManagedTarget(child, { timeoutMs: 2_000 });
      expect(await targetReady).toContain("TARGET_READY");
      await writeProcessGroupProbe(probe, child.pid, [
        { pid: targetPid, pgid: child.pid + 1 }
      ], { livePids: [targetPid] });

      const firstTerm = waitForOutput(child.stdout, "TERM_RECEIVED_1");
      signalManagedProcessTree(child, "SIGTERM");
      expect(await firstTerm).toContain("TERM_RECEIVED_1");

      signalManagedProcessTree(child, "SIGKILL");
      const secondTerm = waitForOutput(child.stdout, "TERM_RECEIVED_2");
      signalManagedProcessTree(child, "SIGTERM");
      expect(await secondTerm).toContain("TERM_RECEIVED_2");

      expect(getSupervisedProcessTreeStatus(child)).toBe("active");
      expect(child.targetExited).toBe(false);
      const liveRows = readTestProcessRows(targetPid);
      expect(liveRows).toContainEqual(expect.objectContaining({ pid: targetPid, pgid: child.pid }));
    }, async () => cleanupProcessGroupProbeChild(child, targetPid, closed, fixture));
  });

  test.skipIf(process.platform === "win32")("keeps cleanup unknown when process-group observation is unavailable", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "connector-unobservable-group-"));
    const probe = createProcessGroupProbe(fixture);
    const child = await spawnWithProcessGroupProbe(probe, [
      "-e",
      "process.on('SIGTERM', () => process.stdout.write('TERM_RECEIVED\\\\n')); process.stdout.write('TARGET_READY\\\\n'); setInterval(() => {}, 1000)"
    ]);
    const closed = once(child, "close");
    const targetReady = waitForTargetReadiness(child);
    const messages = [];
    child.on("message", (message) => messages.push(message?.type));
    let targetPid;

    await finishTestWithCleanup("Unavailable-scan supervision", async () => {
      targetPid = await waitForManagedTarget(child, { timeoutMs: 2_000 });
      expect(await targetReady).toContain("TARGET_READY");
      await writeProcessGroupProbe(probe, child.pid, [], { status: 1 });

      const termOutput = waitForOutput(child.stdout, "TERM_RECEIVED");
      signalManagedProcessTree(child, "SIGTERM");
      expect(await termOutput).toContain("TERM_RECEIVED");
      signalManagedProcessTree(child, "SIGKILL");
      await waitForChildClose(child, closed);

      expect(child.signalCode).toBe("SIGKILL");
      expect(messages).not.toContain("tree-complete");
      expect(getManagedProcessTreeStatus(child, process.platform)).toBe("unknown");
    }, async () => cleanupProcessGroupProbeChild(child, targetPid, closed, fixture));
  });

  test.skipIf(process.platform === "win32")("keeps cleanup unknown when process-group observation is malformed", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "connector-malformed-group-observation-"));
    const probe = createProcessGroupProbe(fixture);
    const child = await spawnWithProcessGroupProbe(probe, [
      "-e",
      "process.on('SIGTERM', () => process.stdout.write('TERM_RECEIVED\\n')); process.stdout.write('TARGET_READY\\n'); setInterval(() => {}, 1000)"
    ]);
    const closed = once(child, "close");
    const targetReady = waitForTargetReadiness(child);
    const messages = [];
    child.on("message", (message) => messages.push(message?.type));
    let targetPid;

    await finishTestWithCleanup("Malformed-scan supervision", async () => {
      targetPid = await waitForManagedTarget(child, { timeoutMs: 2_000 });
      expect(await targetReady).toContain("TARGET_READY");
      await writeProcessGroupProbe(probe, child.pid, [], { stdout: "invalid process identity row\\n" });

      const termOutput = waitForOutput(child.stdout, "TERM_RECEIVED");
      signalManagedProcessTree(child, "SIGTERM");
      expect(await termOutput).toContain("TERM_RECEIVED");
      signalManagedProcessTree(child, "SIGKILL");
      await waitForChildClose(child, closed);

      expect(child.signalCode).toBe("SIGKILL");
      expect(messages).not.toContain("tree-complete");
      expect(getManagedProcessTreeStatus(child, process.platform)).toBe("unknown");
    }, async () => cleanupProcessGroupProbeChild(child, targetPid, closed, fixture));
  });

  test.skipIf(process.platform === "win32")("keeps cleanup unknown when process-group observation times out", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "connector-unobservable-timeout-"));
    const probe = createProcessGroupProbe(fixture);
    const child = await spawnWithProcessGroupProbe(probe, [
      "-e",
      "process.on('SIGTERM', () => process.stdout.write('TERM_RECEIVED\\\\n')); process.stdout.write('TARGET_READY\\\\n'); setInterval(() => {}, 1000)"
    ]);
    const closed = once(child, "close");
    const targetReady = waitForTargetReadiness(child);
    let targetPid;

    await finishTestWithCleanup("Timed-out scan supervision", async () => {
      targetPid = await waitForManagedTarget(child, { timeoutMs: 2_000 });
      expect(await targetReady).toContain("TARGET_READY");
      await writeProcessGroupProbe(probe, child.pid, [], { errorCode: "ETIMEDOUT" });

      const termOutput = waitForOutput(child.stdout, "TERM_RECEIVED");
      signalManagedProcessTree(child, "SIGTERM");
      expect(await termOutput).toContain("TERM_RECEIVED");

      signalManagedProcessTree(child, "SIGKILL");
      await waitForChildClose(child, closed);
      expect(child.signalCode).toBe("SIGKILL");
      expect(getManagedProcessTreeStatus(child, process.platform)).toBe("unknown");
    }, async () => cleanupProcessGroupProbeChild(child, targetPid, closed, fixture));
  });

  test.skipIf(process.platform === "win32")("keeps cleanup unknown when completion acknowledgment is withheld", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "connector-missing-completion-ack-"));
    const probe = createProcessGroupProbe(fixture);
    const child = await spawnWithProcessGroupProbe(probe, [
      "-e",
      "process.on('SIGTERM', () => { process.stdout.write('TERM_RECEIVED\\\\n'); process.exit(0); }); process.stdout.write('TARGET_READY\\\\n'); setInterval(() => {}, 1000)"
    ]);
    const closed = once(child, "close");
    const targetReady = waitForTargetReadiness(child);
    const messages = [];
    child.on("message", (message) => messages.push(message?.type));
    let acknowledgmentsWithheld = 0;
    const sendOriginal = child.send.bind(child);
    const send = vi.spyOn(child, "send").mockImplementation((message, ...args) => {
      if (message?.type === "tree-complete-ack") {
        acknowledgmentsWithheld += 1;
        return true;
      }
      return sendOriginal(message, ...args);
    });
    let targetPid;

    await finishTestWithCleanup("Missing-ack supervision", async () => {
      targetPid = await waitForManagedTarget(child, { timeoutMs: 2_000 });
      expect(await targetReady).toContain("TARGET_READY");
      await writeProcessGroupProbe(probe, child.pid, [{ pid: targetPid, pgid: child.pid }], { livePids: [targetPid] });

      const termOutput = waitForOutput(child.stdout, "TERM_RECEIVED");
      signalManagedProcessTree(child, "SIGTERM");
      expect(await termOutput).toContain("TERM_RECEIVED");
      await waitForChildClose(child, closed);

      expect(acknowledgmentsWithheld).toBe(1);
      expect(messages).toContain("tree-complete-candidate");
      expect(messages).not.toContain("tree-complete");
      expect(child.signalCode).toBe("SIGKILL");
      expect(getManagedProcessTreeStatus(child, process.platform)).toBe("unknown");
    }, async () => {
      send.mockRestore();
      return cleanupProcessGroupProbeChild(child, targetPid, closed, fixture);
    });
  });

  test.skipIf(process.platform === "win32")("keeps cleanup unknown when the supervisor exits before completion evidence", async () => {
    const child = spawnSupervisedProcess(process.execPath, [
      "-e",
      "process.stdout.write('TARGET_READY\\\\n'); setInterval(() => {}, 1000)"
    ]);
    const closed = once(child, "close");
    const targetReady = waitForTargetReadiness(child);
    const targetStarted = waitForManagedTarget(child, { timeoutMs: 2_000 });
    const messages = [];
    child.on("message", (message) => messages.push(message?.type));
    let targetPid;

    await finishTestWithCleanup("Supervisor-exit supervision", async () => {
      const startupAbort = new globalThis.AbortController();
      const targetWait = waitForManagedTarget(child, { signal: startupAbort.signal, timeoutMs: 2_000 });
      startupAbort.abort(new Error("Synthetic startup waiter cancellation."));
      await expect(targetWait).rejects.toThrow("Synthetic startup waiter cancellation.");
      targetPid = await targetStarted;
      expect(await targetReady).toContain("TARGET_READY");
      expect(targetPid).toBeGreaterThan(0);

      if (!child.kill("SIGKILL")) throw new Error("Direct supervisor signal was not accepted.");
      await waitForChildClose(child, closed);

      expect(getManagedProcessTreeStatus(child, process.platform)).toBe("unknown");
      expect(messages).not.toContain("tree-complete-candidate");
      expect(messages).not.toContain("tree-complete");
    }, async () => cleanupProcessGroupProbeChild(child, targetPid, closed));
  });

  test("does not signal a reused target PID outside its managed process group", () => {
    const child = { pid: 820_001, targetPid: 820_011 };
    const rows = [{ pid: 820_011, ppid: 1, pgid: 820_020, state: "S" }];
    const signalCalls = [];

    expect(() => signalTestTargetIfOwned(child, child.targetPid, rows, (pid, signal) => signalCalls.push([pid, signal])))
      .toThrow(/no longer belongs to its managed process group/i);
    expect(signalCalls).toEqual([]);
  });

  test("signals only the current target in its managed process group", () => {
    const child = { pid: 830_001, targetPid: 830_011 };
    const rows = [
      { pid: child.pid, ppid: 1, pgid: child.pid, state: "S" },
      { pid: child.targetPid, ppid: child.pid, pgid: child.pid, state: "S" }
    ];
    const signalCalls = [];

    expect(signalTestTargetIfOwned(child, child.targetPid, rows, (pid, signal) => signalCalls.push([pid, signal]))).toBe(true);
    expect(signalCalls).toEqual([[child.targetPid, "SIGKILL"]]);
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
