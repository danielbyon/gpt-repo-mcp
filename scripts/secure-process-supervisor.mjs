import { fork, spawn, spawnSync } from "node:child_process";
import { constants as osConstants } from "node:os";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";

const supervisorPath = fileURLToPath(import.meta.url);
const supervisedProcesses = new WeakMap();
const GROUP_SCAN_TIMEOUT_MS = 150;
const GROUP_CLEANUP_TIMEOUT_MS = 900;
const GROUP_QUIET_INTERVAL_MS = 25;
const COMPLETION_ACK_TIMEOUT_MS = 1_000;
const OWNER_DISCONNECT_ESCALATION_MS = 250;

/** Runs a command in a POSIX process group and keeps its group ID owned until completion is acknowledged. */
export function spawnSupervisedProcess(command, args, options = {}) {
  const child = fork(supervisorPath, ["--run-supervisor"], {
    detached: true,
    execArgv: [],
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    windowsHide: true
  });
  const state = {
    status: "active",
    targetPid: undefined,
    targetExited: false,
    targetExitCode: undefined,
    targetSignal: undefined,
    targetError: undefined
  };
  supervisedProcesses.set(child, state);
  child.targetPid = undefined;
  child.targetExited = false;
  child.targetExitCode = undefined;
  child.targetSignal = undefined;
  child.targetError = undefined;

  child.on("message", (message) => {
    if (!message || typeof message !== "object") return;
    if (message.type === "target-started" && Number.isInteger(message.pid) && message.pid > 0) {
      state.targetPid = message.pid;
      child.targetPid = message.pid;
      child.emit("managedTargetStarted", message.pid);
    } else if (message.type === "target-exited") {
      state.targetExited = true;
      state.targetExitCode = message.code;
      state.targetSignal = message.signal;
      child.targetExited = true;
      child.targetExitCode = message.code;
      child.targetSignal = message.signal;
      child.emit("managedTargetExit", message.code, message.signal);
    } else if (message.type === "target-error") {
      state.targetError = typeof message.message === "string" ? message.message : "Target process failed to start.";
      child.targetError = state.targetError;
      child.emit("managedTargetStartError", new Error(state.targetError));
    } else if (message.type === "tree-complete-candidate") {
      child.send({ type: "tree-complete-ack" }, () => undefined);
    } else if (message.type === "tree-complete") {
      state.status = "verified-complete";
    }
  });
  child.once("exit", () => {
    if (state.status !== "verified-complete") state.status = "unknown";
  });

  const targetOptions = {
    ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
    ...(options.env === undefined ? {} : { env: options.env }),
    ...(options.windowsHide === undefined ? {} : { windowsHide: options.windowsHide }),
    ...(options.shell === undefined ? {} : { shell: options.shell }),
    ...(options.uid === undefined ? {} : { uid: options.uid }),
    ...(options.gid === undefined ? {} : { gid: options.gid }),
    ...(options.argv0 === undefined ? {} : { argv0: options.argv0 })
  };
  child.send({ type: "launch", command, args, options: targetOptions }, (error) => {
    if (error && state.status === "active") {
      state.status = "unknown";
    }
  });
  return child;
}

export function spawnManagedProcess(command, args, options = {}) {
  if (process.platform === "win32") {
    return spawn(command, args, { ...options, detached: false, stdio: ["ignore", "pipe", "pipe"] });
  }
  return spawnSupervisedProcess(command, args, options);
}

export function getSupervisedProcessTreeStatus(child) {
  return supervisedProcesses.get(child)?.status;
}

export function waitForManagedTarget(child, options = {}) {
  const state = supervisedProcesses.get(child);
  if (!state) {
    if (Number.isInteger(child?.pid) && child.pid > 0) return Promise.resolve(child.pid);
    return waitForChildSpawn(child, options);
  }
  if (state.targetPid) return Promise.resolve(state.targetPid);
  if (state.targetError) return Promise.reject(new Error(state.targetError));
  return new Promise((resolve, reject) => {
    let timer;
    let settled = false;
    const cleanup = () => {
      child.off("managedTargetStarted", onStarted);
      child.off("managedTargetStartError", onStartError);
      child.off("error", onError);
      child.off("exit", onExit);
      options.signal?.removeEventListener("abort", onAbort);
      if (timer !== undefined) globalThis.clearTimeout(timer);
    };
    const finish = (error, pid) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve(pid);
    };
    const onStarted = (pid) => finish(undefined, pid);
    const onStartError = (error) => finish(error);
    const onError = (error) => finish(error);
    const onExit = () => finish(new Error("Managed process exited before its target started."));
    const onAbort = () => finish(options.signal.reason instanceof Error
      ? options.signal.reason
      : new Error("Managed process startup was cancelled."));

    child.once("managedTargetStarted", onStarted);
    child.once("managedTargetStartError", onStartError);
    child.once("error", onError);
    child.once("exit", onExit);
    options.signal?.addEventListener("abort", onAbort, { once: true });
    if (Number.isFinite(options.timeoutMs) && options.timeoutMs > 0) {
      timer = globalThis.setTimeout(() => finish(new Error("Managed process target startup timed out.")), options.timeoutMs);
    }
    if (options.signal?.aborted) {
      onAbort();
      return;
    }
    if (state.targetPid) onStarted(state.targetPid);
    else if (state.targetError) onStartError(new Error(state.targetError));
    else if (child.exitCode !== null && child.exitCode !== undefined || child.signalCode) onExit();
  });
}

function waitForChildSpawn(child, options) {
  return new Promise((resolve, reject) => {
    let timer;
    const cleanup = () => {
      child.off("spawn", onSpawn);
      child.off("error", onError);
      child.off("exit", onExit);
      options.signal?.removeEventListener("abort", onAbort);
      if (timer !== undefined) globalThis.clearTimeout(timer);
    };
    const finish = (error, pid) => {
      cleanup();
      if (error) reject(error);
      else resolve(pid);
    };
    const onSpawn = () => finish(undefined, child.pid);
    const onError = (error) => finish(error);
    const onExit = () => finish(new Error("Managed process exited before it started."));
    const onAbort = () => finish(options.signal.reason instanceof Error
      ? options.signal.reason
      : new Error("Managed process startup was cancelled."));
    child.once("spawn", onSpawn);
    child.once("error", onError);
    child.once("exit", onExit);
    options.signal?.addEventListener("abort", onAbort, { once: true });
    if (Number.isFinite(options.timeoutMs) && options.timeoutMs > 0) {
      timer = globalThis.setTimeout(() => finish(new Error("Managed process startup timed out.")), options.timeoutMs);
    }
    if (options.signal?.aborted) {
      onAbort();
      return;
    }
    if (Number.isInteger(child.pid) && child.pid > 0) onSpawn();
  });
}

async function runSupervisor() {
  let target;
  let targetExit;
  let targetClosed = false;
  let terminationRequested = false;
  let finalizing = false;
  let completionAck;

  process.on("SIGTERM", () => { terminationRequested = true; });
  process.on("SIGINT", () => { terminationRequested = true; });
  process.on("disconnect", () => {
    terminationRequested = true;
    if (finalizing) return;
    try {
      process.kill(-process.pid, "SIGTERM");
    } catch {
      // A disconnected owner cannot receive a cleanup result.
    }
    globalThis.setTimeout(() => {
      try {
        process.kill(-process.pid, "SIGKILL");
      } catch {
        process.exitCode = 1;
      }
    }, OWNER_DISCONNECT_ESCALATION_MS);
  });
  process.on("message", (message) => {
    if (!message || typeof message !== "object") return;
    if (message.type === "tree-complete-ack") {
      completionAck?.();
      return;
    }
    if (message.type === "signal" && (message.signal === "SIGTERM" || message.signal === "SIGINT" || message.signal === "SIGKILL")) {
      if (message.signal === "SIGKILL" && stopDirectTargetIfExclusive()) return;
      try {
        process.kill(-process.pid, message.signal);
      } catch {
        // The supervisor owns this process group while it is alive.
      }
      return;
    }
    if (message.type === "launch" && !target) {
      if (terminationRequested) {
        targetClosed = true;
        void finishTarget(1, null);
        return;
      }
      launchTarget(message);
    }
  });

  function stopDirectTargetIfExclusive() {
    try {
      const members = scanOwnedProcessGroup();
      if (members.length === 0) return true;
      if (target && Number.isInteger(target.pid) && members.length === 1 && members[0].pid === target.pid) {
        target.kill("SIGKILL");
        return true;
      }
    } catch {
      return false;
    }
    return false;
  }

  function launchTarget(message) {
    if (typeof message.command !== "string" || !Array.isArray(message.args)) {
      targetClosed = true;
      void finishTarget(127, null);
      return;
    }
    try {
      target = spawn(message.command, message.args, {
        ...message.options,
        detached: false,
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (error) {
      notify({ type: "target-error", message: error instanceof Error ? error.message : "Target process failed to start." });
      targetClosed = true;
      void finishTarget(127, null);
      return;
    }
    target.stdout?.pipe(process.stdout, { end: false });
    target.stderr?.pipe(process.stderr, { end: false });
    target.once("spawn", () => notify({ type: "target-started", pid: target.pid }));
    target.once("error", (error) => {
      notify({ type: "target-error", message: error instanceof Error ? error.message : "Target process failed to start." });
      void finishTarget(127, null);
    });
    target.once("exit", (code, signal) => {
      targetExit = { code, signal };
      notify({ type: "target-exited", ...targetExit });
      void finishTarget(code, signal);
    });
    target.once("close", () => {
      targetClosed = true;
      if (!finalizing && !targetExit) void finishTarget(127, null);
    });
  }

  async function finishTarget(code, signal) {
    if (finalizing) return;
    finalizing = true;
    const deadline = performance.now() + GROUP_CLEANUP_TIMEOUT_MS;
    let termSent = false;
    let quietScans = 0;

    while (performance.now() < deadline) {
      let members;
      try {
        members = scanOwnedProcessGroup();
      } catch {
        members = undefined;
      }
      if (members?.length === 0 && targetClosed) {
        quietScans += 1;
        if (quietScans >= 2) {
          await reportCompletion(code, signal);
          return;
        }
      } else {
        quietScans = 0;
        if (!termSent) {
          termSent = true;
          try {
            process.kill(-process.pid, "SIGTERM");
          } catch {
            // Keep checking until the bounded cleanup deadline.
          }
        }
      }
      await delay(GROUP_QUIET_INTERVAL_MS);
    }

    notify({ type: "tree-cleanup-incomplete" });
    try {
      process.kill(-process.pid, "SIGKILL");
    } catch {
      process.exitCode = 1;
      process.disconnect();
    }
  }

  async function reportCompletion(code, signal) {
    notify({ type: "tree-complete-candidate" });
    const acknowledged = await new Promise((resolve) => {
      let settled = false;
      const timer = globalThis.setTimeout(() => finish(false), COMPLETION_ACK_TIMEOUT_MS);
      completionAck = () => finish(true);
      function finish(value) {
        if (settled) return;
        settled = true;
        globalThis.clearTimeout(timer);
        completionAck = undefined;
        resolve(value);
      }
    });
    if (!acknowledged) {
      try {
        process.kill(-process.pid, "SIGKILL");
      } catch {
        process.exitCode = 1;
        process.disconnect();
      }
      return;
    }
    notify({ type: "tree-complete" }, (error) => {
      if (error) {
        process.exitCode = 1;
        process.disconnect();
        return;
      }
      process.exitCode = exitCodeForTarget(code, signal);
      process.disconnect();
    });
  }

  function notify(message, callback) {
    if (!process.connected || typeof process.send !== "function") {
      callback?.(new Error("Supervisor IPC channel is closed."));
      return;
    }
    process.send(message, callback ?? (() => undefined));
  }
}

function scanOwnedProcessGroup() {
  const result = spawnSync("ps", ["-A", "-o", "pid=", "-o", "pgid="], {
    encoding: "utf8",
    timeout: GROUP_SCAN_TIMEOUT_MS,
    windowsHide: true,
    env: { ...process.env, LC_ALL: "C" }
  });
  if (result.error || result.status !== 0 || result.signal || typeof result.stdout !== "string") {
    throw new Error("Unable to inspect the managed process group.");
  }
  const rows = result.stdout.split(/\r?\n/).filter((line) => line.trim() !== "").map((line) => {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s*$/);
    if (!match) throw new Error("Process-group probe returned an invalid row.");
    return { pid: Number(match[1]), pgid: Number(match[2]) };
  });
  if (!rows.some((row) => row.pid === process.pid && row.pgid === process.pid)) {
    throw new Error("Process-group probe could not verify its owner.");
  }
  return rows.filter((row) => row.pgid === process.pid && row.pid !== process.pid && row.pid !== result.pid);
}

function exitCodeForTarget(code, signal) {
  if (Number.isInteger(code)) return code;
  if (!signal) return 1;
  const signalNumber = osConstants.signals[signal];
  return Number.isInteger(signalNumber) ? 128 + signalNumber : 1;
}

function delay(milliseconds) {
  return new Promise((resolve) => globalThis.setTimeout(resolve, milliseconds));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1] && process.argv[2] === "--run-supervisor") {
  void runSupervisor();
}
