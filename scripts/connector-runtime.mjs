import process from "node:process";
import { spawn } from "node:child_process";
import { getSupervisedProcessTreeStatus } from "./secure-process-supervisor.mjs";

const processTreeTerminationEvidence = new WeakMap();
const TASKKILL_TIMEOUT_MS = 1_000;

export function createConnectorRuntime(options = {}) {
  const output = options.output ?? process.stdout;
  const reportError = options.reportError ?? ((message) => globalThis.console.error(message));
  const exit = options.exit ?? ((code) => process.exit(code));
  const schedule = options.schedule ?? ((callback, delay) => globalThis.setTimeout(callback, delay));
  const signalChild = options.signalChild ?? ((child, signal) => child.kill(signal));
  const signalExitedChildren = options.signalExitedChildren ?? false;
  const failOnUnexpectedCleanExit = options.failOnUnexpectedCleanExit ?? false;
  const isProcessTreeAlive = options.isProcessTreeAlive ?? (() => false);
  const cancelSchedule = options.cancelSchedule ?? ((timer) => globalThis.clearTimeout(timer));
  const onShutdown = options.onShutdown ?? (() => undefined);
  const processTreeCleanup = options.processTreeCleanup ?? false;
  const processTreeCleanupTimeoutMs = options.processTreeCleanupTimeoutMs ?? 2_000;
  const children = new Set();
  let shuttingDown = false;
  let cleanupFinished = false;
  let shutdownWorkPending = false;
  let shutdownCode;
  let killTimer;
  let exitTimer;
  let cleanupDeadlineTimer;

  function track(child, label, trackOptions = {}) {
    const expectedExit = trackOptions.expectedExit ?? false;
    const state = {
      child,
      label,
      exited: child.exitCode !== null && child.exitCode !== undefined || child.signalCode !== null && child.signalCode !== undefined
    };
    children.add(state);
    prefixOutput(child.stdout, label, output, trackOptions.onLine);
    prefixOutput(child.stderr, label, output, trackOptions.onLine);
    child.once("exit", (code, signal) => {
      state.exited = true;
      if (shuttingDown) {
        checkForCompletion();
        return;
      }
      if (expectedExit) return;
      reportError(`[${label}] exited (code=${code ?? "null"}, signal=${signal ?? "null"}). Stopping other process.`);
      terminateAndExit(failOnUnexpectedCleanExit && code === 0 ? 1 : code ?? 1);
    });
    child.once("managedTargetExit", (code, signal) => {
      if (shuttingDown || expectedExit) return;
      reportError(`[${label}] exited (code=${code ?? "null"}, signal=${signal ?? "null"}). Stopping other process.`);
      terminateAndExit(failOnUnexpectedCleanExit && code === 0 ? 1 : code ?? 1);
    });
    child.once("error", (error) => {
      if (shuttingDown || expectedExit) {
        return;
      }
      reportError(`[${label}] failed to start: ${error.message}`);
      terminateAndExit(1);
    });
    child.once("close", () => {
      state.exited = true;
      retireStoppedChild(state);
      checkForCompletion();
    });
    return child;
  }

  function terminateAndExit(code) {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    shutdownCode = code;
    let shutdownWork;
    try {
      shutdownWork = onShutdown();
    } catch (error) {
      reportShutdownWorkFailure(error);
    }
    if (shutdownWork && typeof shutdownWork.then === "function") {
      shutdownWorkPending = true;
      Promise.resolve(shutdownWork).then(
        () => finishShutdownWork(),
        (error) => {
          reportShutdownWorkFailure(error);
          finishShutdownWork();
        }
      );
    }
    signalChildren("SIGTERM");
    killTimer = schedule(() => {
      killTimer = undefined;
      if (cleanupFinished) return;
      signalChildren("SIGKILL");
      if (!processTreeCleanup) return;
      checkForCompletion();
      if (!cleanupFinished) {
        cleanupDeadlineTimer = schedule(() => {
          cleanupDeadlineTimer = undefined;
          if (!shutdownWorkPending && allManagedProcessesStopped()) {
            finish(shutdownCode);
            return;
          }
          const remaining = [...children]
            .filter((state) => !state.exited || processTreeIsAlive(state.child))
            .map((state) => `${state.label} (pid ${state.child.pid ?? "unknown"})`);
          if (shutdownWorkPending) remaining.push("startup helper cleanup (pending)");
          reportError(`Secure startup shutdown incomplete: process-tree completion could not be verified after SIGKILL: ${remaining.join(", ")}.`);
          finish(Math.max(1, shutdownCode), true);
        }, processTreeCleanupTimeoutMs);
      }
    }, 1500);
    if (processTreeCleanup) {
      checkForCompletion();
    } else {
      exitTimer = schedule(() => finish(shutdownCode), 1700);
    }
  }

  function shutdown(signal, message) {
    if (shuttingDown) {
      return;
    }
    output.write(`Received ${signal}. ${message}\n`);
    terminateAndExit(0);
  }

  function signalChildren(signal) {
    for (const state of children) {
      if (!state.exited) {
        signalChild(state.child, signal);
      } else if (signalExitedChildren) {
        if (!processTreeIsAlive(state.child)) {
          children.delete(state);
        } else {
          signalChild(state.child, signal);
        }
      }
    }
  }

  function retireStoppedChild(state) {
    if (processTreeCleanup && state.exited && !processTreeIsAlive(state.child)) {
      children.delete(state);
    }
  }

  function processTreeIsAlive(child) {
    try {
      return isProcessTreeAlive(child);
    } catch {
      return true;
    }
  }

  function checkForCompletion() {
    if (!processTreeCleanup || !shuttingDown || cleanupFinished || shutdownWorkPending) return;
    if (!allManagedProcessesStopped()) return;
    finish(shutdownCode);
  }

  function finishShutdownWork() {
    shutdownWorkPending = false;
    if (processTreeCleanup) checkForCompletion();
  }

  function reportShutdownWorkFailure(error) {
    shutdownCode = Math.max(1, shutdownCode ?? 0);
    const message = error instanceof Error ? error.message : "unknown shutdown cleanup error";
    reportError(`Secure startup cleanup failed: ${message}`);
  }

  function allManagedProcessesStopped() {
    for (const state of children) {
      if (!state.exited) return false;
      if (processTreeIsAlive(state.child)) return false;
      children.delete(state);
    }
    return true;
  }

  function finish(code, allowPendingShutdownWork = false) {
    if (cleanupFinished) return;
    if (processTreeCleanup && shutdownWorkPending && !allowPendingShutdownWork) return;
    cleanupFinished = true;
    if (killTimer !== undefined) cancelSchedule(killTimer);
    if (exitTimer !== undefined) cancelSchedule(exitTimer);
    if (cleanupDeadlineTimer !== undefined) cancelSchedule(cleanupDeadlineTimer);
    exit(code);
  }

  return {
    shutdown,
    terminateAndExit,
    track
  };
}

/** Signal a managed process through its current owner; POSIX secure launches use the live group supervisor. */
export function signalManagedProcessTree(child, signal, platform = process.platform, spawnImpl = spawn) {
  if (!Number.isInteger(child.pid) || child.pid <= 0) {
    child.kill(signal);
    return;
  }
  const supervisedStatus = getSupervisedProcessTreeStatus(child);
  if (supervisedStatus !== undefined) {
    if (supervisedStatus !== "active" || !child.connected) return;
    try {
      child.send({ type: "signal", signal }, () => undefined);
    } catch {
      // The supervisor owns the process group and will report missing completion evidence.
    }
    return;
  }
  if (platform === "win32") {
    if (getManagedProcessTreeStatus(child, platform) !== "active") return;
    const args = ["/PID", String(child.pid), "/T"];
    if (signal === "SIGKILL") args.push("/F");
    processTreeTerminationEvidence.delete(child);
    let taskkill;
    try {
      taskkill = spawnImpl("taskkill.exe", args, { stdio: "ignore", windowsHide: true });
    } catch {
      child.kill(signal);
      return;
    }
    let settled = false;
    const timeout = globalThis.setTimeout(() => {
      if (settled) return;
      settled = true;
      taskkill.kill("SIGKILL");
      processTreeTerminationEvidence.delete(child);
      child.kill(signal);
    }, TASKKILL_TIMEOUT_MS);
    taskkill.once("error", () => {
      if (settled) return;
      settled = true;
      globalThis.clearTimeout(timeout);
      processTreeTerminationEvidence.delete(child);
      child.kill(signal);
    });
    taskkill.once("close", (code) => {
      if (settled) return;
      settled = true;
      globalThis.clearTimeout(timeout);
      if (signal === "SIGKILL" && code === 0) {
        processTreeTerminationEvidence.set(child, "taskkill-success");
      } else if (code !== 0) {
        processTreeTerminationEvidence.delete(child);
        child.kill(signal);
      }
    });
    return taskkill;
  }
  const exited = child.exitCode !== null && child.exitCode !== undefined
    || child.signalCode !== null && child.signalCode !== undefined;
  if (!exited) child.kill(signal);
}

/** Report whether a dedicated process group still contains a managed process. */
export function isManagedProcessTreeAlive(child, platform = process.platform) {
  return getManagedProcessTreeStatus(child, platform) !== "verified-complete";
}

/** Reports whether a managed tree is active, verified complete, or unknown. */
export function getManagedProcessTreeStatus(child, platform = process.platform) {
  if (!child) return "unknown";
  const supervisedStatus = getSupervisedProcessTreeStatus(child);
  if (supervisedStatus !== undefined) return supervisedStatus;
  const exited = child.exitCode !== null && child.exitCode !== undefined
    || child.signalCode !== null && child.signalCode !== undefined;
  if (platform === "win32") {
    if (!Number.isInteger(child.pid) || child.pid <= 0) return "unknown";
    if (!exited) return "active";
    return processTreeTerminationEvidence.get(child) === "taskkill-success" ? "verified-complete" : "unknown";
  }
  if (!exited) return "active";
  return "unknown";
}

function prefixOutput(stream, label, output, onLine) {
  if (!stream) {
    return;
  }
  let buffer = "";
  const writeLine = (line) => {
    onLine?.(line);
    output.write(`[${label}] ${line}\n`);
  };
  stream.on("data", (chunk) => {
    buffer += chunk.toString();
    const lines = buffer.split(/\r?\n/);
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      writeLine(line);
    }
  });
  stream.on("end", () => {
    if (buffer.length > 0) {
      writeLine(buffer);
    }
  });
}
