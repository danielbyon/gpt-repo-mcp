import { spawn, type ChildProcess } from "node:child_process";
import type { Readable } from "node:stream";
import { runWindowsProcessWithTail } from "./windows-process-host.js";

const TERMINATION_GRACE_MS = 250;
const FORCE_SETTLE_GRACE_MS = 1_000;
const PROCESS_GROUP_POLL_MS = 20;

const POSIX_GROUP_LAUNCHER = String.raw`
const { spawn } = require("node:child_process");
const { createWriteStream } = require("node:fs");
const reportStream = createWriteStream(null, { fd: 3, autoClose: false });
const report = (value) => reportStream.write(JSON.stringify(value) + "\n");
let controlBuffer = "";
let stopping = false;
let started = false;
let commandResult;
let keepAlive;

function holdGroup() {
  if (stopping) return;
  stopping = true;
  keepAlive = setInterval(() => {}, 1_000);
  report({ type: "stopping" });
}

function startCommand() {
  if (stopping) {
    report({ type: "not_started" });
    if (keepAlive) clearInterval(keepAlive);
    process.stdin.destroy();
    process.exitCode = 125;
    return;
  }
  started = true;
  const command = spawn(process.argv[1], process.argv.slice(2), {
    cwd: process.cwd(),
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true
  });
  command.stdout?.pipe(process.stdout, { end: false });
  command.stderr?.pipe(process.stderr, { end: false });
  command.once("error", (error) => process.stderr.write(String(error.message) + "\n"));
  command.once("close", (code, signal) => {
    commandResult = {
      type: "completed",
      exit_code: typeof code === "number" ? code : undefined,
      signal: signal || undefined
    };
    report(commandResult);
  });
}

process.on("SIGTERM", holdGroup);
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  controlBuffer += chunk;
  const lines = controlBuffer.split("\n");
  controlBuffer = lines.pop() || "";
  for (const line of lines) {
    if (line === "start" && !started) startCommand();
    else if (line === "cancel" && !started) {
      report({ type: "not_started" });
      process.stdin.destroy();
      process.exitCode = 125;
    } else if (line === "release" && commandResult && !stopping) {
      process.stdin.destroy();
      process.exitCode = commandResult.exit_code ?? 1;
    }
  }
});
report({ type: "ready" });
`;

type ProcessTailOptions = {
  timeout_ms: number;
  tail_bytes: number;
  signal?: AbortSignal;
};

type PipedChildProcess = ChildProcess & {
  stdout: NonNullable<ChildProcess["stdout"]>;
  stderr: NonNullable<ChildProcess["stderr"]>;
};

type GroupAnchorMessage = {
  type?: unknown;
  exit_code?: unknown;
  signal?: unknown;
};

type StopReason = "timeout" | "cancelled";
type SignalAttempt = "sent" | "gone" | "failed";

export type ProcessTailResult = {
  exit_code?: number;
  signal?: string;
  timed_out: boolean;
  cancelled: boolean;
  /** True when no command started or the managed process group/job is confirmed empty. */
  cleanup_confirmed?: boolean;
  duration_ms: number;
  stdout_tail: string;
  stderr_tail: string;
};

export async function runProcessWithTail(input: {
  executable: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
} & ProcessTailOptions): Promise<ProcessTailResult> {
  input.signal?.throwIfAborted();
  if (process.platform === "win32") return runWindowsProcessWithTail(input);

  const started = Date.now();
  const anchored = true;
  const child = spawn(
    anchored ? process.execPath : input.executable,
    anchored ? ["-e", POSIX_GROUP_LAUNCHER, input.executable, ...input.args] : input.args,
    {
      cwd: input.cwd,
      env: input.env,
      stdio: anchored ? ["pipe", "pipe", "pipe", "pipe"] : ["ignore", "pipe", "pipe"],
      detached: anchored
    }
  ) as PipedChildProcess;
  return superviseSpawnedProcessWithTail(child, {
    timeout_ms: input.timeout_ms,
    tail_bytes: input.tail_bytes,
    signal: input.signal,
    started_at_ms: started,
    anchored
  });
}

/**
 * Supervises the command, retaining its output tail and bounding shutdown time.
 * POSIX commands run below a small group anchor, and their output flows through
 * captured pipes. A descendant that inherits those pipes keeps command completion
 * pending. The anchor stays alive until the supervisor accepts completion or
 * finishes escalation, so a later signal cannot target a reused group ID.
 */
async function superviseSpawnedProcessWithTail(
  child: PipedChildProcess,
  input: ProcessTailOptions & { started_at_ms?: number; anchored: boolean }
): Promise<ProcessTailResult> {
  const started = input.started_at_ms ?? Date.now();
  return new Promise((resolve) => {
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    const append = (current: Buffer, chunk: Buffer) => {
      const combined = Buffer.concat([current, chunk]);
      return combined.length > input.tail_bytes ? combined.subarray(combined.length - input.tail_bytes) : combined;
    };
    child.stdout.on("data", (chunk: Buffer) => { stdout = append(stdout, chunk); });
    child.stderr.on("data", (chunk: Buffer) => { stderr = append(stderr, chunk); });

    let timedOut = false;
    let cancelled = false;
    let stopRequested = false;
    let settled = false;
    let anchorReady = false;
    let commandStartSent = false;
    let commandCompleted: { exit_code?: number; signal?: string } | undefined;
    let completionCleanup = false;
    let noTaskStarted = false;
    let childClosed = false;
    let closedResult: { exit_code?: number; signal?: string } = {};
    let forced = false;
    let controlBuffer = "";
    let forceTimer: NodeJS.Timeout | undefined;
    let preReadyTimer: NodeJS.Timeout | undefined;
    let forceSettleTimer: NodeJS.Timeout | undefined;
    let groupPollTimer: NodeJS.Timeout | undefined;
    let forceDeadline = 0;

    const controlStream = input.anchored ? child.stdio[3] as Readable | null : null;

    const clearTimers = (): void => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (forceTimer) clearTimeout(forceTimer);
      if (preReadyTimer) clearTimeout(preReadyTimer);
      if (forceSettleTimer) clearTimeout(forceSettleTimer);
      if (groupPollTimer) clearTimeout(groupPollTimer);
    };

    const finish = (result: {
      exit_code?: number;
      signal?: string;
      timed_out?: boolean;
      cancelled?: boolean;
      cleanup_confirmed?: boolean;
      stderrSuffix?: string;
    }): void => {
      if (settled) return;
      settled = true;
      clearTimers();
      input.signal?.removeEventListener("abort", abortHandler);
      controlStream?.destroy();
      child.stdin?.destroy();
      const stderrText = result.stderrSuffix
        ? append(stderr, Buffer.from(`\n${result.stderrSuffix}`, "utf8")).toString("utf8").trim()
        : stderr.toString("utf8");
      const output: ProcessTailResult = {
        ...(typeof result.exit_code === "number" ? { exit_code: result.exit_code } : {}),
        ...(result.signal ? { signal: result.signal } : {}),
        timed_out: result.timed_out ?? timedOut,
        cancelled: result.cancelled ?? cancelled,
        ...(result.cleanup_confirmed !== undefined ? { cleanup_confirmed: result.cleanup_confirmed } : {}),
        duration_ms: Date.now() - started,
        stdout_tail: stdout.toString("utf8"),
        stderr_tail: stderrText
      };
      resolve(output);
    };

    const finishStopped = (confirmed: boolean): void => {
      finish({
        ...closedResult,
        ...(forced && !completionCleanup ? { signal: "SIGKILL" } : {}),
        timed_out: timedOut,
        cancelled,
        cleanup_confirmed: input.anchored ? confirmed : false
      });
    };

    const scheduleGroupVerification = (): void => {
      forceDeadline = Date.now() + FORCE_SETTLE_GRACE_MS;
      const verify = (): void => {
        if (settled) return;
        if (childClosed) {
          const groupState = input.anchored && child.pid ? processGroupExists(child.pid) : undefined;
          if (groupState === false) {
            finishStopped(true);
            return;
          }
          if (Date.now() >= forceDeadline) {
            finishStopped(false);
            return;
          }
        } else if (Date.now() >= forceDeadline) {
          child.stdout.destroy();
          child.stderr.destroy();
          child.stdin?.destroy();
          child.unref();
          finishStopped(false);
          return;
        }
        groupPollTimer = setTimeout(verify, PROCESS_GROUP_POLL_MS);
      };
      verify();
    };

    const sendControl = (message: "start" | "cancel" | "release"): boolean => {
      if (!input.anchored || !child.stdin || child.stdin.destroyed) return false;
      try {
        child.stdin.write(`${message}\n`);
        return true;
      } catch {
        return false;
      }
    };

    const scheduleNoStartCleanup = (): void => {
      if (forceSettleTimer) clearTimeout(forceSettleTimer);
      forceSettleTimer = setTimeout(() => {
        if (settled) return;
        if (childClosed) {
          finishStopped(true);
          return;
        }
        child.kill("SIGKILL");
        forceSettleTimer = setTimeout(() => {
          if (!childClosed) {
            child.stdout.destroy();
            child.stderr.destroy();
            child.stdin?.destroy();
            child.unref();
          }
          finishStopped(childClosed);
        }, FORCE_SETTLE_GRACE_MS);
      }, TERMINATION_GRACE_MS);
    };

    const beginTermination = (): void => {
      if (input.anchored && (!child.pid || child.exitCode !== null || child.signalCode !== null || childClosed)) {
        if (childClosed) {
          finishStopped(false);
        } else {
          forceSettleTimer = setTimeout(() => {
            child.stdout.destroy();
            child.stderr.destroy();
            child.stdin?.destroy();
            child.unref();
            finishStopped(false);
          }, FORCE_SETTLE_GRACE_MS);
        }
        return;
      }
      terminateProcessTree(child, "SIGTERM");
      forceTimer = setTimeout(() => {
        if (settled) return;
        if (childClosed) {
          finishStopped(false);
          return;
        }

        // A live unreaped group anchor pins its PID as the process-group identity.
        // If that ownership evidence is gone, do not signal the numeric group ID.
        if (input.anchored && (!child.pid || child.exitCode !== null || child.signalCode !== null)) {
          finishStopped(false);
          return;
        }
        forced = true;
        const attempt = terminateProcessTree(child, "SIGKILL");
        if (input.anchored && attempt === "failed") {
          child.kill("SIGKILL");
          scheduleGroupVerification();
          return;
        }
        scheduleGroupVerification();
      }, TERMINATION_GRACE_MS);
    };

    const stop = (reason: StopReason): void => {
      if (settled || stopRequested) return;
      stopRequested = true;
      timedOut = reason === "timeout";
      cancelled = reason === "cancelled";
      if (timeoutTimer) clearTimeout(timeoutTimer);
      input.signal?.removeEventListener("abort", abortHandler);

      if (!input.anchored) {
        beginTermination();
        return;
      }
      if (!anchorReady) {
        preReadyTimer = setTimeout(() => {
          if (settled || anchorReady) return;
          noTaskStarted = true;
          child.kill("SIGKILL");
          forceSettleTimer = setTimeout(() => {
            if (childClosed) finishStopped(true);
            else {
              child.stdout.destroy();
              child.stderr.destroy();
              child.stdin?.destroy();
              child.unref();
              finishStopped(false);
            }
          }, FORCE_SETTLE_GRACE_MS);
        }, TERMINATION_GRACE_MS);
        return;
      }
      if (!commandStartSent) {
        noTaskStarted = true;
        sendControl("cancel");
        scheduleNoStartCleanup();
        return;
      }
      beginTermination();
    };

    const abortHandler = (): void => stop("cancelled");

    const acceptControlMessage = (message: GroupAnchorMessage): void => {
      if (message.type === "ready") {
        anchorReady = true;
        if (preReadyTimer) clearTimeout(preReadyTimer);
        if (stopRequested) {
          noTaskStarted = true;
          sendControl("cancel");
          scheduleNoStartCleanup();
        } else {
          commandStartSent = sendControl("start");
          if (!commandStartSent) stop("cancelled");
        }
        return;
      }
      if (message.type === "not_started") {
        noTaskStarted = true;
        if (forceTimer) clearTimeout(forceTimer);
        scheduleNoStartCleanup();
        return;
      }
      if (message.type === "completed") {
        commandCompleted = {
          ...(typeof message.exit_code === "number" ? { exit_code: message.exit_code } : {}),
          ...(typeof message.signal === "string" ? { signal: message.signal } : {})
        };
        if (!stopRequested) {
          completionCleanup = true;
          if (timeoutTimer) clearTimeout(timeoutTimer);
          input.signal?.removeEventListener("abort", abortHandler);
          // A command may leave descendants after its captured pipes close.
          // Keep the anchor alive while terminating its process group.
          beginTermination();
        }
      }
    };

    if (controlStream) {
      controlStream.setEncoding("utf8");
      controlStream.on("data", (chunk: string) => {
        controlBuffer += chunk;
        if (controlBuffer.length > 4_096) {
          controlBuffer = "";
          if (!stopRequested) stop("timeout");
          return;
        }
        const lines = controlBuffer.split("\n");
        controlBuffer = lines.pop() ?? "";
        for (const line of lines) {
          if (!line) continue;
          try {
            acceptControlMessage(JSON.parse(line) as GroupAnchorMessage);
          } catch {
            if (!stopRequested) stop("timeout");
          }
        }
      });
    }

    child.stdin?.on("error", () => {
      if (!completionCleanup && stopRequested && noTaskStarted) scheduleNoStartCleanup();
    });

    child.once("error", (error) => {
      finish({
        timed_out: timedOut,
        cancelled,
        ...(input.anchored ? { cleanup_confirmed: !commandStartSent } : { cleanup_confirmed: false }),
        stderrSuffix: error.message
      });
    });
    child.once("close", (code, signal) => {
      childClosed = true;
      closedResult = commandCompleted ?? {
        ...(typeof code === "number" ? { exit_code: code } : {}),
        ...(signal ? { signal } : {})
      };
      if (completionCleanup) {
        if (forceSettleTimer) clearTimeout(forceSettleTimer);
        scheduleGroupVerification();
      } else if (!stopRequested) {
        finish({
          ...closedResult,
          timed_out: timedOut,
          cancelled,
          ...(input.anchored ? { cleanup_confirmed: !commandStartSent } : { cleanup_confirmed: false })
        });
      } else if (noTaskStarted) {
        finishStopped(true);
      } else if (forced) {
        if (forceSettleTimer) clearTimeout(forceSettleTimer);
        scheduleGroupVerification();
      }
    });

    const timeoutTimer = setTimeout(() => stop("timeout"), input.timeout_ms);
    input.signal?.addEventListener("abort", abortHandler, { once: true });
    if (input.signal?.aborted) abortHandler();
  });
}

function terminateProcessTree(child: Pick<ChildProcess, "pid" | "kill">, signal: NodeJS.Signals): SignalAttempt {
  if (!child.pid) return "failed";
  try {
    process.kill(-child.pid, signal);
    return "sent";
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return "gone";
    return "failed";
  }
}

function processGroupExists(pid: number): boolean | undefined {
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    return undefined;
  }
}
