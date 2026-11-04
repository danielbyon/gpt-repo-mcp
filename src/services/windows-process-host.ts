import { existsSync } from "node:fs";
import { spawn, type ChildProcess } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ProcessTailResult } from "./process-exec.js";
import { decodeWindowsHostFrames, type WindowsHostFrame } from "./windows-process-host-protocol.js";

const START_COMMAND = 0x53;
const CANCEL_COMMAND = 0x43;
const FORCE_SETTLE_GRACE_MS = 1_000;
const MAX_PROTOCOL_BUFFER_BYTES = 65_541;
const crossSpawn = createRequire(import.meta.url)("cross-spawn") as {
  _parse(command: string, args: string[], options: { env: NodeJS.ProcessEnv }): {
    command: string;
    args: string[];
    file?: string;
    options: { windowsVerbatimArguments?: boolean };
  };
};

export type WindowsProcessHostInput = {
  executable: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  timeout_ms: number;
  tail_bytes: number;
  signal?: AbortSignal;
};

export type WindowsProcessHostLaunch = { executable: string; args: string[] };

/** Runs a command through the Windows host and requires an explicit terminal frame for cleanup status. */
export async function runWindowsProcessWithTail(
  input: WindowsProcessHostInput,
  launch?: WindowsProcessHostLaunch
): Promise<ProcessTailResult> {
  input.signal?.throwIfAborted();
  const startedAt = Date.now();
  const helperPath = launch?.executable ?? windowsProcessHostPath();
  const helperArgs = launch?.args ?? windowsHostArgs(input);
  const helperEnv = {
    ...input.env,
    // Keep Windows system command resolution available without forwarding the server environment.
    ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {})
  };
  const child = spawn(helperPath, helperArgs, {
    cwd: input.cwd,
    env: helperEnv,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true
  }) as ChildProcess & {
    stdin: NonNullable<ChildProcess["stdin"]>;
    stdout: NonNullable<ChildProcess["stdout"]>;
    stderr: NonNullable<ChildProcess["stderr"]>;
  };

  return superviseWindowsHost(child, input, startedAt);
}

function windowsHostArgs(input: WindowsProcessHostInput): string[] {
  // CreateProcessW treats its explicit application name as a path and does not search PATH.
  // Use cross-spawn's resolved file for executables and preserve its command and quoting for shell shims.
  const parsed = crossSpawn._parse(input.executable, input.args, { env: input.env });
  const executable = parsed.command === input.executable && parsed.file ? parsed.file : parsed.command;
  return [
    "--",
    ...(parsed.options.windowsVerbatimArguments ? ["--verbatim"] : []),
    executable,
    ...parsed.args
  ];
}

function superviseWindowsHost(
  child: ChildProcess & {
    stdin: NonNullable<ChildProcess["stdin"]>;
    stdout: NonNullable<ChildProcess["stdout"]>;
    stderr: NonNullable<ChildProcess["stderr"]>;
  },
  input: WindowsProcessHostInput,
  startedAt: number
): Promise<ProcessTailResult> {
  return new Promise((resolve) => {
    let stdout: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let stderr: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let protocolBuffer: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let timedOut = false;
    let cancelled = false;
    let stopRequested = false;
    let terminalResult: Extract<WindowsHostFrame, { type: "result" }> | undefined;
    let terminalResultAccepted = false;
    let protocolFailure: string | undefined;
    let spawnFailure: string | undefined;
    let helperSpawned = false;
    let childClosed = false;
    let childExitCode: number | null = null;
    let childSignal: NodeJS.Signals | null = null;
    let forceTimer: NodeJS.Timeout | undefined;
    let settleTimer: NodeJS.Timeout | undefined;
    let resultTimer: NodeJS.Timeout | undefined;
    let settled = false;

    const appendTail = (tail: Buffer, chunk: Buffer): Buffer => {
      const combined = Buffer.concat([tail, chunk]);
      return combined.length > input.tail_bytes ? combined.subarray(combined.length - input.tail_bytes) : combined;
    };

    const clearTimers = (): void => {
      clearTimeout(timeoutTimer);
      if (forceTimer) clearTimeout(forceTimer);
      if (settleTimer) clearTimeout(settleTimer);
      if (resultTimer) clearTimeout(resultTimer);
    };

    const finish = (cleanupConfirmed: boolean, stderrSuffix?: string): void => {
      if (settled) return;
      settled = true;
      clearTimers();
      input.signal?.removeEventListener("abort", abortHandler);
      child.stdin?.destroy();
      child.stdout?.removeAllListeners("data");
      child.stderr?.removeAllListeners("data");
      child.stdout?.destroy();
      child.stderr?.destroy();
      const stderrText = stderrSuffix
        ? appendTail(stderr, Buffer.from(`\n${stderrSuffix}`, "utf8")).toString("utf8").trim()
        : stderr.toString("utf8");
      const status = terminalResult?.status;
      resolve({
        ...(status === "completed" || status === "cancelled_confirmed" ? { exit_code: terminalResult?.exit_code } : {}),
        ...(cancelled || timedOut ? { signal: "SIGKILL" } : childSignal ? { signal: childSignal } : {}),
        timed_out: timedOut,
        cancelled,
        cleanup_confirmed: cleanupConfirmed,
        duration_ms: Date.now() - startedAt,
        stdout_tail: stdout.toString("utf8"),
        stderr_tail: stderrText,
        ...(typeof childExitCode === "number" && !terminalResult && cleanupConfirmed ? { exit_code: childExitCode } : {})
      });
    };

    const sendCancel = (): void => {
      if (!child.stdin.destroyed && child.stdin.writable) {
        child.stdin.write(Buffer.from([CANCEL_COMMAND]), (error) => {
          if (error && !protocolFailure) protocolFailure = `Could not signal the Windows process host: ${error.message}`;
        });
      }
      forceTimer = setTimeout(() => {
        if (settled || childClosed) return;
        child.kill("SIGKILL");
        settleTimer = setTimeout(() => {
          if (settled || childClosed) return;
          child.stdout.destroy();
          child.stderr.destroy();
          child.stdin.destroy();
          child.unref();
          finish(false, protocolFailure ?? "Windows process-host termination could not be confirmed.");
        }, FORCE_SETTLE_GRACE_MS);
      }, FORCE_SETTLE_GRACE_MS);
    };

    const requestStop = (reason: "cancelled" | "timeout"): void => {
      if (settled || terminalResultAccepted || stopRequested) return;
      stopRequested = true;
      cancelled = reason === "cancelled";
      timedOut = reason === "timeout";
      input.signal?.removeEventListener("abort", abortHandler);
      clearTimeout(timeoutTimer);
      sendCancel();
    };

    const acceptResult = (frame: Extract<WindowsHostFrame, { type: "result" }>): void => {
      if (terminalResult) {
        protocolFailure = "Windows process host sent more than one result frame.";
        requestStop("cancelled");
        return;
      }
      terminalResult = frame;
      terminalResultAccepted = true;
      clearTimeout(timeoutTimer);
      if (forceTimer) clearTimeout(forceTimer);
      input.signal?.removeEventListener("abort", abortHandler);
      if (frame.status === "launch_failed") {
        spawnFailure = `Windows process host could not start the command (error ${frame.error_code}).`;
      } else if (frame.status === "cleanup_unconfirmed") {
        protocolFailure = `Windows process host could not confirm cleanup (error ${frame.error_code}).`;
      } else if ((frame.status === "cancelled_before_start" || frame.status === "cancelled_confirmed") && !stopRequested) {
        cancelled = true;
      }
      resultTimer = setTimeout(() => {
        if (settled || childClosed) return;
        child.kill("SIGKILL");
        settleTimer = setTimeout(() => {
          if (settled || childClosed) return;
          child.stdout.destroy();
          child.stderr.destroy();
          child.stdin.destroy();
          child.unref();
          finish(false, "Windows process host did not exit after reporting its result.");
        }, FORCE_SETTLE_GRACE_MS);
      }, FORCE_SETTLE_GRACE_MS);
    };

    const handleFrame = (frame: WindowsHostFrame): void => {
      if (terminalResult) {
        protocolFailure = "Windows process host wrote data after its result frame.";
        requestStop("cancelled");
        return;
      }
      if (frame.type === "stdout") stdout = appendTail(stdout, frame.payload);
      else if (frame.type === "stderr") stderr = appendTail(stderr, frame.payload);
      else acceptResult(frame);
    };

    const abortHandler = (): void => requestStop("cancelled");
    const timeoutTimer = setTimeout(() => requestStop("timeout"), input.timeout_ms);

    child.stdout.on("data", (chunk: Buffer) => {
      if (settled) return;
      try {
        const combined = Buffer.concat([protocolBuffer, chunk]);
        const decoded = decodeWindowsHostFrames(combined);
        if (decoded.remainder.length > MAX_PROTOCOL_BUFFER_BYTES) {
          throw new Error("Windows process host sent an oversized incomplete frame.");
        }
        protocolBuffer = decoded.remainder;
        for (const frame of decoded.frames) handleFrame(frame);
      } catch (error) {
        protocolFailure = error instanceof Error ? error.message : String(error);
        requestStop("cancelled");
      }
    });
    child.stderr.on("data", (chunk: Buffer) => { stderr = appendTail(stderr, chunk); });
    child.once("spawn", () => { helperSpawned = true; });
    child.once("error", (error) => {
      if (helperSpawned) {
        protocolFailure = `Windows process host reported an error after launch: ${error.message}`;
      } else {
        spawnFailure = error.message;
      }
    });
    child.once("close", (code, signal) => {
      childClosed = true;
      childExitCode = typeof code === "number" ? code : null;
      childSignal = signal;
      if (protocolBuffer.length > 0 && !protocolFailure) protocolFailure = "Windows process host closed with a truncated frame.";
      if (spawnFailure && !terminalResult && !protocolFailure) {
        finish(true, spawnFailure);
        return;
      }
      if (!terminalResult) {
        finish(false, protocolFailure ?? "Windows process host exited without cleanup evidence.");
        return;
      }
      const cleanupConfirmed = terminalResult.status !== "cleanup_unconfirmed" && !protocolFailure;
      finish(cleanupConfirmed, protocolFailure ?? spawnFailure);
    });

    input.signal?.addEventListener("abort", abortHandler, { once: true });
    if (input.signal?.aborted) abortHandler();
    if (!stopRequested) {
      child.stdin.write(Buffer.from([START_COMMAND]), (error) => {
        if (error && !stopRequested) {
          protocolFailure = `Could not start the Windows process host: ${error.message}`;
          requestStop("cancelled");
        }
      });
    }
  });
}

function windowsProcessHostPath(): string {
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  const binaryName = "windows-process-host.exe";
  const candidates = [
    join(moduleDirectory, binaryName),
    join(moduleDirectory, "..", "..", "dist", binaryName)
  ];
  return candidates.find((candidate) => existsSync(candidate)) ?? candidates[0]!;
}
