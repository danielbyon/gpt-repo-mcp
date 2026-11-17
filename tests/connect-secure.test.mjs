import { EventEmitter, once } from "node:events";
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { Buffer } from "node:buffer";
import { performance } from "node:perf_hooks";
import process from "node:process";
import { existsSync, watch } from "node:fs";
import { chmod, mkdir, mkdtemp, open, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { PassThrough } from "node:stream";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "vitest";
import { redactSensitiveText } from "../src/runtime/path-redaction.ts";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const connectScript = join(repoRoot, "scripts", "connect-secure.mjs");
const OUTPUT_CAPTURE_SETTLEMENT_TIMEOUT_MS = 250;
const MAX_DIAGNOSTIC_STREAM_BYTES = 8 * 1024;
const fixtures = new Set();
const launchers = new Set();
const reservedServers = new Set();

/** Keep fixtures for unconfirmed launchers and report every teardown failure. */
afterEach(async () => {
  const cleanupErrors = [];
  for (const launcher of launchers) {
    try {
      await stopLauncher(launcher);
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  const servers = [...reservedServers];
  const serverResults = await Promise.allSettled(servers.map((server) => new Promise((resolveClose, rejectClose) => {
    server.close((error) => error?.code === "ERR_SERVER_NOT_RUNNING"
      ? resolveClose()
      : error ? rejectClose(error) : resolveClose());
  })));
  serverResults.forEach((result, index) => {
    if (result.status === "fulfilled") reservedServers.delete(servers[index]);
    else cleanupErrors.push(result.reason);
  });
  if (launchers.size === 0) {
    const fixturePaths = [...fixtures];
    const fixtureResults = await Promise.allSettled(fixturePaths.map((path) => rm(path, { recursive: true, force: true })));
    fixtureResults.forEach((result, index) => {
      if (result.status === "fulfilled") fixtures.delete(fixturePaths[index]);
      else cleanupErrors.push(result.reason);
    });
  }
  if (cleanupErrors.length > 0) {
    throw new AggregateError(cleanupErrors, `Secure connector test cleanup failed in ${cleanupErrors.length} operation(s).`);
  }
});

describe("secure connector startup order", () => {
  test("reports the exit tuple and both output streams when readiness is absent", async () => {
    let stdout = "";
    let stderr = "";
    const child = spawn(process.execPath, [
      "-e",
      'process.stdout.write("final stdout"); process.stderr.write("final stderr"); process.exit(7);'
    ], { stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const launcher = {
      child,
      output: () => `${stdout}${stderr}`,
      stdout: () => stdout,
      stderr: () => stderr
    };
    const childClosed = once(child, "close");
    let watchdog;
    const outcome = await Promise.race([
      waitForOutput(launcher, "readiness marker"),
      new Promise((resolveOutcome) => {
        watchdog = globalThis.setTimeout(() => resolveOutcome({ kind: "watchdog" }), 250);
      })
    ]);
    globalThis.clearTimeout(watchdog);
    await childClosed;

    expect(outcome).toMatchObject({
      kind: "closed",
      code: 7,
      signal: null
    });
    expect(stdout).toBe("final stdout");
    expect(stderr).toBe("final stderr");
  });

  test("keeps cleanup unverified for empty or malformed process-group snapshots", () => {
    expect(processGroupHasLiveMembers("", 42)).toBe(true);
    expect(processGroupHasLiveMembers("ps: invalid output", 42)).toBe(true);
    expect(processGroupHasLiveMembers("21 S\nmalformed", 42)).toBe(true);
    expect(processGroupHasLiveMembers("21 S\n", 42)).toBe(false);
    expect(processGroupHasLiveMembers("42 S\n", 42)).toBe(true);
    expect(processGroupHasLiveMembers("42 Z\n", 42)).toBe(false);
  });

  test("settles readiness waiting on launcher exit while a descendant holds output pipes", async () => {
    let stdout = "";
    let stderr = "";
    const startedAt = performance.now();
    const timeline = { closedAfterMs: null, exitCode: null, signal: null };
    const child = spawn(process.execPath, [
      "-e",
      'const { spawn } = require("node:child_process"); spawn(process.execPath, ["-e", "setTimeout(() => process.exit(0), 1500)"], { stdio: "inherit" }); setTimeout(() => process.exit(7), 25);'
    ], { stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("exit", (code, signal) => {
      timeline.exitCode = code;
      timeline.signal = signal;
    });
    child.once("close", () => { timeline.closedAfterMs = performance.now() - startedAt; });
    const launcher = {
      child,
      startedAt,
      timeline,
      stdout: () => stdout,
      stderr: () => stderr,
      output: () => `${stdout}${stderr}`
    };
    const childClosed = once(child, "close");

    try {
      const outcome = await waitForOutput(launcher, "readiness marker");
      expect(outcome).toMatchObject({
        kind: "closed",
        code: 7,
        signal: null,
        outputCapture: { status: "incomplete", complete: false }
      });
      expect(timeline.closedAfterMs).toBeNull();
    } finally {
      await childClosed;
    }
  }, 10_000);

  test("bounds final output settlement after child exit while inherited streams remain open", async () => {
    const fixture = await createFixture();
    const child = new EventEmitter();
    const stdoutStream = new PassThrough();
    const stderrStream = new PassThrough();
    stdoutStream.setEncoding("utf8");
    stderrStream.setEncoding("utf8");
    child.stdout = stdoutStream;
    child.stderr = stderrStream;
    child.exitCode = null;
    child.signalCode = null;

    let stdout = "";
    let stderr = "";
    const startedAt = performance.now();
    const startedAtEpochMs = Date.now();
    const timeline = {
      startedAt: new Date(startedAtEpochMs).toISOString(),
      exitedAfterMs: null,
      closedAfterMs: null,
      exitCode: null,
      signal: null,
      closeCode: null,
      closeSignal: null
    };
    stdoutStream.on("data", (chunk) => { stdout += chunk; });
    stderrStream.on("data", (chunk) => { stderr += chunk; });
    const launcher = {
      id: "late-stream-output",
      child,
      fixture,
      secrets: [],
      startedAt,
      startedAtEpochMs,
      timeline,
      stdout: () => stdout,
      stderr: () => stderr,
      output: () => `${stdout}${stderr}`
    };
    const childClosed = once(child, "close");
    const streamCloses = Promise.all([once(stdoutStream, "close"), once(stderrStream, "close")]);

    globalThis.setTimeout(() => {
      stdoutStream.write("early stdout");
      stderrStream.write("early stderr");
      child.exitCode = 7;
      timeline.exitedAfterMs = performance.now() - startedAt;
      timeline.exitCode = 7;
      child.emit("exit", 7, null);

      globalThis.setTimeout(() => {
        stdoutStream.write("late stdout");
        stderrStream.write("late stderr");
      }, 20);
      globalThis.setTimeout(async () => {
        stdoutStream.end();
        stderrStream.end();
        await streamCloses;
        timeline.closedAfterMs = performance.now() - startedAt;
        timeline.closeCode = 7;
        timeline.closeSignal = null;
        child.emit("close", 7, null);
      }, 1_500);
    }, 0);

    try {
      const readinessStartedAt = performance.now();
      const outcome = await waitForOutput(launcher, "readiness marker");
      expect(outcome).toMatchObject({
        kind: "closed",
        code: 7,
        signal: null,
        outputCapture: {
          status: "incomplete",
          complete: false,
          reason: "streams_open_after_child_exit"
        }
      });
      expect(outcome.stdout).not.toContain("late stdout");
      expect(performance.now() - readinessStartedAt).toBeLessThan(750);

      const diagnosticsStartedAt = performance.now();
      const diagnostics = await collectLauncherDiagnostics(launcher);
      expect(diagnostics.outputCapture).toMatchObject({
        status: "incomplete",
        complete: false,
        reason: "stream_close_timeout",
        settlementTimeoutMs: 250,
        streamsClosed: { stdout: false, stderr: false }
      });
      expect(diagnostics.stdout).toContain("late stdout");
      expect(diagnostics.stderr).toContain("late stderr");
      expect(performance.now() - diagnosticsStartedAt).toBeLessThan(750);

      await childClosed;
      expect(timeline.closedAfterMs).not.toBeNull();
    } finally {
      await childClosed;
    }
  }, 5_000);

  test("returns redacted launcher output, marker state, and stage timing", async () => {
    const fixture = await createFixture();
    const secret = "synthetic-launcher-secret-7f8a";
    await writeFile(fixture.paths.mcpReadyFile, JSON.stringify({ token: secret, state: "ready" }), "utf8");

    let stdout = "";
    let stderr = "";
    const startedAtEpochMs = Date.now() - 1_000;
    const startedAt = performance.now();
    const timeline = {
      startedAt: new Date(startedAtEpochMs).toISOString(),
      spawnedAfterMs: 0,
      exitedAfterMs: null,
      closedAfterMs: null
    };
    const child = spawn(process.execPath, [
      "-e",
      `process.stdout.write(${JSON.stringify(`final stdout ${secret}`)}); process.stderr.write(${JSON.stringify(`final stderr ${secret}`)}); process.exit(7);`
    ], { stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("exit", (code, signal) => {
      timeline.exitedAfterMs = performance.now() - startedAt;
      timeline.exitCode = code;
      timeline.signal = signal;
    });
    child.once("close", (code, signal) => {
      timeline.closedAfterMs = performance.now() - startedAt;
      timeline.closeCode = code;
      timeline.closeSignal = signal;
    });
    const launcher = {
      id: "diagnostic-capture",
      child,
      fixture,
      secrets: [secret],
      startedAt,
      startedAtEpochMs,
      timeline,
      stdout: () => stdout,
      stderr: () => stderr,
      output: () => `${stdout}${stderr}`
    };
    const outcome = await waitForOutput(launcher, "readiness marker");
    expect(outcome).toMatchObject({ kind: "closed", code: 7, signal: null });
    if (timeline.closedAfterMs === null) await once(child, "close");

    const diagnostics = await collectLauncherDiagnostics(launcher);
    const serialized = JSON.stringify(diagnostics);
    expect(diagnostics).toMatchObject({
      exit: { code: 7, signal: null },
      markers: { mcpReady: { state: "json", value: { token: "[REDACTED_SECRET]", state: "ready" } } }
    });
    expect(diagnostics.stdout).toContain("[REDACTED]");
    expect(diagnostics.stderr).toContain("[REDACTED]");
    expect(diagnostics.stageTimings).toEqual(expect.arrayContaining([
      expect.objectContaining({ stage: "mcpReady", elapsedFromLauncherStartMs: expect.any(Number) })
    ]));
    expect(serialized).not.toContain(secret);
  });

  test("redacts escaped secrets from nested diagnostics and marker values", () => {
    const diagnosticSecret = 'generic:"quoted"\\path\nwith\ttabs\u0000control';
    const markerSecret = 'marker:"quoted"\\path\r\nwith\u0001control';
    const secrets = [diagnosticSecret, markerSecret];
    const diagnostic = {
      details: { nested: [{ value: diagnosticSecret }, "keep-array-item"] },
      markers: { mcpReady: { state: "json", value: [{ description: markerSecret }, "ready"] } }
    };

    const redacted = redactDiagnosticValue(diagnostic, secrets);
    const serialized = JSON.stringify(redacted);

    for (const secret of secrets) {
      expect(serialized).not.toContain(secret);
      expect(serialized).not.toContain(JSON.stringify(secret).slice(1, -1));
    }
    expect(redacted).toEqual({
      details: { nested: [{ value: "[REDACTED]" }, "keep-array-item"] },
      markers: { mcpReady: { state: "json", value: [{ description: "[REDACTED]" }, "ready"] } }
    });
  });

  test("redacts a secret when a bounded marker ends inside a UTF-8 character", async () => {
    const secret = "synthetic-π-secret";
    const partialSecret = Buffer.from(secret).subarray(0, Buffer.byteLength("synthetic-") + 1);
    const markerContents = Buffer.concat([Buffer.from("diagnostic "), partialSecret]);
    const marker = await readMarkerSnapshot("synthetic-marker", [secret], {
      openFile: async () => ({
        stat: async () => ({ mtimeMs: 1_234, size: markerContents.length + 1 }),
        read: async (buffer, offset) => ({
          bytesRead: markerContents.copy(buffer, offset)
        }),
        close: async () => {}
      })
    });

    expect(marker.truncated).toBe(true);
    expect(marker.value).toBe("diagnostic [REDACTED]");
  });

  test("redacts a secret when bounded output ends inside a UTF-8 character", () => {
    const secret = "synthetic-π-secret";
    const partialSecret = Buffer.from(secret).subarray(0, Buffer.byteLength("synthetic-") + 1);
    const capturedBytes = Buffer.concat([Buffer.from("diagnostic "), partialSecret]);
    const capture = createBoundedCapture(capturedBytes.length);
    capture.append(Buffer.concat([capturedBytes, Buffer.from(" beyond limit") ]));

    const snapshot = capture.snapshot([secret]);

    expect(snapshot.truncated).toBe(true);
    expect(snapshot.text).toBe("diagnostic [REDACTED]");
  });

  test("collects bare environment secrets for password and private-key names", () => {
    const environment = {
      DB_PWD: "synthetic-db-password",
      PRIVATE_KEY: "synthetic-private-key",
      LOG_LEVEL: "debug"
    };

    expect(collectSecretValues(environment)).toEqual([
      "synthetic-db-password",
      "synthetic-private-key"
    ]);
  });

  test("redacts a partial secret at the bounded marker boundary", async () => {
    const secret = "synthetic-marker-boundary-secret";
    const partialSecret = secret.slice(0, 12);
    const markerContents = Buffer.from(`${"x".repeat(4_096 - partialSecret.length)}${secret}`);
    const marker = await readMarkerSnapshot("synthetic-marker", [secret], {
      openFile: async () => ({
        stat: async () => ({ mtimeMs: 1_234, size: markerContents.length }),
        read: async (buffer, offset, length) => ({
          bytesRead: markerContents.copy(buffer, offset, 0, Math.min(length, markerContents.length))
        }),
        close: async () => {}
      })
    });

    expect(marker.truncated).toBe(true);
    expect(marker.value.endsWith("[REDACTED]")).toBe(true);
    expect(marker.value).not.toContain(partialSecret);
  });

  test("redacts a partial secret after a short read from an oversized marker", async () => {
    const secret = "synthetic-marker-boundary-secret";
    const partialSecret = secret.slice(0, 12);
    const markerContents = Buffer.from(`diagnostic ${partialSecret}`);
    const marker = await readMarkerSnapshot("synthetic-marker", [secret], {
      openFile: async () => ({
        stat: async () => ({ mtimeMs: 1_234, size: 5_000 }),
        read: async (buffer, offset) => ({ bytesRead: markerContents.copy(buffer, offset) }),
        close: async () => {}
      })
    });

    expect(marker.truncated).toBe(true);
    expect(marker.value.endsWith("[REDACTED]")).toBe(true);
    expect(marker.value).not.toContain(partialSecret);
  });

  test("redacts a partial secret after a short read from a small marker", async () => {
    const secret = "synthetic-marker-boundary-secret";
    const partialSecret = secret.slice(0, 12);
    const markerContents = Buffer.from(`diagnostic ${partialSecret}`);
    const markerSize = 100;
    expect(markerContents.length).toBeLessThan(markerSize);
    const marker = await readMarkerSnapshot("synthetic-marker", [secret], {
      openFile: async () => ({
        stat: async () => ({ mtimeMs: 1_234, size: markerSize }),
        read: async (buffer, offset, length) => ({
          bytesRead: markerContents.copy(buffer, offset, 0, Math.min(length, markerContents.length))
        }),
        close: async () => {}
      })
    });

    expect(marker).toMatchObject({ sizeBytes: markerSize, truncated: true });
    expect(marker.value.endsWith("[REDACTED]")).toBe(true);
    expect(marker.value).not.toContain(partialSecret);
  });

  test("preserves complete JSON values when the marker file is truncated after them", async () => {
    const secret = "synthetic-marker-boundary-secret";
    const completeValue = `complete-${secret.slice(0, 12)}`;
    const json = JSON.stringify({ label: completeValue });
    const markerContents = Buffer.from(`${json}${" ".repeat(4_097 - json.length)}`);
    const marker = await readMarkerSnapshot("synthetic-marker", [secret], {
      openFile: async () => ({
        stat: async () => ({ mtimeMs: 1_234, size: markerContents.length }),
        read: async (buffer, offset, length) => ({
          bytesRead: markerContents.copy(buffer, offset, 0, Math.min(length, markerContents.length))
        }),
        close: async () => {}
      })
    });

    expect(marker).toMatchObject({
      state: "json",
      truncated: true,
      value: { label: completeValue }
    });
  });

  test("safely represents circular and unsupported diagnostic values", () => {
    const circular = { label: "safe" };
    circular.self = circular;
    const diagnostic = {
      circular,
      unsupported: {
        bigint: 1n,
        callback: () => "must not serialize",
        symbol: Symbol("unsupported"),
        missing: undefined
      }
    };

    const redacted = redactDiagnosticValue(diagnostic);

    expect(redacted).toEqual({
      circular: { label: "safe", self: "[Circular]" },
      unsupported: {
        bigint: "[UNSUPPORTED:bigint]",
        callback: "[UNSUPPORTED:function]",
        symbol: "[UNSUPPORTED:symbol]",
        missing: "[UNSUPPORTED:undefined]"
      }
    });
    expect(() => JSON.stringify(redacted)).not.toThrow();
  });

  test("reports marker-handle close failures without dropping the marker snapshot", async () => {
    const markerContents = Buffer.from(JSON.stringify({ state: "ready" }));
    const marker = await readMarkerSnapshot("synthetic-marker", [], {
      openFile: async () => ({
        stat: async () => ({ mtimeMs: 1_234, size: markerContents.length }),
        read: async (buffer, offset, length) => ({
          bytesRead: markerContents.copy(buffer, offset, 0, Math.min(length, markerContents.length))
        }),
        close: async () => {
          throw Object.assign(new Error("synthetic marker close failure"), { code: "EIO" });
        }
      })
    });

    expect(marker).toMatchObject({
      state: "close_error",
      previousState: "json",
      value: { state: "ready" },
      modifiedAtEpochMs: 1_234,
      closeErrorCode: "EIO"
    });
  });

  test("preserves cleanup and diagnostic failures together", async () => {
    const fixture = await createFixture();
    const launcher = startLauncher(fixture, { MCP_STARTUP_WAIT_TIMEOUT: "5s" });
    await writeFile(fixture.paths.mcpBoundMarker, "not-json", "utf8");
    Object.defineProperty(launcher.child, "stdout", {
      configurable: true,
      get() { throw new Error("synthetic diagnostic capture failure"); }
    });

    let failure;
    try {
      await stopLauncher(launcher);
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(AggregateError);
    const messages = failure.errors.map((error) => error.message).join(" ");
    expect(messages).toContain("invalid_process_marker");
    expect(messages).toContain("synthetic diagnostic capture failure");
    expect(failure.errors.length).toBe(2);
    launchers.delete(launcher);
  });

  test("retains launcher tracking when exit cannot be confirmed", async () => {
    const fixture = await createFixture();
    const child = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    child.kill = () => true;
    const launcher = {
      id: "unconfirmed-launcher-exit",
      child,
      fixture,
      secrets: [],
      startedAt: performance.now(),
      startedAtEpochMs: Date.now(),
      timeline: {
        startedAt: new Date().toISOString(),
        exitCode: null,
        signal: null,
        closeCode: null,
        closeSignal: null
      },
      stdout: () => "",
      stderr: () => "",
      output: () => ""
    };
    launchers.add(launcher);

    let failure;
    try {
      await stopLauncher(launcher);
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(AggregateError);
    expect(failure.errors.map((error) => error.message).join(" ")).toContain("launcher_exit_unconfirmed");
    expect(launchers.has(launcher)).toBe(true);
    launchers.delete(launcher);
  }, 10_000);

  test("waits for complete marker contents after observing an empty file", async () => {
    const fixture = await createFixture();
    const markerPath = join(fixture.root, "complete-marker");
    await writeFile(markerPath, "", "utf8");
    const child = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    let reads = 0;
    let resolveFirstRead;
    const firstRead = new Promise((resolveRead) => { resolveFirstRead = resolveRead; });
    const contents = ["", "ready"];
    const markerRead = async () => {
      const value = contents[reads++];
      if (reads === 1) resolveFirstRead(value);
      return value;
    };
    let notifyChange;
    let closeCount = 0;
    let watcher;
    const launcher = { child, output: () => "" };
    const waiting = waitForFile(markerPath, launcher, "ready", {
      readFile: markerRead,
      watch: (_directory, listener) => {
        notifyChange = listener;
        watcher = new EventEmitter();
        watcher.close = () => { closeCount += 1; };
        return watcher;
      }
    });

    const firstObservation = await Promise.race([
      firstRead.then((value) => ({ kind: "read", value })),
      waiting.then((value) => ({ kind: "resolved", value }))
    ]);
    expect(firstObservation).toEqual({ kind: "read", value: "" });

    notifyChange("change", "complete-marker");
    await expect(waiting).resolves.toBe("ready");
    expect(closeCount).toBe(1);
    expect(watcher.listenerCount("error")).toBe(0);
    expect(child.listenerCount("exit")).toBe(0);
  });

  test("rejects a complete readiness marker when the launcher exits during the read", async () => {
    const fixture = await createFixture();
    const markerPath = join(fixture.root, "readiness-race-marker");
    const child = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    let watcher;
    const launcher = { child, output: () => "launcher output" };
    const markerRead = async () => {
      child.exitCode = 0;
      child.emit("exit", 0, null);
      return "ready";
    };
    const waiting = waitForFile(markerPath, launcher, "ready", {
      readFile: markerRead,
      requireLauncherAlive: true,
      watch: () => {
        watcher = new EventEmitter();
        watcher.close = () => undefined;
        return watcher;
      }
    });

    await expect(waiting).rejects.toThrow(/Launcher exited before .* was complete[\s\S]*launcher output/);
    expect(child.listenerCount("exit")).toBe(0);
    expect(watcher.listenerCount("error")).toBe(0);
  });

  test("does not report buffered readiness output after the launcher closes", async () => {
    const child = new EventEmitter();
    child.exitCode = 0;
    child.signalCode = null;
    const launcher = {
      child,
      timeline: { closedAfterMs: 10, closeCode: 0, closeSignal: null },
      output: () => "Secure MCP Tunnel passed readiness",
      stdout: () => "Secure MCP Tunnel passed readiness",
      stderr: () => ""
    };

    await expect(waitForOutput(launcher, "Secure MCP Tunnel passed readiness"))
      .resolves.toMatchObject({ kind: "closed", code: 0, signal: null });
  });

  test("requires the launcher to remain open when a readiness check expects success", async () => {
    const child = new EventEmitter();
    child.exitCode = 0;
    child.signalCode = null;
    const launcher = {
      child,
      timeline: { closedAfterMs: 10, closeCode: 0, closeSignal: null },
      output: () => "Secure MCP Tunnel passed readiness",
      stdout: () => "Secure MCP Tunnel passed readiness",
      stderr: () => ""
    };

    await expect(waitForSuccessfulReadiness(launcher, "Secure MCP Tunnel passed readiness"))
      .rejects.toThrow("did not remain open through readiness output");
  });

  test("rejects an incomplete marker if the launcher exits and cleans up the watcher", async () => {
    const fixture = await createFixture();
    const markerPath = join(fixture.root, "incomplete-marker");
    await writeFile(markerPath, "", "utf8");
    const child = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    let resolveRead;
    const firstRead = new Promise((resolveMarkerRead) => { resolveRead = resolveMarkerRead; });
    let closeCount = 0;
    let watcher;
    const launcher = { child, output: () => "launcher output" };
    const waiting = waitForFile(markerPath, launcher, "ready", {
      readFile: async () => {
        resolveRead("");
        return "";
      },
      watch: () => {
        watcher = new EventEmitter();
        watcher.close = () => { closeCount += 1; };
        return watcher;
      }
    });
    await firstRead;

    child.emit("exit", 7, null);

    await expect(waiting).rejects.toThrow(/exited before .* was complete[\s\S]*launcher output/);
    expect(closeCount).toBe(1);
    expect(watcher.listenerCount("error")).toBe(0);
    expect(child.listenerCount("exit")).toBe(0);
  });

  test("waits for fresh MCP discovery before launching the tunnel and reaps both managed children", async () => {
    const fixture = await createFixture();
    const launcher = startLauncher(fixture);
    try {
      await waitForFile(fixture.paths.mcpProbeMarker, launcher, "probe-seen", { requireLauncherAlive: true });
      expect(existsSync(fixture.paths.tunnelStartedMarker)).toBe(false);

      await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
      await waitForFile(fixture.paths.tunnelStartedMarker, launcher, isCompleteJsonObject, { requireLauncherAlive: true });
      await waitForFile(fixture.paths.tunnelReadyMarker, launcher, "ready", { requireLauncherAlive: true });
      await waitForSuccessfulReadiness(launcher, "Secure MCP Tunnel passed readiness");

      const tunnelStart = JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8"));
      expect(tunnelStart).toMatchObject({
        profile: "issue-42-test-profile",
        mcpTimeout: "2.25s",
        tunnelTimeout: "4s",
        listenAddr: "127.0.0.1:0"
      });
      expect(tunnelStart.urlFile).toContain("gpt-repo-tunnel-health-");
      expect(tunnelStart.urlFile).not.toBe(fixture.paths.mcpReadyFile);
      expect((await stat(dirname(tunnelStart.urlFile))).mode & 0o777).toBe(0o700);

      const launcherExit = once(launcher.child, "exit");
      const mcpStopped = waitForFile(fixture.paths.mcpStoppedMarker, launcher, "stopped");
      const tunnelStopped = waitForFile(fixture.paths.tunnelStoppedMarker, launcher, "stopped");
      launcher.child.kill("SIGTERM");
      const [code, signal] = await launcherExit;
      expect(code, launcher.output()).toBe(0);
      expect(signal).toBeNull();
      await expect(mcpStopped).resolves.toBe("stopped");
      await expect(tunnelStopped).resolves.toBe("stopped");
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("does not let completed Windows startup helpers poison owner-requested shutdown", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const nodeOptions = [process.env.NODE_OPTIONS, `--import=${fixture.paths.windowsPlatformPreload}`]
      .filter(Boolean)
      .join(" ");
    const launcher = startLauncher(fixture, {
      NODE_OPTIONS: nodeOptions,
      TEMP: tmpdir(),
      TMP: tmpdir()
    });
    try {
      await waitForSuccessfulReadiness(launcher, "Secure MCP Tunnel passed readiness");
      const helperCalls = (await readFile(fixture.paths.tunnelHelperLog, "utf8")).trim().split("\n");
      expect(helperCalls.length).toBeGreaterThanOrEqual(3);

      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      const [code] = await launcherExit;

      expect(code, launcher.output()).toBe(0);
      expect(launcher.output()).not.toContain("process-tree completion could not be verified after SIGKILL");
      const helperPids = helperCalls.map((line) => Number(line.split("\t").at(-1)));
      const taskkillTargets = (await readFile(fixture.paths.taskkillLog, "utf8"))
        .trim()
        .split("\n")
        .map(Number);
      expect(taskkillTargets.some((pid) => helperPids.includes(pid))).toBe(false);
    } finally {
      await stopLauncher(launcher);
    }
  }, 10_000);

  test("waits for bounded Windows helper cancellation before owner shutdown exits", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const nodeOptions = [process.env.NODE_OPTIONS, `--import=${fixture.paths.windowsPlatformPreload}`]
      .filter(Boolean)
      .join(" ");
    const launcher = startLauncher(fixture, {
      NODE_OPTIONS: nodeOptions,
      TEMP: tmpdir(),
      TMP: tmpdir(),
      TUNNEL_TEST_HELP_MODE: null,
      TUNNEL_TEST_HEALTH_MODE: "hang"
    });
    try {
      const helperPid = Number(await waitForFile(fixture.paths.tunnelHelperPidMarker, launcher, isPositiveIntegerText, { requireLauncherAlive: true }));
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      const [code] = await launcherExit;

      expect(code, launcher.output()).toBe(0);
      expect(isPidRunning(helperPid)).toBe(false);
    } finally {
      await stopLauncher(launcher);
    }
  }, 10_000);

  test("probes the tokenized MCP route when only the legacy token variable is set", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, {
      GPT_REPO_PUBLIC_PATH_TOKEN: null,
      REPO_READER_PUBLIC_PATH_TOKEN: "legacy token/42"
    });
    try {
      await waitForSuccessfulReadiness(launcher, "Secure MCP Tunnel passed readiness");
      expect(await readFile(fixture.paths.mcpRouteMarker, "utf8")).toBe("/t/legacy%20token%2F42/mcp");
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      await expect(launcherExit).resolves.toEqual([0, null]);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("fails startup when the MCP child exits cleanly before binding", async () => {
    const fixture = await createFixture();
    const launcher = startLauncher(fixture, { MCP_TEST_EXIT_EARLY: "0" });
    try {
      const [code] = await waitForLauncherExit(launcher);
      expect(code, launcher.output()).not.toBe(0);
      expect(existsSync(fixture.paths.tunnelStartedMarker)).toBe(false);
      expect(launcher.output()).toContain("[mcp] exited (code=0, signal=null)");
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("fails startup when the tunnel child exits cleanly before readiness", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, { TUNNEL_TEST_EXIT_EARLY: "0" });
    try {
      await waitForFile(fixture.paths.tunnelStartedMarker, launcher, isCompleteJsonObject, { requireLauncherAlive: true });
      const [code] = await waitForLauncherExit(launcher);
      expect(code, launcher.output()).not.toBe(0);
      expect(existsSync(fixture.paths.tunnelReadyMarker)).toBe(false);
      expect(launcher.output()).toContain("[tunnel] exited (code=0, signal=null)");
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("accepts HEALTH_LISTEN_ADDR=:0 only after local endpoint ownership is verified", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, { HEALTH_LISTEN_ADDR: ":0" });
    try {
      await waitForSuccessfulReadiness(launcher, "Secure MCP Tunnel passed readiness");
      expect(JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8")).listenAddr).toBe(":0");
      expect(existsSync(fixture.paths.tunnelReadyMarker)).toBe(true);
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      await expect(launcherExit).resolves.toEqual([0, null]);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("preserves a YAML-only fixed TCP health listener", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const configuredPort = await reservePort();
    await writeFile(fixture.paths.profileFile, `health:\n  listen_addr: 127.0.0.1:${configuredPort}\n`, "utf8");
    const launcher = startLauncher(fixture, {
      HEALTH_LISTEN_ADDR: null,
      HEALTH_UNIX_SOCKET: null
    });
    try {
      await waitForSuccessfulReadiness(launcher, "Secure MCP Tunnel passed readiness");
      expect(JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8")).listenAddr)
        .toBe(`127.0.0.1:${configuredPort}`);
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      await expect(launcherExit).resolves.toEqual([0, null]);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("preserves a YAML-only health Unix socket", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    await writeFile(fixture.paths.profileFile, `health:\n  unix_socket: ${fixture.paths.healthSocket}\n`, "utf8");
    const launcher = startLauncher(fixture, {
      HEALTH_LISTEN_ADDR: null,
      HEALTH_UNIX_SOCKET: null
    });
    try {
      await waitForSuccessfulReadiness(launcher, "Secure MCP Tunnel passed readiness");
      const tunnelStart = JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8"));
      expect(tunnelStart).not.toHaveProperty("listenAddr");
      expect(tunnelStart.unixSocket).toBe(fixture.paths.healthSocket);
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      await expect(launcherExit).resolves.toEqual([0, null]);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("lets an explicit health environment override win over the profile YAML listener", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const configuredPort = await reservePort();
    await writeFile(fixture.paths.profileFile, `health:\n  listen_addr: 127.0.0.1:${configuredPort}\n`, "utf8");
    const launcher = startLauncher(fixture, { HEALTH_LISTEN_ADDR: "127.0.0.1:0" });
    try {
      await waitForSuccessfulReadiness(launcher, "Secure MCP Tunnel passed readiness");
      expect(JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8")).listenAddr).toBe("127.0.0.1:0");
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      await expect(launcherExit).resolves.toEqual([0, null]);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("uses APPDATA for a Windows named profile when no higher-precedence directory is set", async () => {
    const fixture = await createFixture();
    const [appDataPort, userProfileDecoyPort] = await reservePorts(2);
    const appData = join(fixture.root, "roaming");
    const userProfile = join(fixture.root, "user-profile");
    const selectedDir = join(appData, "tunnel-client");
    const decoyDir = join(userProfile, ".config", "tunnel-client");
    const selectedProfile = await writeProfileHealth(selectedDir, appDataPort);
    await writeProfileHealth(decoyDir, userProfileDecoyPort);

    await assertProfileDirectorySelection(fixture, {
      platform: "win32",
      selectedDir,
      selectedProfile,
      port: appDataPort,
      overrides: { APPDATA: appData, USERPROFILE: userProfile }
    });
  });

  test("keeps an explicit Windows profile directory above XDG, HOME, and APPDATA", async () => {
    const fixture = await createFixture();
    const [selectedPort, xdgPort, homePort, appDataPort] = await reservePorts(4);
    const explicitDir = join(fixture.root, "explicit-profiles");
    const xdgHome = join(fixture.root, "xdg");
    const home = join(fixture.root, "home");
    const appData = join(fixture.root, "roaming");
    const selectedProfile = await writeProfileHealth(explicitDir, selectedPort);
    await writeProfileHealth(join(xdgHome, "tunnel-client"), xdgPort);
    await writeProfileHealth(join(home, ".config", "tunnel-client"), homePort);
    await writeProfileHealth(join(appData, "tunnel-client"), appDataPort);

    await assertProfileDirectorySelection(fixture, {
      platform: "win32",
      selectedDir: explicitDir,
      selectedProfile,
      port: selectedPort,
      overrides: {
        TUNNEL_CLIENT_PROFILE_DIR: explicitDir,
        XDG_CONFIG_HOME: xdgHome,
        HOME: home,
        APPDATA: appData
      }
    });
  });

  test("uses XDG_CONFIG_HOME ahead of HOME and the Windows config directory", async () => {
    const fixture = await createFixture();
    const [xdgPort, homePort, appDataPort] = await reservePorts(3);
    const xdgHome = join(fixture.root, "xdg");
    const home = join(fixture.root, "home");
    const appData = join(fixture.root, "roaming");
    const selectedDir = join(xdgHome, "tunnel-client");
    const selectedProfile = await writeProfileHealth(selectedDir, xdgPort);
    await writeProfileHealth(join(home, ".config", "tunnel-client"), homePort);
    await writeProfileHealth(join(appData, "tunnel-client"), appDataPort);

    await assertProfileDirectorySelection(fixture, {
      platform: "win32",
      selectedDir,
      selectedProfile,
      port: xdgPort,
      overrides: { XDG_CONFIG_HOME: xdgHome, HOME: home, APPDATA: appData }
    });
  });

  test("uses HOME ahead of the Windows UserConfigDir fallback", async () => {
    const fixture = await createFixture();
    const [homePort, appDataPort] = await reservePorts(2);
    const home = join(fixture.root, "home");
    const appData = join(fixture.root, "roaming");
    const selectedDir = join(home, ".config", "tunnel-client");
    const selectedProfile = await writeProfileHealth(selectedDir, homePort);
    await writeProfileHealth(join(appData, "tunnel-client"), appDataPort);

    await assertProfileDirectorySelection(fixture, {
      platform: "win32",
      selectedDir,
      selectedProfile,
      port: homePort,
      overrides: { HOME: home, APPDATA: appData }
    });
  });

  test.each(["darwin", "linux"])("preserves HOME-based profile lookup on %s", async (platform) => {
    const fixture = await createFixture();
    const [homePort, appDataPort] = await reservePorts(2);
    const home = join(fixture.root, "home");
    const appData = join(fixture.root, "roaming");
    const selectedDir = join(home, ".config", "tunnel-client");
    const selectedProfile = await writeProfileHealth(selectedDir, homePort);
    await writeProfileHealth(join(appData, "tunnel-client"), appDataPort);

    await assertProfileDirectorySelection(fixture, {
      platform,
      selectedDir,
      selectedProfile,
      port: homePort,
      overrides: { HOME: home, APPDATA: appData }
    });
  });

  test("cancels and reaps an in-flight tunnel health helper on shutdown", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, { TUNNEL_TEST_HEALTH_MODE: "hang" });
    try {
      const helperPid = Number(await waitForFile(fixture.paths.tunnelHelperPidMarker, launcher, isPositiveIntegerText, { requireLauncherAlive: true }));
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      const [code] = await launcherExit;
      expect(code, launcher.output()).toBe(0);
      expect(isPidRunning(helperPid)).toBe(false);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("does not launch the tunnel when the configured MCP port is already occupied", async () => {
    const fixture = await createFixture();
    const occupied = createServer();
    reservedServers.add(occupied);
    await new Promise((resolveListen, reject) => {
      occupied.once("error", reject);
      occupied.listen(0, "127.0.0.1", resolveListen);
    });
    const port = occupied.address().port;
    const launcher = startLauncher(fixture, { PORT: String(port) });
    try {
      const launcherExit = once(launcher.child, "exit");
      await waitForFile(fixture.paths.mcpBindErrorMarker, launcher, isCompleteJsonObject);
      const [code] = await launcherExit;
      expect(code).not.toBe(0);
      expect(existsSync(fixture.paths.tunnelStartedMarker)).toBe(false);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("preserves caller health settings and requires its stale URL file to be refreshed", async () => {
    const fixture = await createFixture();
    const callerUrlFile = fixture.paths.callerHealthUrlFile;
    await writeFile(callerUrlFile, "http://127.0.0.1:1\n", { mode: 0o600 });
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, {
      HEALTH_LISTEN_ADDR: "127.0.0.1:0",
      HEALTH_URL_FILE: callerUrlFile
    });
    try {
      await waitForFile(fixture.paths.tunnelStartedMarker, launcher, isCompleteJsonObject, { requireLauncherAlive: true });
      const tunnelStart = JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8"));
      expect(tunnelStart.listenAddr).toBe("127.0.0.1:0");
      expect(tunnelStart.urlFile).toBe(callerUrlFile);
      await waitForFile(fixture.paths.tunnelReadyMarker, launcher, "ready", { requireLauncherAlive: true });
      expect(await readFile(callerUrlFile, "utf8")).not.toBe("http://127.0.0.1:1\n");
      await waitForSuccessfulReadiness(launcher, "Secure MCP Tunnel passed readiness");
      const launcherExit = once(launcher.child, "exit");
      const mcpStopped = waitForFile(fixture.paths.mcpStoppedMarker, launcher, "stopped");
      const tunnelStopped = waitForFile(fixture.paths.tunnelStoppedMarker, launcher, "stopped");
      launcher.child.kill("SIGTERM");
      const [code] = await launcherExit;
      expect(code).toBe(0);
      await expect(mcpStopped).resolves.toBe("stopped");
      await expect(tunnelStopped).resolves.toBe("stopped");
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("rejects a refreshed caller URL file when another process owns its endpoint", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.callerHealthUrlFile, "http://127.0.0.1:1\n", { mode: 0o600 });
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, {
      HEALTH_LISTEN_ADDR: "127.0.0.1:0",
      HEALTH_URL_FILE: fixture.paths.callerHealthUrlFile,
      MCP_TEST_HEALTH_OWNER_MODE: "different-process"
    });
    try {
      const outcome = await Promise.race([
        waitForOutput(launcher, "Secure MCP Tunnel passed readiness").then((result) => result.kind === "output" ? "ready" : result.kind === "closed" ? "exited" : result.kind),
        once(launcher.child, "exit").then(() => "exited")
      ]);

      expect(outcome).toBe("exited");
      expect(launcher.child.exitCode).not.toBe(0);
      expect(launcher.output()).toContain("health endpoint is not owned by the newly launched tunnel process");
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("rejects a different process owning the private default health endpoint", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, { MCP_TEST_HEALTH_OWNER_MODE: "different-process" });
    try {
      const outcome = await Promise.race([
        waitForOutput(launcher, "Secure MCP Tunnel passed readiness").then((result) => result.kind === "output" ? "ready" : result.kind === "closed" ? "exited" : result.kind),
        once(launcher.child, "exit").then(() => "exited")
      ]);

      expect(outcome).toBe("exited");
      expect(launcher.child.exitCode).not.toBe(0);
      expect(launcher.output()).toContain("Tunnel health endpoint is not owned by the newly launched tunnel process.");
      expect(existsSync(fixture.paths.tunnelReadyMarker)).toBe(false);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("rejects an invalid Go duration before starting either component", async () => {
    const fixture = await createFixture();
    const launcher = startLauncher(fixture, { MCP_STARTUP_WAIT_TIMEOUT: "30 seconds" });
    const [code] = await once(launcher.child, "exit");

    expect(code).not.toBe(0);
    expect(launcher.output()).toContain("MCP_STARTUP_WAIT_TIMEOUT must use Go time.Duration syntax");
    expect(existsSync(fixture.paths.mcpBoundMarker)).toBe(false);
    expect(existsSync(fixture.paths.tunnelStartedMarker)).toBe(false);
  });

  test("rejects readiness when the launcher exits after the marker read", async () => {
    const fixture = await createFixture();
    const port = await reservePort();
    const afterMarkerRead = async (launcher) => {
      const exited = once(launcher.child, "exit");
      expect(launcher.child.kill("SIGKILL")).toBe(true);
      await exited;
    };

    await expect(assertHealthProfileReady(
      fixture,
      "health:\n  listen_addr: env:TEST_PROFILE_HEALTH_ADDR\n",
      {
        HEALTH_LISTEN_ADDR: null,
        HEALTH_UNIX_SOCKET: null,
        TEST_PROFILE_HEALTH_ADDR: `127.0.0.1:${port}`
      },
      { listenAddr: `127.0.0.1:${port}` },
      { afterMarkerRead }
    )).rejects.toThrow("exited during readiness validation");
  });

  test("resolves an env reference for the selected TCP health listener", async () => {
    const fixture = await createFixture();
    const port = await reservePort();

    const marker = await assertHealthProfileReady(
      fixture,
      "health:\n  listen_addr: EnV:TEST_PROFILE_HEALTH_ADDR\n",
      {
        HEALTH_LISTEN_ADDR: null,
        HEALTH_UNIX_SOCKET: null,
        TEST_PROFILE_HEALTH_ADDR: `127.0.0.1:${port}`
      },
      { listenAddr: `127.0.0.1:${port}` }
    );

    expect(marker.listenAddr).toBe(`127.0.0.1:${port}`);
  });

  test("resolves a file reference for the selected TCP health listener", async () => {
    const fixture = await createFixture();
    const port = await reservePort();
    const valueFile = join(fixture.root, "health-listen-address");
    await writeFile(valueFile, `127.0.0.1:${port}\n`, "utf8");

    const marker = await assertHealthProfileReady(
      fixture,
      `health:\n  listen_addr: file:${valueFile}\n`,
      { HEALTH_LISTEN_ADDR: null, HEALTH_UNIX_SOCKET: null },
      { listenAddr: `127.0.0.1:${port}` }
    );

    expect(marker.listenAddr).toBe(`127.0.0.1:${port}`);
  });

  test("resolves an env reference for the selected Unix health socket", async () => {
    const fixture = await createFixture();

    const marker = await assertHealthProfileReady(
      fixture,
      "health:\n  unix_socket: env:ISSUE42_PROFILE_HEALTH_SOCKET\n",
      {
        HEALTH_LISTEN_ADDR: null,
        HEALTH_UNIX_SOCKET: null,
        ISSUE42_PROFILE_HEALTH_SOCKET: fixture.paths.healthSocket
      },
      { unixSocket: fixture.paths.healthSocket }
    );

    expect(marker.unixSocket).toBe(fixture.paths.healthSocket);
  });

  test("resolves a file reference for the selected Unix health socket", async () => {
    const fixture = await createFixture();
    const valueFile = join(fixture.root, "health-unix-socket");
    await writeFile(valueFile, `${fixture.paths.healthSocket}\n`, "utf8");

    const marker = await assertHealthProfileReady(
      fixture,
      `health:\n  unix_socket: FiLe:${valueFile}\n`,
      { HEALTH_LISTEN_ADDR: null, HEALTH_UNIX_SOCKET: null },
      { unixSocket: fixture.paths.healthSocket }
    );

    expect(marker.unixSocket).toBe(fixture.paths.healthSocket);
  });

  test("keeps the direct health environment override above a valid profile reference", async () => {
    const fixture = await createFixture();
    const profilePort = await reservePort();
    const overridePort = await reservePort();

    const marker = await assertHealthProfileReady(
      fixture,
      "health:\n  listen_addr: env:TEST_PROFILE_HEALTH_ADDR\n",
      {
        HEALTH_LISTEN_ADDR: `127.0.0.1:${overridePort}`,
        HEALTH_UNIX_SOCKET: null,
        TEST_PROFILE_HEALTH_ADDR: `127.0.0.1:${profilePort}`
      },
      { listenAddr: `127.0.0.1:${overridePort}` }
    );

    expect(marker.listenAddr).toBe(`127.0.0.1:${overridePort}`);
  });

  test("rejects a missing TCP profile reference before applying an environment override", async () => {
    const fixture = await createFixture();
    await expectHealthProfileRejected(
      fixture,
      "health:\n  listen_addr: env:ISSUE42_MISSING_HEALTH_ADDR\n",
      { HEALTH_LISTEN_ADDR: "127.0.0.1:0", HEALTH_UNIX_SOCKET: null },
      "health.listen_addr",
      "ISSUE42_MISSING_HEALTH_ADDR"
    );
  });

  test("rejects an unreadable Unix socket file reference without exposing its path", async () => {
    const fixture = await createFixture();
    const missingValueFile = join(fixture.root, "private-health-value");
    await expectHealthProfileRejected(
      fixture,
      `health:\n  unix_socket: file:${missingValueFile}\n`,
      { HEALTH_LISTEN_ADDR: null, HEALTH_UNIX_SOCKET: fixture.paths.healthSocket },
      "health.unix_socket",
      missingValueFile
    );
  });

  test("rejects a missing Unix socket environment reference before applying an override", async () => {
    const fixture = await createFixture();
    const variableName = "ISSUE42_MISSING_HEALTH_SOCKET";
    await expectHealthProfileRejected(
      fixture,
      `health:\n  unix_socket: env:${variableName}\n`,
      { HEALTH_LISTEN_ADDR: null, HEALTH_UNIX_SOCKET: fixture.paths.healthSocket, [variableName]: null },
      "health.unix_socket",
      variableName
    );
  });

  test("rejects an invalid referenced TCP address without logging its resolved value", async () => {
    const fixture = await createFixture();
    const privateValue = "private-health-address";
    await expectHealthProfileRejected(
      fixture,
      "health:\n  listen_addr: env:ISSUE42_INVALID_HEALTH_ADDR\n",
      {
        HEALTH_LISTEN_ADDR: null,
        HEALTH_UNIX_SOCKET: null,
        ISSUE42_INVALID_HEALTH_ADDR: `${privateValue}\ninvalid`
      },
      "health.listen_addr",
      privateValue
    );
  });

  test("treats a malformed managed-process marker as a cleanup failure", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture);
    const markerPath = fixture.paths.tunnelStartedMarker;
    await waitForSuccessfulReadiness(launcher, "Secure MCP Tunnel passed readiness");
    await waitForFile(markerPath, launcher, isCompleteJsonObject, { requireLauncherAlive: true });
    const originalMarker = await readFile(markerPath, "utf8");
    await writeFile(markerPath, "{", "utf8");

    try {
      await expect(stopLauncher(launcher)).rejects.toThrow("cleanup was incomplete");
    } finally {
      await writeFile(markerPath, originalMarker, "utf8");
      launcher.stopPromise = null;
    }
  });

  test("treats a missing managed-process marker after readiness as a cleanup failure", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture);
    const markerPath = fixture.paths.tunnelStartedMarker;
    await waitForSuccessfulReadiness(launcher, "Secure MCP Tunnel passed readiness");
    await waitForFile(markerPath, launcher, isCompleteJsonObject, { requireLauncherAlive: true });
    const originalMarker = await readFile(markerPath, "utf8");
    await rm(markerPath);

    try {
      await expect(stopLauncher(launcher)).rejects.toThrow("cleanup was incomplete");
    } finally {
      await writeFile(markerPath, originalMarker, "utf8");
      launcher.stopPromise = null;
    }
  }, 10_000);
});

/** Accept the health marker only while its launcher is alive; tests can trigger an exit after the asynchronous read. */
async function assertHealthProfileReady(fixture, profile, overrides, expected, { afterMarkerRead } = {}) {
  await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
  await writeFile(fixture.paths.profileFile, profile, "utf8");
  const launcher = startLauncher(fixture, overrides);
  try {
    const outcome = await waitForOutput(launcher, "Secure MCP Tunnel passed readiness");
    if (outcome.kind !== "output") {
      const diagnostic = await collectLauncherDiagnostics(launcher, { readinessOutcome: outcome });
      throw new Error(`Secure connector exited before readiness: ${JSON.stringify(diagnostic)}`);
    }
    const markerContents = await readFile(fixture.paths.tunnelStartedMarker, "utf8");
    await afterMarkerRead?.(launcher);
    if (launcher.child.exitCode !== null || launcher.child.signalCode !== null
      || launcher.timeline.exitedAfterMs !== null) {
      const diagnostic = await collectLauncherDiagnostics(launcher, {
        readinessOutcome: outcome,
        markerValidation: "launcher_exited"
      });
      throw new Error(`Secure connector exited during readiness validation: ${JSON.stringify(diagnostic)}`);
    }
    const marker = JSON.parse(markerContents);
    expect(marker).toMatchObject(expected);
    return marker;
  } finally {
    await stopLauncher(launcher);
  }
}

async function expectHealthProfileRejected(fixture, profile, overrides, field, hiddenValue) {
  await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
  await writeFile(fixture.paths.profileFile, profile, "utf8");
  const launcher = startLauncher(fixture, overrides);
  try {
    const [code] = await once(launcher.child, "close");
    expect(code).not.toBe(0);
    expect(launcher.output()).toContain(field);
    expect(launcher.output()).not.toContain(hiddenValue);
    expect(existsSync(fixture.paths.tunnelStartedMarker)).toBe(false);
  } finally {
    await stopLauncher(launcher);
  }
}

async function createFixture() {
  const root = await mkdtemp(join(tmpdir(), "connect-secure-startup-"));
  fixtures.add(root);
  const bin = join(root, "bin");
  await mkdir(bin);
  await mkdir(join(root, "profiles"));
  const paths = {
    config: join(root, "config.json"),
    mcpReadyFile: join(root, "mcp-ready"),
    mcpBoundMarker: join(root, "mcp-bound.json"),
    mcpProbeMarker: join(root, "mcp-probe"),
    mcpRouteMarker: join(root, "mcp-route"),
    mcpBindErrorMarker: join(root, "mcp-bind-error.json"),
    mcpStoppedMarker: join(root, "mcp-stopped"),
    callerHealthUrlFile: join(root, "caller-health.url"),
    profileDir: join(root, "profiles"),
    profileFile: join(root, "profiles", "issue-42-test-profile.yaml"),
    healthSocket: join(root, "health.sock"),
    tunnelStartedMarker: join(root, "tunnel-started.json"),
    tunnelReadyMarker: join(root, "tunnel-ready"),
    tunnelHelperLog: join(root, "tunnel-helper-calls.log"),
    taskkillLog: join(root, "taskkill-targets.log"),
    tunnelHelperPidMarker: join(root, "tunnel-health-helper.pid"),
    tunnelStoppedMarker: join(root, "tunnel-stopped"),
    windowsPlatformPreload: join(root, "simulate-windows-platform.mjs")
  };
  await writeFile(paths.config, JSON.stringify({ repos: [], limits: {} }), "utf8");
  const npmScript = join(bin, "npm.mjs");
  const lsofScript = join(bin, "lsof.mjs");
  const taskkillScript = join(bin, "taskkill.mjs");
  const powershellScript = join(bin, "powershell.mjs");
  const tunnelClient = join(root, "tunnel-client.mjs");
  await writeFile(npmScript, fakeNpmSource(), { mode: 0o755 });
  await writeFile(lsofScript, fakeLsofSource(), { mode: 0o755 });
  await writeFile(taskkillScript, fakeTaskkillSource(), { mode: 0o755 });
  await writeFile(powershellScript, fakePowershellSource(), { mode: 0o755 });
  await writeFile(paths.windowsPlatformPreload, windowsPlatformPreloadSource(), "utf8");
  await writeFile(tunnelClient, fakeTunnelClientSource(), { mode: 0o755 });
  await chmod(npmScript, 0o755);
  await chmod(lsofScript, 0o755);
  await chmod(taskkillScript, 0o755);
  await chmod(powershellScript, 0o755);
  await chmod(tunnelClient, 0o755);
  await symlink(npmScript, join(bin, "npm"));
  await symlink(lsofScript, join(bin, "lsof"));
  await symlink(taskkillScript, join(bin, "taskkill.exe"));
  await symlink(powershellScript, join(bin, "powershell.exe"));
  return { root, bin, paths, tunnelClient };
}

/** Start the connector fixture with separate bounded stdout and stderr captures. */
function startLauncher(fixture, overrides = {}) {
  const env = {
    ...process.env,
    PATH: `${fixture.bin}:${process.env.PATH ?? ""}`,
    CONTROL_PLANE_API_KEY: "synthetic-test-key",
    GPT_REPO_CONFIG: fixture.paths.config,
    GPT_REPO_PUBLIC_PATH_TOKEN: "route token/42",
    PORT: "0",
    MCP_STARTUP_WAIT_TIMEOUT: "2.25s",
    TUNNEL_STARTUP_WAIT_TIMEOUT: "4s",
    TUNNEL_CLIENT_PROFILE: "issue-42-test-profile",
    TUNNEL_CLIENT_PROFILE_DIR: fixture.paths.profileDir,
    TUNNEL_CLIENT_BIN: fixture.tunnelClient,
    MCP_TEST_READY_FILE: fixture.paths.mcpReadyFile,
    MCP_TEST_BOUND_MARKER: fixture.paths.mcpBoundMarker,
    MCP_TEST_PROBE_MARKER: fixture.paths.mcpProbeMarker,
    MCP_TEST_ROUTE_MARKER: fixture.paths.mcpRouteMarker,
    MCP_TEST_BIND_ERROR_MARKER: fixture.paths.mcpBindErrorMarker,
    MCP_TEST_STOP_MARKER: fixture.paths.mcpStoppedMarker,
    TUNNEL_TEST_START_MARKER: fixture.paths.tunnelStartedMarker,
    TUNNEL_TEST_HELPER_LOG: fixture.paths.tunnelHelperLog,
    TUNNEL_TEST_TASKKILL_LOG: fixture.paths.taskkillLog,
    TUNNEL_TEST_READY_MARKER: fixture.paths.tunnelReadyMarker,
    TUNNEL_TEST_HELPER_PID_MARKER: fixture.paths.tunnelHelperPidMarker,
    TUNNEL_TEST_STOP_MARKER: fixture.paths.tunnelStoppedMarker,
    ...overrides
  };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === null) delete env[key];
  }
  const secrets = collectSecretValues(env);
  const stdout = createBoundedCapture(MAX_DIAGNOSTIC_STREAM_BYTES);
  const stderr = createBoundedCapture(MAX_DIAGNOSTIC_STREAM_BYTES);
  const combined = createBoundedCapture(2 * MAX_DIAGNOSTIC_STREAM_BYTES);
  const startedAt = performance.now();
  const startedAtEpochMs = Date.now();
  const timeline = { startedAt: new Date(startedAtEpochMs).toISOString(), spawnedAfterMs: null, exitedAfterMs: null, closedAfterMs: null };
  const child = spawn(process.execPath, [connectScript], {
    cwd: fixture.root,
    env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout.on("data", (chunk) => { stdout.append(chunk); combined.append(chunk); });
  child.stderr.on("data", (chunk) => { stderr.append(chunk); combined.append(chunk); });
  child.once("spawn", () => { timeline.spawnedAfterMs = performance.now() - startedAt; });
  child.once("exit", (code, signal) => {
    timeline.exitedAfterMs = performance.now() - startedAt;
    timeline.exitCode = code;
    timeline.signal = signal;
  });
  child.once("close", (code, signal) => {
    timeline.closedAfterMs = performance.now() - startedAt;
    timeline.closeCode = code;
    timeline.closeSignal = signal;
  });
  const launcher = {
    id: randomUUID(),
    child,
    fixture,
    secrets,
    startedAt,
    startedAtEpochMs,
    timeline,
    stdout: () => stdout.snapshot(secrets),
    stderr: () => stderr.snapshot(secrets),
    output: () => combined.snapshot(secrets).text
  };
  launchers.add(launcher);
  return launcher;
}

function fakeNpmSource() {
  return `#!/usr/bin/env node
import { existsSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";

const host = process.env.GPT_REPO_HOST || "127.0.0.1";
const port = Number(process.env.PORT);
const readyFile = process.env.MCP_TEST_READY_FILE;
if (process.env.MCP_TEST_EXIT_EARLY === "0") process.exit(0);
const effectiveToken = process.env.GPT_REPO_PUBLIC_PATH_TOKEN ?? process.env.REPO_READER_PUBLIC_PATH_TOKEN;
const route = effectiveToken ? "/t/" + encodeURIComponent(effectiveToken) + "/mcp" : "/mcp";
const sessionId = "isolated-startup-probe-session";
const server = createServer(async (request, response) => {
  writeFileSync(process.env.MCP_TEST_ROUTE_MARKER, request.url);
  let raw = "";
  for await (const chunk of request) raw += chunk.toString();
  if (request.url !== route) { response.writeHead(404).end(); return; }
  if (request.method === "DELETE") { response.writeHead(200).end(); return; }
  const body = raw ? JSON.parse(raw) : {};
  if (body.method === "initialize") {
    if (!existsSync(readyFile)) {
      writeFileSync(process.env.MCP_TEST_PROBE_MARKER, "probe-seen");
      response.writeHead(503).end();
      return;
    }
    response.writeHead(200, { "content-type": "application/json", "mcp-session-id": sessionId });
    response.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2025-03-26" } }));
    return;
  }
  if (body.method === "notifications/initialized") { response.writeHead(202).end(); return; }
  if (body.method === "tools/list") {
    response.writeHead(200, { "content-type": "application/json", "mcp-session-id": sessionId });
    response.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { tools: [{ name: "repo_list_roots" }] } }));
    return;
  }
  response.writeHead(400).end();
});
process.on("SIGTERM", () => {
  writeFileSync(process.env.MCP_TEST_STOP_MARKER, "stopped");
  server.close(() => process.exit(0));
});
server.once("error", (error) => {
  writeFileSync(process.env.MCP_TEST_BIND_ERROR_MARKER, JSON.stringify({ pid: process.pid, code: error.code }));
  process.exit(1);
});
server.listen(port, host, () => {
  const address = server.address();
  const actualPort = typeof address === "object" ? address.port : port;
  const urlHost = host.includes(":") ? "[" + host + "]" : host;
  const displayRoute = effectiveToken ? "/t/[token]/mcp" : "/mcp";
  writeFileSync(process.env.MCP_TEST_BOUND_MARKER, JSON.stringify({ pid: process.pid, port: actualPort }));
  process.stderr.write("gpt-repo-mcp listening on http://" + urlHost + ":" + actualPort + displayRoute + "\\n");
});
`;
}

function fakeTunnelClientSource() {
  return `#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
if (args[0] !== "run") writeFileSync(process.env.TUNNEL_TEST_HELPER_LOG, args.slice(0, 2).join(" ") + "\\t" + process.pid + "\\n", { flag: "a" });
if (args[0] === "health" && args[1] === "--help") {
  if (process.env.TUNNEL_TEST_HELP_MODE === "hang") {
    writeFileSync(process.env.TUNNEL_TEST_HELPER_PID_MARKER, String(process.pid));
    process.on("SIGTERM", () => {});
    setInterval(() => {}, 1000);
    await new Promise(() => {});
  }
  process.stdout.write("Usage:\\n  tunnel-client health [flags]\\n--json --require-control-plane-poll --pid --url-file\\n");
  process.exit(0);
}

if (args[0] === "run" && args[1] === "--help") {
  process.stdout.write("HEALTH_LISTEN_ADDR HEALTH_URL_FILE\\n");
  process.exit(0);
}
if (args[0] === "health") {
  if (process.env.TUNNEL_TEST_HEALTH_MODE === "hang") {
    writeFileSync(process.env.TUNNEL_TEST_HELPER_PID_MARKER, String(process.pid));
    process.on("SIGTERM", () => {});
    setInterval(() => {}, 1000);
    await new Promise(() => {});
  }
  const pid = Number(args[args.indexOf("--pid") + 1]);
  const urlFile = args[args.indexOf("--url-file") + 1];
  const baseUrl = readFileSync(urlFile, "utf8").trim();
  const result = { process: { pid, running: true }, base_url: baseUrl, healthz: { ok: true }, readyz: { ok: true }, control_plane_poll: { ok: true, value: 1 }, result: "ok" };
  writeFileSync(process.env.TUNNEL_TEST_READY_MARKER, "ready");
  process.stdout.write(JSON.stringify(result));
  process.exit(0);
}
if (args[0] !== "run") process.exit(64);
if (process.env.TUNNEL_TEST_EXIT_EARLY === "0") {
  writeFileSync(process.env.TUNNEL_TEST_START_MARKER, JSON.stringify({ pid: process.pid }));
  process.exit(0);
}

const profile = args[args.indexOf("--profile") + 1];
const explicitProfileDir = process.env.TUNNEL_CLIENT_PROFILE_DIR?.trim();
const xdgConfigHome = process.env.XDG_CONFIG_HOME?.trim();
const home = process.env.HOME?.trim();
const configHome = xdgConfigHome || (home ? join(home, ".config") : process.platform === "win32" ? process.env.APPDATA : undefined);
if (!explicitProfileDir && !configHome) throw new Error("Test tunnel profile directory is not configured.");
const profileDir = explicitProfileDir || join(configHome, "tunnel-client");
const profilePath = process.env.TUNNEL_CLIENT_PROFILE_FILE || process.env.TUNNEL_CLIENT_CONFIG || join(profileDir, profile + ".yaml");
const yaml = existsSync(profilePath) ? readFileSync(profilePath, "utf8") : "";
const yamlSetting = (name) => yaml.match(new RegExp("^\\\\s*" + name + ":\\\\s*([^\\\\r\\\\n#]+)", "m"))?.[1]?.trim();
const resolveYamlSetting = (raw) => {
 if (!raw) return undefined;
 const value = raw.trim();
 const lower = value.toLowerCase();
 let resolved = value;
 if (lower.startsWith("env:")) {
  const name = value.slice(4).trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || !process.env[name]?.trim()) throw new Error("Invalid test health reference.");
  resolved = process.env[name].trim();
 } else if (lower.startsWith("file:")) {
  const path = value.slice(5).trim();
  try { resolved = readFileSync(path, "utf8").trim(); } catch { throw new Error("Invalid test health reference."); }
 }
 if (!resolved || resolved.includes(String.fromCharCode(10)) || resolved.includes(String.fromCharCode(13))) throw new Error("Invalid test health reference.");
 return resolved;
};
const profileListener = resolveYamlSetting(yamlSetting("listen_addr"));
const profileSocket = resolveYamlSetting(yamlSetting("unix_socket"));
const listener = process.env.HEALTH_LISTEN_ADDR || profileListener;
const socket = process.env.HEALTH_UNIX_SOCKET || profileSocket;
const effectiveListener = listener || (!socket ? "127.0.0.1:0" : undefined);
const separator = effectiveListener?.lastIndexOf(":") ?? -1;
const host = effectiveListener?.slice(0, separator).replace(/^\\\\[|\\\\]$/g, "") || "127.0.0.1";
const port = effectiveListener ? Number(effectiveListener.slice(separator + 1)) : undefined;
const server = createServer((request, response) => {
  if (request.url === "/healthz") { response.writeHead(200).end("live"); return; }
  if (request.url === "/readyz") { response.writeHead(200).end("ready"); return; }
  if (request.url === "/metrics") {
    const newline = String.fromCharCode(10);
    response.writeHead(200, { "content-type": "text/plain" });
    response.end(["# TYPE commands_poll_last_successful_timestamp_seconds gauge", "commands_poll_last_successful_timestamp_seconds 1"].join(newline) + newline);
    return;
  }
  response.writeHead(404).end();
});
process.on("SIGTERM", () => {
  writeFileSync(process.env.TUNNEL_TEST_STOP_MARKER, "stopped");
  server.close(() => process.exit(0));
});
writeFileSync(process.env.TUNNEL_TEST_START_MARKER, JSON.stringify({
  pid: process.pid,
  profile: args[args.indexOf("--profile") + 1],
  profilePath: resolve(profilePath),
  mcpTimeout: process.env.MCP_STARTUP_WAIT_TIMEOUT,
  tunnelTimeout: process.env.TUNNEL_STARTUP_WAIT_TIMEOUT,
  listenAddr: listener,
  unixSocket: socket,
  urlFile: process.env.HEALTH_URL_FILE
}));
server.once("error", () => process.exit(2));
server.listen(socket || port, socket ? undefined : host, () => {
  const address = server.address();
  const resolvedUrl = socket ? "http://127.0.0.1" : "http://127.0.0.1:" + (typeof address === "object" ? address.port : port);
  writeFileSync(process.env.HEALTH_URL_FILE, resolvedUrl + "\\n", { mode: 0o600 });
});
`;
}

function fakeLsofSource() {
  return `#!/usr/bin/env node
import { readFileSync } from "node:fs";
const args = process.argv.slice(2);
const pidIndex = args.indexOf("-p");
const requestedPid = Number(args[pidIndex + 1]);
const pid = process.env.MCP_TEST_HEALTH_OWNER_MODE === "different-process" ? requestedPid + 1 : requestedPid;
const name = args.includes("-U")
  ? JSON.parse(readFileSync(process.env.TUNNEL_TEST_START_MARKER, "utf8")).unixSocket
  : "127.0.0.1:" + Number(args.find((argument) => argument.startsWith("-iTCP:"))?.slice("-iTCP:".length));
process.stdout.write("p" + pid + "\\ntIPv4\\nn" + name + "\\n");
`;
}

function windowsPlatformPreloadSource(platform = "win32") {
  return `const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
Object.defineProperty(process, "platform", { ...descriptor, value: ${JSON.stringify(platform)} });
`;
}

function fakeTaskkillSource() {
  return `#!/bin/sh
pid=
forced=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    /PID) shift; pid="$1" ;;
    /F) forced=true ;;
  esac
  shift
done
printf '%s\\n' "$pid" >> "$TUNNEL_TEST_TASKKILL_LOG"
if [ "$forced" = true ] && kill -0 "$pid" 2>/dev/null; then
  kill -KILL "$pid" 2>/dev/null || exit 1
fi
`;
}

function fakePowershellSource() {
  return `#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
const start = JSON.parse(readFileSync(process.env.TUNNEL_TEST_START_MARKER, "utf8"));
const url = new URL(readFileSync(start.urlFile, "utf8").trim());
const pid = start.pid;
writeFileSync(process.env.TUNNEL_TEST_HELPER_LOG, "powershell\\t" + process.pid + "\\n", { flag: "a" });
process.stdout.write(JSON.stringify({ LocalAddress: url.hostname, LocalPort: Number(url.port), OwningProcess: pid }));
`;
}

async function reservePort() {
  const server = createServer();
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const port = server.address().port;
  await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  return port;
}

async function reservePorts(count) {
  const servers = Array.from({ length: count }, () => createServer());
  await Promise.all(servers.map((server) => new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  })));
  const ports = servers.map((server) => server.address().port);
  await Promise.all(servers.map((server) => new Promise((resolveClose, reject) => {
    server.close((error) => error ? reject(error) : resolveClose());
  })));
  return ports;
}

async function writeProfileHealth(profileDir, port) {
  await mkdir(profileDir, { recursive: true });
  const profilePath = join(profileDir, "issue-42-test-profile.yaml");
  await writeFile(profilePath, `health:\n  listen_addr: 127.0.0.1:${port}\n`, "utf8");
  return profilePath;
}

async function assertProfileDirectorySelection(fixture, { platform, selectedDir, selectedProfile, port, overrides }) {
  await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
  let preloadPath = fixture.paths.windowsPlatformPreload;
  if (platform !== "win32") {
    preloadPath = join(fixture.root, `simulate-${platform}-platform.mjs`);
    await writeFile(preloadPath, windowsPlatformPreloadSource(platform), "utf8");
  }
  const nodeOptions = [process.env.NODE_OPTIONS, `--import=${preloadPath}`].filter(Boolean).join(" ");
  const launcher = startLauncher(fixture, {
    NODE_OPTIONS: nodeOptions,
    TEMP: tmpdir(),
    TMP: tmpdir(),
    TUNNEL_CLIENT_PROFILE_DIR: null,
    TUNNEL_CLIENT_PROFILE_FILE: null,
    TUNNEL_CLIENT_CONFIG: null,
    XDG_CONFIG_HOME: null,
    HOME: null,
    HEALTH_LISTEN_ADDR: null,
    HEALTH_UNIX_SOCKET: null,
    ...overrides
  });
  try {
    await waitForSuccessfulReadiness(launcher, "Secure MCP Tunnel passed readiness");
    const tunnelStart = JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8"));
    expect(tunnelStart.profile).toBe("issue-42-test-profile");
    expect(tunnelStart.profilePath).toBe(selectedProfile);
    expect(tunnelStart.listenAddr).toBe(`127.0.0.1:${port}`);
    expect(tunnelStart.listenAddr).not.toBe("127.0.0.1:0");
    expect(selectedDir).toBe(dirname(selectedProfile));
    const launcherExit = once(launcher.child, "exit");
    launcher.child.kill("SIGTERM");
    await expect(launcherExit).resolves.toEqual([0, null]);
  } finally {
    await stopLauncher(launcher);
  }
}

function waitForLauncherExit(launcher) {
  if (launcher.child.exitCode !== null) return Promise.resolve([launcher.child.exitCode, null]);
  if (launcher.child.signalCode !== null) return Promise.resolve([null, launcher.child.signalCode]);
  return once(launcher.child, "exit");
}

function isCompleteJsonObject(contents) {
  try {
    const value = JSON.parse(contents);
    return value !== null && typeof value === "object" && !Array.isArray(value);
  } catch {
    return false;
  }
}

function isPositiveIntegerText(contents) {
  return /^[1-9]\d*$/.test(contents.trim());
}

/** Wait for marker contents and optionally require the launcher to stay alive. */
async function waitForFile(path, launcher, expected, dependencies = {}) {
  if (typeof expected !== "string" && typeof expected !== "function") {
    throw new TypeError("waitForFile requires expected marker contents or a predicate");
  }
  const matchesExpected = typeof expected === "function" ? expected : (contents) => contents === expected;
  const readMarker = dependencies.readFile ?? readFile;
  const watchMarker = dependencies.watch ?? watch;
  const requireLauncherAlive = dependencies.requireLauncherAlive === true;

  return new Promise((resolveRead, reject) => {
    let settled = false;
    let reading = false;
    let readAgain = false;
    let exitDetails;
    let watcher;
    let onWatcherError;

    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      launcher?.child.off("exit", onExit);
      let finalError = error;
      try {
        watcher?.off("error", onWatcherError);
        watcher?.close();
      } catch (closeError) {
        finalError ??= closeError;
      }
      if (finalError) reject(finalError);
      else resolveRead(value);
    };

    const incompleteError = () => new Error(
      `Launcher exited before ${path} was complete (code=${exitDetails.code}, signal=${exitDetails.signal}).\n${launcher.output()}`
    );
    const launcherExited = () => exitDetails !== undefined
      || Boolean(launcher?.child && (
        (launcher.child.exitCode !== null && launcher.child.exitCode !== undefined)
        || (launcher.child.signalCode !== null && launcher.child.signalCode !== undefined)
      ));

    const readAndCheck = async () => {
      try {
        const contents = await readMarker(path, "utf8");
        if (matchesExpected(contents)) {
          if (requireLauncherAlive && launcherExited()) finish(incompleteError());
          else finish(undefined, contents);
        } else if (exitDetails && !readAgain) {
          finish(incompleteError());
        }
      } catch (error) {
        if (error?.code === "ENOENT") {
          if (exitDetails && !readAgain) finish(incompleteError());
        } else {
          finish(error);
        }
      }
    };

    const runRequestedReads = async () => {
      try {
        do {
          readAgain = false;
          await readAndCheck();
        } while (readAgain && !settled);
      } finally {
        reading = false;
        if (readAgain && !settled) requestRead();
      }
    };

    const requestRead = () => {
      if (settled) return;
      if (reading) {
        readAgain = true;
        return;
      }
      reading = true;
      void runRequestedReads();
    };

    const onExit = (code, signal) => {
      exitDetails = { code, signal };
      requestRead();
    };
    onWatcherError = (error) => finish(error);

    try {
      watcher = watchMarker(dirname(path), () => requestRead());
      watcher.on("error", onWatcherError);
      launcher?.child?.once("exit", onExit);
      if (launcher?.child && (
        (launcher.child.exitCode !== null && launcher.child.exitCode !== undefined)
        || (launcher.child.signalCode !== null && launcher.child.signalCode !== undefined)
      )) {
        onExit(launcher.child.exitCode, launcher.child.signalCode);
      }
      requestRead();
    } catch (error) {
      finish(error);
    }
  });
}

function waitForSuccessfulReadiness(launcher, fragment) {
  return waitForOutput(launcher, fragment).then(async (result) => {
    if (result.kind !== "output") {
      const diagnostics = await collectLauncherDiagnostics(launcher, { readinessOutcome: result });
      throw new Error(`Launcher did not remain open through readiness output: ${JSON.stringify(diagnostics)}.`);
    }
    return result;
  });
}

/** Resolve on expected output or child exit; stream completeness is reported separately. */
function waitForOutput(launcher, fragment) {
  const hasExited = () => launcher.timeline?.closedAfterMs !== null
    && launcher.timeline?.closedAfterMs !== undefined
    || (launcher.child.exitCode !== null && launcher.child.exitCode !== undefined)
    || (launcher.child.signalCode !== null && launcher.child.signalCode !== undefined);
  const closedOutcome = (code, signal, closeObserved = false) => ({
    kind: "closed",
    code: code ?? launcher.timeline?.closeCode ?? launcher.child.exitCode ?? null,
    signal: signal ?? launcher.timeline?.closeSignal ?? launcher.child.signalCode ?? null,
    stdout: outputText(launcher.stdout()),
    stderr: outputText(launcher.stderr()),
    outputCapture: outputCaptureSummary(launcher, {
      closeObserved,
      reason: "streams_open_after_child_exit"
    }),
    elapsedMs: launcherElapsedMs(launcher)
  });
  if (launcher.output().includes(fragment)) {
    return Promise.resolve(hasExited() ? closedOutcome() : { kind: "output", elapsedMs: launcherElapsedMs(launcher) });
  }
  if (hasExited()) return Promise.resolve(closedOutcome());
  return new Promise((resolveOutput) => {
    let settled = false;
    const cleanup = () => {
      launcher.child.stdout?.off("data", check);
      launcher.child.stderr?.off("data", check);
      launcher.child.off("exit", onExit);
      launcher.child.off("close", onClose);
      launcher.child.off("error", onError);
    };
    const finish = (result) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolveOutput(result);
    };
    const check = () => {
      if (launcher.output().includes(fragment)) {
        finish(hasExited() ? closedOutcome() : { kind: "output", elapsedMs: launcherElapsedMs(launcher) });
      }
    };
    const onClose = (code, signal) => finish(closedOutcome(code, signal, true));
    const onExit = (code, signal) => finish(closedOutcome(code, signal));
    const onError = (error) => finish({
      kind: "error",
      message: error instanceof Error ? error.message : "Child process error.",
      stdout: outputText(launcher.stdout()),
      stderr: outputText(launcher.stderr()),
      outputCapture: outputCaptureSummary(launcher, { reason: "child_error_before_stream_close" }),
      elapsedMs: launcherElapsedMs(launcher)
    });
    launcher.child.stdout?.on("data", check);
    launcher.child.stderr?.on("data", check);
    launcher.child.once("exit", onExit);
    launcher.child.once("close", onClose);
    launcher.child.once("error", onError);
    if (hasExited()) {
      finish(closedOutcome());
    } else {
      check();
    }
  });
}

/** Mark output complete only after the child closes or every available stream closes. */
function outputCaptureSummary(launcher, {
  closeObserved = false,
  reason = "streams_open_at_snapshot",
  settlementTimeoutMs = null,
  settledAfterMs = null
} = {}) {
  const stdoutClosed = launcher.child.stdout ? launcher.child.stdout.closed === true : null;
  const stderrClosed = launcher.child.stderr ? launcher.child.stderr.closed === true : null;
  const complete = closeObserved || launcher.timeline?.closedAfterMs != null
    || (stdoutClosed !== null || stderrClosed !== null)
      && (stdoutClosed === null || stdoutClosed) && (stderrClosed === null || stderrClosed);
  return {
    status: complete ? "complete" : "incomplete",
    complete,
    reason: complete ? null : reason,
    settlementTimeoutMs,
    settledAfterMs,
    streamsClosed: { stdout: stdoutClosed, stderr: stderrClosed }
  };
}

/** Wait briefly for output streams to close before recording their final diagnostics. */
function settleLauncherOutput(launcher, timeoutMs = OUTPUT_CAPTURE_SETTLEMENT_TIMEOUT_MS) {
  const startedAt = performance.now();
  const current = outputCaptureSummary(launcher);
  if (current.complete) {
    return Promise.resolve(outputCaptureSummary(launcher, {
      settlementTimeoutMs: timeoutMs,
      settledAfterMs: 0
    }));
  }

  return new Promise((resolveOutput) => {
    let settled = false;
    let timer;
    const finish = (closeObserved, reason) => {
      if (settled) return;
      settled = true;
      globalThis.clearTimeout(timer);
      launcher.child.off("close", onClose);
      resolveOutput(outputCaptureSummary(launcher, {
        closeObserved,
        reason,
        settlementTimeoutMs: timeoutMs,
        settledAfterMs: Math.max(0, performance.now() - startedAt)
      }));
    };
    const onClose = () => finish(true, null);
    launcher.child.once("close", onClose);
    timer = globalThis.setTimeout(() => finish(false, "stream_close_timeout"), timeoutMs);
    if (outputCaptureSummary(launcher).complete) finish(false, null);
  });
}

function stopLauncher(launcher) {
  if (!launcher.stopPromise) {
    launcher.stopPromise = stopLauncherOnce(launcher).catch((error) => {
      launcher.stopPromise = undefined;
      throw error;
    });
  }
  return launcher.stopPromise;
}

/** Stop the launcher and verify marker-owned process groups are gone. */
async function stopLauncherOnce(launcher) {
  const { child, fixture } = launcher;
  const cleanup = { launcherSignal: null, processGroups: [], errors: [] };
  if (child.exitCode === null && child.signalCode === null) {
    cleanup.launcherSignal = "SIGTERM";
    child.kill("SIGTERM");
    let exit = await waitForChildExit(child, 2_000);
    if (!exit) {
      cleanup.launcherSignal = "SIGKILL";
      child.kill("SIGKILL");
      exit = await waitForChildExit(child, 2_000);
    }
    if (!exit) cleanup.errors.push("launcher_exit_unconfirmed");
  }
  const managedProcessMarkers = [
    {
      markerPath: fixture.paths.mcpBoundMarker,
      downstreamMarkers: [fixture.paths.mcpProbeMarker, fixture.paths.mcpRouteMarker,
        fixture.paths.tunnelStartedMarker, fixture.paths.tunnelReadyMarker, fixture.paths.tunnelHelperPidMarker]
    },
    {
      markerPath: fixture.paths.tunnelStartedMarker,
      downstreamMarkers: [fixture.paths.tunnelReadyMarker, fixture.paths.tunnelHelperPidMarker]
    }
  ];
  for (const { markerPath, downstreamMarkers } of managedProcessMarkers) {
    try {
      const marker = JSON.parse(await readFile(markerPath, "utf8"));
      if (!Number.isSafeInteger(marker?.pid) || marker.pid < 1) throw new TypeError("Managed process marker has no valid pid.");
      if (process.platform !== "win32") {
        const group = { marker: markerPath, pid: marker.pid, signal: "SIGKILL" };
        try {
          process.kill(-marker.pid, "SIGKILL");
          group.signalSent = true;
        } catch (error) {
          if (error?.code === "ESRCH") group.alreadyExited = true;
          else {
            group.error = error?.code ?? "signal_error";
            cleanup.errors.push(group.error);
          }
        }
        group.stillRunning = !(await waitForProcessGroupExit(marker.pid, 2_000));
        cleanup.processGroups.push(group);
      }
    } catch (error) {
      if (error?.code === "ENOENT") {
        const laterStageObserved = downstreamMarkers.some((path) => existsSync(path));
        cleanup.processGroups.push({
          marker: markerPath,
          status: laterStageObserved ? "missing_after_later_stage" : "absent_without_later_stage_evidence"
        });
        if (laterStageObserved) cleanup.errors.push("process_marker_missing_after_later_stage");
      } else {
        cleanup.errors.push(error instanceof SyntaxError || error instanceof TypeError
          ? "invalid_process_marker"
          : error?.code ?? "marker_cleanup_error");
      }
    }
  }
  const cleanupIncomplete = cleanup.errors.length > 0 || cleanup.processGroups.some((group) => group.stillRunning);
  const failures = [];
  if (cleanupIncomplete) {
    let diagnosticSuffix = "";
    try {
      const diagnostics = await collectLauncherDiagnostics(launcher, { cleanup });
      diagnosticSuffix = ` Diagnostics: ${JSON.stringify(diagnostics)}`;
    } catch (error) {
      failures.push(error);
    }
    const safeCleanup = redactDiagnosticValue(cleanup, launcher.secrets);
    failures.unshift(new Error(`Secure connector cleanup was incomplete: ${JSON.stringify(safeCleanup)}${diagnosticSuffix}`));
  }
  if (failures.length > 0) {
    throw new AggregateError(failures, "Secure connector cleanup was incomplete.");
  }
  launchers.delete(launcher);
}

/** Capture redacted streams, marker snapshots, stage timing, and stream-settlement state. */
async function collectLauncherDiagnostics(launcher, extra = {}) {
  const outputCapture = await settleLauncherOutput(launcher);
  const markerEntries = launcher.fixture?.paths ? Object.entries({
    mcpReady: launcher.fixture.paths.mcpReadyFile,
    mcpBound: launcher.fixture.paths.mcpBoundMarker,
    mcpProbe: launcher.fixture.paths.mcpProbeMarker,
    mcpRoute: launcher.fixture.paths.mcpRouteMarker,
    mcpBindError: launcher.fixture.paths.mcpBindErrorMarker,
    mcpStopped: launcher.fixture.paths.mcpStoppedMarker,
    tunnelStarted: launcher.fixture.paths.tunnelStartedMarker,
    tunnelReady: launcher.fixture.paths.tunnelReadyMarker,
    tunnelHelperPid: launcher.fixture.paths.tunnelHelperPidMarker,
    tunnelStopped: launcher.fixture.paths.tunnelStoppedMarker
  }) : [];
  const markers = Object.fromEntries(await Promise.all(markerEntries.map(async ([name, path]) => [name, await readMarkerSnapshot(path, launcher.secrets)])));
  const stageTimings = Object.entries(markers)
    .filter(([, marker]) => Number.isFinite(marker.modifiedAtEpochMs))
    .map(([name, marker]) => ({
      stage: name,
      markerModifiedAt: new Date(marker.modifiedAtEpochMs).toISOString(),
      elapsedFromLauncherStartMs: Math.max(0, marker.modifiedAtEpochMs - launcher.startedAtEpochMs)
    }));
  return redactDiagnosticValue({
    schemaVersion: 1,
    launcherId: launcher.id,
    testName: expect.getState().currentTestName ?? null,
    startedAt: launcher.timeline.startedAt,
    pid: launcher.child.pid ?? null,
    exit: { code: launcher.timeline.exitCode ?? null, signal: launcher.timeline.signal ?? null },
    close: { code: launcher.timeline.closeCode ?? null, signal: launcher.timeline.closeSignal ?? null },
    timeline: launcher.timeline,
    stdout: launcher.stdout(),
    stderr: launcher.stderr(),
    outputCapture,
    markers,
    stageTimings,
    ...extra
  }, launcher.secrets);
}

/** Read a bounded marker snapshot and record read or close failures with its timestamp. */
async function readMarkerSnapshot(path, secrets, { openFile = open } = {}) {
  let handle;
  let snapshot;
  try {
    handle = await openFile(path, "r");
    const info = await handle.stat();
    const buffer = Buffer.alloc(4_097);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const truncated = info.size > bytesRead || bytesRead > 4_096;
    const contents = decodeDiagnosticBytes(buffer.subarray(0, Math.min(bytesRead, 4_096)), truncated);
    let value = contents;
    let state = contents.length === 0 ? "empty" : "text";
    if (contents.length > 0) {
      try {
        value = JSON.parse(contents);
        state = "json";
      } catch {
        if (!truncated && contents.trimStart().startsWith("{")) state = "invalid_json";
      }
    }
    snapshot = {
      state,
      value: redactDiagnosticValue(value, secrets, { truncated: truncated && state === "text" }),
      modifiedAtEpochMs: info.mtimeMs,
      sizeBytes: info.size,
      truncated
    };
  } catch (error) {
    snapshot = error?.code === "ENOENT"
      ? { state: "absent", value: null, modifiedAtEpochMs: null, sizeBytes: 0, truncated: false }
      : { state: "read_error", errorCode: error?.code ?? "unknown", modifiedAtEpochMs: null, sizeBytes: null, truncated: false };
  }
  try {
    await handle?.close();
  } catch (error) {
    return {
      ...snapshot,
      state: "close_error",
      previousState: snapshot.state,
      closeErrorCode: error?.code ?? "unknown"
    };
  }
  return snapshot;
}

function launcherElapsedMs(launcher) {
  return Math.max(0, performance.now() - (launcher.startedAt ?? performance.now()));
}

function outputText(value) {
  return typeof value === "string" ? value : String(value?.text ?? "");
}

function isProcessGroupRunning(pid) {
  try {
    process.kill(-pid, 0);
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    if (error?.code !== "EPERM") return true;
  }
  try {
    const processStates = execFileSync("ps", ["-Ao", "pgid=,stat="], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 1_000
    });
    return processGroupHasLiveMembers(processStates, pid);
  } catch {
    return true;
  }
}

/** Return the launcher's exit tuple, or null if it misses the bounded wait. */
async function waitForChildExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return { code: child.exitCode, signal: child.signalCode };
  }
  return new Promise((resolveExit) => {
    let settled = false;
    const finish = (exit) => {
      if (settled) return;
      settled = true;
      globalThis.clearTimeout(timer);
      child.off("exit", onExit);
      resolveExit(exit);
    };
    const onExit = (code, signal) => finish({ code, signal });
    const timer = globalThis.setTimeout(() => finish(null), timeoutMs);
    child.once("exit", onExit);
    if (child.exitCode !== null || child.signalCode !== null) onExit(child.exitCode, child.signalCode);
  });
}

/** Return true only after no live member remains in the process group. */
async function waitForProcessGroupExit(pid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!isProcessGroupRunning(pid)) return true;
    await new Promise((resolveDelay) => globalThis.setTimeout(resolveDelay, 25));
  }
  return !isProcessGroupRunning(pid);
}

function isPidRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    throw error;
  }
}

/** Collect values from sensitive-looking environment keys so diagnostics can redact bare echoes. */
function collectSecretValues(environment) {
  return [...new Set(Object.entries(environment)
    .filter(([name, value]) => /(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|client[_-]?secret|refresh[_-]?token|private[_-]?key|token|secret|password|passwd|pwd|credential|cookie|authorization)/i.test(name)
      && typeof value === "string" && value.length > 0)
    .map(([, value]) => value))];
}

function redactDiagnosticText(value, secrets = [], { truncated = false } = {}) {
  let text = String(value ?? "");
  const literalSecrets = [...new Set(secrets.filter((secret) => typeof secret === "string" && secret.length > 0))]
    .sort((left, right) => right.length - left.length);
  for (const secret of literalSecrets) text = text.split(secret).join("[REDACTED]");
  text = redactSensitiveText(text).replace(/\bBearer\s+[-A-Za-z0-9._~+/]+=*/gi, "Bearer [REDACTED]");
  if (truncated) {
    for (const secret of literalSecrets) {
      const maxOverlap = Math.min(secret.length - 1, text.length);
      for (let overlap = maxOverlap; overlap > 0; overlap -= 1) {
        if (text.endsWith(secret.slice(0, overlap))) {
          text = `${text.slice(0, -overlap)}[REDACTED]`;
          break;
        }
      }
    }
  }
  return text;
}

/** Decode captured bytes without inventing text for a truncated UTF-8 suffix. */
function decodeDiagnosticBytes(bytes, truncated) {
  return new TextDecoder("utf-8", { ignoreBOM: true }).decode(bytes, { stream: truncated });
}

/**
 * Redact string data before JSON serialization so escaping cannot hide a registered secret.
 * Preserve JSON-compatible structure and replace cycles or unsupported values with fixed markers.
 */
function redactDiagnosticValue(value, secrets = [], { truncated = false } = {}) {
  const activeObjects = new WeakSet();

  const sanitize = (candidate) => {
    if (typeof candidate === "string") return redactDiagnosticText(candidate, secrets, { truncated });
    if (candidate === null || typeof candidate === "boolean" || typeof candidate === "number") return candidate;
    if (typeof candidate === "undefined") return "[UNSUPPORTED:undefined]";
    if (typeof candidate === "bigint") return "[UNSUPPORTED:bigint]";
    if (typeof candidate === "function") return "[UNSUPPORTED:function]";
    if (typeof candidate === "symbol") return "[UNSUPPORTED:symbol]";
    if (typeof candidate !== "object") return "[UNSUPPORTED]";

    if (activeObjects.has(candidate)) return "[Circular]";
    activeObjects.add(candidate);
    try {
      if (Array.isArray(candidate)) {
        let length;
        try {
          length = candidate.length;
        } catch {
          return "[UNREADABLE]";
        }
        const sanitized = [];
        Object.defineProperty(sanitized, "toJSON", { value: undefined });
        for (let index = 0; index < length; index += 1) {
          try {
            sanitized.push(sanitize(candidate[index]));
          } catch {
            sanitized.push("[UNREADABLE]");
          }
        }
        return sanitized;
      }

      let prototype;
      let keys;
      try {
        prototype = Object.getPrototypeOf(candidate);
        keys = Object.keys(candidate);
      } catch {
        return "[UNREADABLE]";
      }
      if (prototype !== Object.prototype && prototype !== null) return "[UNSUPPORTED:object]";

      const sanitized = Object.create(null);
      for (const key of keys) {
        const safeKey = redactDiagnosticText(key, secrets, { truncated });
        let safeValue;
        try {
          safeValue = sanitize(candidate[key]);
        } catch {
          safeValue = "[UNREADABLE]";
        }
        Object.defineProperty(sanitized, safeKey, {
          value: safeValue,
          enumerable: true,
          configurable: true,
          writable: true
        });
      }
      return sanitized;
    } catch {
      return "[UNREADABLE]";
    } finally {
      activeObjects.delete(candidate);
    }
  };

  let safeValue;
  try {
    safeValue = sanitize(value);
  } catch {
    safeValue = "[UNREADABLE]";
  }

  let serialized;
  try {
    serialized = JSON.stringify(safeValue);
  } catch {
    serialized = JSON.stringify("[UNREADABLE]");
  }

  try {
    return JSON.parse(redactDiagnosticText(serialized, []));
  } catch {
    return "[UNREADABLE]";
  }
}

/** Capture at most maxBytes while continuing to drain the child stream. */
function createBoundedCapture(maxBytes) {
  const chunks = [];
  let bytesCaptured = 0;
  let totalBytes = 0;
  let truncated = false;
  return {
    append(value) {
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(String(value));
      totalBytes += chunk.length;
      const remaining = maxBytes - bytesCaptured;
      if (remaining <= 0) {
        truncated ||= chunk.length > 0;
        return;
      }
      const retained = chunk.subarray(0, remaining);
      chunks.push(retained);
      bytesCaptured += retained.length;
      truncated ||= retained.length < chunk.length;
    },
    snapshot(secrets = []) {
      const raw = decodeDiagnosticBytes(Buffer.concat(chunks, bytesCaptured), truncated);
      return {
        text: redactDiagnosticText(raw, secrets, { truncated }),
        bytesCaptured,
        totalBytes,
        maxBytes,
        truncated
      };
    }
  };
}

/** Treat empty or malformed process output as live until cleanup can be verified. */
function processGroupHasLiveMembers(processStates, groupId) {
  const lines = processStates.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length === 0) return true;
  for (const line of lines) {
    const match = line.trim().match(/^(\d+)\s+(\S+)$/);
    if (!match) return true;
    const [, candidateGroup, state] = match;
    if (Number(candidateGroup) === groupId && !state.startsWith("Z")) return true;
  }
  return false;
}
