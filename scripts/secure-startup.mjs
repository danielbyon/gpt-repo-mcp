import { constants } from "node:fs";
import { spawn } from "node:child_process";
import { lstat, open } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import process from "node:process";
import { performance } from "node:perf_hooks";
import { getManagedProcessTreeStatus, signalManagedProcessTree } from "./connector-runtime.mjs";
import { spawnSupervisedProcess } from "./secure-process-supervisor.mjs";

const MAX_GO_DURATION_NS = (1n << 63n) - 1n;
const NS_PER_MS = 1_000_000n;
// Fractions beyond this precision cannot change whole nanoseconds for the hour unit.
const MAX_DURATION_FRACTION_DIGITS = 24;
const DEFAULT_MAX_TIMEOUT_MS = 10 * 60_000;
const DEFAULT_RETRY_INTERVAL_MS = 250;
const HELPER_KILL_ESCALATION_MS = 250;
const HELPER_CLEANUP_TIMEOUT_MS = 1_000;
const PROBE_CANCELLATION_GRACE_MS = 2_000;
const MCP_PROTOCOL_VERSION = "2025-03-26";

export const DEFAULT_MCP_STARTUP_WAIT_TIMEOUT = "30s";
export const DEFAULT_TUNNEL_STARTUP_WAIT_TIMEOUT = "60s";

const durationUnits = [
  ["ns", 1n],
  ["us", 1_000n],
  ["µs", 1_000n],
  ["μs", 1_000n],
  ["ms", 1_000_000n],
  ["s", 1_000_000_000n],
  ["m", 60_000_000_000n],
  ["h", 3_600_000_000_000n]
].sort(([left], [right]) => right.length - left.length);

/**
 * Runs one startup helper and owns its cleanup for the command's lifetime.
 * On Windows, the tree can remain unknown after the parent exits because current process APIs
 * cannot inspect descendants safely through a PID that may have been reused. The command result
 * keeps that status as unknown. Cancellation and observed live trees use bounded TERM/KILL cleanup.
 */
export async function runCancellableCommand(command, args, options = {}) {
  const {
    signal,
    timeout,
    platform = process.platform,
    spawnProcess,
    processTreeStatus = (child) => getManagedProcessTreeStatus(child, platform),
    signalProcessTree = (child, childSignal) => signalManagedProcessTree(child, childSignal, platform),
    maxBuffer = 1_000_000,
    encoding = "utf8",
    windowsHide = true,
    ...spawnOptions
  } = options;
  const launchProcess = spawnProcess ?? (platform === "win32" ? spawn : spawnSupervisedProcess);
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    const controller = new globalThis.AbortController();
    const stdoutChunks = [];
    const stderrChunks = [];
    let outputBytes = 0;
    let child;
    let closeCode;
    let closeSignal;
    let spawnError;
    let overflowError;
    let processClosed = false;
    let abortStarted = false;
    let settled = false;
    let escalationTimer;
    let cleanupTimer;
    let timeoutTimer;

    const output = () => ({
      stdout: globalThis.Buffer.concat(stdoutChunks).toString(encoding),
      stderr: globalThis.Buffer.concat(stderrChunks).toString(encoding)
    });
    const treeStatus = () => {
      try {
        return processTreeStatus(child);
      } catch {
        return "unknown";
      }
    };
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimers();
      signal?.removeEventListener("abort", abortFromParent);
      controller.signal.removeEventListener("abort", abortProcessTree);
      if (error) {
        Object.assign(error, output());
        reject(error);
      } else {
        resolve({ ...output(), ...result });
      }
    };
    const clearTimers = () => {
      if (timeoutTimer !== undefined) globalThis.clearTimeout(timeoutTimer);
      if (child && escalationTimer !== undefined && treeStatus() === "verified-complete") {
        globalThis.clearTimeout(escalationTimer);
      }
      if (child && cleanupTimer !== undefined && treeStatus() === "verified-complete") {
        globalThis.clearTimeout(cleanupTimer);
      }
    };
    const abortProcessTree = () => {
      if (!child || abortStarted) return;
      abortStarted = true;
signalProcessTree(child, "SIGTERM");
      escalationTimer = globalThis.setTimeout(() => {
        escalationTimer = undefined;
signalProcessTree(child, "SIGKILL");
        cleanupTimer = globalThis.setTimeout(() => {
          cleanupTimer = undefined;
          if (treeStatus() !== "verified-complete") {
            const error = new Error("Startup helper process tree completion could not be verified after SIGKILL.");
            error.code = "ERR_PROCESS_TREE_CLEANUP";
            error.killed = true;
            error.processTreeStatus = treeStatus();
            finish(error);
          } else {
            finish(abortReason(controller.signal));
          }
        }, HELPER_CLEANUP_TIMEOUT_MS);
        settleAfterClose();
      }, HELPER_KILL_ESCALATION_MS);
      settleAfterClose();
    };
    const settleAfterClose = () => {
      if (!processClosed || settled) return;
      if (controller.signal.aborted) {
        if (treeStatus() !== "verified-complete") return;
        finish(abortReason(controller.signal));
        return;
      }
      const status = treeStatus();
      if (status === "active") {
controller.abort(new Error("Startup helper exited while its process tree remained active."));
        return;
      }
      if (spawnError) {
        finish(spawnError);
      } else if (platform !== "win32" && status === "unknown") {
        const error = new Error("Startup helper process-tree completion could not be verified.");
        error.code = "ERR_PROCESS_TREE_CLEANUP";
        error.killed = true;
        error.processTreeStatus = status;
        finish(error);
      } else if (closeCode === 0) {
        finish(undefined, { code: closeCode, signal: closeSignal, processTreeStatus: status });
      } else {
        const error = new Error(`Startup helper exited (code=${closeCode ?? "null"}, signal=${closeSignal ?? "null"}).`);
        error.code = closeCode;
        error.signal = closeSignal;
        error.killed = closeSignal !== null;
        error.processTreeStatus = status;
        finish(error);
      }
    };
    const abortFromParent = () => controller.abort(abortReason(signal));
    const collect = (chunks, chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > maxBuffer) {
        overflowError = new Error(`Startup helper output exceeded ${maxBuffer} bytes.`);
        overflowError.code = "ERR_CHILD_PROCESS_STDIO_MAXBUFFER";
        controller.abort(overflowError);
        return;
      }
      chunks.push(chunk);
    };

    try {
      child = launchProcess(command, args, {
        ...spawnOptions,
        detached: platform !== "win32",
        windowsHide,
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (error) {
      finish(error);
      return;
    }
    child.stdout.on("data", (chunk) => collect(stdoutChunks, chunk));
    child.stderr.on("data", (chunk) => collect(stderrChunks, chunk));
    child.once("error", (error) => { spawnError = error; });
    child.once("close", (code, exitSignal) => {
      closeCode = code;
      closeSignal = exitSignal;
      processClosed = true;
      settleAfterClose();
    });
    controller.signal.addEventListener("abort", abortProcessTree, { once: true });
    signal?.addEventListener("abort", abortFromParent, { once: true });
    if (signal?.aborted) abortFromParent();

    const timeoutError = new Error(`Startup helper timed out after ${timeout} ms.`);
    timeoutError.code = "ETIMEDOUT";
    timeoutError.killed = true;
    if (Number.isFinite(timeout) && timeout > 0) {
      timeoutTimer = globalThis.setTimeout(() => controller.abort(timeoutError), Math.max(1, Math.ceil(timeout)));
    }
  });
}

function abortReason(signal) {
  return signal?.reason instanceof Error ? signal.reason : new Error("Startup was cancelled.");
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw abortReason(signal);
}

/** Parse Go time.Duration syntax while returning the caller's original value unchanged. */
export function parseDurationMs(value, name, options = {}) {
  const maxMs = options.maxMs ?? DEFAULT_MAX_TIMEOUT_MS;
  const nanoseconds = parseGoDurationNanoseconds(value, name);
  if (nanoseconds <= 0n) {
    throw new Error(`${name} must be a positive Go duration.`);
  }
  const maxNanoseconds = BigInt(maxMs) * NS_PER_MS;
  if (nanoseconds > maxNanoseconds) {
    throw new Error(`${name} must not exceed ${maxMs / 60_000} minutes.`);
  }
  return {
    value,
    timeoutMs: Math.max(1, Number(nanoseconds / NS_PER_MS) + (nanoseconds % NS_PER_MS > 0n ? 1 : 0))
  };
}

function parseGoDurationNanoseconds(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} must use Go time.Duration syntax.`);
  }
  if (value === "0" || value === "+0" || value === "-0") {
    return 0n;
  }

  let index = 0;
  let sign = 1n;
  if (value[index] === "+" || value[index] === "-") {
    if (value[index] === "-") sign = -1n;
    index += 1;
  }
  if (index === value.length) {
    throw new Error(`${name} must use Go time.Duration syntax.`);
  }

  let total = 0n;
  while (index < value.length) {
    const numberStart = index;
    while (isAsciiDigit(value[index])) index += 1;
    const integerPart = value.slice(numberStart, index);

    let fractionPart = "";
    if (value[index] === ".") {
      index += 1;
      const fractionStart = index;
      while (isAsciiDigit(value[index])) index += 1;
      fractionPart = value.slice(fractionStart, index);
    }
    if (integerPart.length === 0 && fractionPart.length === 0) {
      throw new Error(`${name} must use Go time.Duration syntax.`);
    }

    const unit = durationUnits.find(([suffix]) => value.startsWith(suffix, index));
    if (!unit) {
      throw new Error(`${name} must use Go time.Duration syntax.`);
    }
    const [suffix, unitNanoseconds] = unit;
    index += suffix.length;

    const canonicalInteger = integerPart.replace(/^0+/, "") || "0";
    if (canonicalInteger.length > 19) throw new Error(`${name} overflows Go time.Duration.`);
    let component = BigInt(canonicalInteger) * unitNanoseconds;
    if (fractionPart.length > 0) {
      const significantFraction = fractionPart.slice(0, MAX_DURATION_FRACTION_DIGITS);
      const fractionNumerator = BigInt(significantFraction) * unitNanoseconds;
      component += fractionNumerator / (10n ** BigInt(significantFraction.length));
    }
    total += component;
    if (total > MAX_GO_DURATION_NS) {
      throw new Error(`${name} overflows Go time.Duration.`);
    }
  }

  return total * sign;
}

function isAsciiDigit(value) {
  return value !== undefined && value >= "0" && value <= "9";
}

/** Build the exact MCP route the configured server authorizes, using loopback for wildcard binds. */
export function buildMcpProbeUrl({ host, port, publicPathToken, boundPort }) {
  const effectivePort = boundPort ?? Number(port);
  if (!Number.isInteger(effectivePort) || effectivePort < 1 || effectivePort > 65_535) {
    throw new Error("The effective MCP listener port is invalid.");
  }
  const normalizedHost = normalizeProbeHost(host);
  const authorityHost = normalizedHost.includes(":") ? `[${normalizedHost}]` : normalizedHost;
  const route = publicPathToken
    ? `/t/${encodeURIComponent(publicPathToken)}/mcp`
    : "/mcp";
  return `http://${authorityHost}:${effectivePort}${route}`;
}

function normalizeProbeHost(value) {
  const host = String(value ?? "").trim().replace(/^\[|\]$/g, "");
  if (!host || host === "0.0.0.0" || host === "*") return "127.0.0.1";
  if (host === "::" || host === "::0") return "::1";
  return host;
}

/** Wait for the server's own successful bind line; an occupied listener cannot satisfy this gate. */
export function waitForMcpListener({ child, port, timeoutMs, now = () => performance.now(), signal }) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    let settled = false;
    const timer = globalThis.setTimeout(() => finish(new Error("MCP startup timed out before its listener bound.")), timeoutMs);
    const onAbort = () => finish(abortReason(signal));

    const cleanup = () => {
      globalThis.clearTimeout(timer);
      child.stdout?.off("data", onData);
      child.stderr?.off("data", onData);
      child.off("exit", onExit);
      child.off("error", onError);
      signal?.removeEventListener("abort", onAbort);
    };
    const finish = (error, boundPort) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve({ boundPort, elapsedMs: Math.max(0, now() - startedAt) });
    };
    const onLine = (line) => {
      const match = line.match(/gpt-repo-mcp listening on http:\/\/(?:\[[^\]]+\]|[^:\s]+):(\d+)\/(?:mcp|t\/\[token\]\/mcp)$/);
      if (!match) return;
      const boundPort = Number(match[1]);
      if (!Number.isInteger(boundPort) || boundPort < 1 || boundPort > 65_535) return;
      if (Number(port) !== 0 && boundPort !== Number(port)) {
        finish(new Error("MCP listener bound a port different from the configured PORT."));
        return;
      }
      finish(undefined, boundPort);
    };
    const onData = (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() ?? "";
      for (const line of lines) onLine(line);
    };
    const onExit = (code, signal) => {
      finish(new Error(`MCP process exited before binding (code=${code ?? "null"}, signal=${signal ?? "null"}).`));
    };
    const onError = (error) => finish(new Error(`MCP process failed to start: ${error.message}`));
    const startedAt = now();

    if (signal?.aborted) {
      finish(abortReason(signal));
      return;
    }
    if ((child.exitCode !== null && child.exitCode !== undefined) || child.signalCode) {
      finish(new Error("MCP process exited before binding."));
      return;
    }
    child.stdout?.on("data", onData);
    child.stderr?.on("data", onData);
    child.once("exit", onExit);
    child.once("error", onError);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/** Exercise the Streamable HTTP initialize and discovery flow against a fresh server session. */
export async function probeMcp({ url, fetchImpl = globalThis.fetch, requestTimeoutMs = 5_000, signal }) {
  let sessionId;
  let outcome;
  try {
    const initialized = await postMcp(fetchImpl, url, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "gpt-repo-secure-startup", version: "1.0.0" }
      }
    }, undefined, requestTimeoutMs, signal);
    if (initialized.state !== "ready") return initialized;
    sessionId = initialized.sessionId;

    const notification = await postMcp(fetchImpl, url, {
      jsonrpc: "2.0",
      method: "notifications/initialized"
    }, sessionId, requestTimeoutMs, signal);
    if (notification.state !== "ready") {
      outcome = notification;
    } else {
      const tools = await postMcp(fetchImpl, url, {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {}
      }, sessionId, requestTimeoutMs, signal);
      if (tools.state !== "ready") {
        outcome = tools;
      } else if (!tools.tools.includes("repo_list_roots")) {
        outcome = { state: "failed", reason: "required_tool_missing" };
      } else {
        outcome = { state: "ready", reason: "mcp_protocol_ready" };
      }
    }
  } catch (error) {
    if (signal?.aborted) throw abortReason(signal);
    outcome = classifyMcpException(error);
  } finally {
    if (sessionId && !signal?.aborted) {
      const closed = await deleteMcpSession(fetchImpl, url, sessionId, requestTimeoutMs, signal);
      if (!closed) outcome = { state: "failed", reason: "probe_session_cleanup_failed" };
    }
  }
  return outcome ?? { state: "failed", reason: "unknown_mcp_probe_failure" };
}

async function postMcp(fetchImpl, url, body, sessionId, requestTimeoutMs, signal) {
  let response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json",
        ...(sessionId ? { "mcp-session-id": sessionId, "mcp-protocol-version": MCP_PROTOCOL_VERSION } : {})
      },
      body: JSON.stringify(body),
      signal: makeRequestSignal(signal, requestTimeoutMs)
    });
  } catch (error) {
    if (signal?.aborted) throw abortReason(signal);
    return classifyMcpException(error, body.method);
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    const reason = `http_${response.status}`;
    return isRetryableHttpStatus(response.status)
      ? { state: "pending", reason }
      : { state: "failed", reason };
  }
  if (body.method === "notifications/initialized") {
    const raw = await response.text();
    const message = raw ? parseJsonRpcMessage(raw) : undefined;
    if (message?.error) return { state: "failed", reason: "initialized_notification_rejected" };
    return { state: "ready" };
  }

  const raw = await response.text();
  const message = parseJsonRpcMessage(raw, body.id);
  if (!message || message.error || !message.result) {
    return { state: "failed", reason: "invalid_mcp_response" };
  }
  if (body.method === "initialize") {
    const returnedSessionId = response.headers.get("mcp-session-id");
    if (!returnedSessionId) return { state: "failed", reason: "missing_mcp_session" };
    return { state: "ready", sessionId: returnedSessionId };
  }
  return {
    state: "ready",
    tools: Array.isArray(message.result.tools)
      ? message.result.tools.map((tool) => tool?.name).filter((name) => typeof name === "string")
      : []
  };
}

function parseJsonRpcMessage(raw, expectedId) {
  const candidates = [raw];
  for (const line of raw.split(/\r?\n/)) {
    if (line.startsWith("data:")) candidates.push(line.slice(5).trim());
  }
  for (const candidate of candidates) {
    if (!candidate || candidate === "[DONE]") continue;
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && (expectedId === undefined || parsed.id === expectedId)) return parsed;
    } catch {
      // Streamable HTTP responses may wrap JSON-RPC messages in server-sent events.
    }
  }
  return undefined;
}

async function deleteMcpSession(fetchImpl, url, sessionId, requestTimeoutMs, signal) {
  try {
    const response = await fetchImpl(url, {
      method: "DELETE",
      headers: {
        Accept: "application/json, text/event-stream",
        "mcp-session-id": sessionId
      },
      signal: makeRequestSignal(signal, requestTimeoutMs)
    });
    await response.text();
    return response.ok;
  } catch {
    return false;
  }
}

function makeRequestSignal(signal, timeoutMs) {
  const timeoutSignal = globalThis.AbortSignal.timeout(Math.max(1, Math.ceil(timeoutMs)));
  return signal ? globalThis.AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
}

function classifyMcpException(error, method) {
  const code = error?.cause?.code ?? error?.code;
  if (code === "ECONNREFUSED") {
    return { state: "pending", reason: "connection_pending" };
  }
  if (code === "ECONNRESET" || code === "EHOSTUNREACH" || code === "ETIMEDOUT" || error?.name === "TimeoutError") {
    return method === "initialize"
      ? { state: "failed", reason: "initialize_response_uncertain" }
      : { state: "pending", reason: "connection_pending" };
  }
  if (error?.name === "TypeError" && /fetch failed/i.test(error.message)) {
    if (method === "initialize") return { state: "failed", reason: "initialize_response_uncertain" };
    return { state: "pending", reason: "connection_pending" };
  }
  return { state: "failed", reason: "mcp_probe_error" };
}

function isRetryableHttpStatus(status) {
  return status === 429 || status === 502 || status === 503 || status === 504;
}

/** Retry only pending MCP outcomes; permanent protocol and route errors fail immediately. */
export async function waitForMcpReadiness({
  url,
  timeoutMs,
  probe = probeMcp,
  now = () => performance.now(),
  sleep = delay,
  retryIntervalMs = DEFAULT_RETRY_INTERVAL_MS,
  deadline: fixedDeadline,
  signal
}) {
  const deadline = fixedDeadline ?? now() + timeoutMs;
  let lastReason = "connection_pending";
  for (;;) {
    throwIfAborted(signal);
    const remainingBeforeProbe = deadline - now();
    if (remainingBeforeProbe <= 0) throw new Error(`MCP startup timed out (${lastReason}).`);
    const timeoutError = new Error(`MCP startup timed out (${lastReason}).`);
    const result = await runProbeWithinDeadline(probe, {
      url,
      requestTimeoutMs: Math.min(5_000, remainingBeforeProbe)
    }, { deadline, now, signal, timeoutError });
    if (result.state === "ready") return result;
    if (result.state === "failed") {
      throw new Error(`MCP startup failed (${result.reason}).`);
    }
    lastReason = result.reason ?? lastReason;
    const remaining = deadline - now();
    if (remaining <= 0) throw new Error(`MCP startup timed out (${lastReason}).`);
    await sleep(Math.max(1, Math.min(retryIntervalMs, Math.ceil(remaining))), signal);
  }
}

async function runProbeWithinDeadline(probe, values, { deadline, now, signal, timeoutError }) {
  throwIfAborted(signal);
  const remainingMs = deadline - now();
  if (remainingMs <= 0) throw timeoutError;

  const controller = new globalThis.AbortController();
  const abortFromParent = () => controller.abort(abortReason(signal));
  let probeSettled = false;
  const probePromise = Promise.resolve().then(() => {
    throwIfAborted(controller.signal);
    return probe({ ...values, signal: controller.signal });
  }).then(
    (value) => ({ kind: "result", value }),
    (error) => ({ kind: "error", error })
  ).then((outcome) => {
    probeSettled = true;
    return outcome;
  });
  const aborted = new Promise((resolve) => {
    controller.signal.addEventListener("abort", () => resolve({ kind: "aborted" }), { once: true });
  });
  const deadlineTimer = globalThis.setTimeout(() => controller.abort(timeoutError), Math.max(1, Math.ceil(remainingMs)));
  signal?.addEventListener("abort", abortFromParent, { once: true });
  if (signal?.aborted) abortFromParent();

  try {
    const outcome = await Promise.race([probePromise, aborted]);
    if (outcome.kind === "aborted") {
      if (!await waitForProbeSettlement(probePromise, () => probeSettled)) {
        throw probeCancellationIncompleteError();
      }
      if (signal?.aborted) throw abortReason(signal);
      throw timeoutError;
    }
    if (now() >= deadline) {
      controller.abort(timeoutError);
      if (!await waitForProbeSettlement(probePromise, () => probeSettled)) {
        throw probeCancellationIncompleteError();
      }
      throw timeoutError;
    }
    if (signal?.aborted) {
      controller.abort(abortReason(signal));
      if (!await waitForProbeSettlement(probePromise, () => probeSettled)) {
        throw probeCancellationIncompleteError();
      }
      throw abortReason(signal);
    }
    if (outcome.kind === "error") throw outcome.error;
    return outcome.value;
  } finally {
    globalThis.clearTimeout(deadlineTimer);
    signal?.removeEventListener("abort", abortFromParent);
  }
}

async function waitForProbeSettlement(probePromise, isSettled) {
  if (isSettled()) return true;
  let timer;
  const settled = await Promise.race([
    probePromise.then(() => true),
    new Promise((resolve) => {
      timer = globalThis.setTimeout(() => resolve(false), PROBE_CANCELLATION_GRACE_MS);
    })
  ]);
  if (timer !== undefined) globalThis.clearTimeout(timer);
  return settled;
}

function probeCancellationIncompleteError() {
  const error = new Error(`Probe did not stop within ${PROBE_CANCELLATION_GRACE_MS}ms cleanup grace.`);
  error.code = "ERR_PROBE_CANCELLATION_INCOMPLETE";
  return error;
}

/** Read a health URL file and its filesystem identity without accepting a stale entry. */
export async function readHealthUrlSnapshot(path, dependencies = {}) {
  const openFile = dependencies.openFileImpl ?? open;
  const lstatFile = dependencies.lstatImpl ?? lstat;
  let handle;
  try {
    throwIfAborted(dependencies.signal);
    const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
    handle = await openFile(path, flags);
    throwIfAborted(dependencies.signal);
    const before = await handle.stat({ bigint: true });
    const content = await handle.readFile({ encoding: "utf8" });
    const after = await handle.stat({ bigint: true });
    const pathMetadata = await lstatFile(path, { bigint: true });
    throwIfAborted(dependencies.signal);
    const identity = healthUrlFileIdentity(before);
    if (!sameHealthUrlFileIdentity(identity, healthUrlFileIdentity(after))
      || !sameHealthUrlFileIdentity(identity, healthUrlFileIdentity(pathMetadata))) {
      throw new Error("Tunnel health URL file changed while reading.");
    }
    return {
      content: content.trim(),
      identity
    };
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  } finally {
    await handle?.close();
  }
}

function healthUrlFileIdentity(metadata) {
  return {
    dev: String(metadata.dev),
    ino: String(metadata.ino),
    size: String(metadata.size),
    mtimeNs: String(metadata.mtimeNs),
    ctimeNs: String(metadata.ctimeNs)
  };
}

function sameHealthUrlFileIdentity(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

export function isFreshHealthUrlSnapshot(before, after) {
  if (!after?.content) return false;
  if (!before) return true;
  return Object.keys(after.identity).some((key) => after.identity[key] !== before.identity[key]);
}

/** Wait for a health URL file written by this launch, then validate its endpoint identity. */
export async function waitForFreshHealthUrl({
  path,
  before,
  listenAddr,
  unixSocket,
  tunnelPid,
  timeoutMs,
  isProcessAlive = () => true,
  now = () => performance.now(),
  sleep = delay,
  readSnapshot = readHealthUrlSnapshot,
  retryIntervalMs = DEFAULT_RETRY_INTERVAL_MS,
  deadline: fixedDeadline,
  signal
}) {
  const deadline = fixedDeadline ?? now() + timeoutMs;
  for (;;) {
    throwIfAborted(signal);
    if (!isProcessAlive(tunnelPid)) throw new Error("Tunnel process exited before publishing its health URL.");
    const remainingBeforeRead = deadline - now();
    if (remainingBeforeRead <= 0) throw new Error("Tunnel did not publish a fresh health URL for this launch.");
    const timeoutError = new Error("Tunnel did not publish a fresh health URL for this launch.");
    const after = await runProbeWithinDeadline(
      ({ signal: readSignal }) => readSnapshot(path, { signal: readSignal }),
      {},
      { deadline, now, signal, timeoutError }
    );
    if (isFreshHealthUrlSnapshot(before, after)) {
      return validateTunnelHealthUrl(after.content, { listenAddr, unixSocket, tunnelPid });
    }
    const remaining = deadline - now();
    if (remaining <= 0) throw new Error("Tunnel did not publish a fresh health URL for this launch.");
    await sleep(Math.max(1, Math.min(retryIntervalMs, Math.ceil(remaining))), signal);
  }
}

/** Validate the instance URL and any PID/endpoint identity reported by the health command. */
export function validateTunnelHealthUrl(value, options = {}) {
  const { listenAddr, tunnelPid, report, unixSocket } = options;
  let url;
  try {
    url = new globalThis.URL(value);
  } catch {
    if (!unixSocket) throw new Error("Tunnel health URL file does not contain a valid URL.");
    url = new globalThis.URL("http://127.0.0.1");
  }

  if (unixSocket) {
    if (!unixSocket.startsWith("/")) throw new Error("HEALTH_UNIX_SOCKET must be an absolute path.");
    validateReportedHealthIdentity(report, url, tunnelPid, { unixSocket: true });
    return { url: "http://127.0.0.1", socketPath: unixSocket };
  }
  if (!(["http:", "https:"].includes(url.protocol) && isLoopbackHost(url.hostname))) {
    throw new Error("Tunnel health URL must use a loopback HTTP endpoint.");
  }
  if (url.username || url.password || url.hash || url.search) {
    throw new Error("Tunnel health URL contains unsupported components.");
  }
  const expected = listenAddr ? parseListenAddress(listenAddr) : undefined;
  const effectiveHealthPort = Number(url.port || (url.protocol === "https:" ? 443 : 80));
  if (effectiveHealthPort < 1
    || expected && (expected.port !== 0 && effectiveHealthPort !== expected.port
      || !healthListenerHostMatches(expected.host, url.hostname))) {
    throw new Error("Tunnel health URL does not match the configured health listener.");
  }
  if (url.pathname !== "/" && url.pathname !== "") {
    throw new Error("Tunnel health URL must be an admin base URL.");
  }
  validateReportedHealthIdentity(report, url, tunnelPid);
  return { url: url.origin, socketPath: undefined };
}

function validateReportedHealthIdentity(report, url, tunnelPid, options = {}) {
  if (!report || typeof report !== "object") return;
  const reportedPid = report.pid ?? report.process_pid ?? report.process?.pid;
  if (reportedPid !== undefined && Number(reportedPid) !== Number(tunnelPid)) {
    throw new Error("Tunnel health PID mismatch.");
  }
  const reportedUrl = report.health_url ?? report.current_health_url ?? report.base_url ?? report.url;
  if (typeof reportedUrl === "string") {
    if (options.unixSocket) return;
    let normalized;
    try {
      normalized = new globalThis.URL(reportedUrl).origin;
    } catch {
      throw new Error("Tunnel health endpoint mismatch.");
    }
    if (normalized !== url.origin) throw new Error("Tunnel health endpoint mismatch.");
  }
}

function parseListenAddress(value) {
  const address = String(value).trim();
  const match = address.match(/^(?:\[([^\]]+)\]|(.*)):(\d+)$/);
  if (!match) throw new Error("HEALTH_LISTEN_ADDR must include a host and port.");
  const port = Number(match[3]);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new Error("HEALTH_LISTEN_ADDR contains an invalid port.");
  }
  return { host: match[1] ?? match[2], port };
}

function healthListenerHostMatches(listenHost, urlHost) {
  const expected = normalizeHealthHost(listenHost);
  const actual = normalizeHealthHost(urlHost);
  if (expected === "") return isLoopbackHost(actual);
  if (expected === "0.0.0.0") return isLoopbackHost(actual) && !actual.includes(":") && actual !== "localhost";
  if (expected === "::" || expected === "::0") return isLoopbackHost(actual) && actual.includes(":");
  if (expected === "*" || expected === "localhost") return isLoopbackHost(actual);
  return expected === actual;
}

function normalizeHealthHost(host) {
  return String(host ?? "").trim().replace(/^\[|\]$/g, "").toLowerCase();
}

/** Check that a caller-configured health endpoint is listening in the new tunnel process. */
export async function isHealthEndpointOwnedByProcess({
  tunnelPid,
  healthUrl,
  socketPath,
  execFileImpl = runCancellableCommand,
  platform = process.platform,
  timeoutMs = 3_000,
  signal
}) {
  throwIfAborted(signal);
  if (!Number.isInteger(Number(tunnelPid)) || Number(tunnelPid) <= 0) return false;
  if (platform === "win32") {
    return isWindowsHealthEndpointOwned({ tunnelPid, healthUrl, socketPath, execFileImpl, timeoutMs, signal });
  }

  const args = ["-nP", "-a", "-p", String(tunnelPid)];
  if (socketPath) {
    args.push("-U");
  } else {
    const url = new globalThis.URL(healthUrl);
    const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
    args.push(`-iTCP:${port}`, "-sTCP:LISTEN");
  }
  args.push("-Fptn");

  let stdout;
  try {
    ({ stdout } = await execFileImpl("lsof", args, {
      timeout: Math.min(3_000, timeoutMs),
      maxBuffer: 64_000,
      signal
    }));
  } catch (error) {
    if (signal?.aborted) throw abortReason(signal);
    if (error?.code === 1 && !String(error.stderr ?? "").trim()) return false;
    throw new Error("Cannot verify caller-configured tunnel health endpoint ownership with lsof.", { cause: error });
  }
  throwIfAborted(signal);
  return lsofOutputOwnsEndpoint(stdout, tunnelPid, healthUrl, socketPath);
}

function lsofOutputOwnsEndpoint(output, tunnelPid, healthUrl, socketPath) {
  let currentPid;
  let currentType;
  const entries = [];
  for (const line of String(output ?? "").split(/\r?\n/)) {
    if (line.startsWith("p")) currentPid = Number(line.slice(1));
    else if (line.startsWith("t")) currentType = line.slice(1);
    else if (line.startsWith("n") && currentPid === Number(tunnelPid)) {
      entries.push({ name: line.slice(1), type: currentType });
    }
  }
  if (socketPath) {
    return entries.some(({ name }) => name.replace(/ \(LISTEN\)$/, "") === socketPath);
  }
  const url = new globalThis.URL(healthUrl);
  const expectedPort = Number(url.port || (url.protocol === "https:" ? 443 : 80));
  const expectedHost = normalizeHealthHost(url.hostname);
  return entries.some(({ name, type }) => {
    const match = name.replace(/ \(LISTEN\)$/, "").match(/^(?:\[([^\]]+)\]|(.+)):(\d+)$/);
    if (!match || Number(match[3]) !== expectedPort) return false;
    return healthListenerAddressMatches(match[1] ?? match[2], expectedHost, type);
  });
}

function healthListenerAddressMatches(listenerHost, urlHost, type) {
  const listener = normalizeHealthHost(listenerHost);
  const url = normalizeHealthHost(urlHost);
  if (type === "IPv4") {
    if (url.includes(":") || !/^\d+(?:\.\d+){3}$/.test(url)) return false;
    return listener === url || listener === "0.0.0.0" || listener === "*";
  }
  if (type === "IPv6") {
    if (!url.includes(":")) return false;
    return listener === url || listener === "::" || listener === "*";
  }
  return false;
}

async function isWindowsHealthEndpointOwned({ tunnelPid, healthUrl, socketPath, execFileImpl, timeoutMs, signal }) {
  if (socketPath) {
    throw new Error("Cannot verify a caller-configured Unix health socket on Windows.");
  }
  const url = new globalThis.URL(healthUrl);
  const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
  const command = [
    `Get-NetTCPConnection -State Listen -LocalPort ${port} -ErrorAction SilentlyContinue`,
    "Select-Object LocalAddress,LocalPort,OwningProcess",
    "ConvertTo-Json -Compress"
  ].join(" | ");
  let stdout;
  try {
    ({ stdout } = await execFileImpl("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", command], {
      timeout: Math.min(3_000, timeoutMs),
      maxBuffer: 64_000,
      windowsHide: true,
      signal
    }));
  } catch (error) {
    if (signal?.aborted) throw abortReason(signal);
    throw new Error("Cannot verify caller-configured tunnel health endpoint ownership with PowerShell.", { cause: error });
  }
  throwIfAborted(signal);
  let listeners;
  try {
    const parsed = JSON.parse(stdout || "[]");
    listeners = Array.isArray(parsed) ? parsed : [parsed];
  } catch (error) {
    throw new Error("Windows returned invalid health listener ownership data.", { cause: error });
  }
  return listeners.some((listener) => Number(listener.OwningProcess) === Number(tunnelPid)
    && Number(listener.LocalPort) === port
    && healthListenerAddressMatches(listener.LocalAddress, url.hostname, listener.LocalAddress.includes(":") ? "IPv6" : "IPv4"));
}

function isLoopbackHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return host === "localhost" || host === "::1" || host.startsWith("127.");
}

/** True when detailed health has recorded at least one completed control-plane poll. */
export function hasSuccessfulControlPlanePoll(details) {
  if (unsupportedControlPlaneRecords(details).length > 0) return false;
  const component = details?.schema_version === 1 ? details.components?.["control-plane"] : undefined;
  if (!component) return false;
  const status = String(component.status ?? "").toLowerCase();
  const state = String(component.state ?? "").toLowerCase();
  const evidence = component.details;
  const failureCategory = String(evidence?.failure_category ?? "").toLowerCase();
  const consecutiveFailures = Number(evidence?.consecutive_failures ?? 0);
  if (status !== "ok"
    || ["failed", "error", "unhealthy", "disabled", "retrying", "starting", "pending", "unknown"].includes(state)
    || (failureCategory !== "" && failureCategory !== "none")
    || !Number.isFinite(consecutiveFailures)
    || consecutiveFailures > 0) {
    return false;
  }
  return isValidTimestamp(evidence?.last_success);
}

function unsupportedControlPlaneRecords(details) {
  if (!details || typeof details !== "object") return [];
  const records = [];
  const component = details.components?.["control-plane"];
  if (details.schema_version !== 1 && component && typeof component === "object" && !Array.isArray(component)) {
    records.push(component);
  }
  const candidates = [
    details?.control_plane_poll,
    details?.polling?.control_plane_poll,
    details?.control_plane_poll_health?.control_plane_poll,
    details?.control_plane_poll_health
  ];
  records.push(...candidates.filter((record) => record && typeof record === "object" && !Array.isArray(record)));
  return records;
}

function isValidTimestamp(value) {
  if (typeof value === "number") return Number.isFinite(value) && value > 0;
  if (typeof value !== "string") return false;
  const normalized = value.trim();
  if (!normalized) return false;
  if (/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(normalized)) {
    return Number.isFinite(Number(normalized)) && Number(normalized) > 0;
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/i.test(normalized)) {
    return false;
  }
  const parsed = Date.parse(normalized);
  return Number.isFinite(parsed) && parsed > 0;
}

function hasControlPlaneFailure(details) {
  const component = details?.schema_version === 1 ? details.components?.["control-plane"] : undefined;
  if (unsupportedControlPlaneRecords(details).length > 0) return true;
  if (!component) return false;
  const evidence = component.details;
  const failureCategory = String(evidence?.failure_category ?? "").toLowerCase();
  const status = String(component.status ?? "").toLowerCase();
  const state = String(component.state ?? "").toLowerCase();
  return status !== "ok"
    || ["failed", "error", "unhealthy", "disabled", "retrying", "starting", "pending", "unknown"].includes(state)
    || Number(evidence?.consecutive_failures ?? 0) > 0
    || (failureCategory !== "" && failureCategory !== "none");
}

function hasPermanentControlPlaneFailure(details) {
  const component = details?.schema_version === 1 ? details.components?.["control-plane"] : undefined;
  const permanentRecord = (record) => {
    const status = String(record.status ?? "").toLowerCase();
    const state = String(record.state ?? "").toLowerCase();
    return ["failed", "error", "unhealthy"].includes(status)
      || ["failed", "error", "unhealthy"].includes(state)
      || record.ok === false
      || record.success === false;
  };
  if (unsupportedControlPlaneRecords(details).some(permanentRecord)) return true;
  if (!component) return false;
  const status = String(component.status ?? "").toLowerCase();
  const state = String(component.state ?? "").toLowerCase();
  return ["failed", "error", "unhealthy"].includes(status)
    || ["failed", "error", "unhealthy"].includes(state);
}

function hasSuccessfulControlPlanePollMetric(metrics) {
  if (typeof metrics !== "string") return false;
  for (const line of metrics.split(/\r?\n/)) {
    const match = line.match(/^commands_poll_last_successful_timestamp_seconds(?:\{[^}]*\})?\s+([^\s]+)/);
    if (!match) continue;
    const timestamp = Number(match[1]);
    if (Number.isFinite(timestamp) && timestamp > 0) return true;
  }
  return false;
}

/** Probe the documented HTTP readiness endpoints for clients without the health subcommand. */
export async function probeTunnelHttp(baseUrl, options = {}) {
  const requestImpl = options.request ?? defaultHttpProbeRequest;
  const socketPath = options.socketPath;
  const requestOptions = {
    socketPath,
    timeoutMs: integerTimeout(options.requestTimeoutMs),
    signal: options.signal
  };
  let ready;
  try {
    ready = await requestImpl(new globalThis.URL("/readyz", baseUrl).toString(), {
      ...requestOptions
    });
  } catch (error) {
    if (options.signal?.aborted) throw abortReason(options.signal);
    return { state: "pending", reason: classifyHttpException(error) };
  }
  const readyData = parseJson(ready.body);
  const readyText = `${safeReason(readyData)} ${typeof ready.body === "string" ? ready.body.slice(0, 2_000) : ""}`.toLowerCase();
  if (isPermanentReadinessError(readyText)) {
    return { state: "failed", reason: permanentReadinessReason(readyText) ?? safeReasonCode(readyData, ready.status) };
  }
  if (ready.status !== 200) {
    const readiness = classifyHttpReadiness(ready.status, readyData, ready.body);
    if (readiness.state === "failed" || ready.status !== 503) return readiness;
    try {
      const detailsResponse = await requestImpl(new globalThis.URL("/health?details=true", baseUrl).toString(), {
        ...requestOptions
      });
      if (detailsResponse.status === 200) {
        const details = parseJson(detailsResponse.body);
        if (isPermanentReadinessError(JSON.stringify(details ?? {}).toLowerCase())
          || hasPermanentControlPlaneFailure(details)) {
          return { state: "failed", reason: safeReasonCode(details, detailsResponse.status) };
        }
      }
    } catch {
      if (options.signal?.aborted) throw abortReason(options.signal);
    }
    return readiness;
  }
  if (readyData && typeof readyData === "object") {
    const readinessState = String(readyData.status ?? readyData.state ?? "").toLowerCase();
    if (readyData.ready === false || ["pending", "starting", "not_ready", "in_progress"].includes(readinessState)) {
      return { state: "pending", reason: safeReasonCode(readyData, ready.status) };
    }
    if (["failed", "error", "unhealthy"].includes(readinessState)) {
      return { state: "failed", reason: safeReasonCode(readyData, ready.status) };
    }
  }
  if (/oauth discovery pending|mcp startup probe timed out|control.plane.poll.pending|\bnot.ready\b|\bpending\b|\bstarting\b|\bin.progress\b/.test(readyText)) {
    return { state: "pending", reason: safeReasonCode(readyData, ready.status) };
  }
  if (/\bfailed\b|\berror\b|\bunhealthy\b/.test(readyText)) {
    return { state: "failed", reason: safeReasonCode(readyData, ready.status) };
  }

  let detailsResponse;
  try {
    detailsResponse = await requestImpl(new globalThis.URL("/health?details=true", baseUrl).toString(), {
      ...requestOptions
    });
  } catch (error) {
    if (options.signal?.aborted) throw abortReason(options.signal);
    return { state: "pending", reason: classifyHttpException(error) };
  }
  let details;
  if (detailsResponse.status === 200) {
    details = parseJson(detailsResponse.body);
    if (!details || typeof details !== "object") {
      return { state: "failed", reason: "invalid_health_details" };
    }
    if (isPermanentReadinessError(JSON.stringify(details).toLowerCase())) {
      return { state: "failed", reason: safeReasonCode(details, detailsResponse.status) };
    }
    if (hasPermanentControlPlaneFailure(details)) {
      return { state: "failed", reason: safeReasonCode(details, detailsResponse.status) };
    }
    if (hasSuccessfulControlPlanePoll(details)) {
      return { state: "ready", reason: "readyz_and_control_plane_poll_ready" };
    }
    if (hasControlPlaneFailure(details)) {
      return { state: "pending", reason: safeReasonCode(details, detailsResponse.status) };
    }
  } else if (detailsResponse.status !== 404) {
    const detailsOutcome = classifyHttpReadiness(
      detailsResponse.status,
      parseJson(detailsResponse.body),
      detailsResponse.body
    );
    if (detailsOutcome.state === "failed") return detailsOutcome;
  }

  let metricsResponse;
  try {
    metricsResponse = await requestImpl(new globalThis.URL("/metrics", baseUrl).toString(), requestOptions);
  } catch (error) {
    if (options.signal?.aborted) throw abortReason(options.signal);
    return { state: "pending", reason: classifyHttpException(error) };
  }
  if (metricsResponse.status !== 200) {
    const metricsOutcome = classifyHttpReadiness(
      metricsResponse.status,
      parseJson(metricsResponse.body),
      metricsResponse.body
    );
    if (metricsOutcome.state === "failed" && metricsResponse.status !== 404) return metricsOutcome;
    return { state: "pending", reason: "control_plane_poll_pending" };
  }
  if (isPermanentReadinessError(String(metricsResponse.body).toLowerCase())) {
    return { state: "failed", reason: safeReasonCode(parseJson(metricsResponse.body), metricsResponse.status) };
  }
  return hasSuccessfulControlPlanePollMetric(metricsResponse.body)
    ? { state: "ready", reason: "readyz_and_control_plane_poll_ready" }
    : { state: "pending", reason: "control_plane_poll_pending" };
}

function classifyHttpReadiness(status, data, body) {
  const text = `${safeReason(data)} ${typeof body === "string" ? body.slice(0, 2_000) : ""}`.toLowerCase();
  const reason = safeReasonCode(data, status);
  if (isPermanentReadinessError(text)) return { state: "failed", reason };
  if (status === 429 || status === 502 || status === 503 || status === 504 || /pending|starting|not.ready|in.progress|timed.out/.test(text)) {
    return { state: "pending", reason };
  }
  return { state: "failed", reason };
}

function safeReason(value) {
  if (!value || typeof value !== "object") return "";
  return [value.reason, value.reason_code, value.error, value.status, value.state]
    .filter((item) => typeof item === "string")
    .join(" ");
}

function safeReasonCode(value, status) {
  const known = new Set([
    "catalog_failed",
    "discovery_failed",
    "oauth_discovery_pending",
    "oauth_discovery_failed",
    "mcp_probe_failed",
    "mcp_startup_probe_timed_out",
    "control_plane_poll_pending",
    "profile_invalid",
    "config_invalid",
    "unauthorized",
    "forbidden",
    "ready",
    "pending",
    "starting"
  ]);
  const candidates = [
    value?.reason_code,
    value?.reason,
    value?.status,
    value?.state,
    value?.components?.["control-plane"]?.reason_code,
    value?.components?.["control-plane"]?.details?.failure_category,
    value?.components?.["control-plane"]?.details?.last_error,
    value?.readyz?.body,
    value?.healthz?.body,
    value?.control_plane_poll?.error,
    value?.control_plane_poll?.last_error
  ];
  const permanentReason = permanentReadinessReason(candidates.filter((candidate) => typeof candidate === "string").join(" "));
  if (permanentReason) return permanentReason;
  for (const candidate of candidates) {
    if (typeof candidate !== "string") continue;
    const normalized = candidate.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
    if (known.has(normalized)) return normalized;
    for (const reason of known) {
      if (candidate.toLowerCase().includes(reason.replaceAll("_", " "))
          || candidate.toLowerCase().includes(reason)) return reason;
    }
  }
  return `http_${status}`;
}

function isPermanentReadinessError(text) {
  return Boolean(permanentReadinessReason(text));
}

function permanentReadinessReason(text) {
  if (/catalog[\s_.-]+(?:failed|failure|error)/i.test(text)) return "catalog_failed";
  if (/oauth.{0,120}(?:failed|failure|invalid|error|rejected)|(?:failed|failure|invalid|error|rejected).{0,120}oauth/i.test(text)) {
    return "oauth_discovery_failed";
  }
  if (/(?:profile|config(?:uration)?).{0,120}(?:invalid|failed|failure|error|malformed|missing|rejected)|(?:invalid|failed|failure|error|malformed|missing|rejected).{0,120}(?:profile|config(?:uration)?)/i.test(text)) {
    return /profile/i.test(text) ? "profile_invalid" : "config_invalid";
  }
  if (/unauthorized/i.test(text)) return "unauthorized";
  if (/forbidden/i.test(text)) return "forbidden";
  if (/api[\s_.-]*key.{0,40}required/i.test(text)) return "config_invalid";
  if (/tunnel[\s_.-]*id.{0,40}required|mcp[\s_.-]*server[\s_.-]*url.{0,40}required/i.test(text)) return "config_invalid";
  return undefined;
}

function parseJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

function classifyHttpException(error) {
  const code = error?.code ?? error?.cause?.code;
  if (["ECONNREFUSED", "ECONNRESET", "EHOSTUNREACH", "ETIMEDOUT"].includes(code) || error?.name === "TimeoutError") {
    return "health_endpoint_pending";
  }
  return "health_endpoint_unavailable";
}

async function defaultHttpProbeRequest(url, options = {}) {
  const timeoutMs = integerTimeout(options.timeoutMs ?? 3_000);
  if (!options.socketPath) {
    const response = await globalThis.fetch(url, { signal: makeRequestSignal(options.signal, timeoutMs) });
    return { status: response.status, body: await response.text() };
  }
  return new Promise((resolve, reject) => {
    const target = new globalThis.URL(url);
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      options.signal?.removeEventListener("abort", onAbort);
      if (error) reject(error);
      else resolve(value);
    };
    const request = httpRequest({
      socketPath: options.socketPath,
      path: `${target.pathname}${target.search}`,
      method: "GET",
      timeout: timeoutMs,
      headers: { Host: target.host }
    }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk;
        if (body.length > 64_000) request.destroy(new Error("Health response exceeded the size limit."));
      });
      response.on("end", () => finish(undefined, { status: response.statusCode ?? 0, body }));
    });
    const onAbort = () => request.destroy(abortReason(options.signal));
    request.once("timeout", () => request.destroy(Object.assign(new Error("Health request timed out."), { code: "ETIMEDOUT" })));
    request.once("error", (error) => finish(error));
    options.signal?.addEventListener("abort", onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
    request.end();
  });
}

function integerTimeout(value) {
  return Math.max(1, Math.ceil(value ?? 3_000));
}

/** Select the full CLI check when present, retaining a strict HTTP fallback for reduced clients. */
export function selectTunnelHealthMode({ healthHelp, runHelp }) {
  const supportsUrlFile = /(?:HEALTH_URL_FILE|--health\.url-file)/.test(runHelp);
  const supportsListenAddr = /(?:HEALTH_LISTEN_ADDR|--health\.listen-addr)/.test(runHelp);
  if (!supportsUrlFile || !supportsListenAddr) {
    throw new Error("Configured tunnel-client cannot publish an instance-specific health URL.");
  }
  const supportsHealthCommand = /Usage:\s*[\s\S]*tunnel-client health \[flags\]/.test(healthHelp)
    && /--json\b/.test(healthHelp)
    && /--require-control-plane-poll\b/.test(healthHelp)
    && /--pid\b/.test(healthHelp)
    && /--url-file\b/.test(healthHelp);
  return supportsHealthCommand ? "command" : "http";
}

/** Convert one-shot health command output into a fail-closed readiness result. */
export function classifyTunnelHealthCommand({
  exitCode,
  stdout,
  stderr,
  healthUrl,
  tunnelPid,
  listenAddr,
  unixSocket,
  processIdentityVerified = false
}) {
  const report = parseJsonReport(stdout);
  const combined = [
    safeReason(report),
    report?.readyz?.body,
    report?.readyz?.error,
    report?.healthz?.body,
    report?.healthz?.error,
    report?.control_plane_poll?.error,
    stdout,
    stderr
  ].filter((value) => typeof value === "string").join(" ").toLowerCase();
  if (isPermanentReadinessError(combined)) {
    return { state: "failed", reason: safeReasonCode(report, exitCode) };
  }
  const poll = report?.control_plane_poll;
  const pollMetricNotExposed = poll?.ok === false
    && /missing commands_poll_last_successful_timestamp_seconds metric/i.test(poll.error ?? "");
  const firstPollNotCompleted = exitCode === 2
    && report?.result === "fail"
    && report?.healthz?.ok === true
    && report?.readyz?.ok === true
    && poll?.ok === false
    && (poll.value === undefined || poll.value === 0)
    && typeof poll.error === "string"
    && poll.error.trim().toLowerCase() === "no successful control-plane poll observed";
  if (pollMetricNotExposed || firstPollNotCompleted) {
    return { state: "pending", reason: "control_plane_poll_pending" };
  }
  if (exitCode === 0) {
    if (!report || !hasReadySignal(report, processIdentityVerified)) {
      return { state: "failed", reason: "invalid_health_report" };
    }
    try {
      validateTunnelHealthUrl(healthUrl, { tunnelPid, listenAddr, unixSocket, report });
    } catch (error) {
      return { state: "failed", reason: error.message.includes("PID") ? "health_pid_mismatch" : "health_endpoint_mismatch" };
    }
    return { state: "ready", reason: "tunnel_health_ready" };
  }
  if (/oauth discovery pending|mcp startup probe timed out|control.plane.poll.pending|connection refused|connection reset|context deadline exceeded|i\/o timeout|temporary unavailable|\bpending\b|\bstarting\b/.test(combined)) {
    return { state: "pending", reason: safeReasonCode(report, exitCode) };
  }
  return { state: "failed", reason: safeReasonCode(report, exitCode) };
}

function parseJsonReport(output) {
  if (typeof output !== "string") return undefined;
  const candidates = [output.trim(), ...output.split(/\r?\n/).reverse()];
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === "object") return parsed;
    } catch {
      // Health commands may include a diagnostic line before their JSON result.
    }
  }
  return undefined;
}

function hasReadySignal(report, processIdentityVerified) {
  const pollTimestamp = report.control_plane_poll?.value ?? report.control_plane_poll?.last_success;
  return processIdentityVerified === true
    && report.result === "ok"
    && report.process?.running === true
    && report.process.pid !== undefined
    && report.healthz?.ok === true
    && report.readyz?.ok === true
    && report.control_plane_poll?.ok === true
    && isValidTimestamp(pollTimestamp);
}

/** Retry pending tunnel health, but stop immediately when health reports a permanent error. */
export async function waitForTunnelReadiness({
  probe,
  timeoutMs,
  tunnelPid,
  isProcessAlive = () => true,
  now = () => performance.now(),
  sleep = delay,
  retryIntervalMs = DEFAULT_RETRY_INTERVAL_MS,
  deadline: fixedDeadline,
  signal
}) {
  const deadline = fixedDeadline ?? now() + timeoutMs;
  let lastReason = "tunnel_health_pending";
  for (;;) {
    throwIfAborted(signal);
    if (!isProcessAlive(tunnelPid)) throw new Error("Tunnel process exited before readiness.");
    const remainingBeforeProbe = deadline - now();
    if (remainingBeforeProbe <= 0) throw new Error(`Tunnel readiness timed out (${lastReason}).`);
    const timeoutError = new Error(`Tunnel readiness timed out (${lastReason}).`);
    const result = await runProbeWithinDeadline(probe, {
      tunnelPid,
      remainingMs: Math.min(remainingBeforeProbe, Math.ceil(remainingBeforeProbe))
    }, { deadline, now, signal, timeoutError });
    if (!isProcessAlive(tunnelPid)) throw new Error("Tunnel process exited before readiness.");
    if (result.state === "ready") return result;
    if (result.state === "failed") throw new Error(`Tunnel startup failed (${result.reason}).`);
    lastReason = result.reason ?? lastReason;
    const remaining = deadline - now();
    if (remaining <= 0) throw new Error(`Tunnel readiness timed out (${lastReason}).`);
    await sleep(Math.max(1, Math.min(retryIntervalMs, Math.ceil(remaining))), signal);
  }
}

function delay(durationMs, signal) {
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    const timer = globalThis.setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, durationMs);
    const onAbort = () => {
      globalThis.clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      reject(abortReason(signal));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}
