import { access, chmod, mkdtemp, readFile, realpath } from "node:fs/promises";
import { constants, rmSync } from "node:fs";
import process from "node:process";
import { performance } from "node:perf_hooks";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { load as loadYaml } from "js-yaml";
import { createConnectorRuntime, isManagedProcessTreeAlive, signalManagedProcessTree } from "./connector-runtime.mjs";
import { spawnManagedProcess, waitForManagedTarget } from "./secure-process-supervisor.mjs";
import {
  DEFAULT_MCP_STARTUP_WAIT_TIMEOUT,
  DEFAULT_TUNNEL_STARTUP_WAIT_TIMEOUT,
  buildMcpProbeUrl,
  classifyTunnelHealthCommand,
  isHealthEndpointOwnedByProcess,
  parseDurationMs,
  probeTunnelHttp,
  readHealthUrlSnapshot,
  runCancellableCommand,
  selectTunnelHealthMode,
  waitForFreshHealthUrl,
  waitForMcpListener,
  waitForMcpReadiness,
  waitForTunnelReadiness
} from "./secure-startup.mjs";

const DEFAULT_CONFIG_PATH = "./config.local.json";
const DEFAULT_PORT = "8787";
const DEFAULT_PROFILE = "gpt-repo-local";
const startupController = new globalThis.AbortController();
const activeStartupHelpers = new Set();
const runtime = createConnectorRuntime({
  signalChild: signalManagedProcessTree,
  signalExitedChildren: true,
  failOnUnexpectedCleanExit: true,
  isProcessTreeAlive: isManagedProcessTreeAlive,
  processTreeCleanup: true,
  processTreeCleanupTimeoutMs: 2_000,
  onShutdown: () => {
    startupController.abort(new Error("Secure connector startup cancelled."));
    return waitForStartupHelpers();
  }
});
let privateHealthDirectory;

process.on("SIGINT", () => handleShutdown("SIGINT"));
process.on("SIGTERM", () => handleShutdown("SIGTERM"));
process.once("exit", () => {
  if (privateHealthDirectory) {
    try {
      rmSync(privateHealthDirectory, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup for the private health endpoint metadata.
    }
  }
});

await loadDotEnv(".env");
await ensureConfigExists(envValue("GPT_REPO_CONFIG", "REPO_READER_CONFIG", DEFAULT_CONFIG_PATH));
ensureRequiredEnv("CONTROL_PLANE_API_KEY");
try {
  await startProcesses(startupController.signal);
} catch (error) {
  if (!startupController.signal.aborted) {
    globalThis.console.error(`[secure-connect] ${error instanceof Error ? error.message : "Startup failed."}`);
    runtime.terminateAndExit(1);
  }
}

async function loadDotEnv(path) {
  let raw;
  try {
    raw = await readFile(path, "utf8");
  } catch (error) {
    if (isNotFoundError(error)) {
      return;
    }
    throw error;
  }

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) {
      continue;
    }
    const [key, ...valueParts] = trimmed.split("=");
    if (!key || process.env[key] !== undefined) {
      continue;
    }
    process.env[key] = unquoteEnvValue(valueParts.join("="));
  }
}

function unquoteEnvValue(value) {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith("\"") && trimmed.endsWith("\"")) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

async function ensureConfigExists(configPath) {
  try {
    await access(configPath, constants.F_OK);
  } catch {
    globalThis.console.error(`Missing ${configPath}. Run: cp config.example.json ${configPath}`);
    process.exit(1);
  }
}

function ensureRequiredEnv(name) {
  if (!process.env[name]) {
    globalThis.console.error(`Missing ${name}. Add it to .env or export it before running npm run connect:secure.`);
    process.exit(1);
  }
}

function envValue(primaryName, legacyName, fallback) {
  const primary = process.env[primaryName];
  if (primary && primary.trim() !== "") {
    return primary;
  }
  const legacy = legacyName ? process.env[legacyName] : undefined;
  if (legacy && legacy.trim() !== "") {
    return legacy;
  }
  return fallback;
}

async function startProcesses(signal) {
  throwIfAborted(signal);
  const configPath = envValue("GPT_REPO_CONFIG", "REPO_READER_CONFIG", DEFAULT_CONFIG_PATH);
  const port = Number(envValue("PORT", undefined, DEFAULT_PORT));
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new Error("PORT must be an integer from 0 to 65535.");
  }
  const host = envValue("GPT_REPO_HOST", undefined, "127.0.0.1").trim();
  const logFormat = envValue("GPT_REPO_LOG_FORMAT", "REPO_READER_LOG_FORMAT", "pretty");
  const mcpTimeout = parseDurationMs(
    process.env.MCP_STARTUP_WAIT_TIMEOUT ?? DEFAULT_MCP_STARTUP_WAIT_TIMEOUT,
    "MCP_STARTUP_WAIT_TIMEOUT"
  );
  const tunnelTimeout = parseDurationMs(
    process.env.TUNNEL_STARTUP_WAIT_TIMEOUT ?? DEFAULT_TUNNEL_STARTUP_WAIT_TIMEOUT,
    "TUNNEL_STARTUP_WAIT_TIMEOUT"
  );
  const tunnelClientBin = envValue("TUNNEL_CLIENT_BIN", undefined, "tunnel-client");
  const tunnelClientProfile = envValue("TUNNEL_CLIENT_PROFILE", undefined, DEFAULT_PROFILE);
  const healthMode = await inspectTunnelClient(tunnelClientBin, signal);
  throwIfAborted(signal);
  const healthContext = await prepareTunnelHealthContext(tunnelClientProfile);
  throwIfAborted(signal);

  globalThis.console.log("Starting GPT Repo MCP and OpenAI Secure MCP Tunnel.");
  globalThis.console.log(`Running: tunnel-client run --profile ${tunnelClientProfile}`);
  globalThis.console.log("Open ChatGPT connector settings, choose Tunnel, and select the configured tunnel while this process is running.");
  globalThis.console.log(`Tunnel profile: ${tunnelClientProfile}`);
  globalThis.console.log(`Waiting up to ${mcpTimeout.value} for the configured MCP endpoint to become ready.`);

  throwIfAborted(signal);
  const mcpStartedAt = performance.now();
  const mcp = spawnManagedProcess("npm", ["run", "dev"], {
    env: {
      ...process.env,
      GPT_REPO_CONFIG: configPath,
      REPO_READER_CONFIG: configPath,
      PORT: String(port),
      GPT_REPO_LOG_FORMAT: logFormat,
      REPO_READER_LOG_FORMAT: logFormat,
      MCP_STARTUP_WAIT_TIMEOUT: mcpTimeout.value
    },
    stdio: ["ignore", "pipe", "pipe"],
    detached: process.platform !== "win32"
  });
  runtime.track(mcp, "mcp");

  const mcpDeadline = mcpStartedAt + mcpTimeout.timeoutMs;
  await waitForManagedTarget(mcp, { signal, timeoutMs: mcpTimeout.timeoutMs });
  const listenerTimeoutMs = mcpDeadline - performance.now();
  if (listenerTimeoutMs <= 0) throw new Error("MCP startup timed out before its listener bound.");
  const listener = await waitForMcpListener({ child: mcp, port, timeoutMs: listenerTimeoutMs, signal });
  const probeUrl = buildMcpProbeUrl({
    host,
    port,
    boundPort: listener.boundPort,
    publicPathToken: process.env.GPT_REPO_PUBLIC_PATH_TOKEN ?? process.env.REPO_READER_PUBLIC_PATH_TOKEN
  });
  const mcpRemainingMs = mcpDeadline - performance.now();
  if (mcpRemainingMs <= 0) throw new Error("MCP startup timed out before protocol readiness.");
  await waitForMcpReadiness({ url: probeUrl, timeoutMs: mcpRemainingMs, deadline: mcpDeadline, signal });
  throwIfAborted(signal);
  globalThis.console.log("MCP initialize and repo_list_roots discovery are ready.");

  const tunnelEnvironment = {
    ...process.env,
    ...healthContext.environment,
    MCP_STARTUP_WAIT_TIMEOUT: mcpTimeout.value
  };
  throwIfAborted(signal);
  const tunnelStartedAt = performance.now();
  const tunnelDeadline = tunnelStartedAt + tunnelTimeout.timeoutMs;
  const tunnel = spawnManagedProcess(tunnelClientBin, ["run", "--profile", tunnelClientProfile], {
    env: tunnelEnvironment,
    stdio: ["ignore", "pipe", "pipe"],
    detached: process.platform !== "win32"
  });
  runtime.track(tunnel, "tunnel");

  const tunnelStartRemainingMs = tunnelDeadline - performance.now();
  if (tunnelStartRemainingMs <= 0) throw new Error("Tunnel startup timed out before the runtime started.");
  const tunnelPid = await waitForManagedTarget(tunnel, { signal, timeoutMs: tunnelStartRemainingMs });
  const isTunnelAlive = () => tunnel.targetExited !== true && tunnel.exitCode === null && tunnel.signalCode === null;
  const healthIdentity = await waitForFreshHealthUrl({
    path: healthContext.urlFile,
    before: healthContext.before,
    listenAddr: healthContext.listenAddr,
    unixSocket: healthContext.unixSocket,
    tunnelPid,
    timeoutMs: Math.max(1, tunnelDeadline - performance.now()),
    isProcessAlive: isTunnelAlive,
    deadline: tunnelDeadline,
    signal
  });
  const ownerCheckRemainingMs = tunnelDeadline - performance.now();
  if (ownerCheckRemainingMs <= 0) throw new Error("Tunnel readiness timed out before endpoint ownership was verified.");
  if (!await isHealthEndpointOwnedByProcess({
    tunnelPid,
    healthUrl: healthIdentity.url,
    socketPath: healthIdentity.socketPath,
    timeoutMs: ownerCheckRemainingMs,
    signal,
    execFileImpl: runStartupHelper
  })) {
    throw new Error("Tunnel health endpoint is not owned by the newly launched tunnel process.");
  }
  const tunnelRemainingMs = tunnelDeadline - performance.now();
  if (tunnelRemainingMs <= 0) throw new Error("Tunnel readiness timed out before its health check completed.");
  const probe = healthMode === "command"
    ? async ({ remainingMs, signal: probeSignal }) => {
      const result = await runTunnelHealthCommand(
        tunnelClientBin,
        healthContext.urlFile,
        tunnelPid,
        Math.min(5_000, remainingMs),
        probeSignal
      );
      return classifyTunnelHealthCommand({
        ...result,
        healthUrl: healthIdentity.url,
        tunnelPid,
        unixSocket: healthIdentity.socketPath,
    listenAddr: healthContext.listenAddr,
        processIdentityVerified: true
      });
    }
    : async ({ remainingMs, signal: probeSignal }) => probeTunnelHttp(healthIdentity.url, {
      socketPath: healthIdentity.socketPath,
      requestTimeoutMs: Math.min(3_000, remainingMs),
      signal: probeSignal
    });
  await waitForTunnelReadiness({
    probe,
    tunnelPid,
    timeoutMs: tunnelRemainingMs,
    deadline: tunnelDeadline,
    signal,
    isProcessAlive: isTunnelAlive
  });
  globalThis.console.log("Secure MCP Tunnel passed readiness and successful control-plane poll checks.");
}

function handleShutdown(signal) {
  runtime.shutdown(signal, "Shutting down MCP server and secure tunnel.");
}

function throwIfAborted(signal) {
  if (signal?.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error("Secure connector startup cancelled.");
  }
}

async function inspectTunnelClient(binary, signal) {
  const [healthHelp, runHelp] = await Promise.all([
    captureHelp(binary, ["health", "--help"], signal),
    captureHelp(binary, ["run", "--help"], signal)
  ]);
  return selectTunnelHealthMode({ healthHelp, runHelp });
}

async function captureHelp(binary, args, signal) {
  try {
    const { stdout, stderr } = await runStartupHelper(binary, args, {
      timeout: 5_000,
      maxBuffer: 1_000_000,
      env: process.env,
      signal
    });
    return `${stdout}\n${stderr}`;
  } catch (error) {
    if (error?.code === "ERR_PROCESS_TREE_CLEANUP") throw error;
    if (signal?.aborted) throwIfAborted(signal);
    return `${error?.stdout ?? ""}\n${error?.stderr ?? ""}`;
  }
}

async function prepareTunnelHealthContext(profile) {
  const profileHealth = await readTunnelProfileHealth(profile);
  const configuredListenAddr = process.env.HEALTH_LISTEN_ADDR?.trim() || profileHealth.listenAddr;
  const configuredUnixSocket = process.env.HEALTH_UNIX_SOCKET?.trim() || profileHealth.unixSocket;
  const callerUrlFile = process.env.HEALTH_URL_FILE?.trim();
  const environment = {};
  let urlFile = callerUrlFile;
  if (!urlFile) {
    privateHealthDirectory = await mkdtemp(join(tmpdir(), "gpt-repo-tunnel-health-"));
    await chmod(privateHealthDirectory, 0o700);
    urlFile = join(privateHealthDirectory, "health.url");
    environment.HEALTH_URL_FILE = urlFile;
  }
  let listenAddr = configuredListenAddr;
  let unixSocket = configuredUnixSocket ? resolve(configuredUnixSocket) : undefined;
  if (!listenAddr && !unixSocket) {
    listenAddr = "127.0.0.1:0";
    environment.HEALTH_LISTEN_ADDR = "127.0.0.1:0";
  }
  const before = await readHealthUrlSnapshot(urlFile);
  return { environment, urlFile, before, listenAddr, unixSocket };
}

async function readTunnelProfileHealth(profile) {
  if (!profile || profile === "." || profile === ".." || profile.includes("/") || profile.includes("\\")) {
    throw new Error("TUNNEL_CLIENT_PROFILE must be a single profile name.");
  }
  const profileDir = resolveTunnelProfileDirectory();
  let canonicalProfileDir;
  try {
    canonicalProfileDir = await realpath(profileDir);
  } catch (error) {
    if (isNotFoundError(error)) return {};
    throw new Error("Cannot resolve the selected tunnel profile directory.", { cause: error });
  }
  const profilePath = resolve(canonicalProfileDir, `${profile}.yaml`);
  const relativePath = relative(canonicalProfileDir, profilePath);
  if (!relativePath || relativePath.startsWith(`..${sep}`) || relativePath === ".." || isAbsolute(relativePath)) {
    throw new Error("Selected tunnel profile path is outside its profile directory.");
  }
  let canonicalProfilePath;
  try {
    canonicalProfilePath = await realpath(profilePath);
  } catch (error) {
    if (isNotFoundError(error)) return {};
    throw new Error("Cannot resolve the selected tunnel profile file.", { cause: error });
  }
  const canonicalRelativePath = relative(canonicalProfileDir, canonicalProfilePath);
  if (canonicalRelativePath.startsWith(`..${sep}`) || canonicalRelativePath === ".." || isAbsolute(canonicalRelativePath)) {
    throw new Error("Selected tunnel profile file resolves outside its profile directory.");
  }

  let document;
  try {
    document = loadYaml(await readFile(canonicalProfilePath, "utf8"));
  } catch (error) {
    throw new Error("Cannot read the selected tunnel profile health settings.", { cause: error });
  }
  if (document === undefined) return {};
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("Selected tunnel profile must contain a YAML mapping.");
  }
  const health = document.health ?? {};
  if (!health || typeof health !== "object" || Array.isArray(health)) {
    throw new Error("Tunnel profile health settings must be a YAML mapping.");
  }
  const listenAddr = health.listen_addr;
  const unixSocket = health.unix_socket;
  if (listenAddr !== undefined && typeof listenAddr !== "string") {
    throw new Error("Tunnel profile health.listen_addr must be a string.");
  }
  if (unixSocket !== undefined && typeof unixSocket !== "string") {
    throw new Error("Tunnel profile health.unix_socket must be a string.");
  }
  const resolvedListenAddr = await resolveProfileHealthValue("health.listen_addr", listenAddr);
  const resolvedUnixSocket = await resolveProfileHealthValue("health.unix_socket", unixSocket);
  return {
    listenAddr: resolvedListenAddr,
    unixSocket: resolvedUnixSocket
  };
}

// Keep named profile lookup in the same order as tunnel-client's profile resolver.
function resolveTunnelProfileDirectory() {
  const configuredProfileDir = process.env.TUNNEL_CLIENT_PROFILE_DIR?.trim();
  if (configuredProfileDir) return resolve(configuredProfileDir);

  const xdgConfigHome = process.env.XDG_CONFIG_HOME?.trim();
  if (xdgConfigHome) return resolve(xdgConfigHome, "tunnel-client");

  const home = process.env.HOME?.trim();
  if (home) return resolve(home, ".config", "tunnel-client");

  const userConfigDir = process.platform === "win32" ? process.env.APPDATA?.trim() : undefined;
  if (!userConfigDir) throw new Error("Cannot resolve the selected tunnel profile directory.");
  return resolve(userConfigDir, "tunnel-client");
}

/** Resolve the tunnel client's env: and file: references without exposing their values in errors. */
async function resolveProfileHealthValue(field, rawValue) {
  if (rawValue === undefined) return undefined;
  const value = rawValue.trim();
  if (!value) return undefined;
  let resolved = value;
  const lowerValue = value.toLowerCase();
  if (lowerValue.startsWith("env:")) {
    const name = value.slice(4).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
      throw new Error(`Selected tunnel profile ${field} reference is invalid.`);
    }
    resolved = process.env[name]?.trim();
    if (!resolved) {
      throw new Error(`Selected tunnel profile ${field} reference is missing or invalid.`);
    }
  } else if (lowerValue.startsWith("file:")) {
    const path = value.slice(5).trim();
    if (!path) {
      throw new Error(`Selected tunnel profile ${field} reference is invalid.`);
    }
    try {
      resolved = (await readFile(path, "utf8")).trim();
    } catch {
      throw new Error(`Selected tunnel profile ${field} reference is missing or invalid.`);
    }
    if (!resolved) {
      throw new Error(`Selected tunnel profile ${field} reference is missing or invalid.`);
    }
  }
  if (/[\r\n]/.test(resolved)) {
    throw new Error(`Selected tunnel profile ${field} value is invalid.`);
  }
  return resolved;
}

async function runTunnelHealthCommand(binary, urlFile, tunnelPid, timeoutMs, signal) {
  try {
    const { stdout, stderr } = await runStartupHelper(binary, [
      "health",
      "--json",
      "--require-control-plane-poll",
      "--pid",
      String(tunnelPid),
      "--url-file",
      urlFile
    ], {
      timeout: Math.max(1, Math.ceil(timeoutMs)),
      maxBuffer: 256_000,
      env: process.env,
      signal
    });
    return { exitCode: 0, stdout, stderr };
  } catch (error) {
    if (error?.code === "ERR_PROCESS_TREE_CLEANUP") throw error;
    if (signal?.aborted) throwIfAborted(signal);
    if (error?.code === "ETIMEDOUT" || error?.killed) {
      return {
        exitCode: 124,
        stdout: error?.stdout ?? "",
        stderr: `${error?.stderr ?? ""}\ncontext deadline exceeded`
      };
    }
    return {
      exitCode: typeof error?.code === "number" ? error.code : 1,
      stdout: error?.stdout ?? "",
      stderr: error?.stderr ?? ""
    };
  }
}

function runStartupHelper(command, args, options) {
  const pending = runCancellableCommand(command, args, options);
  activeStartupHelpers.add(pending);
  void pending.then(
    () => activeStartupHelpers.delete(pending),
    () => activeStartupHelpers.delete(pending)
  );
  return pending;
}

function waitForStartupHelpers() {
  return Promise.allSettled([...activeStartupHelpers]).then((results) => {
    const incompleteCleanup = results.find((result) => result.status === "rejected"
      && result.reason?.code === "ERR_PROCESS_TREE_CLEANUP");
    if (incompleteCleanup) throw incompleteCleanup.reason;
  });
}

function isNotFoundError(error) {
  return Boolean(
    error &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "ENOENT"
  );
}
