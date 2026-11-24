import { readFile } from "node:fs/promises";
import { selectServerConfigPath } from "./config/store.js";
import { createCodebaseMemoryClientFactory } from "./services/codebase-memory-client.js";
import { CodeIntelligenceService } from "./services/code-intelligence-service.js";
import { ConfigurationRevisionStore, prepareConfigurationCandidate } from "./services/configuration-revision-store.js";
import { createMcpHttpApp } from "./runtime/mcp-http-app.js";
import { resolveServerHost } from "./runtime/network-boundary.js";

const port = Number(process.env.PORT ?? 8787);
const host = resolveServerHost(process.env);
const configPath = selectServerConfigPath(process.env);
const publicPathToken = process.env.GPT_REPO_PUBLIC_PATH_TOKEN ?? process.env.REPO_READER_PUBLIC_PATH_TOKEN;
const maxSessions = readBoundedInteger("GPT_REPO_MAX_SESSIONS", 100, 1, 1_000);
const sessionIdleTtlMs = readBoundedInteger("GPT_REPO_SESSION_IDLE_TTL_MS", 30 * 60_000, 1_000, 24 * 60 * 60_000);

const initialBytes = configPath === undefined
  ? Buffer.from(JSON.stringify({ repos: [], limits: {} }))
  : await readFile(configPath);
const initialCandidate = await prepareConfigurationCandidate(initialBytes, configPath ?? "<default config>");
const codeIntelligenceSettings = initialCandidate.restartSettings;
const codeIntelligence = codeIntelligenceSettings
  ? new CodeIntelligenceService(
      createCodebaseMemoryClientFactory(codeIntelligenceSettings.executable),
      codeIntelligenceSettings.query_timeout_ms,
      codeIntelligenceSettings.index_timeout_ms
    )
  : undefined;
const revisionStore = new ConfigurationRevisionStore({
  configPath,
  initial: initialCandidate,
  ...(codeIntelligence ? { codeIntelligence } : {})
});
const { app, dispose, reloadConfiguration } = createMcpHttpApp({
  revisionStore,
  publicPathToken,
  maxSessions,
  sessionIdleTtlMs
});
export { reloadConfiguration };

const httpServer = app.listen(port, host, () => {
  const localPath = publicPathToken ? "/t/[token]/mcp" : "/mcp";
  const address = httpServer.address();
  const boundPort = address && typeof address !== "string" ? address.port : port;
  const urlHost = host.replace(/^\[|\]$/g, "");
  const urlAuthorityHost = urlHost.includes(":") ? `[${urlHost}]` : urlHost;
  console.error(`gpt-repo-mcp listening on http://${urlAuthorityHost}:${boundPort}${localPath}`);
});

let shuttingDown = false;
async function shutdown(): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  await dispose();
  await new Promise<void>((resolve) => {
    httpServer.close(() => resolve());
  });
}

process.once("SIGINT", () => { void shutdown(); });
process.once("SIGTERM", () => { void shutdown(); });

function readBoundedInteger(name: string, fallback: number, minimum: number, maximum: number): number {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}.`);
  }
  return value;
}
