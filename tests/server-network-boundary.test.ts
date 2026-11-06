import { spawn, type ChildProcess } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

type StartedServer = {
  child: ChildProcess;
  closed: Promise<void>;
  output: () => string;
  outputEvents: EventEmitter;
  port: number;
};

type RequestOutcome<T> = { value: T } | { error: unknown };

const children = new Set<StartedServer>();

describe("server network boundary", () => {
  afterEach(async () => {
    await Promise.all([...children].map((server) => stopChild(server)));
  });

  test("defaults to an explicit loopback binding", async () => {
    const server = await startServer();
    await waitForHealth(server);

    expect(server.output()).toContain(`http://127.0.0.1:${server.port}/mcp`);
  });

  test("reports the effective port when the operating system assigns one", async () => {
    const server = await startServer({ PORT: "0" });
    await waitForHealth(server);

    expect(server.port).toBeGreaterThan(0);
    expect(server.output()).toContain(`http://127.0.0.1:${server.port}/mcp`);
  });

  test("rejects an external bind unless it is explicitly authorized", async () => {
    const server = await startServer({ GPT_REPO_HOST: "0.0.0.0" });
    const exited = await waitForExit(server.child, 4_000);

    expect(exited).toBe(true);
    expect(server.child.exitCode).not.toBe(0);
    expect(server.output()).toContain("GPT_REPO_ALLOW_EXTERNAL_BIND=true");
  });

  test("rejects browser requests from a non-loopback origin and host", async () => {
    const server = await startServer();
    await waitForHealth(server);

    const response = await httpRequest(server.port, {
      Host: "attacker.example",
      Origin: "https://attacker.example"
    });

    expect(response).toMatchObject({ status: 403, body: "Forbidden origin" });
  });

  test("allows an explicitly authorized external bind", async () => {
    const server = await startServer({
      GPT_REPO_ALLOW_EXTERNAL_BIND: "true",
      GPT_REPO_HOST: "0.0.0.0"
    });

    await waitForHealth(server);
    expect(server.output()).toContain(`http://0.0.0.0:${server.port}/mcp`);
  });

  test("bounds MCP sessions and releases capacity on DELETE", async () => {
    const server = await startServer({ GPT_REPO_MAX_SESSIONS: "1" });
    await waitForHealth(server);

    const first = await initializeSession(server.port);
    expect(first.status).toBe(200);
    expect(first.sessionId).toEqual(expect.any(String));

    const rejected = await initializeSession(server.port);
    expect(rejected.status).toBe(503);
    await waitForOutput(server, '"error_category":"session_capacity"');

    const deleted = await fetch(`http://127.0.0.1:${server.port}/mcp`, {
      method: "DELETE",
      headers: {
        Accept: "application/json, text/event-stream",
        "mcp-session-id": first.sessionId ?? ""
      }
    });
    await deleted.text();
    expect(deleted.ok).toBe(true);

    const replacement = await initializeSession(server.port);
    expect(replacement.status).toBe(200);
    expect(replacement.sessionId).toEqual(expect.any(String));
  });

  test("audits an invalid session with safe category and request correlation", async () => {
    const server = await startServer();
    await waitForHealth(server);

    const response = await httpRequest(server.port, {
      "mcp-session-id": "do-not-log-this-session-id"
    });

    expect(response.status).toBe(400);
    await waitForOutput(server, '"error_category":"invalid_session"');
    expect(server.output()).toContain('"request_id":');
    expect(server.output()).not.toContain("do-not-log-this-session-id");
  });

  test("cancels an HTTP/MCP validation without affecting a concurrent invocation", async () => {
    const fixtureRoot = await mkdtemp(join(tmpdir(), "gpt-repo-http-validation-cancel-"));
    const repoRoot = join(fixtureRoot, "repo");
    const configPath = join(fixtureRoot, "config.json");
    const modePath = join(repoRoot, "mode.txt");
    const releasePath = join(repoRoot, "release.txt");
    const validationDirectory = join(repoRoot, ".chatgpt", "validation");
    const latestPath = join(validationDirectory, "latest.json");
    const processControl = await startProcessControl();
    let server: StartedServer | undefined;
    let cancelController: AbortController | undefined;
    let independentController: AbortController | undefined;
    let cancelRequest: Promise<RequestOutcome<ValidationToolResult>> | undefined;
    let independentRequest: Promise<RequestOutcome<ValidationToolResult>> | undefined;
    let testFailed = false;
    let testError: unknown;

    try {
      await mkdir(repoRoot, { recursive: true });
      await writeFile(modePath, "seed\n");
      await writeValidationFixture(repoRoot, processControl.port, modePath, releasePath);
      await writeFile(configPath, JSON.stringify({
        repos: [{
          repo_id: "fixture",
          display_name: "HTTP cancellation fixture",
          root: repoRoot,
          operations: { enabled: true, validation_enabled: true }
        }],
        limits: {}
      }), "utf8");

      server = await startServer({ GPT_REPO_CONFIG: configPath, PORT: "0" });
      await waitForHealth(server);

      const cancelSession = await initializeSession(server.port);
      expect(cancelSession.status).toBe(200);
      expect(cancelSession.sessionId).toEqual(expect.any(String));
      await initializeClient(server.port, cancelSession.sessionId!);
      const seed = await callRepoValidate(server.port, cancelSession.sessionId!, 2);
  const seedCommands = seed.commands.map(({ profile, command, status, exit_code, duration_ms, stdout_tail, stderr_tail }) => ({
    profile,
    command,
    status,
    exit_code,
    duration_ms,
    stdout_tail,
    stderr_tail
  }));
  expect(seed.status, `Seed validation command result:\n${JSON.stringify(seedCommands, null, 2)}`).toBe("passed");
      expect(seed.validation_id).toEqual(expect.any(String));

      const seededLatest = await readFile(latestPath, "utf8");
      const artifactsBeforeCancel = (await readdir(validationDirectory)).sort();
      await writeFile(modePath, "hold\n");

      cancelController = new AbortController();
      cancelRequest = settleRequest(callRepoValidate(server.port, cancelSession.sessionId!, 3, cancelController.signal));
      const cancelledProcesses = await processControl.waitForConnections(2);
      expect(new Set(cancelledProcesses.map(({ pid }) => pid)).size).toBe(2);

      const independentSession = await initializeSession(server.port);
      expect(independentSession.status).toBe(200);
      expect(independentSession.sessionId).toEqual(expect.any(String));
      await initializeClient(server.port, independentSession.sessionId!);
      independentController = new AbortController();
      independentRequest = settleRequest(callRepoValidate(
        server.port,
        independentSession.sessionId!,
        2,
        independentController.signal
      ));
      const independentProcesses = (await processControl.waitForConnections(4)).slice(2);
      expect(new Set(independentProcesses.map(({ pid }) => pid)).size).toBe(2);

      cancelController.abort();
      const disconnect = await cancelRequest;
      expect(disconnect).toMatchObject({ error: { name: "AbortError" } });
      await processControl.waitForClosed(cancelledProcesses);
      expect(independentProcesses.every(({ socket }) => !socket.destroyed)).toBe(true);
      expect(await readFile(latestPath, "utf8")).toBe(seededLatest);
      expect((await readdir(validationDirectory)).sort()).toEqual(artifactsBeforeCancel);

      await writeFile(releasePath, "release\n");
      const independentOutcome = await independentRequest;
      if ("error" in independentOutcome) throw independentOutcome.error;
      const independentResult = independentOutcome.value;
      expect(independentResult.status).toBe("passed");
      expect(independentResult.validation_id).toEqual(expect.any(String));
      expect(independentResult.commands).toHaveLength(1);
      expect(independentResult.commands[0]?.status).toBe("passed");
      const latest = JSON.parse(await readFile(latestPath, "utf8")) as { validation_id: string; status: string };
      const artifactPath = join(repoRoot, independentResult.validation_artifact.path);
      const artifact = JSON.parse(await readFile(artifactPath, "utf8")) as { validation_id: string; status: string };
      expect(latest).toMatchObject({ validation_id: independentResult.validation_id, status: "passed" });
      expect(artifact).toMatchObject({ validation_id: independentResult.validation_id, status: "passed" });
      await processControl.waitForClosed(independentProcesses);
    } catch (error) {
      testFailed = true;
      testError = error;
    }

    cancelController?.abort();
    independentController?.abort();
    const cleanupErrors: unknown[] = [];
    let canRemoveFixture = true;

    try {
      await mkdir(repoRoot, { recursive: true });
      await writeFile(releasePath, "release\n");
    } catch (error) {
      cleanupErrors.push(error);
      canRemoveFixture = false;
    }

    const outstandingRequests = [cancelRequest, independentRequest]
      .filter((task) => task !== undefined);
    const requestSettlements = await Promise.allSettled(outstandingRequests);
    for (const settlement of requestSettlements) {
      if (settlement.status === "rejected") {
        cleanupErrors.push(settlement.reason);
        canRemoveFixture = false;
      }
    }

    const cancelOutcome = cancelRequest ? await cancelRequest : undefined;
    if (cancelOutcome && "error" in cancelOutcome) {
      if (!(cancelController?.signal.aborted && isAbortError(cancelOutcome.error))) {
        cleanupErrors.push(cancelOutcome.error);
      }
    } else if (cancelOutcome) {
      cleanupErrors.push(new Error("The disconnected validation unexpectedly returned a response."));
    }

    const independentOutcome = independentRequest ? await independentRequest : undefined;
    if (independentOutcome && "error" in independentOutcome) {
      if (!(independentController?.signal.aborted && isAbortError(independentOutcome.error))) {
        cleanupErrors.push(independentOutcome.error);
      }
    }

    try {
      await processControl.waitForClosed(processControl.connections());
    } catch (error) {
      cleanupErrors.push(error);
      canRemoveFixture = false;
    }

    try {
      await processControl.close();
    } catch (error) {
      cleanupErrors.push(error);
      canRemoveFixture = false;
    }

    try {
      if (server) await stopChild(server);
    } catch (error) {
      cleanupErrors.push(error);
      canRemoveFixture = false;
    }

    if (canRemoveFixture) {
      try {
        await rm(fixtureRoot, { recursive: true, force: true });
      } catch (error) {
        cleanupErrors.push(error);
      }
    }

    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        testFailed ? [testError, ...cleanupErrors] : cleanupErrors,
        "HTTP cancellation fixture cleanup failed."
      );
    }
    if (testFailed) throw testError;
  }, 20_000);
});

async function initializeSession(port: number): Promise<{ status: number; sessionId: string | null }> {
  const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "session-boundary-test", version: "1.0.0" }
      }
    })
  });
  await response.text();
  return {
    status: response.status,
    sessionId: response.headers.get("mcp-session-id")
  };
}

async function startServer(extraEnv: Record<string, string> = {}): Promise<StartedServer> {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "gpt-repo-network-boundary-"));
  const configPath = join(fixtureRoot, "config.json");
  const port = extraEnv.PORT === undefined ? await freePort() : Number(extraEnv.PORT);
  await writeFile(configPath, JSON.stringify({ repos: [], limits: {} }), "utf8");
  let output = "";
  const outputEvents = new EventEmitter();
  const child = spawn(process.execPath, ["--import", "tsx", "src/server.ts"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      GPT_REPO_CONFIG: configPath,
      PORT: String(port),
      ...extraEnv
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  const recordOutput = (chunk: Buffer): void => {
    output += chunk.toString();
    outputEvents.emit("change");
  };
  child.stdout.on("data", recordOutput);
  child.stderr.on("data", recordOutput);
  let resolveClosed!: () => void;
  let rejectClosed!: (error: unknown) => void;
  const closed = new Promise<void>((resolve, reject) => {
    resolveClosed = resolve;
    rejectClosed = reject;
  });
  const server: StartedServer = { child, closed, output: () => output, outputEvents, port };
  children.add(server);
  child.once("exit", () => outputEvents.emit("change"));
  child.once("close", () => {
    void rm(fixtureRoot, { recursive: true, force: true }).then(
      () => {
        children.delete(server);
        outputEvents.emit("change");
        resolveClosed();
      },
      (error: unknown) => {
        children.delete(server);
        rejectClosed(error);
      }
    );
  });
  return server;
}

async function waitForHealth(server: Awaited<ReturnType<typeof startServer>>): Promise<void> {
  await waitForOutput(server, "gpt-repo-mcp listening on", 4_000);
  if (server.port === 0) {
    const boundPort = server.output().match(/gpt-repo-mcp listening on http:\/\/[^:]+:(\d+)\//)?.[1];
    if (boundPort) server.port = Number(boundPort);
  }
  const response = await fetch(`http://127.0.0.1:${server.port}/health`);
  if (!response.ok) throw new Error(`Server health returned ${response.status}.\n${server.output()}`.trim());
}

async function waitForOutput(
  server: Awaited<ReturnType<typeof startServer>>,
  expected: string,
  timeoutMs = 2_000
): Promise<void> {
  if (server.output().includes(expected)) return;
  const signal = AbortSignal.timeout(timeoutMs);
  try {
    while (!server.output().includes(expected)) {
      if (server.child.exitCode !== null || server.child.signalCode !== null) break;
      await once(server.outputEvents, "change", { signal });
    }
  } catch (error) {
    if (!signal.aborted) throw error;
  }
  if (server.output().includes(expected)) return;
  throw new Error(`Server output did not contain ${expected}.\n${server.output()}`);
}

function httpRequest(port: number, headers: Record<string, string>): Promise<{ status?: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({
      host: "127.0.0.1",
      port,
      path: "/mcp",
      method: "GET",
      headers
    }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        resolve({ status: res.statusCode, body });
      });
    });
    req.once("error", reject);
    req.end();
  });
}

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Could not reserve a local port.");
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
  return address.port;
}

type ValidationToolResult = {
  status: string;
  validation_id: string;
  validation_artifact: { path: string };
  commands: Array<{
    profile?: string;
    command?: string;
    status: string;
    exit_code?: number;
    duration_ms?: number;
    stdout_tail?: string;
    stderr_tail?: string;
  }>;
};

function settleRequest<T>(request: Promise<T>): Promise<RequestOutcome<T>> {
  return request.then(
    (value) => ({ value }),
    (error: unknown) => ({ error })
  );
}

function isAbortError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "name" in error && error.name === "AbortError";
}

type ProcessConnection = { role: string; pid: number; socket: Socket };

async function initializeClient(port: number, sessionId: string): Promise<void> {
  const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
      "MCP-Protocol-Version": "2025-03-26",
      "mcp-session-id": sessionId
    },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })
  });
  await response.text();
  if (!response.ok) throw new Error(`MCP client initialization returned ${response.status}.`);
}

async function callRepoValidate(
  port: number,
  sessionId: string,
  id: number,
  signal?: AbortSignal
): Promise<ValidationToolResult> {
  const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
      "MCP-Protocol-Version": "2025-03-26",
      "mcp-session-id": sessionId
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: {
        name: "repo_validate",
        arguments: { repo_id: "fixture", profile: "smoke", timeout_ms: 5_000 }
      }
    }),
    signal
  });
  const body = await response.text();
  if (!response.ok) throw new Error(`repo_validate returned HTTP ${response.status}: ${body}`);
  const messageBody = response.headers.get("content-type")?.includes("text/event-stream")
    ? body.split(/\r?\n/).find((line) => line.startsWith("data:"))?.slice("data:".length).trim()
    : body;
  if (!messageBody) throw new Error("repo_validate returned no MCP response message.");
  const message = JSON.parse(messageBody) as {
    error?: { message?: string };
    result?: { isError?: boolean; structuredContent?: ValidationToolResult };
  };
  if (message.error) throw new Error(message.error.message ?? "MCP request failed.");
  if (message.result?.isError) throw new Error("repo_validate returned an MCP tool error.");
  if (!message.result?.structuredContent) throw new Error("repo_validate omitted its structured result.");
  return message.result.structuredContent;
}

async function writeValidationFixture(
  repoRoot: string,
  controlPort: number,
  modePath: string,
  releasePath: string
): Promise<void> {
  const runnerPath = join(repoRoot, "runner.cjs");
  const releaseWaiter = [
    "function waitForRelease(path) {",
    "const { existsSync, watch } = require('node:fs');",
    "const { basename, dirname } = require('node:path');",
    "return new Promise(resolve => {",
    "const releaseName = basename(path);",
    "const watcher = watch(dirname(path), (_event, filename) => {",
    "if (filename && filename.toString() !== releaseName) return;",
    "if (existsSync(path)) { watcher.close(); resolve(); }",
    "});",
    "if (existsSync(path)) { watcher.close(); resolve(); }",
    "});",
    "}"
  ].join("\n");
  const reportProcess = (role: string): string => [
    "const { createConnection } = require('node:net');",
    `const socket = createConnection({ host: '127.0.0.1', port: ${controlPort} }, () => {`,
    `socket.write(${JSON.stringify(`${role}:`)} + String(process.pid) + '\\n');`,
    "});",
    "socket.on('error', () => {});"
  ].join("\n");
  const runner = [
    "const { readFileSync } = require('node:fs');",
    "const { spawn } = require('node:child_process');",
    `const modePath = ${JSON.stringify(modePath)};`,
    `const releasePath = ${JSON.stringify(releasePath)};`,
    "if (process.argv[2] === 'child') {",
    releaseWaiter,
    "const released = waitForRelease(releasePath);",
    reportProcess("child"),
    "released.then(() => socket.end());",
    "} else if (readFileSync(modePath, 'utf8').trim() === 'hold') {",
    releaseWaiter,
    "const released = waitForRelease(releasePath);",
    reportProcess("parent"),
    `spawn(process.execPath, [${JSON.stringify(runnerPath)}, 'child'], { stdio: 'ignore' });`,
    "released.then(() => socket.end());",
    "} else {",
    "console.log('validation fixture passed');",
    "}"
  ].join("\n");

  await writeFile(join(repoRoot, "package.json"), JSON.stringify({
    name: "http-validation-cancellation-fixture",
    private: true,
    scripts: { smoke: "node runner.cjs" }
  }), "utf8");
  await writeFile(runnerPath, runner, "utf8");
}

/** Tracks fixture-process sockets so tests can observe process exit without PID polling. */
async function startProcessControl(): Promise<{
  port: number;
  waitForConnections(count: number, timeoutMs?: number): Promise<ProcessConnection[]>;
  waitForClosed(connections: ProcessConnection[], timeoutMs?: number): Promise<void>;
  connections(): ProcessConnection[];
  close(): Promise<void>;
}> {
  const connections: ProcessConnection[] = [];
  const sockets = new Set<Socket>();
  const changes = new EventEmitter();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.once("end", () => socket.end());
    socket.setEncoding("utf8");
    let input = "";
    let received = false;
    socket.on("data", (chunk: string) => {
      if (received) return;
      input += chunk;
      const newline = input.indexOf("\n");
      if (newline < 0) return;
      received = true;
      const [role, pidText] = input.slice(0, newline).split(":");
      const pid = Number(pidText);
      if (!role || !Number.isInteger(pid) || pid <= 0) {
        socket.destroy();
        return;
      }
      connections.push({ role, pid, socket });
      changes.emit("connection");
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Process control server did not bind a TCP port.");

  return {
    port: address.port,
    async waitForConnections(count, timeoutMs = 3_000) {
      const signal = AbortSignal.timeout(timeoutMs);
      try {
        while (connections.length < count) await once(changes, "connection", { signal });
      } catch (error) {
        if (!signal.aborted) throw error;
        throw new Error(`Timed out waiting for ${count} validation process connections; received ${connections.length}.`, { cause: error });
      }
      return connections.slice(0, count);
    },
    async waitForClosed(closedConnections, timeoutMs = 3_000) {
      await Promise.all(closedConnections.map(async ({ pid, socket }) => {
        if (socket.closed) return;
        const signal = AbortSignal.timeout(timeoutMs);
        try {
          await new Promise<void>((resolve, reject) => {
            const cleanup = (): void => {
              socket.removeListener("close", onClose);
              socket.removeListener("error", onError);
              signal.removeEventListener("abort", onAbort);
            };
            const onClose = (): void => {
              cleanup();
              resolve();
            };
            const onError = (error: Error): void => {
              if ("code" in error && error.code === "ECONNRESET") return;
              cleanup();
              reject(error);
            };
            const onAbort = (): void => {
              cleanup();
              reject(signal.reason);
            };

            socket.once("close", onClose);
            socket.on("error", onError);
            signal.addEventListener("abort", onAbort, { once: true });
            if (socket.closed) onClose();
          });
        } catch (error) {
          if (!signal.aborted) throw error;
          throw new Error(`Validation process ${pid} kept its control socket open.`, { cause: error });
        }
      }));
    },
    connections: () => [...connections],
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  };
}

async function waitForExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return true;
  }
  return Promise.race([
    once(child, "exit").then(() => true),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), timeoutMs))
  ]);
}

async function stopChild(server: StartedServer): Promise<void> {
  const { child } = server;
  if (child.exitCode !== null || child.signalCode !== null) {
    await server.closed;
    return;
  }
  child.kill("SIGTERM");
  if (!await waitForExit(child, 1_000)) {
    child.kill("SIGKILL");
    if (child.exitCode === null && child.signalCode === null) await once(child, "exit");
  }
  await server.closed;
}
