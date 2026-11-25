import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { expect, test } from "vitest";
import { selectServerConfigPath } from "../src/config/store.js";
import { RootRegistry } from "../src/services/root-registry.js";

const repoRoot = process.cwd();
const serverEntry = join(repoRoot, "src/server.ts");
const tsxLoaderPath = createRequire(import.meta.url).resolve("tsx/esm");

test("starts with an empty registry when both config variables are absent", async () => {
  const cwd = await createServerCwd();
  try {
    expect(selectServerConfigPath({})).toBeUndefined();
    expect(await listRootsFromStartup(cwd, {})).toEqual({ repos: [] });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}, 15_000);

test("resolves configured roots relative to process.cwd()", async () => {
  const cwd = await createServerCwd();
  try {
    expect(await listRootsFromStartup(cwd, { GPT_REPO_CONFIG: "config.local.json" })).toEqual({
      repos: [{ repo_id: "neighbor", display_name: "Neighbor", root: await realpath(cwd) }]
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}, 15_000);

const emptySelections: Array<[string, NodeJS.ProcessEnv]> = [
  ["GPT_REPO_CONFIG", { GPT_REPO_CONFIG: "" }],
  ["REPO_READER_CONFIG", { REPO_READER_CONFIG: "" }]
];

test.each(emptySelections)("keeps an explicitly empty %s selected", async (_name, env) => {
  const configPath = selectServerConfigPath(env);
  expect(configPath).toBe("");
  await expect(RootRegistry.fromFile(configPath!)).rejects.toThrow();
});

test("keeps an empty GPT_REPO_CONFIG ahead of a valid REPO_READER_CONFIG", async () => {
  const cwd = await createServerCwd();
  try {
    const configPath = selectServerConfigPath({
      GPT_REPO_CONFIG: "",
      REPO_READER_CONFIG: join(cwd, "config.local.json")
    });
    expect(configPath).toBe("");
    await expect(RootRegistry.fromFile(configPath!)).rejects.toThrow();
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test("fails to load an explicitly selected missing file", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "gpt-repo-server-config-missing-"));
  const configPath = join(cwd, "missing.json");
  try {
    expect(selectServerConfigPath({ GPT_REPO_CONFIG: configPath })).toBe(configPath);
    await expect(RootRegistry.fromFile(configPath)).rejects.toThrow();
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test("rejects file configs with canonical validation issues", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "gpt-repo-server-config-invalid-"));
  const configPath = join(cwd, "invalid.json");
  await writeFile(configPath, JSON.stringify({ repos: [], limits: {}, limitz: {} }));
  try {
    expect(selectServerConfigPath({ GPT_REPO_CONFIG: configPath })).toBe(configPath);
    await expect(RootRegistry.fromFile(configPath)).rejects.toThrow("SCHEMA_INVALID");
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

async function createServerCwd(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), "gpt-repo-server-config-"));
  await mkdir(join(cwd, "local-app-data"));
  await writeFile(join(cwd, "config.local.json"), JSON.stringify({
    repos: [{ repo_id: "neighbor", display_name: "Neighbor", root: ".", allow_non_git: true }],
    limits: {}
  }));
  return cwd;
}

async function reservePort(): Promise<number> {
  const listener = createServer();
  await new Promise<void>((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", resolve);
  });
  const address = listener.address();
  if (!address || typeof address === "string") {
    await new Promise<void>((resolve) => listener.close(() => resolve()));
    throw new Error("Could not reserve a loopback port for the isolated server.");
  }
  await new Promise<void>((resolve, reject) => {
    listener.close((error) => error ? reject(error) : resolve());
  });
  return address.port;
}

function startServer(cwd: string, port: number, overrides: NodeJS.ProcessEnv) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    GPT_REPO_TEST_BUILT_SERVER: "1",
    GPT_REPO_ADMIN_TEST_DIRECTORY: join(cwd, "admin-ipc"),
    LOCALAPPDATA: join(cwd, "local-app-data"),
    GPT_REPO_HOST: "127.0.0.1",
    PORT: String(port)
  };
  delete env.GPT_REPO_CONFIG;
  delete env.REPO_READER_CONFIG;
  Object.assign(env, overrides);

  const script = `process.chdir(${JSON.stringify(cwd)}); await import(${JSON.stringify(pathToFileURL(serverEntry).href)});`;
  const child = spawn(process.execPath, [
    "--import", tsxLoaderPath,
    "--input-type=module",
    "--eval", script
  ], {
    cwd: repoRoot,
    env,
    stdio: ["ignore", "ignore", "pipe"]
  });
  let stderr = "";
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk: string) => { stderr = (stderr + chunk).slice(-4_000); });
  return { child, stderr: () => stderr };
}

async function listRootsFromStartup(cwd: string, overrides: NodeJS.ProcessEnv): Promise<unknown> {
  const port = await reservePort();
  const server = startServer(cwd, port, overrides);
  const client = new Client({ name: "server-config-selection-test", version: "1" });
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`));
  let connected = false;

  try {
    await waitForServer(server, `http://127.0.0.1:${port}/health`);
    await client.connect(transport);
    connected = true;
    const result = await client.callTool({ name: "repo_list_roots", arguments: {} });
    expect(result.isError).not.toBe(true);
    return result.structuredContent;
  } finally {
    if (connected) await client.close();
    await stopServer(server.child);
  }
}

async function waitForServer(server: ReturnType<typeof startServer>, healthUrl: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    if (server.child.exitCode !== null || server.child.signalCode !== null) {
      throw new Error(`The isolated server exited during startup: ${server.stderr()}`);
    }
    try {
      const response = await fetch(healthUrl);
      if (response.ok) return;
    } catch {
      // The listener may still be binding.
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`The isolated server did not become ready: ${server.stderr()}`);
}

async function waitForExit(child: ChildProcess, timeoutMs: number): Promise<{ code: number | null } | undefined> {
  if (child.exitCode !== null || child.signalCode !== null) return { code: child.exitCode };
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(undefined), timeoutMs);
    child.once("close", (code) => {
      clearTimeout(timeout);
      resolve({ code });
    });
  });
}

async function stopServer(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  if (await waitForExit(child, 2_000)) return;
  child.kill("SIGKILL");
  await waitForExit(child, 2_000);
}
