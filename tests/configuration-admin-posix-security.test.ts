import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";
import { describe, expect, test } from "vitest";

const repoRoot = resolve(fileURLToPath(new URL("../", import.meta.url)));
const builtServer = join(repoRoot, "dist", "server.js");
const builtCli = join(repoRoot, "dist", "cli", "connect-gpt.js");

describe.skipIf(process.platform === "win32")("POSIX configuration IPC identity enforcement", () => {
  test("a distinct UID cannot connect to the owner endpoint while the owner CLI reloads successfully", async ({ skip }) => {
    const ownerUid = process.getuid?.();
    const outsider = ownerUid === undefined ? undefined : findPasswordlessDistinctUid(ownerUid);
    if (!outsider) {
      const prerequisite = "A distinct installed POSIX user and credentialless `sudo -n -u <user>` are required to qualify UID enforcement.";
      if (process.env.GPT_REPO_REQUIRE_SECURITY_FIXTURES === "1") throw new Error(prerequisite);
      skip(prerequisite);
      return;
    }

    const fixtureRoot = await mkdtemp("/tmp/gpt-repo-admin-security-");
    const adminDirectory = join(fixtureRoot, "owner-admin");
    const configPath = join(fixtureRoot, "config.json");
    await writeFile(configPath, JSON.stringify({ repos: [], limits: {} }), { mode: 0o600 });
    const serverEnv: NodeJS.ProcessEnv = {
      ...process.env,
      GPT_REPO_TEST_BUILT_SERVER: "1",
      GPT_REPO_ADMIN_TEST_DIRECTORY: adminDirectory,
      GPT_REPO_CONFIG: configPath,
      GPT_REPO_HOST: "127.0.0.1",
      PORT: "0"
    };
    let server: ChildProcess | undefined;

    try {
      server = spawn(process.execPath, [builtServer], {
        cwd: repoRoot,
        env: serverEnv,
        stdio: ["ignore", "ignore", "pipe"]
      });
      let serverOutput = "";
      server.stderr?.setEncoding("utf8");
      server.stderr?.on("data", (chunk: string) => {
        serverOutput = (serverOutput + chunk).slice(-8_000);
      });
      server.once("error", () => undefined);

      const port = await waitForServer(server, () => serverOutput);
      const record = await waitForDiscoveryRecord(adminDirectory, () => serverOutput);
      const ownerReload = runCli(builtCli, repoRoot, serverEnv, record.server_pid);
      expect(ownerReload.status, ownerReload.stderr).toBe(0);
      expect(ownerReload.stdout).toContain("Reloaded configuration");
      expect(await fetch(`http://127.0.0.1:${port}/health`).then((response) => response.ok)).toBe(true);

const outsiderScript = String.raw`
import net from "node:net";
import { spawnSync } from "node:child_process";
const [endpoint, cliPath, cwd, adminDirectory, configPath, serverPid] = process.argv.slice(1);
const endpointResult = await new Promise((resolve) => {
  const socket = net.createConnection({ path: endpoint });
  socket.once("connect", () => { socket.destroy(); resolve({ connected: true }); });
  socket.once("error", (error) => resolve({ connected: false, code: error.code }));
});
const cli = spawnSync(process.execPath, [cliPath, "config", "reload", "--instance", serverPid], {
  cwd,
  encoding: "utf8",
  timeout: 10000,
  env: {
    PATH: process.env.PATH,
    GPT_REPO_TEST_BUILT_SERVER: "1",
    GPT_REPO_ADMIN_TEST_DIRECTORY: adminDirectory,
    GPT_REPO_CONFIG: configPath
  }
});
process.stdout.write(JSON.stringify({
  uid: process.getuid(),
  endpointResult,
  cliStatus: cli.status,
  cliError: cli.error?.code,
  cliOutput: (cli.stdout ?? "") + (cli.stderr ?? "")
}));
`;
      const outsiderResult = spawnSync("sudo", [
        "-n", "-u", outsider.name, "--", process.execPath, "-e", outsiderScript,
        record.endpoint, builtCli, repoRoot, adminDirectory, configPath, String(record.server_pid)
      ], { encoding: "utf8", timeout: 15_000, maxBuffer: 1_000_000 });
      expect(outsiderResult.error, outsiderResult.stderr).toBeUndefined();
      expect(outsiderResult.status, outsiderResult.stderr).toBe(0);
      const result = JSON.parse(outsiderResult.stdout) as {
        uid: number;
        endpointResult: { connected: boolean; code?: string };
        cliStatus: number | null;
        cliError?: string;
        cliOutput: string;
      };
      expect(result.uid).toBe(outsider.uid);
      expect(result.uid).not.toBe(ownerUid);
      expect(result.endpointResult).toEqual({ connected: false, code: "EACCES" });
      expect(result.cliStatus).toBe(1);
      expect(result.cliOutput).toContain("EACCES");
    } finally {
      await stopServer(server);
      await rm(fixtureRoot, { recursive: true, force: true });
    }
  }, 30_000);
});

function findPasswordlessDistinctUid(ownerUid: number): { name: string; uid: number } | undefined {
  for (const name of ["nobody", "_www", "daemon"]) {
    const identity = spawnSync("id", ["-u", name], { encoding: "utf8", timeout: 2_000 });
    if (identity.status !== 0) continue;
    const uid = Number(identity.stdout.trim());
    if (!Number.isSafeInteger(uid) || uid === ownerUid) continue;
    const credentialCheck = spawnSync("sudo", ["-n", "-u", name, "--", "id", "-u"], {
      encoding: "utf8",
      timeout: 3_000
    });
    if (credentialCheck.status === 0 && Number(credentialCheck.stdout.trim()) === uid) return { name, uid };
  }
  return undefined;
}

function runCli(cliPath: string, cwd: string, env: NodeJS.ProcessEnv, serverPid: number) {
  return spawnSync(process.execPath, [cliPath, "config", "reload", "--instance", String(serverPid)], {
    cwd,
    env,
    encoding: "utf8",
    timeout: 15_000,
    maxBuffer: 1_000_000
  });
}

async function waitForServer(child: ChildProcess, readOutput: () => string): Promise<number> {
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`Built server exited before binding. ${readOutput()}`);
    }
    const portMatch = readOutput().match(/listening on http:\/\/[^:\s]+:(\d+)\//);
    if (portMatch) {
      const port = Number(portMatch[1]);
      try {
        if (await fetch(`http://127.0.0.1:${port}/health`).then((response) => response.ok)) return port;
      } catch {
        // The listener may need one more event-loop turn before accepting connections.
      }
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
  }
  throw new Error(`Built server did not become healthy. ${readOutput()}`);
}

async function waitForDiscoveryRecord(directory: string, readOutput: () => string): Promise<{
  server_pid: number;
  instance_id: string;
  endpoint: string;
}> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      const recordName = (await readdir(directory)).find((name) => /^server-[0-9]+-[0-9a-f-]{36}\.json$/.test(name));
      if (recordName) return JSON.parse(await readFile(join(directory, recordName), "utf8"));
    } catch {
      // The native endpoint helper may still be creating the private store.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
  }
  throw new Error(`Built server did not publish its owner-local endpoint. ${readOutput()}`);
}

async function stopServer(child: ChildProcess | undefined): Promise<void> {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const stopped = await Promise.race([
    once(child, "exit").then(() => true),
    new Promise<false>((resolveDelay) => setTimeout(() => resolveDelay(false), 2_000))
  ]);
  if (!stopped && child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await once(child, "exit");
  }
}
