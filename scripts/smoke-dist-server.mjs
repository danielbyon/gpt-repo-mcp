import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { waitForMcpListener } from "./secure-startup.mjs";

const START_TIMEOUT_MS = 5_000;
const POLL_INTERVAL_MS = 100;

const tempRoot = await mkdtemp(join(tmpdir(), "gpt-repo-dist-smoke-"));
const configPath = join(tempRoot, "config.json");
let child;

try {
  await writeFile(configPath, JSON.stringify({ repos: [], limits: {} }), "utf8");
  const deadline = Date.now() + START_TIMEOUT_MS;
  child = spawn(process.execPath, ["dist/server.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      GPT_REPO_CONFIG: configPath,
      GPT_REPO_HOST: "127.0.0.1",
      PORT: "0"
    },
    stdio: ["ignore", "pipe", "pipe"]
  });

  let output = "";
  child.stdout.on("data", (chunk) => {
    output = appendBounded(output, chunk.toString());
  });
  child.stderr.on("data", (chunk) => {
    output = appendBounded(output, chunk.toString());
  });

  const { boundPort } = await waitForMcpListener({
    child,
    port: 0,
    timeoutMs: deadline - Date.now()
  }).catch((error) => {
    throw new Error(`${error.message}\n${output}`.trim(), { cause: error });
  });
  await waitForHealth(child, boundPort, deadline, () => output);
  process.stdout.write("Built server passed the /health runtime smoke test.\n");
} finally {
  await stopChild(child);
  await rm(tempRoot, { recursive: true, force: true });
}

async function waitForHealth(childProcess, port, deadline, readOutput) {
  while (Date.now() < deadline) {
    if (childProcess.exitCode !== null || childProcess.signalCode !== null) {
      throw new Error(`Built server exited before becoming healthy.\n${readOutput()}`.trim());
    }
    try {
      const response = await globalThis.fetch(`http://127.0.0.1:${port}/health`, {
        signal: globalThis.AbortSignal.timeout(Math.min(500, Math.max(1, deadline - Date.now())))
      });
      if (response.ok) {
        const body = await response.json();
        if (body?.ok === true && body?.name === "gpt-repo-mcp") {
          return;
        }
      }
    } catch {
      // The process may still be starting.
    }
    await new Promise((resolve) => globalThis.setTimeout(resolve, POLL_INTERVAL_MS));
  }
  throw new Error(`Built server did not become healthy within ${START_TIMEOUT_MS}ms.\n${readOutput()}`.trim());
}

async function stopChild(childProcess) {
  if (!childProcess || childProcess.exitCode !== null || childProcess.signalCode !== null) {
    return;
  }
  childProcess.kill("SIGTERM");
  const stopped = await Promise.race([
    once(childProcess, "exit").then(() => true),
    new Promise((resolve) => globalThis.setTimeout(() => resolve(false), 1_500))
  ]);
  if (!stopped && childProcess.exitCode === null && childProcess.signalCode === null) {
    childProcess.kill("SIGKILL");
    await once(childProcess, "exit");
  }
}

function appendBounded(current, chunk) {
  const combined = current + chunk;
  return combined.length > 8_000 ? combined.slice(-8_000) : combined;
}
