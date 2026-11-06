import { createServer, request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, test } from "vitest";
import { attachMcpRequestCancellation } from "../src/runtime/mcp-request-cancellation.js";
import { runProcessWithTail } from "../src/services/process-exec.js";
import { waitForFile } from "./fixtures/file-event-wait.js";
import { createTempDir } from "./fixtures/temp-dir.js";

describe("MCP HTTP request cancellation", () => {
  test("does not cancel a request after its HTTP response finishes normally", async () => {
    let observeFinishedSignal!: (aborted: boolean) => void;
    const finishedSignal = new Promise<boolean>((resolve) => { observeFinishedSignal = resolve; });
    const server = createServer((req, res) => {
      const signal = attachMcpRequestCancellation(req, res);
      res.once("finish", () => observeFinishedSignal(signal.aborted));
      res.end("complete");
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address() as AddressInfo;
    try {
      await new Promise<void>((resolve, reject) => {
        const clientRequest = httpRequest({ host: "127.0.0.1", port: address.port, method: "POST", path: "/mcp" }, (response) => {
          response.resume();
          response.once("end", resolve);
        });
        clientRequest.once("error", reject);
        clientRequest.end("{}");
      });

      expect(await finishedSignal).toBe(false);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  test("stops and reaps a command tree when the client disconnects", async () => {
    const root = await createTempDir("gpt-mcp-http-cancel-");
    const parentPidPath = `${root}/parent.pid`;
    const childReadyPath = `${root}/child.ready`;
    const childScript = [
      "const { writeFileSync } = require('node:fs');",
      "process.on('SIGTERM', () => {});",
      `writeFileSync(${JSON.stringify(childReadyPath)}, String(process.pid));`,
      "setInterval(() => {}, 1_000);"
    ].join("\n");
    const parentScript = [
      "const { spawn } = require('node:child_process');",
      "const { writeFileSync } = require('node:fs');",
      "process.on('SIGTERM', () => {});",
      `spawn(process.execPath, ['-e', ${JSON.stringify(childScript)}], { stdio: 'ignore' });`,
      `writeFileSync(${JSON.stringify(parentPidPath)}, String(process.pid));`,
      "setInterval(() => {}, 1_000);"
    ].join("\n");

    let completeExecution!: (result: Awaited<ReturnType<typeof runProcessWithTail>>) => void;
    let failExecution!: (error: unknown) => void;
    const execution = new Promise<Awaited<ReturnType<typeof runProcessWithTail>>>((resolve, reject) => {
      completeExecution = resolve;
      failExecution = reject;
    });
    const server = createServer((req, res) => {
      const signal = attachMcpRequestCancellation(req, res);
      void (async () => {
        const resultPromise = runProcessWithTail({
          executable: process.execPath,
          args: ["-e", parentScript],
          cwd: root,
          env: process.env,
          timeout_ms: 2_000,
          tail_bytes: 1_024,
          signal
        });
        const childPid = Number(await waitForFile(childReadyPath));
        const parentPid = Number(await waitForFile(parentPidPath));
        if (!isProcessAlive(parentPid) || !isProcessAlive(childPid)) {
          throw new Error("The command tree exited before the client disconnected.");
        }
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.write("command running\n");
        completeExecution(await resultPromise);
      })().catch(failExecution);
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address() as AddressInfo;
    const clientRequest = httpRequest({ host: "127.0.0.1", port: address.port, method: "POST", path: "/mcp" });
    clientRequest.on("error", () => undefined);
    clientRequest.on("response", (response) => {
      response.on("data", (chunk: Buffer) => {
        if (chunk.toString("utf8").includes("command running")) response.destroy();
      });
    });
    clientRequest.end("{}");

    try {
      const result = await execution;
      expect(result).toMatchObject({ cancelled: true, timed_out: false, cleanup_confirmed: true });
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }, 5_000);
});

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ESRCH") return false;
    throw error;
  }
}
