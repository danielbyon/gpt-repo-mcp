import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { lstat } from "node:fs/promises";
import { once } from "node:events";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type {
  ConfigurationAdminDiscoveryRecord
} from "./configuration-admin-client.js";
import { ConfigurationAdminIpcError } from "./configuration-admin-error.js";
import {
  MAX_CONFIGURATION_ADMIN_FRAME_BYTES,
  decodeAdminFrame,
  encodeAdminFrame,
  parseAdminRequest,
  parseAdminResponse,
  type ConfigurationAdminRequest,
  type ConfigurationAdminResponse
} from "./configuration-admin-protocol.js";

const STARTUP_TIMEOUT_MS = 3_000;
const HELPER_TIMEOUT_MS = 7_000;
const MAX_DISCOVERY_BYTES = 1_048_576;
const MAX_CONTROL_LINE_BYTES = Math.ceil((MAX_CONFIGURATION_ADMIN_FRAME_BYTES + 4) * 4 / 3) + 16;

const DiscoveryRecordSchema = z.object({
  protocol_version: z.literal(1),
  server_pid: z.number().int().positive(),
  helper_pid: z.number().int().positive(),
  instance_id: z.string().uuid(),
  endpoint: z.string().min(1)
}).strict();

/** Starts the native pipe server and binds it to the Node server process. */
export async function startWindowsConfigurationAdminHost(options: {
  serverPid: number;
  instanceId: string;
  onHelperPid?: (helperPid: number) => void;
  handle: (value: unknown) => Promise<ConfigurationAdminResponse>;
}): Promise<Readonly<{ record: ConfigurationAdminDiscoveryRecord; close: () => Promise<void> }>> {
  const helperPath = await resolveWindowsConfigurationAdminHostPath();
  const child = spawn(helperPath, ["serve", String(options.serverPid), options.instanceId], {
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true
  });
  child.stderr.resume();
  if (!child.pid) {
    child.kill();
    throw ipcError("WINDOWS_HELPER_START_FAILED", "pre-dispatch", "The local administrative helper could not be started.");
  }
  options.onHelperPid?.(child.pid);

  const host = new WindowsHostProcess(child, options.handle, options.serverPid, options.instanceId);
  try {
    const record = await host.waitUntilReady();
    return Object.freeze({ record, close: () => host.close() });
  } catch (error) {
    await host.abortStartup();
    throw error;
  }
}

/** Reads Windows discovery records through the helper that validates their ACLs. */
export async function readWindowsConfigurationAdminRecords(): Promise<ConfigurationAdminDiscoveryRecord[]> {
  const helperPath = await resolveWindowsConfigurationAdminHostPath();
  const output = await runHelper(helperPath, ["discover"], undefined, 3_000, MAX_DISCOVERY_BYTES);
  let parsed: unknown;
  try {
    parsed = JSON.parse(output.toString("utf8"));
  } catch {
    throw ipcError("WINDOWS_DISCOVERY_FAILED", "pre-dispatch", "The local administrative discovery store could not be read.");
  }
  const container = z.object({ records: z.array(DiscoveryRecordSchema) }).strict().parse(parsed);
  return container.records.map((record) => validateWindowsRecord(record));
}

/** Uses the native client helper to open the pipe with individual access rights. */
export async function requestWindowsConfigurationAdmin(
  record: ConfigurationAdminDiscoveryRecord,
  value: ConfigurationAdminRequest
): Promise<ConfigurationAdminResponse> {
  const request = parseAdminRequest(value);
  const target = validateWindowsRecord(record);
  let helperPath: string;
  try {
    helperPath = await resolveWindowsConfigurationAdminHostPath();
  } catch (error) {
    throw asIpcError(error, "WINDOWS_HELPER_UNAVAILABLE", "pre-dispatch", "The local administrative helper is unavailable.");
  }

  const frame = encodeAdminFrame(request);
  const output = await runHelper(helperPath, ["client", target.endpoint], frame, HELPER_TIMEOUT_MS,
    MAX_CONFIGURATION_ADMIN_FRAME_BYTES + 64, request.operation === "reload");
  const markerEnd = output.indexOf(0x0a);
  if (markerEnd < 0) {
    throw ipcError(
      "WINDOWS_HELPER_OUTCOME_UNKNOWN",
      request.operation === "reload" ? "indeterminate" : "pre-dispatch",
      request.operation === "reload"
        ? "The reload may have run, but the native helper did not report its outcome."
        : "The native probe did not return a response."
    );
  }

  const marker = output.subarray(0, markerEnd).toString("ascii");
  if (marker === "NOT_DISPATCHED") {
    throw ipcError("WINDOWS_PIPE_UNAVAILABLE", "pre-dispatch", "The native helper confirmed that it could not write the request.");
  }
  if (marker === "INDETERMINATE") {
    throw ipcError("WINDOWS_PIPE_INDETERMINATE", "indeterminate", "The reload may have run, but the native helper could not confirm the response.");
  }
  if (marker !== "RESPONSE") {
    throw ipcError(
      "WINDOWS_HELPER_OUTCOME_UNKNOWN",
      request.operation === "reload" ? "indeterminate" : "pre-dispatch",
      request.operation === "reload"
        ? "The reload may have run, but the native helper returned no valid outcome."
        : "The native probe returned an invalid outcome."
    );
  }

  try {
    const response = parseAdminResponse(decodeAdminFrame(output.subarray(markerEnd + 1)));
    if (response.request_id !== request.request_id
      || (request.operation === "probe" && response.operation !== "probe_result")
      || (request.operation === "reload" && response.operation !== "reload_result")) {
      throw new Error("Uncorrelated response.");
    }
    return response;
  } catch {
    throw ipcError(
      "WINDOWS_HELPER_BAD_RESPONSE",
      request.operation === "reload" ? "indeterminate" : "pre-dispatch",
      request.operation === "reload"
        ? "The reload may have run, but its response could not be verified."
        : "The native probe response could not be verified."
    );
  }
}

/** Resolves the packaged helper beside dist output or the development dist folder. */
export async function resolveWindowsConfigurationAdminHostPath(): Promise<string> {
  const testHelper = process.env.GPT_REPO_ADMIN_TEST_HELPER === "1";
  const filename = testHelper
    ? "windows-configuration-admin-host.test.exe"
    : "windows-configuration-admin-host.exe";
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(moduleDirectory, filename),
    join(moduleDirectory, "..", filename),
    resolve(moduleDirectory, "../../dist", filename)
  ];

  for (const candidate of candidates) {
    try {
      const info = await lstat(candidate);
      if (info.isFile() && !info.isSymbolicLink() && info.nlink === 1) return candidate;
    } catch {
      // Try the next layout used by source and packaged distributions.
    }
  }
  throw ipcError("WINDOWS_HELPER_UNAVAILABLE", "pre-dispatch", "The Windows administrative helper executable is missing.");
}

class WindowsHostProcess {
  private bufferedOutput = Buffer.alloc(0);
  private readyRecord: ConfigurationAdminDiscoveryRecord | undefined;
  private readyResolve: ((record: ConfigurationAdminDiscoveryRecord) => void) | undefined;
  private readyReject: ((error: Error) => void) | undefined;
  private requestInFlight = false;
  private closed = false;
  private readonly readyPromise: Promise<ConfigurationAdminDiscoveryRecord>;

  constructor(
    private readonly child: ChildProcessWithoutNullStreams,
    private readonly handle: (value: unknown) => Promise<ConfigurationAdminResponse>,
    private readonly serverPid: number,
    private readonly instanceId: string
  ) {
    this.readyPromise = new Promise((resolveReady, rejectReady) => {
      this.readyResolve = resolveReady;
      this.readyReject = rejectReady;
    });
    child.stdout.on("data", (chunk: Buffer) => this.onOutput(chunk));
    child.once("error", () => this.failBeforeReady("WINDOWS_HELPER_START_FAILED"));
    child.once("exit", (code, signal) => {
      const exitDetail = code === null ? `signal ${signal ?? "unknown"}` : `exit code ${code}`;
      this.failBeforeReady(
        "WINDOWS_HELPER_EXITED",
        `The local administrative helper exited before establishing a verified endpoint (${exitDetail}).`
      );
    });
  }

  async waitUntilReady(): Promise<ConfigurationAdminDiscoveryRecord> {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        this.readyPromise,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(ipcError(
            "WINDOWS_HELPER_START_TIMEOUT",
            "pre-dispatch",
            "The local administrative helper did not start before the deadline."
          )), STARTUP_TIMEOUT_MS);
        })
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async abortStartup(): Promise<void> {
    this.closed = true;
    if (this.child.exitCode !== null || this.child.signalCode !== null) return;
    const shutdownWritten = await this.writeControlLine("SHUTDOWN\n");
    this.child.stdin.end();
    if (!shutdownWritten) this.child.kill();
    try {
      await waitForExit(this.child, HELPER_TIMEOUT_MS);
    } catch {
      this.child.kill();
      await waitForExit(this.child, 1_000).catch(() => undefined);
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (this.child.exitCode !== null || this.child.signalCode !== null) return;
    const shutdownWritten = await this.writeControlLine("SHUTDOWN\n");
    this.child.stdin.end();
    if (!shutdownWritten) this.child.kill();
    try {
      await waitForExit(this.child, HELPER_TIMEOUT_MS);
    } catch {
      this.child.kill();
      await waitForExit(this.child, 1_000).catch(() => undefined);
      throw ipcError("WINDOWS_HELPER_SHUTDOWN_TIMEOUT", "pre-dispatch", "The local administrative helper did not stop before the deadline.");
    }
    if (this.child.exitCode !== 0) {
      throw ipcError("WINDOWS_HELPER_SHUTDOWN_FAILED", "pre-dispatch", "The local administrative helper did not clean up its endpoint.");
    }
  }

  private writeControlLine(line: string): Promise<boolean> {
    return new Promise((resolveWrite) => {
      try {
        this.child.stdin.write(line, (error) => resolveWrite(error === null));
      } catch {
        resolveWrite(false);
      }
    });
  }

  private onOutput(chunk: Buffer): void {
    if (this.closed) return;
    this.bufferedOutput = Buffer.concat([this.bufferedOutput, chunk]);
    if (this.bufferedOutput.byteLength > MAX_CONTROL_LINE_BYTES * 2) {
      this.child.kill();
      this.failBeforeReady("WINDOWS_HELPER_OUTPUT_TOO_LARGE");
      return;
    }
    for (;;) {
      const newline = this.bufferedOutput.indexOf(0x0a);
      if (newline < 0) {
        if (this.bufferedOutput.byteLength > MAX_CONTROL_LINE_BYTES) {
          this.child.kill();
          this.failBeforeReady("WINDOWS_HELPER_OUTPUT_TOO_LARGE");
        }
        return;
      }
      const line = this.bufferedOutput.subarray(0, newline).toString("utf8");
      this.bufferedOutput = this.bufferedOutput.subarray(newline + 1);
      if (!this.readyRecord) this.acceptReadyLine(line);
      else if (line.startsWith("REQUEST\t")) void this.forwardRequest(line.slice("REQUEST\t".length));
      else void this.writeControlLine("ABORT\n");
    }
  }

  private acceptReadyLine(line: string): void {
    if (!line.startsWith("READY\t")) {
      this.failBeforeReady("WINDOWS_HELPER_BAD_READY");
      return;
    }
    try {
      const record = validateWindowsRecord(JSON.parse(line.slice("READY\t".length)));
      if (record.server_pid !== this.serverPid || record.helper_pid !== this.child.pid
        || record.instance_id !== this.instanceId) throw new Error("Instance mismatch.");
      this.readyRecord = record;
      this.readyResolve?.(record);
      this.readyResolve = undefined;
      this.readyReject = undefined;
    } catch {
      this.failBeforeReady("WINDOWS_HELPER_BAD_READY");
    }
  }

  private async forwardRequest(encodedFrame: string): Promise<void> {
    if (this.closed) return;
    if (this.requestInFlight || !isCanonicalBase64(encodedFrame)) {
      await this.writeControlLine("ABORT\n");
      return;
    }
    this.requestInFlight = true;
    try {
      const frame = Buffer.from(encodedFrame, "base64");
      if (frame.byteLength > MAX_CONFIGURATION_ADMIN_FRAME_BYTES + 4) throw new Error("Oversized request.");
      const request = parseAdminRequest(decodeAdminFrame(frame));
      const response = parseAdminResponse(await this.handle(request));
      if (response.request_id !== request.request_id) throw new Error("Request correlation failed.");
      if (this.closed) return;
      const line = `RESPONSE\t${encodeAdminFrame(response).toString("base64")}\n`;
      const responseWritten = await this.writeControlLine(line);
      if (!responseWritten && !this.closed) await this.writeControlLine("ABORT\n");
    } catch {
      if (!this.closed) await this.writeControlLine("ABORT\n");
    } finally {
      this.requestInFlight = false;
    }
  }

  private failBeforeReady(
    code: string,
    message = "The local administrative helper did not establish a verified endpoint."
  ): void {
    if (!this.readyReject) return;
    const reject = this.readyReject;
    this.readyReject = undefined;
    this.readyResolve = undefined;
    reject(ipcError(code, "pre-dispatch", message));
  }
}

async function runHelper(
  helperPath: string,
  args: string[],
  input: Uint8Array | undefined,
  timeoutMs: number,
  maximumOutputBytes: number,
  mutation = false
): Promise<Buffer> {
  const child = spawn(helperPath, args, { stdio: ["pipe", "pipe", "ignore"], windowsHide: true });
  const chunks: Buffer[] = [];
  let outputLength = 0;
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill();
  }, timeoutMs);
  const outputPromise = new Promise<Buffer>((resolveOutput, rejectOutput) => {
    child.stdout.on("data", (chunk: Buffer) => {
      outputLength += chunk.byteLength;
      if (outputLength > maximumOutputBytes) {
        child.kill();
        rejectOutput(ipcError("WINDOWS_HELPER_OUTPUT_TOO_LARGE", mutation ? "indeterminate" : "pre-dispatch", "The native helper output exceeded its limit."));
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    child.once("error", () => rejectOutput(ipcError("WINDOWS_HELPER_START_FAILED", "pre-dispatch", "The native helper could not be started.")));
    child.once("close", (code) => {
      if (timedOut) {
        rejectOutput(ipcError(
          "WINDOWS_HELPER_TIMEOUT",
          mutation ? "indeterminate" : "pre-dispatch",
          mutation ? "The reload may have run, but the native helper timed out." : "The native probe timed out."
        ));
      } else if (code !== 0 && args[0] !== "client") {
        rejectOutput(ipcError("WINDOWS_HELPER_FAILED", "pre-dispatch", "The local administrative helper failed."));
      } else {
        resolveOutput(Buffer.concat(chunks));
      }
    });
  });
  child.stdin.end(input);
  try {
    return await outputPromise;
  } finally {
    clearTimeout(timer);
  }
}

function validateWindowsRecord(value: unknown): ConfigurationAdminDiscoveryRecord {
  const record = DiscoveryRecordSchema.parse(value);
  const expected = `\\\\.\\pipe\\gpt-repo-mcp-${record.server_pid}-${record.instance_id}`;
  if (record.endpoint !== expected) {
    throw ipcError("INVALID_DISCOVERY_RECORD", "pre-dispatch", "The discovered pipe endpoint is not in the supported local namespace.");
  }
  return Object.freeze(record);
}

function isCanonicalBase64(value: string): boolean {
  return value.length > 0 && value.length <= MAX_CONTROL_LINE_BYTES
    && /^[A-Za-z0-9+/]+={0,2}$/.test(value)
    && Buffer.from(value, "base64").toString("base64") === value;
}

function ipcError(code: string, phase: "pre-dispatch" | "indeterminate", message: string): ConfigurationAdminIpcError {
  return new ConfigurationAdminIpcError(code, phase, message);
}

function asIpcError(error: unknown, code: string, phase: "pre-dispatch" | "indeterminate", message: string): ConfigurationAdminIpcError {
  return error instanceof ConfigurationAdminIpcError ? error : ipcError(code, phase, message);
}

async function waitForExit(child: ChildProcessWithoutNullStreams, timeoutMs: number): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      once(child, "exit").then(() => undefined),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("Process exit timed out.")), timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
