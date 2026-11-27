import { spawn, type ChildProcess, type ChildProcessWithoutNullStreams } from "node:child_process";
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

const CONNECTION_TIMEOUT_MS = 2_000;
const PROBE_TIMEOUT_MS = 2_000;
const CONTROL_WRITE_TIMEOUT_MS = 2_000;
const RELOAD_ACKNOWLEDGMENT_TIMEOUT_MS = 30_000;
const SHUTDOWN_TIMEOUT_MS = 7_000;
const MAX_DISCOVERY_BYTES = 1_048_576;
const MAX_CONTROL_LINE_BYTES = Math.ceil((MAX_CONFIGURATION_ADMIN_FRAME_BYTES + 4) * 4 / 3) + 16;
const MAX_HELPER_CREATION_TIME = "18446744073709551615";

const HelperCreationTimeSchema = z.string().max(20).regex(/^[1-9][0-9]*$/)
  .refine((value) => value.length < MAX_HELPER_CREATION_TIME.length
    || (value.length === MAX_HELPER_CREATION_TIME.length && value <= MAX_HELPER_CREATION_TIME));

const DiscoveryRecordSchema = z.object({
  protocol_version: z.literal(1),
  server_pid: z.number().int().positive(),
  helper_pid: z.number().int().positive(),
  helper_creation_time: HelperCreationTimeSchema.optional(),
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
  const host = new WindowsHostProcess(child, options.handle, options.serverPid, options.instanceId);
  child.stderr.resume();
  if (!child.pid) {
    host.reportMissingPid();
  } else {
    options.onHelperPid?.(child.pid);
  }
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
  const output = await runHelper(helperPath, ["discover"], undefined, CONNECTION_TIMEOUT_MS, MAX_DISCOVERY_BYTES);
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
  if (!target.helper_creation_time) {
    throw ipcError(
      "WINDOWS_HELPER_IDENTITY_UNAVAILABLE",
      "pre-dispatch",
      "The discovered endpoint does not include a verifiable helper process identity."
    );
  }
  let helperPath: string;
  try {
    helperPath = await resolveWindowsConfigurationAdminHostPath();
  } catch (error) {
    throw asIpcError(error, "WINDOWS_HELPER_UNAVAILABLE", "pre-dispatch", "The local administrative helper is unavailable.");
  }

  const frame = encodeAdminFrame(request);
  const timeoutMs = request.operation === "probe" ? PROBE_TIMEOUT_MS : RELOAD_ACKNOWLEDGMENT_TIMEOUT_MS;
  const output = await runHelper(helperPath, [
    "client",
    target.endpoint,
    String(timeoutMs),
    String(target.helper_pid),
    target.helper_creation_time
  ], frame, timeoutMs,
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
  if (marker.startsWith("NOT_DISPATCHED\t")) {
    const errorCode = marker.slice("NOT_DISPATCHED\t".length);
    throw ipcError(
      errorCode === "5" ? "WINDOWS_PIPE_ACCESS_DENIED" : "WINDOWS_PIPE_UNAVAILABLE",
      "pre-dispatch",
      errorCode === "5"
        ? "Windows denied access to the owner-local administrative pipe."
        : "The native helper confirmed that it could not write the request."
    );
  }
  if (marker === "INDETERMINATE") {
    const phase = request.operation === "reload" ? "indeterminate" : "pre-dispatch";
    throw ipcError(
      "WINDOWS_PIPE_INDETERMINATE",
      phase,
      request.operation === "reload"
        ? "The reload may have run, but the native helper could not confirm the response."
        : "The native helper could not confirm the probe response."
    );
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
  private readonly pendingConnections = new Map<string, object>();
  private closed = false;
  private failed = false;
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
    child.stdout.on("error", () => this.failHost("WINDOWS_HELPER_CONTROL_READ_FAILED"));
    child.stdout.on("close", () => this.failWhenStreamCloses("WINDOWS_HELPER_CONTROL_READ_CLOSED"));
    child.stdin.on("error", () => this.failHost("WINDOWS_HELPER_CONTROL_WRITE_FAILED"));
    child.stdin.on("close", () => this.failWhenStreamCloses("WINDOWS_HELPER_CONTROL_WRITE_CLOSED"));
    child.stderr.on("error", () => this.failHost("WINDOWS_HELPER_STDERR_FAILED"));
    child.stderr.on("close", () => this.failWhenStreamCloses("WINDOWS_HELPER_STDERR_CLOSED"));
    child.on("error", () => this.failHost("WINDOWS_HELPER_START_FAILED"));
    child.once("exit", (code, signal) => {
      const exitDetail = code === null ? `signal ${signal ?? "unknown"}` : `exit code ${code}`;
      const message = `The local administrative helper exited before establishing a verified endpoint (${exitDetail}).`;
      this.failBeforeReady("WINDOWS_HELPER_EXITED", message);
      this.failHost("WINDOWS_HELPER_EXITED", message, false);
    });
    child.once("close", () => this.failWhenStreamCloses("WINDOWS_HELPER_CLOSED"));
  }

  reportMissingPid(): void {
    this.failHost("WINDOWS_HELPER_START_FAILED");
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
          )), CONNECTION_TIMEOUT_MS);
        })
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async abortStartup(): Promise<void> {
    this.closed = true;
    if (this.child.exitCode !== null || this.child.signalCode !== null || this.failed) {
      terminateChild(this.child);
      return;
    }
    const shutdownWritten = await this.writeControlLine("SHUTDOWN\n");
    this.child.stdin.end();
    if (!shutdownWritten) terminateChild(this.child);
    try {
      await waitForExit(this.child, SHUTDOWN_TIMEOUT_MS);
    } catch {
      terminateChild(this.child);
      await waitForExit(this.child, 1_000).catch(() => undefined);
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (this.child.exitCode !== null || this.child.signalCode !== null) return;
    const shutdownWritten = await this.writeControlLine("SHUTDOWN\n");
    this.child.stdin.end();
    if (!shutdownWritten) terminateChild(this.child);
    try {
      await waitForExit(this.child, SHUTDOWN_TIMEOUT_MS);
    } catch {
      terminateChild(this.child);
      await waitForExit(this.child, 1_000).catch(() => undefined);
      throw ipcError("WINDOWS_HELPER_SHUTDOWN_TIMEOUT", "pre-dispatch", "The local administrative helper did not stop before the deadline.");
    }
    if (this.child.exitCode !== 0) {
      throw ipcError("WINDOWS_HELPER_SHUTDOWN_FAILED", "pre-dispatch", "The local administrative helper did not clean up its endpoint.");
    }
  }

  private writeControlLine(line: string): Promise<boolean> {
    return new Promise((resolveWrite) => {
      let settled = false;
      const finish = (written: boolean): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolveWrite(written);
      };
      const timer = setTimeout(() => finish(false), CONTROL_WRITE_TIMEOUT_MS);
      try {
        this.child.stdin.write(line, (error) => finish(error == null));
      } catch {
        finish(false);
      }
    });
  }

  private onOutput(chunk: Buffer): void {
    if (this.closed || this.failed) return;
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
      else this.acceptControlLine(line);
    }
  }

  private acceptControlLine(line: string): void {
    const requestPrefix = "REQUEST\t";
    if (line.startsWith(requestPrefix)) {
      const separator = line.indexOf("\t", requestPrefix.length);
      if (separator < 0) {
        this.failHost("WINDOWS_HELPER_BAD_CONTROL_MESSAGE");
        return;
      }
      const connectionId = line.slice(requestPrefix.length, separator);
      const encodedFrame = line.slice(separator + 1);
      if (!isCanonicalConnectionId(connectionId) || !isCanonicalBase64(encodedFrame)
        || this.pendingConnections.has(connectionId)) {
        this.failHost("WINDOWS_HELPER_BAD_CONTROL_MESSAGE");
        return;
      }
      void this.forwardRequest(connectionId, encodedFrame);
      return;
    }

    const abortPrefix = "ABORT\t";
    if (line.startsWith(abortPrefix)) {
      const connectionId = line.slice(abortPrefix.length);
      if (!isCanonicalConnectionId(connectionId)) {
        this.failHost("WINDOWS_HELPER_BAD_CONTROL_MESSAGE");
        return;
      }
      this.pendingConnections.delete(connectionId);
      return;
    }

    this.failHost("WINDOWS_HELPER_BAD_CONTROL_MESSAGE");
  }

  private acceptReadyLine(line: string): void {
    if (!line.startsWith("READY\t")) {
      this.failBeforeReady("WINDOWS_HELPER_BAD_READY");
      return;
    }
    try {
      const record = validateWindowsRecord(JSON.parse(line.slice("READY\t".length)));
      if (record.server_pid !== this.serverPid || record.helper_pid !== this.child.pid
        || !record.helper_creation_time || record.instance_id !== this.instanceId) {
        throw new Error("Instance identity mismatch.");
      }
      this.readyRecord = record;
      this.readyResolve?.(record);
      this.readyResolve = undefined;
      this.readyReject = undefined;
    } catch {
      this.failBeforeReady("WINDOWS_HELPER_BAD_READY");
    }
  }

  private async forwardRequest(connectionId: string, encodedFrame: string): Promise<void> {
    if (this.closed || this.failed) return;
    const pendingToken = {};
    this.pendingConnections.set(connectionId, pendingToken);
    try {
      const frame = Buffer.from(encodedFrame, "base64");
      if (frame.byteLength > MAX_CONFIGURATION_ADMIN_FRAME_BYTES + 4) throw new Error("Oversized request.");
      const request = parseAdminRequest(decodeAdminFrame(frame));
      const response = parseAdminResponse(await this.handle(request));
      if (response.request_id !== request.request_id) throw new Error("Request correlation failed.");
      if (this.closed || this.failed || this.pendingConnections.get(connectionId) !== pendingToken) return;
      this.pendingConnections.delete(connectionId);
      const line = `RESPONSE\t${connectionId}\t${encodeAdminFrame(response).toString("base64")}\n`;
      const responseWritten = await this.writeControlLine(line);
      if (!responseWritten && !this.closed && !this.failed) {
        this.failHost("WINDOWS_HELPER_CONTROL_WRITE_FAILED");
      }
    } catch {
      if (!this.closed && !this.failed
        && this.pendingConnections.get(connectionId) === pendingToken) {
        this.pendingConnections.delete(connectionId);
        await this.writeControlLine(`ABORT\t${connectionId}\n`);
      }
    }
  }

  private failWhenStreamCloses(code: string): void {
    if (this.closed || this.failed || this.child.exitCode !== null || this.child.signalCode !== null) return;
    this.failHost(code);
  }

  private failHost(
    code: string,
    message = "The local administrative helper control channel failed.",
    terminate = true
  ): void {
    if (this.failed) return;
    this.failed = true;
    this.pendingConnections.clear();
    this.failBeforeReady(code, message);
    if (terminate && this.child.exitCode === null && this.child.signalCode === null) {
      terminateChild(this.child);
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
  const deadline = performance.now() + timeoutMs;
  const child = spawn(helperPath, args, { stdio: ["pipe", "pipe", "ignore"], windowsHide: true });
  const chunks: Buffer[] = [];
  let outputLength = 0;
  return await new Promise<Buffer>((resolveOutput, rejectOutput) => {
    let settled = false;
    const fail = (error: Error, terminate = true): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (terminate) terminateChild(child);
      rejectOutput(error);
    };
    const finish = (value: Buffer): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveOutput(value);
    };
    // Without a native NOT_DISPATCHED marker, a stream error cannot prove the request was not sent.
    const processErrorPhase = child.pid !== undefined && mutation ? "indeterminate" : "pre-dispatch";

    child.stdout.on("data", (chunk: Buffer) => {
      if (settled) return;
      outputLength += chunk.byteLength;
      if (outputLength > maximumOutputBytes) {
        fail(ipcError("WINDOWS_HELPER_OUTPUT_TOO_LARGE", processErrorPhase, "The native helper output exceeded its limit."));
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    child.stdout.on("error", () => {
      fail(ipcError("WINDOWS_HELPER_CONTROL_READ_FAILED", processErrorPhase, "The native helper control channel could not be read."));
    });
    child.stdin.on("error", () => {
      fail(ipcError("WINDOWS_HELPER_CONTROL_WRITE_FAILED", processErrorPhase, "The native helper control channel could not be written."));
    });
    child.on("error", () => {
      fail(ipcError("WINDOWS_HELPER_START_FAILED", "pre-dispatch", "The native helper could not be started."), false);
    });
    child.once("close", (code) => {
      if (settled) return;
      if (code !== 0 && args[0] !== "client") {
        fail(ipcError("WINDOWS_HELPER_FAILED", "pre-dispatch", "The local administrative helper failed."), false);
      } else {
        finish(Buffer.concat(chunks));
      }
    });
    const remaining = Math.max(0, deadline - performance.now());
    const timer = setTimeout(() => {
      fail(ipcError(
        "WINDOWS_HELPER_TIMEOUT",
        processErrorPhase,
        mutation ? "The reload may have run, but the native helper timed out." : "The native probe timed out."
      ));
    }, remaining);
    try {
      child.stdin.end(input);
    } catch {
      fail(ipcError("WINDOWS_HELPER_CONTROL_WRITE_FAILED", processErrorPhase, "The native helper control channel could not be written."));
    }
  });
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

function isCanonicalConnectionId(value: string): boolean {
  return /^[1-9][0-9]*-[1-9][0-9]*$/.test(value);
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

function terminateChild(child: ChildProcess): void {
  if (child.pid === undefined || child.exitCode !== null || child.signalCode !== null) return;
  try {
    child.kill();
  } catch {
    // A spawn error or exit race can leave no process handle to terminate.
  }
}
