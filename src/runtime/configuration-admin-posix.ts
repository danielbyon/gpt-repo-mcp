import { randomUUID } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { chmod, lstat, mkdir, open, readdir, rename, unlink } from "node:fs/promises";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";
import type { ConfigurationAdminDiscoveryRecord } from "./configuration-admin-client.js";
import { ConfigurationAdminIpcError } from "./configuration-admin-error.js";
import {
  CONFIGURATION_ADMIN_PROTOCOL_VERSION,
  MAX_CONFIGURATION_ADMIN_FRAME_BYTES,
  decodeAdminFrame,
  encodeAdminFrame,
  parseAdminRequest,
  parseAdminResponse,
  type ConfigurationAdminRequest,
  type ConfigurationAdminResponse
} from "./configuration-admin-protocol.js";

const CONNECTION_AND_PROBE_TIMEOUT_MS = 2_000;
const RELOAD_ACK_TIMEOUT_MS = 30_000;
const STATUS_RESPONSE_TIMEOUT_MS = RELOAD_ACK_TIMEOUT_MS;
const SOCKET_MODE = 0o600;
const PRIVATE_DIRECTORY_MODE = 0o700;
const DIRECTORY_READ_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
const FILE_READ_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);

/** Starts a private Unix-domain endpoint and publishes its instance record. */
export async function startPosixConfigurationAdminServer(options: {
  directory: string;
  serverPid: number;
  instanceId: string;
  handle: (value: unknown) => Promise<ConfigurationAdminResponse>;
}): Promise<Readonly<{ record: ConfigurationAdminDiscoveryRecord; close: () => Promise<void> }>> {
  const directory = resolve(options.directory);
  await verifyPrivateDirectory(directory);
  if (!Number.isSafeInteger(options.serverPid) || options.serverPid <= 0 || !isUuid(options.instanceId)) {
    throw new ConfigurationAdminIpcError("INVALID_INSTANCE", "pre-dispatch", "The administrative endpoint identity is invalid.");
  }

  const endpointPath = join(directory, `instance-${options.instanceId}.sock`);
  if (Buffer.byteLength(endpointPath) > 100) {
    throw new ConfigurationAdminIpcError("ENDPOINT_PATH_TOO_LONG", "pre-dispatch", "The administrative endpoint path is too long for a local socket.");
  }
  const recordPath = join(directory, `server-${options.serverPid}-${options.instanceId}.json`);
  const record: ConfigurationAdminDiscoveryRecord = Object.freeze({
    protocol_version: CONFIGURATION_ADMIN_PROTOCOL_VERSION,
    server_pid: options.serverPid,
    instance_id: options.instanceId,
    endpoint: endpointPath
  });

  const sockets = new Set<Socket>();
  const server = createServer({ allowHalfOpen: true }, (socket) => {
    if (sockets.size >= 32) {
      socket.destroy();
      return;
    }
    const acceptedAt = performance.now();
    sockets.add(socket);
    socket.on("error", () => socket.destroy());
    const frameDeadline = acceptedAt + CONNECTION_AND_PROBE_TIMEOUT_MS;
    const statusDeadline = acceptedAt + STATUS_RESPONSE_TIMEOUT_MS;
    void serveConnection(socket, options.handle, frameDeadline, statusDeadline).finally(() => sockets.delete(socket));
  });
  server.maxConnections = 32;
  server.on("error", () => undefined);

  let socketIdentity: { dev: number; ino: number } | undefined;
  let recordPublished = false;
  try {
    await listen(server, endpointPath);
    await chmod(endpointPath, SOCKET_MODE);
    const socketInfo = await lstat(endpointPath);
    verifyOwnedSocket(socketInfo, endpointPath);
    socketIdentity = { dev: socketInfo.dev, ino: socketInfo.ino };
    await publishDiscoveryRecord(directory, recordPath, record);
    recordPublished = true;
  } catch (error) {
    await closeServer(server);
    if (socketIdentity) await unlinkSocketIfSame(endpointPath, socketIdentity).catch(() => undefined);
    if (recordPublished) await removeDiscoveryRecord(recordPath, record).catch(() => undefined);
    throw asIpcError(error, "IPC_START_FAILED", "pre-dispatch", "Owner-local administrative IPC could not be initialized.");
  }

  let closed = false;
  return Object.freeze({
    record,
    async close() {
      if (closed) return;
      closed = true;
      for (const socket of sockets) socket.destroy();
      await closeServer(server);
      const cleanupErrors: unknown[] = [];
      try {
        await removeDiscoveryRecord(recordPath, record);
      } catch (error) {
        cleanupErrors.push(error);
      }
      if (socketIdentity) {
        try {
          await unlinkSocketIfSame(endpointPath, socketIdentity);
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
      if (cleanupErrors.length > 0) {
        throw new AggregateError(cleanupErrors, "Administrative IPC endpoint cleanup was incomplete.");
      }
    }
  });
}

/** Returns records from an owner-protected POSIX discovery directory. */
export async function readPosixConfigurationAdminRecords(
  directory: string
): Promise<ConfigurationAdminDiscoveryRecord[]> {
  const absoluteDirectory = resolve(directory);
  try {
    await lstat(absoluteDirectory);
  } catch (error) {
    if (isNotFound(error)) return [];
    throw error;
  }
  await verifyPrivateDirectory(absoluteDirectory);

  const entries = await readdir(absoluteDirectory);
  const records: ConfigurationAdminDiscoveryRecord[] = [];
  for (const name of entries) {
    const match = /^server-([1-9][0-9]*)-([0-9a-f-]{36})\.json$/.exec(name);
    if (!match) continue;
    const serverPid = Number(match[1]);
    const instanceId = match[2];
    if (!Number.isSafeInteger(serverPid) || !isUuid(instanceId)) {
      throw new ConfigurationAdminIpcError("INVALID_DISCOVERY_RECORD", "pre-dispatch", "An administrative discovery record is invalid.");
    }
    const recordPath = join(absoluteDirectory, name);
    const record = await readDiscoveryRecord(recordPath, absoluteDirectory, serverPid, instanceId);
    records.push(record);
  }
  return records;
}

/**
 * Status gets one 30-second budget from the start of the request, with a two-second connection limit. Probe and reload
 * keep their existing deadlines. Reloads are never retried after a write attempt.
 */
export async function requestPosixConfigurationAdmin(
  record: ConfigurationAdminDiscoveryRecord,
  value: ConfigurationAdminRequest
): Promise<ConfigurationAdminResponse> {
  const transactionStartedAt = performance.now();
  let dispatched = false;
  let request: ConfigurationAdminRequest;
  let frame: Buffer;
  try {
    request = parseAdminRequest(value);
    frame = encodeAdminFrame(request);
    validateRecord(record);
    const endpointInfo = await lstat(record.endpoint);
    verifyOwnedSocket(endpointInfo, record.endpoint);
  } catch (error) {
    throw asIpcError(error, "IPC_UNAVAILABLE", "pre-dispatch", "The administrative endpoint is unavailable.");
  }
  const statusDeadlineAt = request.operation === "status"
    ? transactionStartedAt + STATUS_RESPONSE_TIMEOUT_MS
    : undefined;

  return await new Promise<ConfigurationAdminResponse>((resolveResponse, rejectResponse) => {
    const socket = createConnection({ path: record.endpoint });
    let received = Buffer.alloc(0);
    let settled = false;
    let deadlineAt = Math.min(
      performance.now() + CONNECTION_AND_PROBE_TIMEOUT_MS,
      statusDeadlineAt ?? Number.POSITIVE_INFINITY
    );
    let deadlineTimer: ReturnType<typeof setTimeout>;
    const phase = (): "pre-dispatch" | "indeterminate" => request.operation === "reload" && dispatched
      ? "indeterminate"
      : "pre-dispatch";

    const clearDeadline = (): void => clearTimeout(deadlineTimer);

    const armDeadlineAt = (absoluteDeadline: number): void => {
      clearDeadline();
      deadlineAt = absoluteDeadline;
      const remainingMs = Math.max(0, deadlineAt - performance.now());
      deadlineTimer = setTimeout(() => {
        fail("IPC_TIMEOUT", "The administrative endpoint did not respond before the deadline.");
      }, remainingMs);
    };

    const armDeadline = (durationMs: number): void => {
      armDeadlineAt(performance.now() + durationMs);
    };

    const deadlineExpired = (): boolean => {
      if (performance.now() < deadlineAt) return false;
      fail("IPC_TIMEOUT", "The administrative endpoint did not respond before the deadline.");
      return true;
    };

    const fail = (code: string, message: string): void => {
      if (settled) return;
      settled = true;
      clearDeadline();
      socket.destroy();
      rejectResponse(new ConfigurationAdminIpcError(code, phase(), message));
    };

    armDeadlineAt(deadlineAt);
    socket.on("connect", () => {
      if (deadlineExpired()) return;
      try {
        if (request.operation === "reload" || request.operation === "status") {
          if (request.operation === "reload") dispatched = true;
          if (request.operation === "reload") armDeadline(RELOAD_ACK_TIMEOUT_MS);
          else if (statusDeadlineAt !== undefined) armDeadlineAt(statusDeadlineAt);
        }
        socket.end(frame);
      } catch {
        fail("IPC_WRITE_FAILED", "The administrative request could not be sent.");
      }
    });
    socket.on("data", (chunk: Buffer) => {
      if (deadlineExpired()) return;
      received = Buffer.concat([received, chunk]);
      if (received.byteLength > MAX_CONFIGURATION_ADMIN_FRAME_BYTES + 4) {
        fail("IPC_FRAME_TOO_LARGE", "The administrative response exceeded the frame limit.");
      }
    });
    socket.on("end", () => {
      if (settled) return;
      if (deadlineExpired()) return;
      try {
        const response = parseAdminResponse(decodeAdminFrame(received));
        if (response.request_id !== request.request_id
          || (request.operation === "probe" && response.operation !== "probe_result")
          || (request.operation === "reload" && response.operation !== "reload_result")
          || (request.operation === "status" && response.operation !== "status_result")) {
          throw new Error("The administrative response does not match its request.");
        }
        settled = true;
        clearDeadline();
        resolveResponse(response);
      } catch {
        fail("IPC_BAD_RESPONSE", "The administrative endpoint returned an invalid or uncorrelated response.");
      }
    });
    socket.on("error", () => fail("IPC_CONNECTION_FAILED", "The administrative endpoint connection failed."));
    socket.on("close", () => {
      if (!settled) fail("IPC_CONNECTION_CLOSED", "The administrative endpoint closed before replying.");
    });
  });
}

/**
 * Returns the private POSIX directory used for endpoint discovery.
 * Marked integration-test servers must set an isolated directory explicitly.
 */
export async function getPosixConfigurationAdminDirectory(): Promise<string> {
  if (process.env.GPT_REPO_TEST_BUILT_SERVER === "1") {
    const testDirectory = process.env.GPT_REPO_ADMIN_TEST_DIRECTORY;
    if (!testDirectory) {
      throw new ConfigurationAdminIpcError(
        "TEST_DIRECTORY_REQUIRED",
        "pre-dispatch",
        "A test server requires an isolated administrative IPC directory."
      );
    }
    const directory = resolve(testDirectory);
    await mkdir(directory, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
    await verifyPrivateDirectory(directory);
    return directory;
  }

  const userId = process.getuid?.();
  if (userId === undefined) {
    throw new ConfigurationAdminIpcError("OWNER_ID_UNAVAILABLE", "pre-dispatch", "The current owner identity is unavailable.");
  }
  const directory = join("/tmp", `gpt-repo-mcp-${userId}`);
  await mkdir(directory, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
  await verifyPrivateDirectory(directory);
  return directory;
}

async function serveConnection(
  socket: Socket,
  handle: (value: unknown) => Promise<ConfigurationAdminResponse>,
  frameDeadline: number,
  statusDeadline: number
): Promise<void> {
  try {
    const requestValue = decodeAdminFrame(await readSocketFrame(socket, frameDeadline));
    const request = parseAdminRequest(requestValue);
    const operationDeadline = request.operation === "probe"
      ? frameDeadline
      : request.operation === "reload"
        ? performance.now() + RELOAD_ACK_TIMEOUT_MS
        : statusDeadline;
    const response = parseAdminResponse(await waitForDeadline(handle(request), operationDeadline, socket));
    if (response.request_id !== request.request_id) return;
    await writeFrameBeforeDeadline(socket, encodeAdminFrame(response), operationDeadline);
  } catch {
    socket.destroy();
  }
}

async function readSocketFrame(socket: Socket, deadlineAt: number): Promise<Buffer> {
  return await new Promise<Buffer>((resolveFrame, rejectFrame) => {
    let bytes = Buffer.alloc(0);
    let settled = false;
    const cleanup = (): void => {
      clearTimeout(deadlineTimer);
      socket.off("data", onData);
      socket.off("end", onEnd);
      socket.off("error", onError);
      socket.off("close", onClose);
    };
    const fail = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      rejectFrame(new Error("Invalid administrative request frame."));
    };
    const deadlineTimer = scheduleDeadline(deadlineAt, fail);
    const onData = (chunk: Buffer): void => {
      if (performance.now() >= deadlineAt) {
        fail();
        return;
      }
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.byteLength > MAX_CONFIGURATION_ADMIN_FRAME_BYTES + 4) {
        fail();
        return;
      }
      if (bytes.byteLength >= 4) {
        const payloadLength = bytes.readUInt32BE(0);
        if (payloadLength === 0 || payloadLength > MAX_CONFIGURATION_ADMIN_FRAME_BYTES
          || bytes.byteLength > payloadLength + 4) fail();
      }
    };
    const onEnd = (): void => {
      if (settled) return;
      if (performance.now() >= deadlineAt) {
        fail();
        return;
      }
      try {
        decodeAdminFrame(bytes);
        settled = true;
        cleanup();
        resolveFrame(bytes);
      } catch {
        fail();
      }
    };
    const onError = (): void => fail();
    const onClose = (): void => fail();
    socket.on("data", onData);
    socket.once("end", onEnd);
    socket.once("error", onError);
    socket.once("close", onClose);
  });
}

/** Waits against one monotonic deadline; socket activity never extends the limit. */
function waitForDeadline<T>(operation: Promise<T>, deadlineAt: number, socket: Socket): Promise<T> {
  return new Promise<T>((resolveOperation, rejectOperation) => {
    if (socket.destroyed) {
      rejectOperation(new Error("Administrative IPC connection closed."));
      return;
    }
    let settled = false;
    const finish = (rejected: boolean, value: unknown): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadlineTimer);
      socket.off("close", onSocketClose);
      if (rejected) rejectOperation(value);
      else resolveOperation(value as T);
    };
    const onSocketClose = (): void => finish(true, new Error("Administrative IPC connection closed."));
    const deadlineTimer = scheduleDeadline(
      deadlineAt,
      () => finish(true, new Error("Administrative IPC operation timed out."))
    );
    socket.once("close", onSocketClose);

    operation.then(
      (value) => {
        if (performance.now() >= deadlineAt) {
          finish(true, new Error("Administrative IPC operation timed out."));
        } else {
          finish(false, value);
        }
      },
      (error: unknown) => finish(true, error)
    );
  });
}

function writeFrameBeforeDeadline(socket: Socket, frame: Buffer, deadlineAt: number): Promise<void> {
  return new Promise<void>((resolveWrite, rejectWrite) => {
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadlineTimer);
      socket.off("error", onError);
      if (error) rejectWrite(error);
      else if (performance.now() >= deadlineAt) rejectWrite(new Error("Administrative IPC response timed out."));
      else resolveWrite();
    };
    const onError = (error: Error): void => finish(error);
    const remainingMs = deadlineAt - performance.now();
    if (remainingMs <= 0) {
      rejectWrite(new Error("Administrative IPC response timed out."));
      return;
    }
    const deadlineTimer = setTimeout(() => finish(new Error("Administrative IPC response timed out.")), remainingMs);
    socket.once("error", onError);
    socket.end(frame, () => finish());
  });
}

function scheduleDeadline(deadlineAt: number, onDeadline: () => void): ReturnType<typeof setTimeout> {
  return setTimeout(onDeadline, Math.max(0, deadlineAt - performance.now()));
}

async function publishDiscoveryRecord(
  directory: string,
  recordPath: string,
  record: ConfigurationAdminDiscoveryRecord
): Promise<void> {
  const temporaryPath = join(directory, `.record-${randomUUID()}.tmp`);
  const file = await open(
    temporaryPath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
    SOCKET_MODE
  );
  try {
    await file.writeFile(JSON.stringify(record), "utf8");
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(temporaryPath, recordPath);
  const directoryHandle = await open(directory, DIRECTORY_READ_FLAGS);
  try {
    await directoryHandle.sync();
  } finally {
    await directoryHandle.close();
  }
}

async function readDiscoveryRecord(
  recordPath: string,
  directory: string,
  expectedPid: number,
  expectedInstanceId: string
): Promise<ConfigurationAdminDiscoveryRecord> {
  const before = await lstat(recordPath);
  verifyOwnedRegularFile(before);
  const file = await open(recordPath, FILE_READ_FLAGS);
  let raw: string;
  try {
    const opened = await file.stat();
    verifyOwnedRegularFile(opened);
    if (opened.dev !== before.dev || opened.ino !== before.ino) {
      throw new ConfigurationAdminIpcError("DISCOVERY_RECORD_CHANGED", "pre-dispatch", "An administrative discovery record changed while it was read.");
    }
    raw = await file.readFile("utf8");
  } finally {
    await file.close();
  }

  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new ConfigurationAdminIpcError("INVALID_DISCOVERY_RECORD", "pre-dispatch", "An administrative discovery record is invalid.");
  }
  if (!isRecord(value)
    || value.protocol_version !== CONFIGURATION_ADMIN_PROTOCOL_VERSION
    || value.server_pid !== expectedPid
    || value.instance_id !== expectedInstanceId
    || value.endpoint !== join(directory, `instance-${expectedInstanceId}.sock`)
    || Object.keys(value).some((key) => !["protocol_version", "server_pid", "instance_id", "endpoint"].includes(key))) {
    throw new ConfigurationAdminIpcError("INVALID_DISCOVERY_RECORD", "pre-dispatch", "An administrative discovery record is invalid.");
  }

  const after = await lstat(recordPath);
  verifyOwnedRegularFile(after);
  if (after.dev !== before.dev || after.ino !== before.ino) {
    throw new ConfigurationAdminIpcError("DISCOVERY_RECORD_CHANGED", "pre-dispatch", "An administrative discovery record changed while it was read.");
  }

  return Object.freeze({
    protocol_version: CONFIGURATION_ADMIN_PROTOCOL_VERSION,
    server_pid: expectedPid,
    instance_id: expectedInstanceId,
    endpoint: value.endpoint
  });
}

async function removeDiscoveryRecord(
  recordPath: string,
  expected: ConfigurationAdminDiscoveryRecord
): Promise<void> {
  let file;
  try {
    file = await open(recordPath, FILE_READ_FLAGS);
  } catch (error) {
    if (isNotFound(error)) return;
    throw error;
  }
  let info: Stats;
  let value: unknown;
  try {
    info = await file.stat();
    verifyOwnedRegularFile(info);
    value = JSON.parse(await file.readFile("utf8"));
  } finally {
    await file.close();
  }
  if (!isRecord(value)
    || value.server_pid !== expected.server_pid
    || value.instance_id !== expected.instance_id
    || value.endpoint !== expected.endpoint) return;
  const current = await lstat(recordPath);
  verifyOwnedRegularFile(current);
  if (current.dev === info.dev && current.ino === info.ino) await unlink(recordPath);
}

async function unlinkSocketIfSame(
  endpointPath: string,
  expected: { dev: number; ino: number }
): Promise<void> {
  let current;
  try {
    current = await lstat(endpointPath);
  } catch (error) {
    if (isNotFound(error)) return;
    throw error;
  }
  verifyOwnedSocket(current, endpointPath);
  if (current.dev === expected.dev && current.ino === expected.ino) await unlink(endpointPath);
}

async function verifyPrivateDirectory(directory: string): Promise<void> {
  if (!isAbsolute(directory) || directory.includes("\u0000")) {
    throw new ConfigurationAdminIpcError("UNSAFE_DISCOVERY_DIRECTORY", "pre-dispatch", "The administrative discovery directory is unsafe.");
  }
  let info;
  try {
    info = await lstat(directory);
  } catch (error) {
    throw asIpcError(error, "UNSAFE_DISCOVERY_DIRECTORY", "pre-dispatch", "The administrative discovery directory is unavailable.");
  }
  const uid = process.getuid?.();
  if (!info.isDirectory() || info.isSymbolicLink() || uid === undefined || info.uid !== uid
    || (info.mode & 0o077) !== 0 || (info.mode & PRIVATE_DIRECTORY_MODE) !== PRIVATE_DIRECTORY_MODE) {
    throw new ConfigurationAdminIpcError("UNSAFE_DISCOVERY_DIRECTORY", "pre-dispatch", "The administrative discovery directory must be an owner-only directory.");
  }
}

function verifyOwnedRegularFile(info: Stats): void {
  const uid = process.getuid?.();
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || uid === undefined
    || info.uid !== uid || (info.mode & 0o077) !== 0 || (info.mode & 0o600) !== 0o600) {
    throw new ConfigurationAdminIpcError("UNSAFE_DISCOVERY_RECORD", "pre-dispatch", "An administrative discovery record is not owner-protected.");
  }
}

function verifyOwnedSocket(info: Stats, endpointPath: string): void {
  const uid = process.getuid?.();
  if (!info.isSocket() || info.isSymbolicLink() || uid === undefined || info.uid !== uid
    || (info.mode & 0o777) !== SOCKET_MODE || !isAbsolute(endpointPath)) {
    throw new ConfigurationAdminIpcError("UNSAFE_ENDPOINT", "pre-dispatch", "The administrative endpoint is not an owner-only local socket.");
  }
}

function validateRecord(record: ConfigurationAdminDiscoveryRecord): void {
  if (record.protocol_version !== CONFIGURATION_ADMIN_PROTOCOL_VERSION
    || !Number.isSafeInteger(record.server_pid) || record.server_pid <= 0
    || !isUuid(record.instance_id) || !isAbsolute(record.endpoint)
    || record.endpoint !== join(dirname(record.endpoint), `instance-${record.instance_id}.sock`)) {
    throw new ConfigurationAdminIpcError("INVALID_DISCOVERY_RECORD", "pre-dispatch", "The administrative discovery record is invalid.");
  }
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNotFound(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function asIpcError(error: unknown, code: string, phase: "pre-dispatch" | "indeterminate", message: string): ConfigurationAdminIpcError {
  return error instanceof ConfigurationAdminIpcError
    ? error
    : new ConfigurationAdminIpcError(code, phase, message);
}

async function listen(server: Server, path: string): Promise<void> {
  await new Promise<void>((resolveListen, rejectListen) => {
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      rejectListen(error);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolveListen();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(path);
  });
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
}
