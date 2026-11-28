import { z } from "zod";
import { configurationSourcesMatch, type ConfigurationSourceIdentity } from "../config/config-source-identity.js";

export const CONFIGURATION_ADMIN_PROTOCOL_VERSION = 1;
export const MAX_CONFIGURATION_ADMIN_FRAME_BYTES = 16_384;

const SourceIdentitySchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("none") }).strict(),
  z.object({
    status: z.literal("unavailable"),
    reason: z.enum(["empty-path", "parent-traversal", "unsupported-path"])
  }).strict(),
  z.object({
    status: z.literal("available"),
    platform: z.enum(["posix", "win32"]),
    path: z.string().min(1)
  }).strict()
]);

const AvailableSourceIdentitySchema = z.object({
  status: z.literal("available"),
  platform: z.enum(["posix", "win32"]),
  path: z.string().min(1)
}).strict();

const ProbeRequestSchema = z.object({
  protocol_version: z.literal(CONFIGURATION_ADMIN_PROTOCOL_VERSION),
  request_id: z.string().uuid(),
  operation: z.literal("probe")
}).strict();

const ReloadRequestSchema = z.object({
  protocol_version: z.literal(CONFIGURATION_ADMIN_PROTOCOL_VERSION),
  request_id: z.string().uuid(),
  operation: z.literal("reload"),
  expected_server_pid: z.number().int().positive(),
  expected_instance_id: z.string().uuid(),
  expected_source_identity: AvailableSourceIdentitySchema
}).strict();

const StatusSourceIdentitySchema = z.union([
  z.object({ status: z.literal("none") }).strict(),
  AvailableSourceIdentitySchema
]);

const StatusRequestSchema = z.object({
  protocol_version: z.literal(CONFIGURATION_ADMIN_PROTOCOL_VERSION),
  request_id: z.string().uuid(),
  operation: z.literal("status"),
  expected_server_pid: z.number().int().positive(),
  expected_instance_id: z.string().uuid(),
  expected_source_identity: StatusSourceIdentitySchema
}).strict();

const ResponseIdentitySchema = z.object({
  protocol_version: z.literal(CONFIGURATION_ADMIN_PROTOCOL_VERSION),
  request_id: z.string().uuid(),
  server_pid: z.number().int().positive(),
  helper_pid: z.number().int().positive().optional(),
  instance_id: z.string().uuid(),
  source_identity: SourceIdentitySchema
}).strict();

const StateResponseSchema = ResponseIdentitySchema.extend({
  operation: z.literal("probe_result"),
  effective_generation: z.number().int().nonnegative(),
  accepted_source_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  pending_restart: z.boolean()
}).strict();

const ReloadResponseSchema = z.discriminatedUnion("outcome", [
  ResponseIdentitySchema.extend({
    operation: z.literal("reload_result"),
    outcome: z.literal("published"),
    effective_generation: z.number().int().nonnegative(),
    accepted_source_sha256: z.string().regex(/^[a-f0-9]{64}$/),
    pending_restart: z.boolean()
  }).strict(),
  ResponseIdentitySchema.extend({
    operation: z.literal("reload_result"),
    outcome: z.literal("rejected"),
    rejection_code: z.enum(["IDENTITY_MISMATCH", "SOURCE_UNAVAILABLE", "SHUTTING_DOWN", "CANDIDATE_REJECTED"]),
    rejection_message: z.string().min(1).max(256),
    active_effective_generation: z.number().int().nonnegative(),
    active_source_sha256: z.string().regex(/^[a-f0-9]{64}$/),
    pending_restart: z.boolean()
  }).strict()
]);

const StatusFieldNamesSchema = z.array(z.string().min(1).max(64).regex(/^[a-z][a-z0-9_]*$/)).max(32);
const StatusIssueCodesSchema = z.array(z.string().min(1).max(64).regex(/^[A-Z][A-Z0-9_]*$/)).max(16);
const StatusHashSchema = z.string().regex(/^[a-f0-9]{64}$/);

const SavedSourceStatusSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("no-source") }).strict(),
  z.object({
    status: z.literal("read-failed"),
    code: z.enum(["FILE_NOT_FOUND", "FILE_READ_FAILED"])
  }).strict(),
  z.object({
    status: z.literal("invalid-json"),
    source_sha256: StatusHashSchema
  }).strict(),
  z.object({
    status: z.literal("validation-failed"),
    category: z.enum(["configuration", "repository-filesystem", "mixed"]),
    source_sha256: StatusHashSchema,
    issue_codes: StatusIssueCodesSchema,
    issue_codes_truncated: z.boolean()
  }).strict(),
  z.object({
    status: z.literal("valid"),
    source_sha256: StatusHashSchema,
    matches_accepted: z.boolean(),
    repository_count: z.number().int().nonnegative(),
    restart_fields: StatusFieldNamesSchema
  }).strict()
]);

const StatusResponseSchema = ResponseIdentitySchema.extend({
  operation: z.literal("status_result"),
  accepted_candidate: z.object({
    source_sha256: StatusHashSchema,
    repository_count: z.number().int().nonnegative(),
    restart_fields: StatusFieldNamesSchema
  }).strict(),
  saved_source: SavedSourceStatusSchema,
  active_hot_revision: z.object({
    generation: z.number().int().nonnegative(),
    repository_count: z.number().int().nonnegative()
  }).strict(),
  initialized_restart_fields: StatusFieldNamesSchema,
  pending_restart_fields: StatusFieldNamesSchema,
  last_reload_outcome: z.enum(["not-run", "accepted", "rejected"])
}).strict();

export type ConfigurationAdminRequest = z.infer<
  typeof ProbeRequestSchema | typeof ReloadRequestSchema | typeof StatusRequestSchema
>;
export type ConfigurationAdminResponse = z.infer<
  typeof StateResponseSchema | typeof ReloadResponseSchema | typeof StatusResponseSchema
>;
export type ConfigurationAdminProbeResponse = Extract<ConfigurationAdminResponse, { operation: "probe_result" }>;
export type ConfigurationAdminReloadRequest = Extract<ConfigurationAdminRequest, { operation: "reload" }>;
export type ConfigurationAdminReloadResponse = Extract<ConfigurationAdminResponse, { operation: "reload_result" }>;
export type ConfigurationAdminStatusRequest = Extract<ConfigurationAdminRequest, { operation: "status" }>;
export type ConfigurationAdminStatusResponse = Extract<ConfigurationAdminResponse, { operation: "status_result" }>;

/** Validates a decoded message before any administrative action is considered. */
export function parseAdminRequest(value: unknown): ConfigurationAdminRequest {
  return z.discriminatedUnion("operation", [ProbeRequestSchema, ReloadRequestSchema, StatusRequestSchema]).parse(value);
}

/** Validates response shape and binds it to the request and selected instance. */
export function parseAdminResponse(value: unknown): ConfigurationAdminResponse {
  const response = z.discriminatedUnion("operation", [StateResponseSchema, ReloadResponseSchema, StatusResponseSchema]).parse(value);
  return response;
}

/** Compares the identity reported by a response with the request's target. */
export function responseMatchesReloadRequest(
  response: ConfigurationAdminReloadResponse,
  request: ConfigurationAdminReloadRequest,
  identity: { serverPid: number; helperPid?: number; instanceId: string; sourceIdentity: ConfigurationSourceIdentity }
): boolean {
  return responseMatchesReloadEndpoint(response, request, identity)
    && configurationSourcesMatch(response.source_identity, identity.sourceIdentity);
}

/** Matches the request correlation and process instance while allowing a source-mismatch rejection. */
export function responseMatchesReloadEndpoint(
  response: ConfigurationAdminReloadResponse,
  request: ConfigurationAdminReloadRequest,
  identity: { serverPid: number; helperPid?: number; instanceId: string }
): boolean {
  return response.request_id === request.request_id
    && response.server_pid === identity.serverPid
    && (identity.helperPid === undefined || response.helper_pid === identity.helperPid)
    && response.instance_id === identity.instanceId;
}

/** Matches a status result to the probed process and its exact configuration source. */
export function responseMatchesStatusRequest(
  response: ConfigurationAdminStatusResponse,
  request: ConfigurationAdminStatusRequest,
  identity: { serverPid: number; helperPid?: number; instanceId: string; sourceIdentity: ConfigurationSourceIdentity }
): boolean {
  return request.expected_server_pid === identity.serverPid
    && request.expected_instance_id === identity.instanceId
    && statusSourceIdentityMatches(request.expected_source_identity, identity.sourceIdentity)
    && response.request_id === request.request_id
    && response.server_pid === identity.serverPid
    && (identity.helperPid === undefined || response.helper_pid === identity.helperPid)
    && response.instance_id === identity.instanceId
    && statusSourceIdentityMatches(response.source_identity, request.expected_source_identity)
    && statusSourceIdentityMatches(response.source_identity, identity.sourceIdentity);
}

function statusSourceIdentityMatches(
  left: ConfigurationSourceIdentity,
  right: ConfigurationSourceIdentity
): boolean {
  if (left.status === "none" || right.status === "none") {
    return left.status === "none" && right.status === "none";
  }
  return configurationSourcesMatch(left, right);
}

const FRAME_HEADER_BYTES = 4;
const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

/** Encodes one JSON value as a four-byte length-prefixed UTF-8 frame. */
export function encodeAdminFrame(value: unknown): Buffer {
  const json = JSON.stringify(value);
  if (json === undefined) {
    throw new Error("Administrative IPC message is not JSON serializable.");
  }

  const payload = Buffer.from(json, "utf8");
  if (payload.byteLength === 0 || payload.byteLength > MAX_CONFIGURATION_ADMIN_FRAME_BYTES) {
    throw new Error(`Administrative IPC frame must be 1 to ${MAX_CONFIGURATION_ADMIN_FRAME_BYTES} bytes.`);
  }

  const frame = Buffer.allocUnsafe(FRAME_HEADER_BYTES + payload.byteLength);
  frame.writeUInt32BE(payload.byteLength, 0);
  payload.copy(frame, FRAME_HEADER_BYTES);
  return frame;
}

/** Decodes exactly one complete JSON frame and rejects invalid UTF-8 or trailing bytes. */
export function decodeAdminFrame(frame: Uint8Array): unknown {
  const bytes = Buffer.from(frame.buffer, frame.byteOffset, frame.byteLength);
  if (bytes.byteLength < FRAME_HEADER_BYTES) {
    throw new Error("Administrative IPC frame is missing its length header.");
  }

  const payloadLength = bytes.readUInt32BE(0);
  if (payloadLength === 0 || payloadLength > MAX_CONFIGURATION_ADMIN_FRAME_BYTES) {
    throw new Error(`Administrative IPC frame length must be 1 to ${MAX_CONFIGURATION_ADMIN_FRAME_BYTES} bytes.`);
  }
  if (bytes.byteLength !== FRAME_HEADER_BYTES + payloadLength) {
    throw new Error("Administrative IPC frame length does not match its payload.");
  }

  const json = strictUtf8.decode(bytes.subarray(FRAME_HEADER_BYTES));
  return JSON.parse(json) as unknown;
}
