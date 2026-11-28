import { randomUUID } from "node:crypto";
import {
  configurationSourcesMatch,
  type ConfigurationSourceIdentity
} from "../config/config-source-identity.js";
import {
  responseMatchesReloadEndpoint,
  responseMatchesReloadRequest,
  responseMatchesStatusRequest,
  type ConfigurationAdminProbeResponse,
  type ConfigurationAdminReloadRequest,
  type ConfigurationAdminReloadResponse,
  type ConfigurationAdminStatusRequest,
  type ConfigurationAdminStatusResponse
} from "./configuration-admin-protocol.js";
import { readConfigurationAdminRecords, sendConfigurationAdminRequest } from "./configuration-admin-host.js";
import { ConfigurationAdminIpcError } from "./configuration-admin-error.js";

export type ConfigurationAdminDiscoveryRecord = Readonly<{
  protocol_version: 1;
  server_pid: number;
  helper_pid?: number;
  helper_creation_time?: string;
  instance_id: string;
  endpoint: string;
}>;

export type ConfigurationAdminProbeResult = ConfigurationAdminProbeResponse;

export type ConfigurationAdminTarget = Readonly<{
  record: ConfigurationAdminDiscoveryRecord;
  probe: ConfigurationAdminProbeResult;
}>;

export type ConfigurationAdminTargetErrorCode =
  | "ADMIN_SOURCE_UNAVAILABLE"
  | "INSTANCE_NOT_FOUND"
  | "INSTANCE_UNAVAILABLE"
  | "SOURCE_MISMATCH"
  | "NO_MATCHING_INSTANCE"
  | "AMBIGUOUS_INSTANCE";

export class ConfigurationAdminTargetError extends Error {
  constructor(readonly code: ConfigurationAdminTargetErrorCode, message: string) {
    super(message);
    this.name = "ConfigurationAdminTargetError";
  }
}

/** Probes matching instances and sends one identity-bound reload request. */
export async function reloadConfigurationAdmin(options: {
  selectedSourceIdentity: ConfigurationSourceIdentity;
  instancePid?: number;
}): Promise<ConfigurationAdminReloadResponse> {
  if (options.selectedSourceIdentity.status !== "available") {
    throw new ConfigurationAdminTargetError(
      "ADMIN_SOURCE_UNAVAILABLE",
      "The selected configuration path cannot be compared safely for administrative reload."
    );
  }

  const records = await readConfigurationAdminRecords();
  const target = await selectConfigurationAdminTarget({
    records,
    selectedSourceIdentity: options.selectedSourceIdentity,
    instancePid: options.instancePid,
    probe: probeConfigurationAdminRecord
  });

  const request: ConfigurationAdminReloadRequest = {
    protocol_version: 1,
    request_id: randomUUID(),
    operation: "reload",
    expected_server_pid: target.record.server_pid,
    expected_instance_id: target.record.instance_id,
    expected_source_identity: options.selectedSourceIdentity
  };
  const response = await sendConfigurationAdminRequest(target.record, request);
  if (response.operation !== "reload_result") {
    throw new ConfigurationAdminIpcError(
      "IPC_BAD_RESPONSE",
      "indeterminate",
      "The reload may have run, but the endpoint returned an unrelated response."
    );
  }

  const endpointIdentity = {
    serverPid: target.record.server_pid,
    helperPid: target.record.helper_pid,
    instanceId: target.record.instance_id
  };
  const matchesEndpoint = responseMatchesReloadEndpoint(response, request, endpointIdentity);
  const matchesTarget = responseMatchesReloadRequest(response, request, {
    ...endpointIdentity,
    sourceIdentity: options.selectedSourceIdentity
  });
  if (response.outcome === "published" && !matchesTarget) {
    throw new ConfigurationAdminIpcError(
      "IPC_IDENTITY_CHANGED",
      "indeterminate",
      "The reload may have run, but the responding server identity changed."
    );
  }
  if (response.outcome === "rejected" && (
    !matchesEndpoint || (!matchesTarget && response.rejection_code !== "IDENTITY_MISMATCH")
  )) {
    throw new ConfigurationAdminIpcError(
      "IPC_IDENTITY_CHANGED",
      "indeterminate",
      "The reload may have run, but the responding server identity changed."
    );
  }
  return response;
}

/** Reads one identity-bound status snapshot without changing the selected server. */
export async function statusConfigurationAdmin(options: {
  selectedSourceIdentity: ConfigurationSourceIdentity;
  allowNoSource: boolean;
  instancePid?: number;
}): Promise<ConfigurationAdminStatusResponse> {
  if (options.selectedSourceIdentity.status !== "available") {
    throw new ConfigurationAdminTargetError(
      "ADMIN_SOURCE_UNAVAILABLE",
      "The selected configuration path cannot be compared safely for administrative status."
    );
  }

  const records = await readConfigurationAdminRecords();
  const target = await selectTarget({
    records,
    instancePid: options.instancePid,
    matchesSource: (identity) => configurationSourcesMatch(options.selectedSourceIdentity, identity)
      || (options.allowNoSource && identity.status === "none"),
    probe: probeConfigurationAdminRecord
  });
  const expectedSourceIdentity = target.probe.source_identity;
  if (expectedSourceIdentity.status !== "none" && expectedSourceIdentity.status !== "available") {
    throw new ConfigurationAdminTargetError("NO_MATCHING_INSTANCE", "No reachable server uses an eligible configuration source.");
  }

  const request: ConfigurationAdminStatusRequest = {
    protocol_version: 1,
    request_id: randomUUID(),
    operation: "status",
    expected_server_pid: target.record.server_pid,
    expected_instance_id: target.record.instance_id,
    expected_source_identity: expectedSourceIdentity
  };
  const response = await sendConfigurationAdminRequest(target.record, request);
  if (response.operation !== "status_result") {
    throw new ConfigurationAdminIpcError(
      "IPC_BAD_RESPONSE",
      "pre-dispatch",
      "The endpoint returned an unrelated response to the status request."
    );
  }

  const matchesIdentity = responseMatchesStatusRequest(response, request, {
    serverPid: target.record.server_pid,
    helperPid: target.record.helper_pid,
    instanceId: target.record.instance_id,
    sourceIdentity: expectedSourceIdentity
  });
  if (!matchesIdentity) {
    throw new ConfigurationAdminIpcError(
      "IPC_IDENTITY_CHANGED",
      "pre-dispatch",
      "The responding server identity did not match the selected status target."
    );
  }
  return response;
}

/** Selects a live server only after its endpoint confirms PID, instance, and source identity. */
export async function selectConfigurationAdminTarget(options: {
  records: readonly ConfigurationAdminDiscoveryRecord[];
  selectedSourceIdentity: ConfigurationSourceIdentity;
  instancePid?: number;
  probe: (record: ConfigurationAdminDiscoveryRecord) => Promise<ConfigurationAdminProbeResult>;
}): Promise<ConfigurationAdminTarget> {
  if (options.selectedSourceIdentity.status !== "available") {
    throw new ConfigurationAdminTargetError(
      "ADMIN_SOURCE_UNAVAILABLE",
      "The selected configuration path cannot be compared safely for administrative reload."
    );
  }

  return await selectTarget({
    records: options.records,
    instancePid: options.instancePid,
    probe: options.probe,
    matchesSource: (identity) => configurationSourcesMatch(options.selectedSourceIdentity, identity)
  });
}

/** Selects a verified target for status, optionally including intentional no-source instances. */
export async function selectConfigurationAdminStatusTarget(options: {
  records: readonly ConfigurationAdminDiscoveryRecord[];
  selectedSourceIdentity: ConfigurationSourceIdentity;
  allowNoSource: boolean;
  instancePid?: number;
  probe: (record: ConfigurationAdminDiscoveryRecord) => Promise<ConfigurationAdminProbeResult>;
}): Promise<ConfigurationAdminTarget> {
  if (options.selectedSourceIdentity.status !== "available") {
    throw new ConfigurationAdminTargetError(
      "ADMIN_SOURCE_UNAVAILABLE",
      "The selected configuration path cannot be compared safely for administrative status."
    );
  }

  return await selectTarget({
    records: options.records,
    instancePid: options.instancePid,
    probe: options.probe,
    matchesSource: (identity) => configurationSourcesMatch(options.selectedSourceIdentity, identity)
      || (options.allowNoSource && identity.status === "none")
  });
}

async function selectTarget(options: {
  records: readonly ConfigurationAdminDiscoveryRecord[];
  instancePid?: number;
  probe: (record: ConfigurationAdminDiscoveryRecord) => Promise<ConfigurationAdminProbeResult>;
  matchesSource: (identity: ConfigurationSourceIdentity) => boolean;
}): Promise<ConfigurationAdminTarget> {
  const records = options.records.filter((record) => options.instancePid === undefined || record.server_pid === options.instancePid);
  if (options.instancePid !== undefined && records.length === 0) {
    throw new ConfigurationAdminTargetError("INSTANCE_NOT_FOUND", `No discovered server has PID ${options.instancePid}.`);
  }

  const probed = await Promise.all(records.map(async (record) => {
    try {
      const result = await options.probe(record);
      if (!probeMatchesRecord(record, result)) return { record, result: undefined, error: undefined };
      return { record, result, error: undefined };
    } catch (error) {
      return { record, result: undefined, error };
    }
  }));

  const live = probed.filter((entry): entry is typeof entry & { result: ConfigurationAdminProbeResult } => entry.result !== undefined);
  if (live.length === 0 && options.instancePid !== undefined) {
    const explicitProbeError = probed.length === 1 ? probed[0].error : undefined;
    if (explicitProbeError instanceof ConfigurationAdminIpcError && explicitProbeError.phase === "pre-dispatch") {
      throw explicitProbeError;
    }
    throw new ConfigurationAdminTargetError("INSTANCE_UNAVAILABLE", `Server PID ${options.instancePid} could not be verified at its discovered endpoint.`);
  }

  const matching = live.filter((entry) => options.matchesSource(entry.result.source_identity));

  if (matching.length === 0) {
    if (options.instancePid !== undefined && live.length > 0) {
      throw new ConfigurationAdminTargetError(
        "SOURCE_MISMATCH",
        `Server PID ${options.instancePid} uses a different configuration source.`
      );
    }
    throw new ConfigurationAdminTargetError(
      "NO_MATCHING_INSTANCE",
      "No reachable server uses the selected configuration source."
    );
  }

  if (options.instancePid === undefined && matching.length > 1) {
    throw new ConfigurationAdminTargetError(
      "AMBIGUOUS_INSTANCE",
      "Several reachable servers use the selected configuration source; specify --instance <PID>."
    );
  }

  return { record: matching[0].record, probe: matching[0].result };
}

async function probeConfigurationAdminRecord(
  record: ConfigurationAdminDiscoveryRecord
): Promise<ConfigurationAdminProbeResult> {
  const request = {
    protocol_version: 1 as const,
    request_id: randomUUID(),
    operation: "probe" as const
  };
  const response = await sendConfigurationAdminRequest(record, request);
  if (response.operation !== "probe_result" || response.request_id !== request.request_id) {
    throw new Error("The administrative probe response is invalid.");
  }
  return response;
}

function probeMatchesRecord(
  record: ConfigurationAdminDiscoveryRecord,
  result: ConfigurationAdminProbeResult
): boolean {
  return result.protocol_version === 1
    && result.operation === "probe_result"
    && result.server_pid === record.server_pid
    && result.instance_id === record.instance_id
    && (record.helper_pid === undefined || result.helper_pid === record.helper_pid);
}
