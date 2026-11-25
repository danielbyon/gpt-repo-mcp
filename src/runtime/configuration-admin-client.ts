import { randomUUID } from "node:crypto";
import {
  configurationSourcesMatch,
  type ConfigurationSourceIdentity
} from "../config/config-source-identity.js";
import {
  responseMatchesReloadEndpoint,
  responseMatchesReloadRequest,
  type ConfigurationAdminProbeResponse,
  type ConfigurationAdminReloadRequest,
  type ConfigurationAdminReloadResponse
} from "./configuration-admin-protocol.js";
import { readConfigurationAdminRecords, sendConfigurationAdminRequest } from "./configuration-admin-host.js";
import { ConfigurationAdminIpcError } from "./configuration-admin-error.js";

export type ConfigurationAdminDiscoveryRecord = Readonly<{
  protocol_version: 1;
  server_pid: number;
  helper_pid?: number;
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
    probe: async (record) => {
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

  const matching = live.filter((entry) => configurationSourcesMatch(
    options.selectedSourceIdentity,
    entry.result.source_identity
  ));

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
