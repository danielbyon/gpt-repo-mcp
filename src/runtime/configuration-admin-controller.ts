import { configurationSourcesMatch, type ConfigurationSourceIdentity } from "../config/config-source-identity.js";
import { isDeepStrictEqual } from "node:util";
import type {
  ConfigurationRevisionState,
  ConfigurationRevisionStore,
  RestartSettings,
  SavedSourceObservation
} from "../services/configuration-revision-store.js";
import {
  parseAdminRequest,
  parseAdminResponse,
  type ConfigurationAdminResponse
} from "./configuration-admin-protocol.js";

type AdminRevisionState = ConfigurationRevisionState;
type AdminRevisionStore = Pick<ConfigurationRevisionStore, "getState" | "captureStatus" | "reloadFromFile">;

/** Binds requests to one server process and its selected configuration path. */
export function createConfigurationAdminController(options: {
  serverPid: number;
  helperPid?: number | (() => number | undefined);
  instanceId: string;
  sourceIdentity: ConfigurationSourceIdentity;
  revisionStore: AdminRevisionStore;
  isShuttingDown?: () => boolean;
}): Readonly<{ handle: (value: unknown) => Promise<ConfigurationAdminResponse> }> {
  const retainedIdentity = Object.freeze({ ...options.sourceIdentity });

  async function handle(value: unknown): Promise<ConfigurationAdminResponse> {
    const request = parseAdminRequest(value);
    if (request.operation === "probe") {
      return parseAdminResponse({
        ...responseIdentity(request.request_id),
        operation: "probe_result",
        ...stateFields(options.revisionStore.getState())
      });
    }

    if (request.operation === "status") {
      if (request.expected_server_pid !== options.serverPid
        || request.expected_instance_id !== options.instanceId
        || !statusSourceIdentityMatches(request.expected_source_identity, retainedIdentity)) {
        throw new Error("The selected server identity no longer matches.");
      }
      if (options.isShuttingDown?.()) {
        throw new Error("The server is shutting down.");
      }

      const snapshot = await options.revisionStore.captureStatus();
      const state = snapshot.state;
      return parseAdminResponse({
        ...responseIdentity(request.request_id),
        operation: "status_result",
        accepted_candidate: {
          source_status: retainedIdentity.status,
          ...(retainedIdentity.status === "available"
            ? { source_sha256: state.acceptedCandidate.sourceSha256 }
            : {}),
          repository_count: state.acceptedCandidate.registry.list().length,
          restart_fields: settingNames(state.acceptedCandidate.restartSettings)
        },
        saved_source: savedSourceFields(snapshot.savedSource),
        active_hot_revision: {
          generation: state.effectiveHotRevision.generation,
          repository_count: state.effectiveHotRevision.runtimeContext.registry.list().length
        },
        initialized_restart_fields: settingNames(state.initializedRestartSettings),
        pending_restart_fields: pendingRestartFieldNames(state),
        last_reload_outcome: state.lastReloadOutcome
      });
    }

    if (retainedIdentity.status !== "available") {
      return rejection(request.request_id, "SOURCE_UNAVAILABLE", "This server has no comparable configuration source.");
    }

    if (request.expected_server_pid !== options.serverPid
      || request.expected_instance_id !== options.instanceId
      || !configurationSourcesMatch(request.expected_source_identity, retainedIdentity)) {
      return rejection(request.request_id, "IDENTITY_MISMATCH", "The selected server identity no longer matches.");
    }

    if (options.isShuttingDown?.()) {
      return rejection(request.request_id, "SHUTTING_DOWN", "The server is shutting down.");
    }

    let completedState: AdminRevisionState;
    try {
      completedState = await options.revisionStore.reloadFromFile();
    } catch {
      return rejection(request.request_id, "CANDIDATE_REJECTED", "The configuration candidate was rejected.");
    }

    return parseAdminResponse({
      ...responseIdentity(request.request_id),
      operation: "reload_result",
      outcome: "published",
      effective_generation: completedState.effectiveHotRevision.generation,
      accepted_source_sha256: completedState.acceptedCandidate.sourceSha256,
      pending_restart: completedState.pendingRestart !== undefined
    });
  }

  function rejection(
    requestId: string,
    rejectionCode: "IDENTITY_MISMATCH" | "SOURCE_UNAVAILABLE" | "SHUTTING_DOWN" | "CANDIDATE_REJECTED",
    message: string
  ): ConfigurationAdminResponse {
    const activeState = options.revisionStore.getState();
    return parseAdminResponse({
      ...responseIdentity(requestId),
      operation: "reload_result",
      outcome: "rejected",
      rejection_code: rejectionCode,
      rejection_message: message,
      active_effective_generation: activeState.effectiveHotRevision.generation,
      active_source_sha256: activeState.acceptedCandidate.sourceSha256,
      pending_restart: activeState.pendingRestart !== undefined
    });
  }

  function responseIdentity(requestId: string) {
    const helperPid = typeof options.helperPid === "function" ? options.helperPid() : options.helperPid;
    return {
      protocol_version: 1,
      request_id: requestId,
      server_pid: options.serverPid,
      ...(helperPid === undefined ? {} : { helper_pid: helperPid }),
      instance_id: options.instanceId,
      source_identity: retainedIdentity
    };
  }

  return Object.freeze({ handle });
}

function stateFields(state: AdminRevisionState) {
  return {
    effective_generation: state.effectiveHotRevision.generation,
    accepted_source_sha256: state.acceptedCandidate.sourceSha256,
    pending_restart: state.pendingRestart !== undefined
  };
}

function statusSourceIdentityMatches(
  expected: { status: "none" } | Extract<ConfigurationSourceIdentity, { status: "available" }>,
  actual: ConfigurationSourceIdentity
): boolean {
  if (expected.status === "none") return actual.status === "none";
  return configurationSourcesMatch(expected, actual);
}

function settingNames(settings: RestartSettings | undefined): string[] {
  return Object.keys(settings ?? {}).sort();
}

function pendingRestartFieldNames(state: AdminRevisionState): string[] {
  const initialized = state.pendingRestart?.initialized;
  const accepted = state.pendingRestart?.accepted;
  const fieldNames = new Set<keyof RestartSettings>([
    ...Object.keys(initialized ?? {}) as (keyof RestartSettings)[],
    ...Object.keys(accepted ?? {}) as (keyof RestartSettings)[]
  ]);
  return [...fieldNames]
    .filter((name) => !isDeepStrictEqual(initialized?.[name], accepted?.[name]))
    .sort();
}

function savedSourceFields(observation: SavedSourceObservation) {
  switch (observation.status) {
    case "no-source":
      return { status: observation.status };
    case "read-failed":
      return { status: observation.status, code: observation.code };
    case "invalid-json":
      return { status: observation.status, source_sha256: observation.sourceSha256 };
    case "validation-failed":
      return {
        status: observation.status,
        category: observation.category,
        source_sha256: observation.sourceSha256,
        issue_codes: observation.issueCodes,
        issue_codes_truncated: observation.issueCodesTruncated
      };
    case "valid":
      return {
        status: observation.status,
        source_sha256: observation.sourceSha256,
        matches_accepted: observation.matchesAccepted,
        repository_count: observation.repositoryCount,
        restart_fields: observation.restartFields
      };
  }
}
