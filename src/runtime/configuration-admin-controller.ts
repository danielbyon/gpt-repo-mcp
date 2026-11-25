import { configurationSourcesMatch, type ConfigurationSourceIdentity } from "../config/config-source-identity.js";
import type { ConfigurationRevisionState } from "../services/configuration-revision-store.js";
import {
  parseAdminRequest,
  parseAdminResponse,
  type ConfigurationAdminResponse
} from "./configuration-admin-protocol.js";

type AdminRevisionState = Readonly<{
  acceptedCandidate: Pick<ConfigurationRevisionState["acceptedCandidate"], "sourceSha256">;
  effectiveHotRevision: Pick<ConfigurationRevisionState["effectiveHotRevision"], "generation">;
  pendingRestart?: ConfigurationRevisionState["pendingRestart"];
}>;

type AdminRevisionStore = Readonly<{
  getState: () => AdminRevisionState;
  reloadFromFile: () => Promise<AdminRevisionState>;
}>;

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

    try {
      const completedState = await options.revisionStore.reloadFromFile();
      return parseAdminResponse({
        ...responseIdentity(request.request_id),
        operation: "reload_result",
        outcome: "published",
        effective_generation: completedState.effectiveHotRevision.generation,
        accepted_source_sha256: completedState.acceptedCandidate.sourceSha256,
        pending_restart: completedState.pendingRestart !== undefined
      });
    } catch {
      return rejection(request.request_id, "CANDIDATE_REJECTED", "The configuration candidate was rejected.");
    }
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
