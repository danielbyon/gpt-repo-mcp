import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";
import { isNotFoundError } from "../runtime/fs-helpers.js";
import type { CodeIntelligenceService } from "./code-intelligence-service.js";
import {
  ConfigurationPreparationError,
  RootRegistry,
  type DeepReadonly,
  type PreparedRootConfiguration,
  type RepoReaderConfig
} from "./root-registry.js";
import type { RuntimeContext } from "../runtime/context.js";

const MAX_STATUS_ISSUE_CODES = 16;
const SAFE_ISSUE_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;

export type RestartSettings = DeepReadonly<NonNullable<RepoReaderConfig["code_intelligence"]>>;

export type ConfigurationCandidate = Readonly<{
  sourceSha256: string;
  registry: RootRegistry;
  restartSettings?: RestartSettings;
}>;

export type EffectiveHotRevision = Readonly<{
  generation: number;
  runtimeContext: RuntimeContext;
}>;

export type PendingRestart = Readonly<{
  initialized?: RestartSettings;
  accepted?: RestartSettings;
}>;

export type ConfigurationRevisionState = Readonly<{
  acceptedCandidate: ConfigurationCandidate;
  initializedRestartSettings?: RestartSettings;
  effectiveHotRevision: EffectiveHotRevision;
  pendingRestart?: PendingRestart;
  lastReloadOutcome: "not-run" | "accepted" | "rejected";
}>;

export type SavedSourceObservation =
  | Readonly<{ status: "no-source" }>
  | Readonly<{ status: "read-failed"; code: "FILE_NOT_FOUND" | "FILE_READ_FAILED" }>
  | Readonly<{ status: "invalid-json"; sourceSha256: string }>
  | Readonly<{
      status: "validation-failed";
      category: "configuration" | "repository-filesystem" | "mixed";
      sourceSha256: string;
      issueCodes: readonly string[];
      issueCodesTruncated: boolean;
    }>
  | Readonly<{
      status: "valid";
      sourceSha256: string;
      matchesAccepted: boolean;
      repositoryCount: number;
      restartFields: readonly string[];
    }>;

export type ConfigurationRevisionStatusSnapshot = Readonly<{
  state: ConfigurationRevisionState;
  savedSource: SavedSourceObservation;
}>;

type CandidateReader = (configPath: string) => Promise<Uint8Array>;
type CandidatePreparer = (bytes: Uint8Array, configPath: string) => Promise<ConfigurationCandidate>;

export type ConfigurationRevisionStoreOptions = Readonly<{
  configPath?: string;
  initial: ConfigurationCandidate;
  codeIntelligence?: CodeIntelligenceService;
  readCandidateBytes?: CandidateReader;
  prepareCandidate?: CandidatePreparer;
}>;

/** Parses and validates the same owned bytes whose digest identifies a candidate. */
export async function prepareConfigurationCandidate(
  bytes: Uint8Array,
  configPath: string
): Promise<ConfigurationCandidate> {
  const ownedBytes = Buffer.from(bytes);
  const sourceSha256 = createHash("sha256").update(ownedBytes).digest("hex");
  const prepared: PreparedRootConfiguration = await RootRegistry.prepareFromBuffer(ownedBytes, configPath);
  return Object.freeze({
    sourceSha256,
    registry: prepared.registry,
    ...(prepared.codeIntelligence ? { restartSettings: prepared.codeIntelligence } : {})
  });
}

/** Publishes fully validated configuration candidates as immutable revisions. */
export class ConfigurationRevisionStore {
  private readonly configPath: string | undefined;
  private readonly readCandidateBytes: CandidateReader;
  private readonly prepareCandidate: CandidatePreparer;
  private readonly codeIntelligence: CodeIntelligenceService | undefined;
  private readonly initializedRestartSettings: RestartSettings | undefined;
  private state: ConfigurationRevisionState;
  private reloadTail: Promise<void> = Promise.resolve();

  constructor(options: ConfigurationRevisionStoreOptions) {
    this.configPath = options.configPath;
    this.readCandidateBytes = options.readCandidateBytes ?? ((path) => readFile(path));
    this.prepareCandidate = options.prepareCandidate ?? prepareConfigurationCandidate;
    this.codeIntelligence = options.codeIntelligence;
    const initialCandidate = freezeCandidate(options.initial);
    this.initializedRestartSettings = initialCandidate.restartSettings;

    const effectiveHotRevision = createEffectiveRevision(1, initialCandidate.registry, this.codeIntelligence);
    this.state = freezeState({
      acceptedCandidate: initialCandidate,
      initializedRestartSettings: this.initializedRestartSettings,
      effectiveHotRevision,
      pendingRestart: pendingRestart(this.initializedRestartSettings, initialCandidate.restartSettings),
      lastReloadOutcome: "not-run"
    });
  }

  capture(): EffectiveHotRevision {
    return this.state.effectiveHotRevision;
  }

  getState(): ConfigurationRevisionState {
    return this.state;
  }

  /** Captures runtime state once, then reads the saved file separately without waiting behind reloads. */
  async captureStatus(): Promise<ConfigurationRevisionStatusSnapshot> {
    const state = this.state;
    const savedSource = await this.observeSavedSource(state);
    return Object.freeze({ state, savedSource });
  }

  /** Queues the complete read, validation, and publication operation in call order. */
  reloadFromFile(): Promise<ConfigurationRevisionState> {
    const configPath = this.configPath;
    if (configPath === undefined) {
      return Promise.reject(new Error("Configuration reload is unavailable without a config file."));
    }

    const reload = async (): Promise<ConfigurationRevisionState> => {
      try {
        return await this.reloadCandidate(configPath);
      } catch (error) {
        this.state = freezeState({ ...this.state, lastReloadOutcome: "rejected" });
        throw error;
      }
    };
    const operation = this.reloadTail.then(reload, reload);
    this.reloadTail = operation.then(() => undefined, () => undefined);
    return operation;
  }

  private async reloadCandidate(configPath: string): Promise<ConfigurationRevisionState> {
    const bytes = Buffer.from(await this.readCandidateBytes(configPath));
    const candidate = freezeCandidate(await this.prepareCandidate(bytes, configPath));
    const current = this.state;
    const sameHotConfiguration = current.effectiveHotRevision.runtimeContext.registry.hasSameHotConfiguration(candidate.registry);
    const effectiveHotRevision = sameHotConfiguration
      ? current.effectiveHotRevision
      : createEffectiveRevision(
          current.effectiveHotRevision.generation + 1,
          candidate.registry,
          this.codeIntelligence
        );

    const next = freezeState({
      acceptedCandidate: candidate,
      initializedRestartSettings: this.initializedRestartSettings,
      effectiveHotRevision,
      pendingRestart: pendingRestart(this.initializedRestartSettings, candidate.restartSettings),
      lastReloadOutcome: "accepted"
    });
    this.state = next;
    return next;
  }

  private async observeSavedSource(state: ConfigurationRevisionState): Promise<SavedSourceObservation> {
    const configPath = this.configPath;
    if (configPath === undefined) return Object.freeze({ status: "no-source" });

    let bytes: Buffer;
    try {
      bytes = Buffer.from(await this.readCandidateBytes(configPath));
    } catch (error) {
      return Object.freeze({
        status: "read-failed",
        code: isNotFoundError(error) ? "FILE_NOT_FOUND" : "FILE_READ_FAILED"
      });
    }

    const sourceSha256 = createHash("sha256").update(bytes).digest("hex");
    try {
      const candidate = freezeCandidate(await this.prepareCandidate(bytes, configPath));
      return Object.freeze({
        status: "valid",
        sourceSha256,
        matchesAccepted: sourceSha256 === state.acceptedCandidate.sourceSha256,
        repositoryCount: candidate.registry.list().length,
        restartFields: settingNames(candidate.restartSettings)
      });
    } catch (error) {
      if (error instanceof ConfigurationPreparationError && error.category === "json") {
        return Object.freeze({ status: "invalid-json", sourceSha256 });
      }

      const category = error instanceof ConfigurationPreparationError
        ? error.category === "repository-filesystem" || error.category === "mixed"
          ? error.category
          : "configuration"
        : "configuration";
      const codes = error instanceof ConfigurationPreparationError
        ? error.issueCodes
        : ["CONFIGURATION_PREPARATION_FAILED"];
      const uniqueCodes = [...new Set(codes.filter((code) => SAFE_ISSUE_CODE_PATTERN.test(code)))];
      const issueCodes = Object.freeze(uniqueCodes.slice(0, MAX_STATUS_ISSUE_CODES));
      return Object.freeze({
        status: "validation-failed",
        category,
        sourceSha256,
        issueCodes,
        issueCodesTruncated: uniqueCodes.length > issueCodes.length
      });
    }
  }
}

function createEffectiveRevision(
  generation: number,
  registry: RootRegistry,
  codeIntelligence: CodeIntelligenceService | undefined
): EffectiveHotRevision {
  const runtimeContext: RuntimeContext = Object.freeze({
    registry,
    ...(codeIntelligence ? { codeIntelligence } : {})
  });
  return Object.freeze({ generation, runtimeContext });
}

function pendingRestart(
  initialized: RestartSettings | undefined,
  accepted: RestartSettings | undefined
): PendingRestart | undefined {
  if (isDeepStrictEqual(initialized, accepted)) return undefined;
  return Object.freeze({
    ...(initialized ? { initialized } : {}),
    ...(accepted ? { accepted } : {})
  });
}

function settingNames(settings: RestartSettings | undefined): readonly string[] {
  return Object.freeze(Object.keys(settings ?? {}).sort());
}

function freezeState(state: ConfigurationRevisionState): ConfigurationRevisionState {
  return Object.freeze(state);
}

function freezeCandidate(candidate: ConfigurationCandidate): ConfigurationCandidate {
  return Object.freeze({
    sourceSha256: candidate.sourceSha256,
    registry: candidate.registry,
    ...(candidate.restartSettings
      ? { restartSettings: Object.freeze({ ...candidate.restartSettings }) }
      : {})
  });
}
