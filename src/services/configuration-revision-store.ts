import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";
import type { CodeIntelligenceService } from "./code-intelligence-service.js";
import { RootRegistry, type DeepReadonly, type PreparedRootConfiguration, type RepoReaderConfig } from "./root-registry.js";
import type { RuntimeContext } from "../runtime/context.js";

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
      pendingRestart: pendingRestart(this.initializedRestartSettings, initialCandidate.restartSettings)
    });
  }

  capture(): EffectiveHotRevision {
    return this.state.effectiveHotRevision;
  }

  getState(): ConfigurationRevisionState {
    return this.state;
  }

  /** Queues the complete read, validation, and publication operation in call order. */
  reloadFromFile(): Promise<ConfigurationRevisionState> {
    const configPath = this.configPath;
    if (configPath === undefined) {
      return Promise.reject(new Error("Configuration reload is unavailable without a config file."));
    }

    const reload = (): Promise<ConfigurationRevisionState> => this.reloadCandidate(configPath);
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
      pendingRestart: pendingRestart(this.initializedRestartSettings, candidate.restartSettings)
    });
    this.state = next;
    return next;
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
