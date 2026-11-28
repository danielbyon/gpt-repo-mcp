import { readFile } from "node:fs/promises";
import { realpath } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import { DEFAULT_LIMITS } from "../policies/limits.js";
import { RepoReaderError } from "../runtime/errors.js";
import { RepoReaderConfigSchema, type RepoReaderConfig as CanonicalRepoReaderConfig } from "../config/schema.js";
import { validateConfigDocument } from "../config/validation.js";

/** Makes nested configuration values read-only for every published registry. */
export type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer U)[]
    ? readonly DeepReadonly<U>[]
    : T extends object
      ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
      : T;

export type RepoConfig = DeepReadonly<CanonicalRepoReaderConfig["repos"][number]>;
export type RepoReaderConfig = z.output<typeof RepoReaderConfigSchema>;
type RepoReaderConfigInput = z.input<typeof RepoReaderConfigSchema>;

export type PreparedRootConfiguration = Readonly<{
  registry: RootRegistry;
  codeIntelligence?: DeepReadonly<NonNullable<RepoReaderConfig["code_intelligence"]>>;
}>;

export type ConfigurationPreparationCategory = "json" | "configuration" | "repository-filesystem" | "mixed";

/** Carries safe failure categories from the canonical configuration preparation path. */
export class ConfigurationPreparationError extends Error {
  readonly issueCodes: readonly string[];

  constructor(
    readonly category: ConfigurationPreparationCategory,
    issueCodes: readonly string[],
    message: string
  ) {
    super(message);
    this.name = "ConfigurationPreparationError";
    this.issueCodes = Object.freeze([...new Set(issueCodes)]);
  }
}

export class RootRegistry {
  private constructor(
    private readonly repos: readonly RepoConfig[],
    readonly limits: DeepReadonly<Required<RepoReaderConfig["limits"]>>
  ) {
    Object.freeze(this);
  }

  static async fromConfig(config: RepoReaderConfigInput): Promise<RootRegistry> {
    const parsed = RepoReaderConfigSchema.parse(config);
    return RootRegistry.create(parsed);
  }

  /** Validates one file buffer before building the immutable registry it describes. */
  static async prepareFromBuffer(raw: Uint8Array, configPath: string): Promise<PreparedRootConfiguration> {
    let document: unknown;
    try {
      document = JSON.parse(Buffer.from(raw).toString("utf8"));
    } catch {
      throw new ConfigurationPreparationError("json", [], `Invalid repository config at ${configPath}: JSON parsing failed.`);
    }

    let validation: Awaited<ReturnType<typeof validateConfigDocument>>;
    try {
      validation = await validateConfigDocument(document);
    } catch (error) {
      const repositoryFilesystemFailure = isFilesystemError(error);
      throw new ConfigurationPreparationError(
        repositoryFilesystemFailure ? "repository-filesystem" : "configuration",
        [repositoryFilesystemFailure ? "REPOSITORY_FILESYSTEM_VALIDATION_FAILED" : "CONFIGURATION_VALIDATION_FAILED"],
        `Invalid repository config at ${configPath}: ${repositoryFilesystemFailure
          ? "repository filesystem validation failed."
          : "configuration validation failed."}`
      );
    }
    if (validation.issues.length > 0 || !validation.config) {
      const details = validation.issues.map(({ code, message }) => `${code}: ${message}`).join("; ");
      const issueCodes = validation.issues.map(({ code }) => code);
      const hasRepositoryFilesystemIssue = issueCodes.some((code) =>
        code === "ROOT_MISSING" || code === "ROOT_NOT_DIRECTORY" || code === "NOT_GIT_REPO"
      );
      const hasConfigurationIssue = issueCodes.some((code) =>
        code !== "ROOT_MISSING" && code !== "ROOT_NOT_DIRECTORY" && code !== "NOT_GIT_REPO"
      ) || issueCodes.length === 0;
      const category: ConfigurationPreparationCategory = hasRepositoryFilesystemIssue && hasConfigurationIssue
        ? "mixed"
        : hasRepositoryFilesystemIssue
          ? "repository-filesystem"
          : "configuration";
      throw new ConfigurationPreparationError(
        category,
        issueCodes.length > 0 ? issueCodes : ["CONFIGURATION_VALIDATION_FAILED"],
        `Invalid repository config at ${configPath}: ${details || "no parsed config was returned"}`
      );
    }

    const parsed = RepoReaderConfigSchema.parse(validation.config);
    let registry: RootRegistry;
    try {
      registry = await RootRegistry.create(parsed);
    } catch (error) {
      const repositoryFilesystemFailure = isFilesystemError(error);
      throw new ConfigurationPreparationError(
        repositoryFilesystemFailure ? "repository-filesystem" : "configuration",
        [repositoryFilesystemFailure ? "ROOT_CANONICALIZATION_FAILED" : "CONFIGURATION_PREPARATION_FAILED"],
        `Invalid repository config at ${configPath}: ${repositoryFilesystemFailure
          ? "repository filesystem validation failed."
          : "configuration preparation failed."}`
      );
    }
    return Object.freeze({
      registry,
      ...(parsed.code_intelligence
        ? { codeIntelligence: deepFreeze(parsed.code_intelligence) }
        : {})
    });
  }

  /** Reads and validates a config file without treating a missing file as empty. */
  static async fromFile(configPath: string): Promise<RootRegistry> {
    return (await RootRegistry.prepareFromBuffer(await readFile(configPath), configPath)).registry;
  }

  list(): Array<Pick<RepoConfig, "repo_id" | "display_name" | "root">> {
    return this.repos.map((repo) => ({
      repo_id: repo.repo_id,
      display_name: repo.display_name,
      root: repo.root
    }));
  }

  get(repoId: string): RepoConfig {
    const repo = this.repos.find((candidate) => candidate.repo_id === repoId);
    if (!repo) {
      throw new RepoReaderError("UNKNOWN_REPO", `Unknown repo_id: ${repoId}`);
    }
    return repo;
  }

  hasSameHotConfiguration(other: RootRegistry): boolean {
    return isDeepStrictEqual(this.repos, other.repos) && isDeepStrictEqual(this.limits, other.limits);
  }

  private static async create(config: RepoReaderConfig): Promise<RootRegistry> {
    const repos: RepoConfig[] = [];
    for (const repo of config.repos) {
      repos.push(deepFreeze({ ...repo, root: await realpath(repo.root) }));
    }
    const limits: Required<RepoReaderConfig["limits"]> = { ...DEFAULT_LIMITS, ...config.limits };
    return new RootRegistry(deepFreeze(repos), deepFreeze(limits));
  }
}

function deepFreeze<T>(value: T): DeepReadonly<T> {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const key of Reflect.ownKeys(value)) {
      deepFreeze((value as Record<PropertyKey, unknown>)[key]);
    }
    Object.freeze(value);
  }
  return value as DeepReadonly<T>;
}

function isFilesystemError(error: unknown): boolean {
  if (typeof error !== "object" || error === null || !("code" in error)) return false;
  const code = (error as NodeJS.ErrnoException).code;
  return typeof code === "string" && /^(?:EACCES|EIO|EISDIR|ELOOP|EMFILE|ENAMETOOLONG|ENFILE|ENOENT|ENOTDIR|ENOSPC|EPERM|EROFS)$/.test(code);
}
