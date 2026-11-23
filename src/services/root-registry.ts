import { readFile } from "node:fs/promises";
import { realpath } from "node:fs/promises";
import { z } from "zod";
import { DEFAULT_LIMITS } from "../policies/limits.js";
import { RepoReaderError } from "../runtime/errors.js";
import { RepoReaderConfigSchema, type RepoReaderConfig as CanonicalRepoReaderConfig } from "../config/schema.js";
import { validateConfigDocument } from "../config/validation.js";

export type RepoConfig = CanonicalRepoReaderConfig["repos"][number];
export type RepoReaderConfig = z.output<typeof RepoReaderConfigSchema>;
type RepoReaderConfigInput = z.input<typeof RepoReaderConfigSchema>;

export class RootRegistry {
  private constructor(
    private readonly repos: RepoConfig[],
    readonly limits: Required<RepoReaderConfig["limits"]>,
    readonly codeIntelligence: RepoReaderConfig["code_intelligence"]
  ) {}

  static async fromConfig(config: RepoReaderConfigInput): Promise<RootRegistry> {
    const parsed = RepoReaderConfigSchema.parse(config);
    const repos = [];
    for (const repo of parsed.repos) {
      repos.push({ ...repo, root: await realpath(repo.root) });
    }
    const limits: Required<RepoReaderConfig["limits"]> = { ...DEFAULT_LIMITS, ...parsed.limits };
    return new RootRegistry(repos, limits, parsed.code_intelligence);
  }

  /** Validates file configs before their repository roots enter the registry. */
  static async fromFile(configPath: string): Promise<RootRegistry> {
    const raw = await readFile(configPath, "utf8");
    const validation = await validateConfigDocument(JSON.parse(raw));
    if (validation.issues.length > 0 || !validation.config) {
      const details = validation.issues.map(({ code, message }) => `${code}: ${message}`).join("; ");
      throw new Error(`Invalid repository config at ${configPath}: ${details || "no parsed config was returned"}`);
    }
    return RootRegistry.fromConfig(validation.config);
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
}
