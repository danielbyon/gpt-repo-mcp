import type { CodeIndexAction, CodeIndexEvent, CodeIndexResult, CodeIndexStatus } from "../contracts/code-index.contract.js";
import type { RepoConfig } from "./root-registry.js";
import {
  findCodebaseMemoryProject,
  type CodebaseMemoryClientFactory
} from "./codebase-memory-client.js";

const MAX_EVENTS = 20;

type IndexJob = {
  status: CodeIndexStatus;
  started_at?: string;
  finished_at?: string;
  events: CodeIndexEvent[];
  warnings: string[];
};

type IndexJobScheduler = (job: () => Promise<void>) => void;

type CodebaseMemoryIndexServiceOptions = {
  scheduleJob?: IndexJobScheduler;
};

export class CodebaseMemoryIndexService {
  private readonly jobs = new Map<string, IndexJob>();
  private readonly scheduleJob: IndexJobScheduler;

  constructor(
    private readonly clientFactory: CodebaseMemoryClientFactory,
    private readonly queryTimeoutMs: number,
    private readonly indexTimeoutMs: number,
    options: CodebaseMemoryIndexServiceOptions = {}
  ) {
    this.scheduleJob = options.scheduleJob ?? ((job) => queueMicrotask(() => { void job(); }));
  }

  isRunning(repoRoot: string): boolean {
    const status = this.jobs.get(repoRoot)?.status;
    return status === "queued" || status === "running";
  }

  async index(repo: RepoConfig, action: CodeIndexAction): Promise<CodeIndexResult> {
    return action === "start" ? this.start(repo) : this.status(repo);
  }

  private async start({ root, repo_id }: RepoConfig): Promise<CodeIndexResult> {
    const existing = this.jobs.get(root);
    if (existing && (existing.status === "queued" || existing.status === "running")) {
      return result(repo_id, "start", existing);
    }

    const queued = job("queued", "Indexing was queued after explicit user approval.");
    this.jobs.set(root, queued);

    // A failed probe still allows an explicit start to attempt indexing.
    if (await this.hasProject(root).catch(() => false)) {
      updateJob(queued, "ready", "The repository already has a Codebase Memory index.");
      queued.finished_at = new Date().toISOString();
    } else {
      try {
        this.scheduleJob(() => this.run(root, queued));
      } catch (error) {
        failJob(queued);
        throw error;
      }
    }
    return result(repo_id, "start", queued);
  }

  private async status({ root, repo_id }: RepoConfig): Promise<CodeIndexResult> {
    const existing = this.jobs.get(root);
    if (existing) return result(repo_id, "status", existing);

    try {
      const state = await this.hasProject(root) ? "ready" : "index_required";
      return result(repo_id, "status", job(state, state === "ready"
        ? "The Codebase Memory index is ready."
        : "The repository has not been indexed."));
    } catch {
      return result(repo_id, "status", job("provider_unavailable", "Codebase Memory is unavailable.", ["CODEBASE_MEMORY_UNAVAILABLE"]));
    }
  }

  private async run(root: string, current: IndexJob): Promise<void> {
    updateJob(current, "running", "Codebase Memory is indexing the approved repository root.");
    current.started_at = new Date().toISOString();

    let next: "ready" | "degraded";
    try {
      const client = await this.clientFactory(root);
      try {
        const response = await client.call("index_repository", {
          repo_path: root,
          mode: "full",
          persistence: false
        }, this.indexTimeoutMs);
        next = validatedIndexStatus(response);
      } finally {
        // A job stays running until the provider closes, even when indexing fails.
        await client.close();
      }
    } catch {
      failJob(current);
      return;
    }

    updateJob(current, next, next === "ready" ? "Codebase Memory indexing completed." : "Indexing completed with degraded coverage.");
    current.finished_at = new Date().toISOString();
  }

  private async hasProject(root: string): Promise<boolean> {
    const client = await this.clientFactory(root);
    try {
      return Boolean(await findCodebaseMemoryProject(client, root, this.queryTimeoutMs));
    } finally {
      try {
        await client.close();
      } catch {
        // A close failure after a probe leaves the lookup result intact.
      }
    }
  }
}

function failJob(state: IndexJob): void {
  state.warnings.push("CODEBASE_MEMORY_INDEX_FAILED");
  updateJob(state, "failed", "Codebase Memory indexing failed.");
  state.finished_at = new Date().toISOString();
}

function validatedIndexStatus(response: Record<string, unknown>): "ready" | "degraded" {
  if (response.status === "degraded") return "degraded";
  if (typeof response.status === "string" && ["indexed", "ready", "completed", "success"].includes(response.status)) return "ready";
  throw new Error("Codebase Memory returned an unknown index status.");
}

function job(status: CodeIndexStatus, message: string, warnings: string[] = []): IndexJob {
  return { status, events: [{ at: new Date().toISOString(), status, message }], warnings };
}

function updateJob(jobState: IndexJob, status: CodeIndexStatus, message: string): void {
  jobState.status = status;
  jobState.events.push({ at: new Date().toISOString(), status, message });
  jobState.events = jobState.events.slice(-MAX_EVENTS);
}

function result(repoId: string, action: CodeIndexAction, state: IndexJob): CodeIndexResult {
  return {
    ok: true,
    repo_id: repoId,
    provider: "codebase_memory",
    action,
    status: state.status,
    ...(state.started_at ? { started_at: state.started_at } : {}),
    ...(state.finished_at ? { finished_at: state.finished_at } : {}),
    events: [...state.events],
    warnings: [...state.warnings]
  };
}
