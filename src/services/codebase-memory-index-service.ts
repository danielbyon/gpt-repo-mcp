import type { CodeIndexAction, CodeIndexEvent, CodeIndexResult, CodeIndexStatus } from "../contracts/code-index.contract.js";
import type { RepoConfig } from "./root-registry.js";
import { createTaskExecutionBoundaryFromEnvironment, type TaskExecutionBoundary, type TaskExecutionSession } from "./task-execution-boundary.js";
import {
  findCodebaseMemoryProject,
  type CodebaseMemoryClient,
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

export type RegisteredRepoResolver = () => RepoConfig;
export type IndexJobScheduler = (job: () => Promise<void>) => void;

export type CodebaseMemoryIndexServiceOptions = {
  loadBoundary?: (repo: RepoConfig) => Promise<TaskExecutionBoundary | undefined>;
  scheduleJob?: IndexJobScheduler;
};

export class CodebaseMemoryIndexService {
  private readonly jobs = new Map<string, IndexJob>();
  private readonly loadBoundary: (repo: RepoConfig) => Promise<TaskExecutionBoundary | undefined>;
  private readonly scheduleJob: IndexJobScheduler;

  constructor(
    private readonly clientFactory: CodebaseMemoryClientFactory,
    private readonly queryTimeoutMs: number,
    private readonly indexTimeoutMs: number,
    options: CodebaseMemoryIndexServiceOptions = {}
  ) {
    this.loadBoundary = options.loadBoundary ?? ((repo) => createTaskExecutionBoundaryFromEnvironment(process.env, {
      cwd: () => repo.root
    }));
    this.scheduleJob = options.scheduleJob ?? ((task) => queueMicrotask(() => { void task(); }));
  }

  isRunning(repoRoot: string): boolean {
    const status = this.jobs.get(repoRoot)?.status;
    return status === "queued" || status === "running";
  }

  async index(
    repo: RepoConfig,
    action: CodeIndexAction,
    resolveRegisteredRepo?: RegisteredRepoResolver
  ): Promise<CodeIndexResult> {
    return action === "start"
      ? this.start(repo, resolveRegisteredRepo)
      : this.status(repo, resolveRegisteredRepo);
  }

  private async start(repo: RepoConfig, resolveRegisteredRepo?: RegisteredRepoResolver): Promise<CodeIndexResult> {
    const existing = this.jobs.get(repo.root);
    if (existing && (existing.status === "queued" || existing.status === "running")) {
      const boundary = await this.loadBoundary(repo);
      await this.validateCachedJob(repo, resolveRegisteredRepo, boundary);
      return result(repo.repo_id, "start", existing);
    }

    const queued = job("queued", "Indexing was queued after explicit user approval.");
    this.jobs.set(repo.root, queued);
    let boundary: TaskExecutionBoundary | undefined;
    let session: TaskExecutionSession | undefined;
    const finishSession = createSessionFinisher(() => session);
    try {
      boundary = await this.loadBoundary(repo);
      if (boundary) {
        session = await boundary.begin({
          repo_id: repo.repo_id,
          root: repo.root,
          registered_repo: registeredRoot(repo),
          ...(resolveRegisteredRepo ? { resolve_registered_repo: () => registeredRoot(resolveRegisteredRepo()) } : {}),
          operation: "index"
        });
      }

      let indexed = false;
      try {
        indexed = await this.hasProject(repo, session);
      } catch (error) {
        if (session) throw error;
      }
      if (indexed) {
        await finishSession();
        updateJob(queued, "ready", "The repository already has a Codebase Memory index.");
        queued.finished_at = new Date().toISOString();
        return result(repo.repo_id, "start", queued);
      }

      this.scheduleJob(() => this.run(repo, queued, session, finishSession));
      return result(repo.repo_id, "start", queued);
    } catch (error) {
      await finishSession({ status: "failed", error }).catch(() => undefined);
      const boundaryFailure = isTaskExecutionBoundaryFailure(error);
      queued.warnings.push(boundaryFailure ? "TASK_EXECUTION_IDENTITY_UNVERIFIED" : "CODEBASE_MEMORY_INDEX_FAILED");
      updateJob(queued, "failed", boundaryFailure
        ? "Task execution identity could not be verified before indexing."
        : "Codebase Memory indexing failed.");
      queued.finished_at = new Date().toISOString();
      throw error;
    }
  }

  private async status(repo: RepoConfig, resolveRegisteredRepo?: RegisteredRepoResolver): Promise<CodeIndexResult> {
    const existing = this.jobs.get(repo.root);
    const boundary = await this.loadBoundary(repo);
    if (existing) {
      await this.validateCachedJob(repo, resolveRegisteredRepo, boundary);
      return result(repo.repo_id, "status", existing);
    }
    let session: TaskExecutionSession | undefined;
    const finishSession = createSessionFinisher(() => session);
    try {
      if (boundary) {
        session = await boundary.begin({
          repo_id: repo.repo_id,
          root: repo.root,
          registered_repo: registeredRoot(repo),
          ...(resolveRegisteredRepo ? { resolve_registered_repo: () => registeredRoot(resolveRegisteredRepo()) } : {}),
          operation: "index"
        });
      }
      const state = await this.hasProject(repo, session) ? "ready" : "index_required";
      await finishSession();
      return result(repo.repo_id, "status", job(state, state === "ready"
        ? "The Codebase Memory index is ready."
        : "The repository has not been indexed."));
    } catch (error) {
      await finishSession({ status: "failed", error }).catch(() => undefined);
      if (boundary) throw error;
      return result(repo.repo_id, "status", job("provider_unavailable", "Codebase Memory is unavailable.", ["CODEBASE_MEMORY_UNAVAILABLE"]));
    }
  }

  private async validateCachedJob(
    repo: RepoConfig,
    resolveRegisteredRepo: RegisteredRepoResolver | undefined,
    boundary: TaskExecutionBoundary | undefined
  ): Promise<void> {
    if (!boundary) return;

    let session: TaskExecutionSession | undefined;
    const finishSession = createSessionFinisher(() => session);
    try {
      session = await boundary.begin({
        repo_id: repo.repo_id,
        root: repo.root,
        registered_repo: registeredRoot(repo),
        ...(resolveRegisteredRepo ? { resolve_registered_repo: () => registeredRoot(resolveRegisteredRepo()) } : {}),
        operation: "index"
      });
      await session.revalidateBeforeProvider();
      await finishSession();
    } catch (error) {
      await finishSession({ status: "failed", error }).catch(() => undefined);
      throw error;
    }
  }

  private async run(
    repo: RepoConfig,
    current: IndexJob,
    session?: TaskExecutionSession,
    finishSession = createSessionFinisher(() => session)
  ): Promise<void> {
    updateJob(current, "running", "Codebase Memory is indexing the approved repository root.");
    current.started_at = new Date().toISOString();
    let client: CodebaseMemoryClient | undefined;
    let next: "ready" | "degraded" | undefined;
    let providerFailed = false;
    let providerError: unknown;
    let cleanupFailed = false;
    let cleanupError: unknown;
    let postflightFailed = false;
    let postflightError: unknown;
    try {
      await session?.revalidateBeforeProvider();
      const executionRoot = session?.execution_root ?? repo.root;
      client = await this.clientFactory(executionRoot);
      await session?.revalidateBeforeProvider();
      const response = await client.call("index_repository", {
        repo_path: executionRoot,
        mode: "full",
        persistence: false
      }, this.indexTimeoutMs);
      next = validatedIndexStatus(response);
    } catch (error) {
      providerFailed = true;
      providerError = error;
    }

    try {
      await client?.close();
    } catch (error) {
      cleanupFailed = true;
      cleanupError = error;
    }

    const operationErrors: unknown[] = [];
    if (providerFailed) operationErrors.push(providerError);
    if (cleanupFailed) operationErrors.push(cleanupError);
    const operationError = operationErrors.length > 1
      ? new AggregateError(operationErrors, "Codebase Memory indexing and cleanup failed.")
      : operationErrors[0];
    try {
      await finishSession(operationErrors.length > 0 ? { status: "failed", error: operationError } : undefined);
    } catch (error) {
      postflightFailed = true;
      postflightError = error;
    }

    if (providerFailed || cleanupFailed || postflightFailed) {
      const boundaryFailure = [providerError, cleanupError, postflightError].some(isTaskExecutionBoundaryFailure);
      current.warnings.push(boundaryFailure ? "TASK_EXECUTION_IDENTITY_UNVERIFIED" : "CODEBASE_MEMORY_INDEX_FAILED");
      updateJob(current, "failed", boundaryFailure
        ? "Task execution identity could not be revalidated before provider invocation."
        : "Codebase Memory indexing failed.");
    } else {
      updateJob(current, next!, next === "ready" ? "Codebase Memory indexing completed." : "Indexing completed with degraded coverage.");
    }
    current.finished_at = new Date().toISOString();
  }

  private async hasProject(repo: RepoConfig, session?: TaskExecutionSession): Promise<boolean> {
    let client: CodebaseMemoryClient | undefined;
    let projectFound = false;
    let providerFailed = false;
    let providerError: unknown;
    try {
      await session?.revalidateBeforeProvider();
      client = await this.clientFactory(session?.execution_root ?? repo.root);
      await session?.revalidateBeforeProvider();
      projectFound = Boolean(await findCodebaseMemoryProject(client, session?.execution_root ?? repo.root, this.queryTimeoutMs));
    } catch (error) {
      providerFailed = true;
      providerError = error;
    }

    let cleanupFailed = false;
    let cleanupError: unknown;
    try {
      await client?.close();
    } catch (error) {
      cleanupFailed = true;
      cleanupError = error;
    }

    if (providerFailed && cleanupFailed) {
      throw new AggregateError([providerError, cleanupError], "Codebase Memory project lookup and cleanup failed.");
    }
    if (providerFailed) throw providerError;
    if (cleanupFailed && session) throw cleanupError;
    return projectFound;
  }
}

function createSessionFinisher(sessionForOperation: () => TaskExecutionSession | undefined) {
  let finishStarted = false;
  return async (outcome?: { status?: "completed" | "failed"; error?: unknown }) => {
    if (finishStarted) return;
    const session = sessionForOperation();
    if (!session) return;
    finishStarted = true;
    return session.finish(outcome);
  };
}

function isTaskExecutionBoundaryFailure(error: unknown): boolean {
  return typeof error === "object" && error !== null
    && "code" in error && error.code === "RUNNER_POLICY_BLOCKED";
}

function registeredRoot(repo: RepoConfig): { repo_id: string; root: string } {
  return { repo_id: repo.repo_id, root: repo.root };
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
