import { randomUUID } from "node:crypto";
import { collectTaskPreservationSnapshot, verifyExecutionIdentity } from "./task-preservation-observation.js";
import {
  TASK_EXECUTION_BOOTSTRAP_ENV,
  assertTaskInputPaths,
  bindTaskPrompt,
  loadTaskExecutionBootstrapAtPath,
  loadTaskExecutionBootstrapFromEnvironment,
  resolveRunIds,
  verifyTaskV3RunBinding,
  verifyTaskV3Runs
} from "./task-execution-bootstrap.js";
import { errorReason, taskExecutionError } from "./task-execution-errors.js";
import { writeTaskExecutionReceipt } from "./task-execution-receipts.js";
import type {
  CollectTaskPreservationInput,
  ExecutionIdentity,
  LoadedTaskExecutionBootstrap,
  TaskExecutionBoundaryOptions,
  TaskExecutionBootstrap,
  TaskExecutionEvidence,
  TaskExecutionInput,
  TaskExecutionProviderGuard,
  TaskExecutionSession,
  TaskPreservationSample,
  VerifiedTaskRunBinding
} from "./task-execution-bootstrap.js";

export {
  TASK_EXECUTION_BOOTSTRAP_ENV,
  bindTaskPrompt,
  bindTaskPromptIfEnrolled,
  loadTaskExecutionBootstrapFromEnvironment,
  verifyTaskV3RunBinding
} from "./task-execution-bootstrap.js";
export type {
  CollectTaskPreservationInput,
  ExecutionIdentity,
  ExecutionIdentityInput,
  LoadedTaskExecutionBootstrap,
  PathMetadata,
  TaskExecutionBoundaryOptions,
  TaskExecutionBootstrap,
  TaskExecutionEvidence,
  TaskExecutionInput,
  TaskExecutionOperation,
  TaskExecutionProviderGuard,
  TaskExecutionRegistrationBaseline,
  TaskExecutionSession,
  TaskPreservationIdentityEvidence,
  TaskPreservationSample,
  TaskPreservationSidecar,
  TaskPreservationSnapshot,
  VerifiedTaskRunBinding
} from "./task-execution-bootstrap.js";
export { readTaskExecutionReceipt } from "./task-execution-receipts.js";

/** Returns no boundary when this owner process has not enrolled a task. */
export async function createTaskExecutionBoundaryFromEnvironment(
  env: NodeJS.ProcessEnv = process.env,
  options: TaskExecutionBoundaryOptions = {}
): Promise<TaskExecutionBoundary | undefined> {
  const loaded = await loadTaskExecutionBootstrapFromEnvironment(env);
  return loaded ? new TaskExecutionBoundary(loaded, options, env) : undefined;
}

function isErrorToolResult(value: unknown): boolean {
  return typeof value === "object" && value !== null && "isError" in value && value.isError === true;
}

/** One task boundary for MCP execution and queued provider work. */
export class TaskExecutionBoundary {
  private loadedValue: LoadedTaskExecutionBootstrap | undefined;

  constructor(
    private readonly source: LoadedTaskExecutionBootstrap | string,
    private readonly options: TaskExecutionBoundaryOptions = {},
    private readonly enrollmentEnvironment?: NodeJS.ProcessEnv
  ) {
    if (typeof source !== "string") {
      this.loadedValue = source;
    }
  }

  private async beginOperation(input: TaskExecutionInput): Promise<TaskExecutionSession> {
    const loaded = await this.load();
    const operationId = randomUUID();
    const startedAt = this.now().toISOString();
    const registeredRepo = input.registered_repo ?? {
      repo_id: input.repo_id ?? "",
      root: input.root ?? ""
    };
    const isRepositoryReview = input.operation === "repository_review";
    let runIds = [...loaded.bootstrap.run_ids];
    let runSelectionError: unknown;
    try {
      runIds = resolveRunIds(loaded.bootstrap, input);
    } catch (error) {
      runSelectionError = error;
    }
    const receiptRunIds = isRepositoryReview ? [] : runIds;
    const runId = isRepositoryReview ? undefined : runIds[0];
    const selectedRunId = !isRepositoryReview && runIds.length === 1 ? runIds[0] : undefined;
    let verifiedRunBindings: VerifiedTaskRunBinding[] = [];
    let pre: TaskPreservationSample | undefined;
    let identity: ExecutionIdentity | undefined;
    try {
      await this.verifyCurrentBootstrap(loaded);
      if (registeredRepo.repo_id !== loaded.bootstrap.repo_id || registeredRepo.root !== loaded.bootstrap.execution_root) {
        throw taskExecutionError("repository_registration_mismatch");
      }
      if (runSelectionError) throw runSelectionError;
      assertTaskInputPaths(loaded.bootstrap, input.task_text);
      identity = await verifyExecutionIdentity({
        bootstrap: loaded.bootstrap,
        repo_id: registeredRepo.repo_id,
        configured_root: registeredRepo.root,
        cwd: (this.options.cwd ?? (() => process.cwd()))()
      });
      if (input.operation === "resume" || input.operation === "review") {
        verifiedRunBindings = await verifyTaskV3Runs(loaded, registeredRepo, runIds);
      }
      pre = await collectTaskPreservationSnapshot(this.sampleInput(loaded.bootstrap, registeredRepo));
    } catch (error) {
      await writeTaskExecutionReceipt({
        loaded,
        operationId,
        runId,
        runIds: receiptRunIds,
        runBindings: verifiedRunBindings,
        operation: input.operation,
        outcome: "failed",
        failureCode: errorReason(error),
        identity,
        pre: null,
        post: null,
        createdAt: startedAt,
        now: () => this.now()
      }).catch(() => undefined);
      throw error;
    }

    let finished = false;
    let providerError: unknown;
    const revalidateBeforeProvider = async (resolveRegisteredRepo = input.resolve_registered_repo): Promise<void> => {
      if (finished) throw taskExecutionError("operation_session_already_finished");
      try {
        if (!resolveRegisteredRepo) throw taskExecutionError("repository_registration_resolver_unavailable");
        const liveRepo = resolveRegisteredRepo();
        if (liveRepo.repo_id !== loaded.bootstrap.repo_id || liveRepo.root !== loaded.bootstrap.execution_root) {
          throw taskExecutionError("repository_registration_changed");
        }
        await this.verifyCurrentBootstrap(loaded);
        const liveIdentity = await verifyExecutionIdentity({
          bootstrap: loaded.bootstrap,
          repo_id: liveRepo.repo_id,
          configured_root: liveRepo.root,
          cwd: (this.options.cwd ?? (() => process.cwd()))()
        });
        if (input.operation === "resume" || input.operation === "review") {
          verifiedRunBindings = await verifyTaskV3Runs(loaded, liveRepo, runIds);
        }
        if (liveIdentity.execution_head !== identity.execution_head) throw taskExecutionError("execution_baseline_changed");
      } catch (error) {
        providerError = error;
        throw error;
      }
    };
    return {
      execution_root: identity.execution_root,
      ...(selectedRunId ? { run_id: selectedRunId } : {}),
      revalidateBeforeProvider,
      bindTaskPrompt: async (prompt, repoId, selectedRunId, sourcePaths, _env, registrationBaseline) => {
        await revalidateBeforeProvider();
        return bindTaskPrompt(prompt, loaded, repoId, selectedRunId, sourcePaths, registrationBaseline);
      },
      finish: async (outcome = {}) => {
        if (finished) throw taskExecutionError("operation_session_already_finished");
        finished = true;
        let post: TaskPreservationSample | null = null;
        let postflightError: unknown;
        try {
          await this.verifyCurrentBootstrap(loaded);
          if (!input.resolve_registered_repo) throw taskExecutionError("repository_registration_resolver_unavailable");
          const liveRepo = input.resolve_registered_repo();
          if (liveRepo.repo_id !== loaded.bootstrap.repo_id || liveRepo.root !== loaded.bootstrap.execution_root) {
            throw taskExecutionError("repository_registration_changed");
          }
          const liveIdentity = await verifyExecutionIdentity({
            bootstrap: loaded.bootstrap,
            repo_id: liveRepo.repo_id,
            configured_root: liveRepo.root,
            cwd: (this.options.cwd ?? (() => process.cwd()))()
          });
          if (liveIdentity.execution_head !== identity.execution_head) throw taskExecutionError("execution_baseline_changed");
          if (input.operation === "resume" || input.operation === "review") {
            verifiedRunBindings = await verifyTaskV3Runs(loaded, liveRepo, runIds);
          } else if ((input.operation === "registration" || input.operation === "queue")
            && outcome.status !== "failed" && !outcome.error) {
            verifiedRunBindings = [await verifyTaskV3RunBinding({ loaded, registered_repo: liveRepo, run_id: runIds[0]! })];
          }
          post = await collectTaskPreservationSnapshot(this.sampleInput(loaded.bootstrap, liveRepo));
        } catch (error) {
          postflightError = error;
        }
        const failed = outcome.status === "failed" || outcome.error || providerError || postflightError;
        const receiptHash = await writeTaskExecutionReceipt({
          loaded,
          operationId,
          runId,
          runIds: receiptRunIds,
          runBindings: verifiedRunBindings,
          operation: input.operation,
          outcome: failed ? "failed" : "completed",
          ...(failed ? { failureCode: errorReason(outcome.error ?? providerError ?? postflightError) } : {}),
          identity,
          pre,
          post,
          createdAt: startedAt,
          now: () => this.now()
        });
        const evidence: TaskExecutionEvidence = {
          operation_id: operationId,
          operation: input.operation,
          verdict: "NOT_PROVEN",
          receipt_sha256: receiptHash
        };
        if (postflightError) throw taskExecutionError("postflight_collection_failed");
        if (providerError) throw providerError;
        return evidence;
      }
    };
  }

  async execute<T>(
    input: TaskExecutionInput,
    work: (explicitCwd: string, providerGuard: TaskExecutionProviderGuard) => Promise<T>
  ): Promise<{ result: T; evidence: TaskExecutionEvidence }> {
    const session = await this.beginOperation(input);
    let result: T | undefined;
    let operationError: unknown;
    let workThrew = false;
    try {
      result = await work(session.execution_root, {
        ...(session.run_id ? { run_id: session.run_id } : {}),
        revalidateBeforeProvider: () => session.revalidateBeforeProvider(),
        bindTaskPrompt: (prompt, repoId, runId, sourcePaths, env, registrationBaseline) =>
          session.bindTaskPrompt(prompt, repoId, runId, sourcePaths, env, registrationBaseline)
      });
      if (isErrorToolResult(result)) operationError = taskExecutionError("mcp_operation_returned_error");
    } catch (error) {
      workThrew = true;
      operationError = error;
    }
    try {
      const evidence = await session.finish(operationError ? { status: "failed", error: operationError } : undefined);
      if (workThrew && operationError) throw operationError;
      return { result: result as T, evidence };
    } catch (postflightError) {
      if (workThrew && operationError) throw operationError;
      throw postflightError;
    }
  }

  private async load(): Promise<LoadedTaskExecutionBootstrap> {
    if (this.loadedValue) return this.loadedValue;
    if (typeof this.source === "string") {
      this.loadedValue = await loadTaskExecutionBootstrapAtPath(this.source);
      return this.loadedValue;
    }
    throw taskExecutionError("bootstrap_unavailable");
  }

  private async verifyCurrentBootstrap(loaded: LoadedTaskExecutionBootstrap): Promise<void> {
    if (!loaded.descriptor_path) return;
    if (this.enrollmentEnvironment
      && this.enrollmentEnvironment[TASK_EXECUTION_BOOTSTRAP_ENV] !== loaded.descriptor_path) {
      throw taskExecutionError("bootstrap_selection_changed");
    }
    const refreshed = await loadTaskExecutionBootstrapAtPath(loaded.descriptor_path);
    if (refreshed.sha256 !== loaded.sha256) throw taskExecutionError("bootstrap_changed_during_operation");
  }

  private sampleInput(bootstrap: TaskExecutionBootstrap, registeredRepo: { repo_id: string; root: string }): CollectTaskPreservationInput {
    return {
      bootstrap,
      repo_id: registeredRepo.repo_id,
      configured_root: registeredRepo.root,
      cwd: (this.options.cwd ?? (() => process.cwd()))(),
      ...(this.options.now ? { now: this.options.now } : {}),
      ...(this.options.run_git ? { run_git: this.options.run_git } : {})
    };
  }

  /** Opens one identity-bound session for synchronous or queued task work. */
  async begin(input: TaskExecutionInput): Promise<TaskExecutionSession> {
    return this.beginOperation(input);
  }

  private now(): Date {
    return (this.options.now ?? (() => new Date()))();
  }
}
