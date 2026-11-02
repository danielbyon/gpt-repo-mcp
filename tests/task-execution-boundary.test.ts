import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { access, chmod, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, test, vi } from "vitest";
import { isCodexRunArtifact } from "../src/services/codex-task-policy.js";
import { delegationBaselineSha256V3 } from "../src/services/delegation-v3-normalizer.js";
import { GitService } from "../src/services/git-service.js";
import { DelegationInteractionStore } from "../src/delegation/interaction-store.js";
import type { RuntimeContext } from "../src/runtime/context.js";
import { codeIndexHandler } from "../src/tools/handlers/code-index.js";
import { writeAgentReplyHandler } from "../src/tools/handlers/delegation.js";
import { createRepoFixture } from "./fixtures/repo-fixture.js";
import { loadTaskExecutionBootstrapAtPath, resolveRunIds } from "../src/services/task-execution-bootstrap.js";
import { taskExecutionPolicyFor } from "../src/tools/task-execution-policy.js";

const execFileAsync = promisify(execFile);

async function initRepo(root: string): Promise<string> {
  await mkdir(root, { recursive: true });
  await writeFile(join(root, "tracked.txt"), "fixture\n");
  await execFileAsync("git", ["init"], { cwd: root });
  await execFileAsync("git", ["config", "user.email", "fixture@example.test"], { cwd: root });
  await execFileAsync("git", ["config", "user.name", "Fixture"], { cwd: root });
  await execFileAsync("git", ["add", "tracked.txt"], { cwd: root });
  await execFileAsync("git", ["commit", "-m", "fixture"], { cwd: root });
  return (await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: root })).stdout.trim();
}

async function removeFixtureAfterSetupFailure(workspace: string, setupError: unknown): Promise<never> {
  try {
    await rm(workspace, { recursive: true, force: true });
  } catch (cleanupError) {
    throw new AggregateError([setupError, cleanupError], "Task fixture setup and cleanup both failed.");
  }
  throw setupError;
}

async function writeBootstrap(workspace: string, overrides: Record<string, unknown> = {}) {
  const primaryPath = join(workspace, "protected");
  const executionPath = join(workspace, "execution");
  try {
    await initRepo(primaryPath);
    await initRepo(executionPath);
  } catch (error) {
    return removeFixtureAfterSetupFailure(workspace, error);
  }
  return writeBootstrapForRoots(workspace, primaryPath, executionPath, overrides);
}

async function writeBootstrapForRoots(
  workspace: string,
  primaryPath: string,
  executionPath: string,
  overrides: Record<string, unknown> = {}
) {
  try {
    const receiptPath = join(workspace, "receipts");
    await mkdir(receiptPath, { mode: 0o700 });
    await chmod(receiptPath, 0o700);
    const primaryRoot = await realpath(primaryPath);
    const executionRoot = await realpath(executionPath);
    const receiptDirectory = await realpath(receiptPath);
    const runIds = overrides.run_ids as string[] | undefined ?? ["2026-11-01T120000Z-fixture-run"];
    const ownerBaseline = await captureOwnerBaseline(executionRoot, runIds[0]!);
    const { expected_baseline: expectedBaselineOverride, ...bootstrapOverrides } = overrides;
    const descriptor = {
      schema: "gpt-repo-mcp.task-bootstrap",
      schema_version: 2,
      task_id: "fixture-task",
      run_ids: runIds,
      repo_id: "fixture-repo",
      protected_root: primaryRoot,
      execution_root: executionRoot,
      expected_baseline: { ...ownerBaseline.pin, ...(expectedBaselineOverride as object | undefined) },
      protected_paths: ["private/config.json"],
      protected_state_inputs: ["HEAD", "refs", "index"],
      explicit_exclusions: ["working-file contents"],
      authorized_source_paths: ["src/**", "tests/**", "docs/**"],
      authorized_ref_transitions: [],
      receipt_directory: receiptDirectory,
      path_token_key: "a".repeat(64),
      limits: {
        bootstrap_bytes: 64 * 1024,
        receipt_bytes: 2 * 1024 * 1024,
        refs: 64,
        untracked_entries: 1000,
        protected_paths: 16,
        path_bytes: 1024,
        inventory_bytes: 1024 * 1024,
        index_bytes: 1024 * 1024,
        sidecar_bytes: 2 * 1024 * 1024,
        tracked_entries: 10_000
      },
      ...bootstrapOverrides
    };
    const bootstrapFile = join(workspace, "owner-task-bootstrap.json");
    await writeFile(bootstrapFile, JSON.stringify(descriptor), { mode: 0o600 });
    await chmod(bootstrapFile, 0o600);
    const bootstrapPath = await realpath(bootstrapFile);
    return { descriptor, bootstrapPath, primaryRoot, executionRoot, receiptDirectory, baseline: ownerBaseline.baseline };
  } catch (error) {
    return removeFixtureAfterSetupFailure(workspace, error);
  }
}

describe("task fixture cleanup", () => {
  test("removes a workspace when bootstrap fixture setup fails", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-fixture-setup-failure-"));
    const setupError = new Error("expected fixture setup failure");
    const overrides = Object.defineProperty({}, "expected_baseline", {
      enumerable: true,
      get: () => { throw setupError; }
    });

    try {
      await expect(writeBootstrap(workspace, overrides)).rejects.toBe(setupError);
      await expect(readdir(workspace)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
});

async function captureOwnerBaseline(executionRoot: string, runId: string) {
  const git = new GitService(executionRoot);
  const status = await git.status();
  const initialChangedPaths = [...new Set(status.files
    .flatMap((file) => [file.original_path, file.path])
    .filter((path): path is string => typeof path === "string")
    .filter((path) => !isCodexRunArtifact(path, runId) && !path.startsWith(".chatgpt/")))].sort((left, right) => left.localeCompare(right));
  const baseline = {
    head_sha: status.head_sha,
    worktree_fingerprint: await git.worktreeFingerprint(),
    initial_changed_paths: initialChangedPaths,
    initial_path_states: await git.pathStates(initialChangedPaths)
  };
  return {
    baseline,
    pin: {
      head_sha: baseline.head_sha,
      worktree_fingerprint: baseline.worktree_fingerprint,
      baseline_sha256: delegationBaselineSha256V3(baseline)
    }
  };
}

async function writeBoundV3Run(
  fixture: Awaited<ReturnType<typeof writeBootstrapForRoots>>,
  runId: string,
  baseline = fixture.baseline
) {
  const runFixtures = await import("./fixtures/delegation-v3-run-fixture.js");
  const { codexRunPaths } = await import("../src/services/codex-run-paths.js");
  const { sha256Text } = await import("../src/services/codex-task-policy.js");
  const api = await import("../src/services/task-execution-boundary.js");
  const manifest = await runFixtures.writeQueuedV3Run(fixture.executionRoot, runId, {
    authorization_scope: ["src/**", "tests/**", "docs/**"],
    baseline
  });
  const paths = codexRunPaths(runId);
  const promptPath = join(fixture.executionRoot, paths.promptPath);
  const sourcePaths = [...new Set([
    ...manifest.task.starting_points,
    ...manifest.authorization.effective_scope,
    ...manifest.baseline.initial_changed_paths
  ])].sort();
  const originalPrompt = await readFile(promptPath, "utf8");
  const prompt = await api.bindTaskPromptIfEnrolled(
    originalPrompt,
    manifest.repo_id,
    runId,
    sourcePaths,
    { [api.TASK_EXECUTION_BOOTSTRAP_ENV]: fixture.bootstrapPath }
  );
  await writeFile(promptPath, prompt);
  const boundManifest = {
    ...manifest,
    prompt_sha256: sha256Text(prompt),
    prompt_byte_count: Buffer.byteLength(prompt, "utf8")
  };
  await writeFile(join(fixture.executionRoot, paths.manifestPath), `${JSON.stringify(boundManifest, null, 2)}\n`);
  return { manifest: boundManifest, originalPrompt, prompt };
}

async function seedReplyableAgentRun(root: string) {
  const runId = "2026-11-01T120000Z-reply-fixture";
  const runDir = join(root, ".chatgpt", "codex-runs", runId);
  const promptPath = `.chatgpt/codex-runs/${runId}/PROMPT.md`;
  const resultPath = `.chatgpt/codex-runs/${runId}/RESULT.md`;
  const resultJsonPath = `.chatgpt/codex-runs/${runId}/RESULT.json`;
  await mkdir(runDir, { recursive: true });
  await writeFile(join(runDir, "PROMPT.md"), "# Reply fixture\n");
  await writeFile(join(runDir, "run.json"), `${JSON.stringify({
    schema_version: 1,
    repo_id: "fixture",
    run_id: runId,
    title: "Reply fixture",
    prompt_path: promptPath,
    result_path: resultPath,
    result_json_path: resultJsonPath,
    created_at: "2026-11-01T12:00:00.000Z",
    runner: { mode: "manual" }
  })}\n`);
  await writeFile(join(runDir, "runner.status.json"), `${JSON.stringify({
    schema_version: 1,
    repo_id: "fixture",
    run_id: runId,
    runner: "codex_sdk",
    status: "awaiting_input",
    revision: 1,
    started_at: "2026-11-01T12:00:00.000Z",
    updated_at: "2026-11-01T12:00:00.000Z",
    completed_at: null,
    prompt_path: promptPath,
    result_path: resultPath,
    result_found: false,
    head_before: null,
    head_after: null,
    worktree_fingerprint_before: null,
    worktree_fingerprint_after: null,
    changed_paths: [],
    validation: { status: "missing", profile: null, artifact_path: null },
    commit: { attempted: false, allowed: false, status: "skipped", commit_sha: null },
    warnings: []
  })}\n`);
  const interactions = new DelegationInteractionStore(root);
  await interactions.writeSession({
    repo_id: "fixture",
    run_id: runId,
    provider: "codex_sdk",
    thread_id: "fixture-thread",
    turn_index: 1,
    last_consumed_reply_turn_index: null,
    created_at: "2026-11-01T12:00:00.000Z"
  });
  const question = await interactions.writeQuestion({
    repo_id: "fixture",
    run_id: runId,
    turn_index: 1,
    questions: [{ question_id: "q-confirm", prompt: "Confirm the fixture." }],
    created_at: "2026-11-01T12:00:00.000Z"
  });
  return { runId, questionSha256: question.sha256, interactions };
}

describe("generic task execution bootstrap", () => {
  test("agent replies revalidate the enrolled identity immediately before writing", async () => {
    const fixture = await createRepoFixture();
    const seeded = await seedReplyableAgentRun(fixture.root);
    let revalidationCalls = 0;
    const context = {
      registry: { get: () => ({ repo_id: "fixture", root: fixture.root }) }
    } as unknown as RuntimeContext;
    const result = await writeAgentReplyHandler({
      repo_id: "fixture",
      run_id: seeded.runId,
      turn_index: 1,
      expected_question_sha256: seeded.questionSha256,
      answers: [{ question_id: "q-confirm", answer: "Confirmed." }]
    }, context, {
      revalidateBeforeProvider: async () => {
        revalidationCalls += 1;
        throw new Error("registration changed before reply write");
      },
      bindTaskPrompt: async (prompt) => prompt
    });

    expect(revalidationCalls).toBe(1);
    expect(result.isError).toBe(true);
    await expect(seeded.interactions.readReply("fixture", seeded.runId, 1)).resolves.toBeUndefined();
  });

  test("requires the owner bootstrap to pin the complete normalized baseline digest", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-bootstrap-baseline-pin-"));
    const api = await import("../src/services/task-execution-boundary.js");
    try {
      const fixture = await writeBootstrap(workspace);
      await expect(api.loadTaskExecutionBootstrapFromEnvironment({
        [api.TASK_EXECUTION_BOOTSTRAP_ENV]: fixture.bootstrapPath
      })).resolves.toBeDefined();

      const incomplete = {
        ...fixture.descriptor,
        expected_baseline: { head_sha: fixture.descriptor.expected_baseline.head_sha }
      };
      await writeFile(fixture.bootstrapPath, JSON.stringify(incomplete));
      await expect(api.loadTaskExecutionBootstrapFromEnvironment({
        [api.TASK_EXECUTION_BOOTSTRAP_ENV]: fixture.bootstrapPath
      })).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("loads owner process enrollment and leaves an un-enrolled process ungoverned", async () => {
    const api = await import("../src/services/task-execution-boundary.js") as unknown as {
      loadTaskExecutionBootstrapFromEnvironment?: (env: NodeJS.ProcessEnv) => Promise<unknown>;
    };
    expect(api.loadTaskExecutionBootstrapFromEnvironment).toBeTypeOf("function");
    if (!api.loadTaskExecutionBootstrapFromEnvironment) return;

    await expect(api.loadTaskExecutionBootstrapFromEnvironment({})).resolves.toBeUndefined();
    await expect(api.loadTaskExecutionBootstrapFromEnvironment({
      GPT_REPO_TASK_BOOTSTRAP_PATH: ""
    })).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
    const workspace = await mkdtemp(join(tmpdir(), "task-bootstrap-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const loaded = await api.loadTaskExecutionBootstrapFromEnvironment({
        GPT_REPO_TASK_BOOTSTRAP_PATH: fixture.bootstrapPath
      });
      expect(loaded).toMatchObject({ bootstrap: {
        task_id: "fixture-task",
        repo_id: "fixture-repo",
        execution_root: fixture.executionRoot,
        authorized_source_paths: ["src/**", "tests/**", "docs/**"]
      } });
      expect(JSON.stringify(loaded)).not.toContain("issue-38");
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("fails closed for malformed, writable, or symlinked enrollment", async () => {
    const api = await import("../src/services/task-execution-boundary.js") as unknown as {
      loadTaskExecutionBootstrapFromEnvironment?: (env: NodeJS.ProcessEnv) => Promise<unknown>;
    };
    expect(api.loadTaskExecutionBootstrapFromEnvironment).toBeTypeOf("function");
    if (!api.loadTaskExecutionBootstrapFromEnvironment) return;

    const workspace = await mkdtemp(join(tmpdir(), "task-bootstrap-invalid-"));
    try {
      const fixture = await writeBootstrap(workspace);
      await expect(api.loadTaskExecutionBootstrapFromEnvironment({
        GPT_REPO_TASK_BOOTSTRAP_PATH: join(workspace, "missing.json")
      })).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      await chmod(fixture.bootstrapPath, 0o644);
      await expect(api.loadTaskExecutionBootstrapFromEnvironment({
        GPT_REPO_TASK_BOOTSTRAP_PATH: fixture.bootstrapPath
      })).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      const linkPath = join(workspace, "bootstrap-link.json");
      await symlink(fixture.bootstrapPath, linkPath);
      await expect(api.loadTaskExecutionBootstrapFromEnvironment({
        GPT_REPO_TASK_BOOTSTRAP_PATH: linkPath
      })).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("authorizes only exact ref transitions including expected absence", async () => {
    const api = await import("../src/services/task-preservation-observation.js") as unknown as {
      compareRefTransitions?: (
        before: Record<string, string>,
        after: Record<string, string>,
        authorized: Array<{ refname: string; before_oid: string | null; after_oid: string | null }>
      ) => Array<{ category: string; state: string }>;
    };
    expect(api.compareRefTransitions).toBeTypeOf("function");
    if (!api.compareRefTransitions) return;

    const oldOid = "1".repeat(40);
    const newOid = "2".repeat(40);
    const thirdOid = "3".repeat(40);
    const transitions = [
      { refname: "refs/heads/change", before_oid: oldOid, after_oid: newOid },
      { refname: "refs/heads/add", before_oid: null, after_oid: newOid },
      { refname: "refs/heads/delete", before_oid: oldOid, after_oid: null }
    ];

    expect(api.compareRefTransitions(
      { "refs/heads/change": oldOid, "refs/heads/delete": oldOid },
      { "refs/heads/change": newOid, "refs/heads/add": newOid },
      transitions
    )).toEqual([
      { category: "owner_authorized", state: "ref:refs/heads/add" },
      { category: "owner_authorized", state: "ref:refs/heads/change" },
      { category: "owner_authorized", state: "ref:refs/heads/delete" }
    ]);

    expect(api.compareRefTransitions(
      { "refs/heads/change": oldOid },
      { "refs/heads/change": thirdOid, "refs/heads/unrelated": newOid },
      transitions
    )).toEqual([
      { category: "unattributed", state: "ref:refs/heads/change" },
      { category: "unattributed", state: "ref:refs/heads/unrelated" }
    ]);

    expect(api.compareRefTransitions(
      { "refs/heads/delete": thirdOid },
      { "refs/heads/add": thirdOid },
      transitions
    )).toEqual([
      { category: "unattributed", state: "ref:refs/heads/add" },
      { category: "unattributed", state: "ref:refs/heads/delete" }
    ]);
  });
});

describe("task execution evidence", () => {
  test("accepts a registered isolated linked worktree and records shared Git administration", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-linked-worktree-"));
    try {
      const primaryRoot = join(workspace, "protected-worktree");
      const executionRoot = join(workspace, "execution-worktree");
      await initRepo(primaryRoot);
      const head = (await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: primaryRoot })).stdout.trim();
      await execFileAsync("git", ["worktree", "add", "--detach", executionRoot, "HEAD"], { cwd: primaryRoot });
      const fixture = await writeBootstrapForRoots(workspace, primaryRoot, executionRoot, {
        authorized_ref_transitions: [{ refname: "refs/heads/authorized", before_oid: null, after_oid: head }]
      });
      const boundaryApi = await import("../src/services/task-execution-boundary.js") as unknown as {
        TaskExecutionBoundary: new (path: string, options?: { cwd?: () => string }) => {
          execute<T>(input: unknown, work: () => Promise<T>): Promise<{ result: T; evidence: { operation_id: string } }>;
        };
        readTaskExecutionReceipt(path: string, id: string): Promise<unknown>;
      };
      const boundary = new boundaryApi.TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const result = await boundary.execute({
        registered_repo: { repo_id: "fixture-repo", root: fixture.executionRoot },
        resolve_registered_repo: () => ({ repo_id: "fixture-repo", root: fixture.executionRoot }),
        operation: "validation",
        run_id: "2026-11-01T120000Z-fixture-run"
      }, async () => {
        await execFileAsync("git", ["branch", "authorized"], { cwd: fixture.executionRoot });
        return "linked worktree accepted";
      });
      const receipt = await boundaryApi.readTaskExecutionReceipt(fixture.bootstrapPath, result.evidence.operation_id) as {
        identity: { shared_refs: boolean; execution_linked_worktree: boolean; shared_protected_admin_state: boolean };
        comparison: { attribution: { owner_authorized_count: number; unattributed_count: number } };
      };

      expect(result.result).toBe("linked worktree accepted");
      expect(receipt.identity).toMatchObject({
        shared_refs: true,
        execution_linked_worktree: true,
        shared_protected_admin_state: true
      });
      expect(receipt.comparison.attribution).toMatchObject({ owner_authorized_count: 1, unattributed_count: 0 });

      const unrelated = await boundary.execute({
        registered_repo: { repo_id: "fixture-repo", root: fixture.executionRoot },
        resolve_registered_repo: () => ({ repo_id: "fixture-repo", root: fixture.executionRoot }),
        operation: "validation",
        run_id: "2026-11-01T120000Z-fixture-run"
      }, async () => {
        await execFileAsync("git", ["branch", "unrelated"], { cwd: fixture.executionRoot });
        return "unrelated ref recorded";
      });
      const unrelatedReceipt = await boundaryApi.readTaskExecutionReceipt(fixture.bootstrapPath, unrelated.evidence.operation_id) as {
        comparison: { attribution: { owner_authorized_count: number; unattributed_count: number } };
      };
      expect(unrelatedReceipt.comparison.attribution).toMatchObject({ owner_authorized_count: 0, unattributed_count: 1 });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("revalidates the live registry immediately before a queued indexing provider call", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-queued-index-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary } = await import("../src/services/task-execution-boundary.js");
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      let currentRepo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };
      const executionRepo = currentRepo;
      let scheduled: (() => Promise<void>) | undefined;
      const calls: string[] = [];
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const beginBoundary = vi.spyOn(boundary, "begin");
      const service = new CodebaseMemoryIndexService(
        async () => ({
          call: async (tool: string) => {
            calls.push(tool);
            return tool === "list_projects" ? { projects: [] } : { status: "indexed" };
          },
          close: async () => undefined
        }),
        100,
        1_000,
        {
          loadBoundary: async () => boundary,
          scheduleJob: (job) => { scheduled = job; }
        }
      );

      const queued = await service.index(currentRepo, "start", () => currentRepo);
      expect(queued.status).toBe("queued");
      expect(scheduled).toBeTypeOf("function");
      currentRepo = { ...currentRepo, root: fixture.primaryRoot };
      await scheduled?.();

      expect(calls).toEqual(["list_projects"]);
      await expect(service.index(executionRepo, "status", () => currentRepo))
        .rejects.toThrow("repository_registration_changed");
      expect(beginBoundary).toHaveBeenCalledTimes(2);
      const receipts = await readdir(fixture.receiptDirectory);
      expect(receipts).toHaveLength(2);
      const receiptApi = await import("../src/services/task-execution-boundary.js");
      const receiptResults = await Promise.all(receipts.map((receipt) =>
        receiptApi.readTaskExecutionReceipt(fixture.bootstrapPath, receipt.replace(/\.json$/, ""))
      ));
      expect(receiptResults).toEqual(expect.arrayContaining([
        expect.objectContaining({ operation_outcome: "failed", verdict: "NOT_PROVEN" }),
        expect.objectContaining({ operation_outcome: "failed", verdict: "NOT_PROVEN" })
      ]));
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("blocks enrolled index status before provider initialization when the registered root is protected primary", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-index-status-wrong-root-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary } = await import("../src/services/task-execution-boundary.js");
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const repo = { repo_id: "fixture-repo", root: fixture.primaryRoot, display_name: "Fixture" };
      const factory = vi.fn(async () => ({
        call: async () => ({ projects: [] }),
        close: async () => undefined
      }));
      const scheduleJob = vi.fn();
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const service = new CodebaseMemoryIndexService(factory, 100, 1_000, {
        loadBoundary: async () => boundary,
        scheduleJob
      });

      await expect(service.index(repo, "status", () => repo)).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      expect(factory).not.toHaveBeenCalled();
      expect(scheduleJob).not.toHaveBeenCalled();
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("checks enrolled index status on the registered execution checkout without starting indexing", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-index-status-execution-root-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary } = await import("../src/services/task-execution-boundary.js");
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };
      const providerCalls: string[] = [];
      const factory = vi.fn(async () => ({
        call: async (tool: string) => {
          providerCalls.push(tool);
          return tool === "list_projects"
            ? { projects: [{ name: "fixture-index", root_path: fixture.executionRoot }] }
            : { status: "indexed" };
        },
        close: async () => undefined
      }));
      const scheduleJob = vi.fn();
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const service = new CodebaseMemoryIndexService(factory, 100, 1_000, {
        loadBoundary: async () => boundary,
        scheduleJob
      });

      const result = await service.index(repo, "status", () => repo);

      expect(result.status).toBe("ready");
      expect(factory).toHaveBeenCalledOnce();
      expect(factory).toHaveBeenCalledWith(fixture.executionRoot);
      expect(providerCalls).toEqual(["list_projects"]);
      expect(scheduleJob).not.toHaveBeenCalled();
      const receipts = await readdir(fixture.receiptDirectory);
      expect(receipts).toHaveLength(1);
      const receiptApi = await import("../src/services/task-execution-boundary.js");
      await expect(receiptApi.readTaskExecutionReceipt(fixture.bootstrapPath, receipts[0]!.replace(/\.json$/, "")))
        .resolves.toMatchObject({ operation_outcome: "completed", verdict: "NOT_PROVEN" });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("rejects cached index status when the live registration changes to the protected primary", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-cached-index-status-wrong-root-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary, readTaskExecutionReceipt } = await import("../src/services/task-execution-boundary.js");
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };
      let liveRepo = repo;
      const providerCalls: string[] = [];
      const factory = vi.fn(async () => ({
        call: async (tool: string) => {
          providerCalls.push(tool);
          return { projects: [] };
        },
        close: async () => undefined
      }));
      const scheduleJob = vi.fn();
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const beginBoundary = vi.spyOn(boundary, "begin");
      const service = new CodebaseMemoryIndexService(factory, 100, 1_000, {
        loadBoundary: async () => boundary,
        scheduleJob
      });

      await expect(service.index(repo, "start", () => liveRepo)).resolves.toMatchObject({ status: "queued" });
      liveRepo = { ...repo, root: fixture.primaryRoot };

      await expect(service.index(repo, "status", () => liveRepo))
        .rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      expect(beginBoundary).toHaveBeenCalledTimes(2);
      expect(factory).toHaveBeenCalledOnce();
      expect(providerCalls).toEqual(["list_projects"]);
      expect(scheduleJob).toHaveBeenCalledOnce();
      const receiptNames = await readdir(fixture.receiptDirectory);
      const receipts = await Promise.all(receiptNames.map((name) =>
        readTaskExecutionReceipt(fixture.bootstrapPath, name.replace(/\.json$/, ""))));
      expect(receipts).toContainEqual(expect.objectContaining({
        operation: "index",
        operation_outcome: "failed",
        failure_code: "repository_registration_changed",
        verdict: "NOT_PROVEN"
      }));
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("rejects cached index start when the live registration changes to the protected primary", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-cached-index-start-wrong-root-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary, readTaskExecutionReceipt } = await import("../src/services/task-execution-boundary.js");
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };
      let liveRepo = repo;
      const providerCalls: string[] = [];
      const factory = vi.fn(async () => ({
        call: async (tool: string) => {
          providerCalls.push(tool);
          return { projects: [] };
        },
        close: async () => undefined
      }));
      const scheduleJob = vi.fn();
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const beginBoundary = vi.spyOn(boundary, "begin");
      const service = new CodebaseMemoryIndexService(factory, 100, 1_000, {
        loadBoundary: async () => boundary,
        scheduleJob
      });

      await expect(service.index(repo, "start", () => liveRepo)).resolves.toMatchObject({ status: "queued" });
      liveRepo = { ...repo, root: fixture.primaryRoot };

      await expect(service.index(repo, "start", () => liveRepo))
        .rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      expect(beginBoundary).toHaveBeenCalledTimes(2);
      expect(factory).toHaveBeenCalledOnce();
      expect(providerCalls).toEqual(["list_projects"]);
      expect(scheduleJob).toHaveBeenCalledOnce();
      const receiptNames = await readdir(fixture.receiptDirectory);
      const receipts = await Promise.all(receiptNames.map((name) =>
        readTaskExecutionReceipt(fixture.bootstrapPath, name.replace(/\.json$/, ""))));
      expect(receipts).toContainEqual(expect.objectContaining({
        operation: "index",
        operation_outcome: "failed",
        failure_code: "repository_registration_changed",
        verdict: "NOT_PROVEN"
      }));
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("validates cached index status and start on the registered execution checkout", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-cached-index-execution-root-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary } = await import("../src/services/task-execution-boundary.js");
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };
      const providerCalls: string[] = [];
      const factory = vi.fn(async () => ({
        call: async (tool: string) => {
          providerCalls.push(tool);
          return { projects: [] };
        },
        close: async () => undefined
      }));
      const scheduleJob = vi.fn();
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const beginBoundary = vi.spyOn(boundary, "begin");
      const service = new CodebaseMemoryIndexService(factory, 100, 1_000, {
        loadBoundary: async () => boundary,
        scheduleJob
      });

      await expect(service.index(repo, "start", () => repo)).resolves.toMatchObject({ status: "queued" });
      await expect(service.index(repo, "start", () => repo)).resolves.toMatchObject({ status: "queued" });
      await expect(service.index(repo, "status", () => repo)).resolves.toMatchObject({ status: "queued" });

      expect(beginBoundary).toHaveBeenCalledTimes(3);
      expect(factory).toHaveBeenCalledOnce();
      expect(providerCalls).toEqual(["list_projects"]);
      expect(scheduleJob).toHaveBeenCalledOnce();
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("fails an enrolled initial project check when client cleanup rejects and finishes once", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-index-initial-cleanup-failure-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary, readTaskExecutionReceipt } = await import("../src/services/task-execution-boundary.js");
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };
      const cleanupError = new Error("provider cleanup failed");
      const close = vi.fn(async () => { throw cleanupError; });
      const scheduleJob = vi.fn();
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const originalBegin = boundary.begin.bind(boundary);
      const sessionFinishes: Array<ReturnType<typeof vi.fn>> = [];
      vi.spyOn(boundary, "begin").mockImplementation(async (input) => {
        const session = await originalBegin(input);
        const finishSession = session.finish.bind(session);
        const finish = vi.fn();
        sessionFinishes.push(finish);
        vi.spyOn(session, "finish").mockImplementation(async (outcome) => {
          finish(outcome);
          return finishSession(outcome);
        });
        return session;
      });
      const service = new CodebaseMemoryIndexService(
        async () => ({ call: async () => ({ projects: [] }), close }),
        100,
        1_000,
        { loadBoundary: async () => boundary, scheduleJob }
      );

      await expect(service.index(repo, "start", () => repo)).rejects.toBe(cleanupError);

      expect(scheduleJob).not.toHaveBeenCalled();
      expect((await service.index(repo, "status", () => repo)).status).toBe("failed");
      expect(sessionFinishes[0]).toHaveBeenCalledOnce();
      expect(sessionFinishes[0]).toHaveBeenCalledWith(expect.objectContaining({ status: "failed", error: cleanupError }));
      expect(sessionFinishes[1]).toHaveBeenCalledOnce();
      const receipts = await readdir(fixture.receiptDirectory);
      expect(receipts).toHaveLength(2);
      const receiptResults = await Promise.all(receipts.map((receipt) =>
        readTaskExecutionReceipt(fixture.bootstrapPath, receipt.replace(/\.json$/, ""))
      ));
      expect(receiptResults).toEqual(expect.arrayContaining([
        expect.objectContaining({ operation_outcome: "failed", verdict: "NOT_PROVEN" }),
        expect.objectContaining({ operation_outcome: "completed", verdict: "NOT_PROVEN" })
      ]));
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("preserves provider and cleanup errors from an enrolled initial project check", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-index-provider-cleanup-failures-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary, readTaskExecutionReceipt } = await import("../src/services/task-execution-boundary.js");
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };
      const providerError = new Error("project lookup failed");
      const cleanupError = new Error("provider cleanup failed");
      const service = new CodebaseMemoryIndexService(
        async () => ({
          call: async () => { throw providerError; },
          close: async () => { throw cleanupError; }
        }),
        100,
        1_000,
        { loadBoundary: async () => new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot }) }
      );

      let failure: unknown;
      try {
        await service.index(repo, "start", () => repo);
      } catch (error) {
        failure = error;
      }

      expect(failure).toBeInstanceOf(AggregateError);
      expect((failure as AggregateError).errors).toEqual([providerError, cleanupError]);
      const receipts = await readdir(fixture.receiptDirectory);
      expect(receipts).toHaveLength(1);
      await expect(readTaskExecutionReceipt(fixture.bootstrapPath, receipts[0]!.replace(/\.json$/, "")))
        .resolves.toMatchObject({ operation_outcome: "failed", verdict: "NOT_PROVEN" });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("fails initial resolver errors before queueing and persists failed NOT_PROVEN evidence", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-index-resolver-recovery-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary, readTaskExecutionReceipt } = await import("../src/services/task-execution-boundary.js");
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      let registryCalls = 0;
      let scheduled: (() => Promise<void>) | undefined;
      const service = new CodebaseMemoryIndexService(
        async () => ({
          call: async (tool: string) => tool === "list_projects" ? { projects: [] } : { status: "indexed" },
          close: async () => undefined
        }),
        100,
        1_000,
        {
          loadBoundary: async () => boundary,
          scheduleJob: (job) => { scheduled = job; }
        }
      );

      const result = await codeIndexHandler({ repo_id: "fixture-repo", action: "start" }, {
        registry: {
          get: () => {
            registryCalls += 1;
            if (registryCalls === 2) throw new Error("registry temporarily unavailable");
            return repo;
          }
        },
        codeIntelligence: service
      } as unknown as RuntimeContext);

      expect(result.isError).toBe(true);
      expect(JSON.stringify(result)).not.toMatch(/"status":"(?:queued|ready)"/);
      expect(scheduled).toBeUndefined();
      expect(registryCalls).toBe(3);
      const status = await service.index(repo, "status", () => repo);
      expect(status.status).toBe("failed");
      const receipts = await readdir(fixture.receiptDirectory);
      expect(receipts).toHaveLength(2);
      const receiptResults = await Promise.all(receipts.map((receipt) =>
        readTaskExecutionReceipt(fixture.bootstrapPath, receipt.replace(/\.json$/, ""))
      ));
      expect(receiptResults).toEqual(expect.arrayContaining([
        expect.objectContaining({ operation_outcome: "failed", verdict: "NOT_PROVEN" }),
        expect.objectContaining({ operation_outcome: "completed", verdict: "NOT_PROVEN" })
      ]));
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("records a failed NOT_PROVEN receipt when postflight has no live registry resolver", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-postflight-no-resolver-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary, readTaskExecutionReceipt } = await import("../src/services/task-execution-boundary.js");
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });

      await expect(boundary.execute({
        registered_repo: { repo_id: "fixture-repo", root: fixture.executionRoot },
        operation: "index"
      }, async () => "queued work completed")).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      const receipts = await readdir(fixture.receiptDirectory);
      expect(receipts).toHaveLength(1);
      await expect(readTaskExecutionReceipt(fixture.bootstrapPath, receipts[0]!.replace(/\.json$/, "")))
        .resolves.toMatchObject({ operation_outcome: "failed", verdict: "NOT_PROVEN" });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("writes a runless repository review receipt with the runless receipt schema", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-repository-review-receipt-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary, readTaskExecutionReceipt } = await import("../src/services/task-execution-boundary.js");
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot };

      const execution = await boundary.execute({
        registered_repo: repo,
        resolve_registered_repo: () => repo,
        operation: "repository_review"
      }, async () => "review completed");

      await expect(readTaskExecutionReceipt(fixture.bootstrapPath, execution.evidence.operation_id))
        .resolves.toMatchObject({
          schema_version: 3,
          operation: "repository_review",
          operation_outcome: "completed",
          run_ids: [],
          run_bindings: [],
          verdict: "NOT_PROVEN"
        });
      const receipt = await readTaskExecutionReceipt(fixture.bootstrapPath, execution.evidence.operation_id) as Record<string, unknown>;
      expect(receipt).not.toHaveProperty("failure_code");
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test.each(["repo_git_review", "repo_semantic_review"] as const)(
    "%s resolves a runless multi-run enrollment to every owner run and writes a runless receipt",
    async (toolName) => {
      const workspace = await mkdtemp(join(tmpdir(), "task-multi-run-repository-review-"));
      try {
        const ownerRunIds = [
          "2026-11-01T120000Z-first-owner-run",
          "2026-11-01T120100Z-second-owner-run"
        ];
        const fixture = await writeBootstrap(workspace, { run_ids: ownerRunIds });
        const loaded = await loadTaskExecutionBootstrapAtPath(fixture.bootstrapPath);
        const request = taskExecutionPolicyFor(toolName)!({ repo_id: "fixture-repo" });
        const repo = { repo_id: "fixture-repo", root: fixture.executionRoot };

        expect(request.operation).toBe("repository_review");
        expect(request.run_id).toBeUndefined();
        expect(request.run_ids).toBeUndefined();
        expect(resolveRunIds(loaded.bootstrap, request)).toEqual(ownerRunIds);

        const boundary = new (await import("../src/services/task-execution-boundary.js")).TaskExecutionBoundary(
          fixture.bootstrapPath,
          { cwd: () => fixture.executionRoot }
        );
        const execution = await boundary.execute({
          ...request,
          registered_repo: repo,
          resolve_registered_repo: () => repo
        }, async (_root, taskExecution) => {
          expect(taskExecution.run_id).toBeUndefined();
          return "review completed";
        });

        expect(execution.result).toBe("review completed");
        await expect(loadTaskExecutionBootstrapAtPath(fixture.bootstrapPath))
          .resolves.toMatchObject({ bootstrap: { run_ids: ownerRunIds } });
        const { readTaskExecutionReceipt } = await import("../src/services/task-execution-boundary.js");
        await expect(readTaskExecutionReceipt(fixture.bootstrapPath, execution.evidence.operation_id))
          .resolves.toMatchObject({
            schema_version: 3,
            operation: "repository_review",
            operation_outcome: "completed",
            run_ids: [],
            run_bindings: [],
            verdict: "NOT_PROVEN"
          });
      } finally {
        await rm(workspace, { recursive: true, force: true });
      }
    }
  );

  test("rejects unauthorized run selectors for a repository review without changing its runless receipt format", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-unauthorized-repository-review-run-"));
    try {
      const ownerRunIds = [
        "2026-11-01T120000Z-first-owner-run",
        "2026-11-01T120100Z-second-owner-run"
      ];
      const fixture = await writeBootstrap(workspace, { run_ids: ownerRunIds });
      const { TaskExecutionBoundary, readTaskExecutionReceipt } = await import("../src/services/task-execution-boundary.js");
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot };
      const work = vi.fn(async () => "review completed");

      await expect(boundary.execute({
        registered_repo: repo,
        resolve_registered_repo: () => repo,
        operation: "repository_review",
        run_ids: [ownerRunIds[0]!, "2026-11-01T120200Z-unauthorized-run"]
      }, work)).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      expect(work).not.toHaveBeenCalled();
      const receipts = await readdir(fixture.receiptDirectory);
      expect(receipts).toHaveLength(1);
      await expect(readTaskExecutionReceipt(fixture.bootstrapPath, receipts[0]!.replace(/\.json$/, "")))
        .resolves.toMatchObject({
          schema_version: 3,
          operation: "repository_review",
          operation_outcome: "failed",
          run_ids: [],
          run_bindings: [],
          verdict: "NOT_PROVEN"
        });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("preserves single-run defaults and explicit repository review selection", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-repository-review-run-selection-"));
    try {
      const ownerRunIds = [
        "2026-11-01T120000Z-first-owner-run",
        "2026-11-01T120100Z-second-owner-run"
      ];
      const fixture = await writeBootstrap(workspace, { run_ids: ownerRunIds });
      const loaded = await loadTaskExecutionBootstrapAtPath(fixture.bootstrapPath);

      expect(resolveRunIds(loaded.bootstrap, { operation: "repository_review" })).toEqual(ownerRunIds);
      expect(resolveRunIds(loaded.bootstrap, { operation: "repository_review", run_id: ownerRunIds[1] }))
        .toEqual([ownerRunIds[1]]);

      const singleRunFixture = await writeBootstrap(join(workspace, "single-run"), { run_ids: [ownerRunIds[0]] });
      const singleRun = await loadTaskExecutionBootstrapAtPath(singleRunFixture.bootstrapPath);
      expect(resolveRunIds(singleRun.bootstrap, { operation: "repository_review" })).toEqual([ownerRunIds[0]]);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("blocks prompt binding when owner enrollment changes after boundary entry", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-prompt-binding-env-change-"));
    const api = await import("../src/services/task-execution-boundary.js");
    try {
      const fixture = await writeBootstrap(workspace);
      const environment: NodeJS.ProcessEnv = { [api.TASK_EXECUTION_BOOTSTRAP_ENV]: fixture.bootstrapPath };
      const boundary = new api.TaskExecutionBoundary(
        fixture.bootstrapPath,
        { cwd: () => fixture.executionRoot },
        environment
      );
      const writePrompt = vi.fn();
      await expect(boundary.execute({
        registered_repo: { repo_id: "fixture-repo", root: fixture.executionRoot },
        resolve_registered_repo: () => ({ repo_id: "fixture-repo", root: fixture.executionRoot }),
        operation: "registration",
        run_id: fixture.descriptor.run_ids[0]
      }, async (_root, taskExecution) => {
        delete environment[api.TASK_EXECUTION_BOOTSTRAP_ENV];
        const prompt = await taskExecution.bindTaskPrompt(
          "prepared task prompt",
          "fixture-repo",
          fixture.descriptor.run_ids[0] as string,
          ["src/**"]
        );
        writePrompt(prompt);
        return "wrote prompt";
      })).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
      expect(writePrompt).not.toHaveBeenCalled();
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("rejects registration baseline drift before writing v3 task artifacts", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-registration-stale-baseline-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const runId = fixture.descriptor.run_ids[0] as string;
      const api = await import("../src/services/task-execution-boundary.js");
      const { DelegationV3TaskService } = await import("../src/services/delegation-v3-task-service.js");
      const { PathSandbox } = await import("../src/services/path-sandbox.js");
      const { WritePolicy } = await import("../src/services/write-policy.js");
      const { securityTaskInput } = await import("./fixtures/delegation-v3-fixtures.js");
      const { codexRunPaths } = await import("../src/services/codex-run-paths.js");
      const paths = codexRunPaths(runId);
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot };
      const boundary = new api.TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      await mkdir(join(fixture.executionRoot, "src"), { recursive: true });
      await writeFile(join(fixture.executionRoot, "src/drift.ts"), "untracked baseline drift\n");
      expect((await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: fixture.executionRoot })).stdout.trim())
        .toBe(fixture.descriptor.expected_baseline.head_sha);

      let rejection: unknown;
      try {
        await boundary.execute({
          registered_repo: repo,
          resolve_registered_repo: () => repo,
          operation: "registration",
          run_id: runId
        }, async (_root, taskExecution) => {
          const taskService = new DelegationV3TaskService(
            fixture.executionRoot,
            new PathSandbox(fixture.executionRoot),
            new WritePolicy({ enabled: true, allowed_globs: [".chatgpt/codex-runs/**"] }),
            undefined,
            taskExecution.bindTaskPrompt
          );
          return taskService.write({ ...securityTaskInput(), repo_id: repo.repo_id, run_id: runId });
        });
      } catch (error) {
        rejection = error;
      }

      const existingArtifacts = (await Promise.all(
        [paths.promptPath, paths.manifestPath, paths.reviewGatePath].map(async (artifactPath) => {
          try {
            await access(join(fixture.executionRoot, artifactPath));
            return artifactPath;
          } catch {
            return undefined;
          }
        })
      )).filter((artifactPath): artifactPath is string => artifactPath !== undefined);
      const diagnostics = rejection && typeof rejection === "object" && "diagnostics" in rejection
        ? rejection.diagnostics as { reason?: unknown }
        : undefined;
      expect({
        errorCode: rejection && typeof rejection === "object" && "code" in rejection ? rejection.code : undefined,
        reason: diagnostics?.reason,
        existingArtifacts
      }).toEqual({
        errorCode: "RUNNER_POLICY_BLOCKED",
        reason: "v3_registration_baseline_mismatch",
        existingArtifacts: []
      });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("uses the owner run set for queued repository indexing", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-index-multi-run-"));
    const runIds = ["2026-11-01T120301Z-index-first", "2026-11-01T120302Z-index-second"];
    try {
      const fixture = await writeBootstrap(workspace, { run_ids: runIds });
      const { TaskExecutionBoundary } = await import("../src/services/task-execution-boundary.js");
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      let scheduled: (() => Promise<void>) | undefined;
      const calls: string[] = [];
      const service = new CodebaseMemoryIndexService(
        async () => ({
          call: async (tool: string) => {
            calls.push(tool);
            return tool === "list_projects" ? { projects: [] } : { status: "indexed" };
          },
          close: async () => undefined
        }),
        100,
        1_000,
        {
          loadBoundary: async () => boundary,
          scheduleJob: (job) => { scheduled = job; }
        }
      );

      await expect(service.index(repo, "start", () => repo)).resolves.toMatchObject({ status: "queued" });
      await scheduled?.();
      expect(calls).toEqual(["list_projects", "index_repository"]);
      const receiptIds = await readdir(fixture.receiptDirectory);
      const receiptApi = await import("../src/services/task-execution-boundary.js");
      await expect(receiptApi.readTaskExecutionReceipt(fixture.bootstrapPath, receiptIds[0]!.replace(/\.json$/, "")))
        .resolves.toMatchObject({ run_ids: runIds, operation: "index" });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("waits for provider close before finishing preservation and rejects postflight failure", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-index-close-before-postflight-"));
    let releaseClose: () => void = () => {};
    let closeStartedResolve: () => void = () => {};
    const closeStarted = new Promise<void>((resolve) => { closeStartedResolve = resolve; });
    const closeGate = new Promise<void>((resolve) => { releaseClose = resolve; });
    try {
      const fixture = await writeBootstrap(workspace);
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };
      const session = {
        execution_root: fixture.executionRoot,
        revalidateBeforeProvider: vi.fn(async () => undefined),
        finish: vi.fn(async () => { throw new Error("postflight collection failed"); })
      };
      const cachedStatusSession = {
        execution_root: fixture.executionRoot,
        revalidateBeforeProvider: vi.fn(async () => undefined),
        finish: vi.fn(async () => undefined)
      };
      let beginCount = 0;
      let clientCount = 0;
      let scheduled: (() => Promise<void>) | undefined;
      const service = new CodebaseMemoryIndexService(
        async () => {
          const clientNumber = ++clientCount;
          return {
            call: async (tool: string) => tool === "list_projects" ? { projects: [] } : { status: "indexed" },
            close: async () => {
              if (clientNumber === 2) {
                closeStartedResolve();
                await closeGate;
              }
            }
          };
        },
        100,
        1_000,
        {
          loadBoundary: async () => ({ begin: async () => beginCount++ === 0 ? session : cachedStatusSession } as never),
          scheduleJob: (job) => { scheduled = job; }
        }
      );

      await expect(service.index(repo, "start", () => repo)).resolves.toMatchObject({ status: "queued" });
      const run = scheduled?.();
      expect(run).toBeDefined();
      await closeStarted;
      try {
        expect(session.finish).not.toHaveBeenCalled();
      } finally {
        releaseClose();
      }
      await run;

      expect(session.finish).toHaveBeenCalledOnce();
      expect((await service.index(repo, "status", () => repo)).status).toBe("failed");
      expect(cachedStatusSession.finish).toHaveBeenCalledOnce();
    } finally {
      releaseClose();
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("captures provider cleanup failures in the task outcome", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-index-cleanup-failure-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };
      const cleanupError = Object.assign(new Error("provider close failed"), { code: "EACCES" });
      const session = {
        execution_root: fixture.executionRoot,
        revalidateBeforeProvider: vi.fn(async () => undefined),
        finish: vi.fn(async () => undefined)
      };
      let clientCount = 0;
      let scheduled: (() => Promise<void>) | undefined;
      const service = new CodebaseMemoryIndexService(
        async () => {
          const clientNumber = ++clientCount;
          return {
            call: async (tool: string) => tool === "list_projects" ? { projects: [] } : { status: "indexed" },
            close: async () => {
              if (clientNumber === 2) throw cleanupError;
            }
          };
        },
        100,
        1_000,
        {
          loadBoundary: async () => ({ begin: async () => session } as never),
          scheduleJob: (job) => { scheduled = job; }
        }
      );

      await expect(service.index(repo, "start", () => repo)).resolves.toMatchObject({ status: "queued" });
      await scheduled?.();

      expect(session.finish).toHaveBeenCalledOnce();
      expect(session.finish).toHaveBeenCalledWith({ status: "failed", error: cleanupError });
      expect((await service.index(repo, "status")).status).toBe("failed");
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("does not retry a task session after postflight finish fails", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-index-finish-once-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };
      const session = {
        execution_root: fixture.executionRoot,
        revalidateBeforeProvider: vi.fn(async () => undefined),
        finish: vi.fn(async () => { throw new Error("postflight collection failed"); })
      };
      const service = new CodebaseMemoryIndexService(
        async () => ({
          call: async () => ({ projects: [{ name: "fixture", root_path: fixture.executionRoot }] }),
          close: async () => undefined
        }),
        100,
        1_000,
        { loadBoundary: async () => ({ begin: async () => session } as never) }
      );

      await expect(service.index(repo, "start", () => repo)).rejects.toThrow("postflight collection failed");
      expect(session.finish).toHaveBeenCalledTimes(1);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("rejects an invalid registered root before querying the indexing provider", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-index-invalid-root-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary } = await import("../src/services/task-execution-boundary.js");
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const calls: string[] = [];
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const service = new CodebaseMemoryIndexService(
        async () => {
          calls.push("client_factory");
          return {
            call: async (tool: string) => { calls.push(tool); return { projects: [] }; },
            close: async () => undefined
          };
        },
        100,
        1_000,
        { loadBoundary: async () => boundary }
      );
      const wrongRepo = { repo_id: "fixture-repo", root: fixture.primaryRoot, display_name: "Wrong root" };

      await expect(service.index(wrongRepo, "start", () => wrongRepo))
        .rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
      expect(calls).toEqual([]);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("rechecks owner bootstrap selection after indexing waits in the queue", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-index-bootstrap-change-"));
    const previous = process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
    try {
      const fixture = await writeBootstrap(workspace);
      const { createTaskExecutionBoundaryFromEnvironment, readTaskExecutionReceipt } = await import("../src/services/task-execution-boundary.js");
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = fixture.bootstrapPath;
      const boundary = await createTaskExecutionBoundaryFromEnvironment(process.env, { cwd: () => fixture.executionRoot });
      if (!boundary) throw new Error("Owner enrollment was not loaded.");
      let scheduled: (() => Promise<void>) | undefined;
      const calls: string[] = [];
      const service = new CodebaseMemoryIndexService(
        async () => ({
          call: async (tool: string) => {
            calls.push(tool);
            return tool === "list_projects" ? { projects: [] } : { status: "indexed" };
          },
          close: async () => undefined
        }),
        100,
        1_000,
        {
          loadBoundary: async () => boundary,
          scheduleJob: (job) => { scheduled = job; }
        }
      );
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot, display_name: "Fixture" };

      expect((await service.index(repo, "start", () => repo)).status).toBe("queued");
      delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      await scheduled?.();

      expect(calls).toEqual(["list_projects"]);
      const receipts = await readdir(fixture.receiptDirectory);
      expect(receipts).toHaveLength(1);
      await expect(readTaskExecutionReceipt(fixture.bootstrapPath, receipts[0]!.replace(/\.json$/, "")))
        .resolves.toMatchObject({ operation_outcome: "failed", verdict: "NOT_PROVEN" });
    } finally {
      if (previous === undefined) delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      else process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = previous;
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("records incomplete preservation inventory without blocking authorized work", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-incomplete-inventory-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary, readTaskExecutionReceipt } = await import("../src/services/task-execution-boundary.js");
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, {
        cwd: () => fixture.executionRoot,
        run_git: async (root, args) => {
          if (args.join(" ") === "ls-files --others --exclude-standard -z") {
            throw new Error("fixture inventory unavailable");
          }
          const { stdout } = await execFileAsync("git", args, { cwd: root });
          return Buffer.from(stdout);
        }
      });
      const work = vi.fn(async () => "authorized work ran");

      const result = await boundary.execute({
        registered_repo: { repo_id: "fixture-repo", root: fixture.executionRoot },
        resolve_registered_repo: () => ({ repo_id: "fixture-repo", root: fixture.executionRoot }),
        operation: "validation",
        run_id: "2026-11-01T120000Z-fixture-run"
      }, work);
      const receipt = await readTaskExecutionReceipt(fixture.bootstrapPath, result.evidence.operation_id) as {
        verdict: string;
        pre: { inventory_complete: boolean };
      };

      expect(result.result).toBe("authorized work ran");
      expect(work).toHaveBeenCalledOnce();
      expect(receipt).toMatchObject({ verdict: "NOT_PROVEN", pre: { inventory_complete: false } });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("verifies written V3 registration artifacts before completing the task boundary", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-v3-registration-postflight-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const { TaskExecutionBoundary } = await import("../src/services/task-execution-boundary.js");
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const work = vi.fn(async () => "registration returned");

      await expect(boundary.execute({
        registered_repo: { repo_id: "fixture-repo", root: fixture.executionRoot },
        operation: "registration",
        run_id: "2026-11-01T120000Z-fixture-run"
      }, work)).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
      expect(work).toHaveBeenCalledOnce();
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("persists a bounded NOT_PROVEN receipt with keyed path tokens and verifies its integrity", async () => {
    const api = await import("../src/services/task-execution-boundary.js") as unknown as {
      TaskExecutionBoundary?: new (bootstrapPath: string, options?: { cwd?: () => string }) => {
        execute<T>(input: unknown, work: () => Promise<T>): Promise<{ result: T; evidence: { operation_id: string; receipt_sha256: string } }>;
      };
      loadTaskExecutionBootstrapFromEnvironment?: (env: NodeJS.ProcessEnv) => Promise<unknown>;
      readTaskExecutionReceipt?: (bootstrapPath: string, operationId: string) => Promise<unknown>;
    };
    expect(api.TaskExecutionBoundary).toBeTypeOf("function");
    expect(api.readTaskExecutionReceipt).toBeTypeOf("function");
    if (!api.TaskExecutionBoundary || !api.readTaskExecutionReceipt) return;

    const workspace = await mkdtemp(join(tmpdir(), "task-receipt-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const boundary = new api.TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const repo = { repo_id: "fixture-repo", root: fixture.executionRoot };
      const result = await boundary.execute({
        registered_repo: repo,
        resolve_registered_repo: () => repo,
        operation: "validation",
        run_id: "2026-11-01T120000Z-fixture-run"
      }, async () => "done");
      const receipt = await api.readTaskExecutionReceipt(fixture.bootstrapPath, result.evidence.operation_id) as {
        verdict: string;
        task_id: string;
        run_id: string;
        identity: Record<string, unknown>;
        pre: { protected_metadata: Array<{ path_token: string }> };
        integrity: { sha256: string };
      };

      expect(result.result).toBe("done");
      expect(receipt).toMatchObject({ verdict: "NOT_PROVEN", task_id: "fixture-task", run_id: "2026-11-01T120000Z-fixture-run" });
      expect(JSON.stringify(receipt)).not.toContain(fixture.primaryRoot);
      expect(JSON.stringify(receipt)).not.toContain("private/config.json");
      expect(receipt.pre.protected_metadata[0]?.path_token).toMatch(/^path:[a-f0-9]{64}$/);
      expect(receipt.integrity.sha256).toBe(result.evidence.receipt_sha256);

      const receiptPath = join(fixture.receiptDirectory, `${result.evidence.operation_id}.json`);
      const persisted = JSON.parse(await readFile(receiptPath, "utf8")) as Record<string, unknown>;
      persisted.task_id = "changed";
      await writeFile(receiptPath, JSON.stringify(persisted));
      await expect(api.readTaskExecutionReceipt(fixture.bootstrapPath, result.evidence.operation_id))
        .rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("refuses to publish a receipt after the external directory is replaced by a symlink", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-receipt-symlink-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const outsideDirectory = join(workspace, "outside-receipts");
      await mkdir(outsideDirectory, { mode: 0o700 });
      const { TaskExecutionBoundary } = await import("../src/services/task-execution-boundary.js");
      const boundary = new TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });

      await expect(boundary.execute({
        registered_repo: { repo_id: "fixture-repo", root: fixture.executionRoot },
        operation: "validation",
        run_id: "2026-11-01T120000Z-fixture-run"
      }, async () => {
        await rm(fixture.receiptDirectory, { recursive: true, force: true });
        await symlink(outsideDirectory, fixture.receiptDirectory);
        return "operation completed";
      })).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
      expect(await readdir(outsideDirectory)).toEqual([]);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("persists failed operation evidence as NOT_PROVEN", async () => {
    const api = await import("../src/services/task-execution-boundary.js");
    const workspace = await mkdtemp(join(tmpdir(), "task-failure-receipt-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const boundary = new api.TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      await expect(boundary.execute({
        registered_repo: { repo_id: "fixture-repo", root: fixture.executionRoot },
        operation: "validation",
        run_id: "2026-11-01T120000Z-fixture-run"
      }, async () => {
        throw Object.assign(new Error("fixture operation failed"), { code: "EACCES" });
      })).rejects.toThrow("fixture operation failed");

      const receiptFiles = await readdir(fixture.receiptDirectory);
      expect(receiptFiles).toHaveLength(1);
      const operationId = receiptFiles[0]!.replace(/\.json$/, "");
      const receipt = await api.readTaskExecutionReceipt(fixture.bootstrapPath, operationId);
      expect(receipt).toMatchObject({
        operation_outcome: "failed",
        failure_code: "filesystem_access_denied",
        verdict: "NOT_PROVEN"
      });
      expect((receipt as { comparison: { attribution: { not_proven: string[] } } }).comparison.attribution.not_proven)
        .toContain("operation_failed");
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("rejects a registered repo_id mapped to another execution root before work starts", async () => {
    const api = await import("../src/services/task-execution-boundary.js") as unknown as {
      TaskExecutionBoundary?: new (bootstrapPath: string, options?: { cwd?: () => string }) => {
        execute<T>(input: unknown, work: () => Promise<T>): Promise<{ result: T }>;
      };
    };
    expect(api.TaskExecutionBoundary).toBeTypeOf("function");
    if (!api.TaskExecutionBoundary) return;

    const workspace = await mkdtemp(join(tmpdir(), "task-registration-binding-"));
    try {
      const fixture = await writeBootstrap(workspace);
      const boundary = new api.TaskExecutionBoundary(fixture.bootstrapPath);
      const work = vi.fn(async () => "must not run");
      await expect(boundary.execute({
        registered_repo: { repo_id: "fixture-repo", root: fixture.primaryRoot },
        operation: "review",
        run_id: "2026-11-01T120000Z-fixture-run"
      }, work)).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
      expect(work).not.toHaveBeenCalled();
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("binds strict V3 prompt, manifest, baseline, and authorized source set to the live registration", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-v3-binding-"));
    const taskFixtures = await import("./fixtures/delegation-v3-fixtures.js");
    const { codexRunPaths } = await import("../src/services/codex-run-paths.js");
    const { sha256Text } = await import("../src/services/codex-task-policy.js");
    const api = await import("../src/services/task-execution-boundary.js");
    const runId = taskFixtures.DELEGATION_V3_FIXTURE_RUN_ID;
    try {
      const fixture = await writeBootstrap(workspace, { run_ids: [runId], repo_id: "fixture" });
      const paths = codexRunPaths(runId);
      const boundRun = await writeBoundV3Run(fixture, runId);
      const manifest = boundRun.manifest;
      const promptPath = join(fixture.executionRoot, paths.promptPath);
      const manifestPath = join(fixture.executionRoot, paths.manifestPath);
      const originalPrompt = boundRun.originalPrompt;
      const boundPrompt = boundRun.prompt;
      const boundManifest = manifest;
      const loaded = await api.loadTaskExecutionBootstrapFromEnvironment({
        [api.TASK_EXECUTION_BOOTSTRAP_ENV]: fixture.bootstrapPath
      });
      expect(loaded).toBeDefined();
      if (!loaded) return;
      const registeredRepo = { repo_id: manifest.repo_id, root: fixture.executionRoot };

      await expect(api.verifyTaskV3RunBinding({ loaded, registered_repo: registeredRepo, run_id: runId })).resolves.toMatchObject({
        run_id: runId,
        baseline_sha256: manifest.baseline_sha256,
        prompt_sha256: manifest.prompt_sha256
      });
      await expect(api.bindTaskPromptIfEnrolled(
        originalPrompt,
        manifest.repo_id,
        runId,
        ["private/config.json"],
        { [api.TASK_EXECUTION_BOOTSTRAP_ENV]: fixture.bootstrapPath }
      )).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
      await expect(api.bindTaskPromptIfEnrolled(
        originalPrompt,
        manifest.repo_id,
        runId,
        ["src/actual-file.ts"],
        { [api.TASK_EXECUTION_BOOTSTRAP_ENV]: fixture.bootstrapPath }
      )).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
      await expect(api.verifyTaskV3RunBinding({
        loaded,
        registered_repo: { ...registeredRepo, root: fixture.primaryRoot },
        run_id: runId
      })).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      const incompleteBinding = await api.bindTaskPromptIfEnrolled(
        originalPrompt,
        manifest.repo_id,
        runId,
        manifest.task.starting_points,
        { [api.TASK_EXECUTION_BOOTSTRAP_ENV]: fixture.bootstrapPath }
      );
      await writeFile(promptPath, incompleteBinding);
      const incompleteManifest = {
        ...boundManifest,
        prompt_sha256: sha256Text(incompleteBinding),
        prompt_byte_count: Buffer.byteLength(incompleteBinding, "utf8")
      };
      await writeFile(manifestPath, `${JSON.stringify(incompleteManifest, null, 2)}\n`);
      await expect(api.verifyTaskV3RunBinding({ loaded, registered_repo: registeredRepo, run_id: runId }))
        .rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      await writeFile(promptPath, `${boundPrompt}tampered`);
      await expect(api.verifyTaskV3RunBinding({ loaded, registered_repo: registeredRepo, run_id: runId }))
        .rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      await writeFile(promptPath, boundPrompt);
      await writeFile(manifestPath, `${JSON.stringify({ ...boundManifest, task_sha256: "f".repeat(64) }, null, 2)}\n`);
      await expect(api.verifyTaskV3RunBinding({ loaded, registered_repo: registeredRepo, run_id: runId }))
        .rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      await writeFile(manifestPath, `${JSON.stringify({ ...boundManifest, baseline_sha256: "f".repeat(64) }, null, 2)}\n`);
      await expect(api.verifyTaskV3RunBinding({ loaded, registered_repo: registeredRepo, run_id: runId }))
        .rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      const changedBaseline = { ...boundManifest.baseline, head_sha: "f".repeat(40) };
      const { delegationBaselineSha256V3 } = await import("../src/services/delegation-v3-normalizer.js");
      await writeFile(manifestPath, `${JSON.stringify({ ...boundManifest, baseline: {
        ...changedBaseline
      }, baseline_sha256: delegationBaselineSha256V3(changedBaseline) }, null, 2)}\n`);
      await expect(api.verifyTaskV3RunBinding({ loaded, registered_repo: registeredRepo, run_id: runId }))
        .rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });

      await writeFile(manifestPath, `${JSON.stringify({ ...boundManifest, unrecognized: true }, null, 2)}\n`);
      await expect(api.verifyTaskV3RunBinding({ loaded, registered_repo: registeredRepo, run_id: runId }))
        .rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("rejects recomputed V3 fingerprint and path-state changes before the handler runs", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-v3-owner-baseline-pin-"));
    const fingerprintRunId = "2026-11-01T120101Z-fingerprint-change";
    const pathStateRunId = "2026-11-01T120102Z-path-state-change";
    const api = await import("../src/services/task-execution-boundary.js");
    try {
      const primaryRoot = join(workspace, "protected");
      const executionRoot = join(workspace, "execution");
      await initRepo(primaryRoot);
      await initRepo(executionRoot);
      await mkdir(join(executionRoot, "src"), { recursive: true });
      await writeFile(join(executionRoot, "src/owner-baseline.ts"), "owner-observed state\n");
      const fixture = await writeBootstrapForRoots(workspace, primaryRoot, executionRoot, {
        run_ids: [fingerprintRunId, pathStateRunId],
        repo_id: "fixture",
        authorized_source_paths: ["src/**", "tests/**", "docs/**", "src/owner-baseline.ts"]
      });
      expect(fixture.baseline.initial_changed_paths).toEqual(["src/owner-baseline.ts"]);
      expect(fixture.baseline.initial_path_states).toHaveLength(1);

      const fingerprintManifest = await writeBoundV3Run(fixture, fingerprintRunId, {
        ...fixture.baseline,
        worktree_fingerprint: "recomputed-fingerprint"
      });
      const originalPathState = fixture.baseline.initial_path_states[0]!;
      const pathStateManifest = await writeBoundV3Run(fixture, pathStateRunId, {
        ...fixture.baseline,
        initial_path_states: [{ ...originalPathState, content_sha256: "c".repeat(64) }]
      });
      expect(fingerprintManifest.manifest.baseline_sha256).not.toBe(fixture.descriptor.expected_baseline.baseline_sha256);
      expect(pathStateManifest.manifest.baseline_sha256).not.toBe(fixture.descriptor.expected_baseline.baseline_sha256);

      const runGit = vi.fn(async () => Buffer.alloc(0));
      const handler = vi.fn(async () => "must not run");
      for (const runId of [fingerprintRunId, pathStateRunId]) {
        const boundary = new api.TaskExecutionBoundary(fixture.bootstrapPath, {
          cwd: () => fixture.executionRoot,
          run_git: runGit
        });
        await expect(boundary.execute({
          registered_repo: { repo_id: "fixture", root: fixture.executionRoot },
          operation: "review",
          run_id: runId
        }, handler)).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
      }
      expect(handler).not.toHaveBeenCalled();
      expect(runGit).not.toHaveBeenCalled();
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("records every verified run and its baseline and prompt digests in multi-run receipts", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-v3-multi-run-receipt-"));
    const runIds = ["2026-11-01T120201Z-review-first", "2026-11-01T120202Z-review-second"];
    const api = await import("../src/services/task-execution-boundary.js");
    try {
      const fixture = await writeBootstrap(workspace, { run_ids: runIds, repo_id: "fixture" });
      const runs = await Promise.all(runIds.map((runId) => writeBoundV3Run(fixture, runId)));
      const boundary = new api.TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const execution = await boundary.execute({
        registered_repo: { repo_id: "fixture", root: fixture.executionRoot },
        resolve_registered_repo: () => ({ repo_id: "fixture", root: fixture.executionRoot }),
        operation: "review",
        run_ids: runIds
      }, async () => "reviewed both runs");
      const receipt = await api.readTaskExecutionReceipt(fixture.bootstrapPath, execution.evidence.operation_id) as {
        schema_version: number;
        run_id: string;
        run_ids: string[];
        run_bindings: Array<{ run_id: string; baseline_sha256: string; prompt_sha256: string }>;
      };

      expect(receipt.schema_version).toBe(2);
      expect(receipt.run_id).toBe(runIds[0]);
      expect(receipt.run_ids).toEqual(runIds);
      expect(receipt.run_bindings).toEqual(runs.map(({ manifest }) => ({
        run_id: manifest.run_id,
        baseline_sha256: manifest.baseline_sha256,
        prompt_sha256: manifest.prompt_sha256
      })));
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("continues to read a valid version 1 preservation receipt", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-receipt-v1-compatibility-"));
    const api = await import("../src/services/task-execution-boundary.js");
    try {
      const fixture = await writeBootstrap(workspace);
      const boundary = new api.TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const execution = await boundary.execute({
        registered_repo: { repo_id: "fixture-repo", root: fixture.executionRoot },
        resolve_registered_repo: () => ({ repo_id: "fixture-repo", root: fixture.executionRoot }),
        operation: "validation",
        run_id: fixture.descriptor.run_ids[0]
      }, async () => "validated");
      const receiptPath = join(fixture.receiptDirectory, `${execution.evidence.operation_id}.json`);
      const legacy = JSON.parse(await readFile(receiptPath, "utf8")) as Record<string, unknown>;
      legacy.schema_version = 1;
      delete legacy.run_ids;
      delete legacy.run_bindings;
      const core = Object.fromEntries(Object.entries(legacy).filter(([key]) => key !== "integrity"));
      legacy.integrity = {
        algorithm: "sha256",
        sha256: createHash("sha256").update(JSON.stringify(core), "utf8").digest("hex")
      };
      await writeFile(receiptPath, `${JSON.stringify(legacy, null, 2)}\n`);

      await expect(api.readTaskExecutionReceipt(fixture.bootstrapPath, execution.evidence.operation_id))
        .resolves.toMatchObject({ schema_version: 1, run_id: fixture.descriptor.run_ids[0] });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("records a failed receipt when a multi-run review has no explicit selection", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-review-run-selection-"));
    const runIds = ["2026-11-01T120401Z-review-first", "2026-11-01T120402Z-review-second"];
    const api = await import("../src/services/task-execution-boundary.js");
    try {
      const fixture = await writeBootstrap(workspace, { run_ids: runIds, repo_id: "fixture" });
      const boundary = new api.TaskExecutionBoundary(fixture.bootstrapPath, { cwd: () => fixture.executionRoot });
      const handler = vi.fn(async () => "must not run");
      await expect(boundary.execute({
        registered_repo: { repo_id: "fixture", root: fixture.executionRoot },
        operation: "review"
      }, handler)).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
      expect(handler).not.toHaveBeenCalled();
      const receiptFiles = await readdir(fixture.receiptDirectory);
      expect(receiptFiles).toHaveLength(1);
      await expect(api.readTaskExecutionReceipt(fixture.bootstrapPath, receiptFiles[0]!.replace(/\.json$/, "")))
        .resolves.toMatchObject({
          operation_outcome: "failed",
          run_ids: runIds,
          run_bindings: []
        });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
});

describe("central task execution MCP seam", () => {
  async function setup(
    workspace: string,
    registeredRoot: (fixture: Awaited<ReturnType<typeof writeBootstrap>>) => string = (fixture) => fixture.executionRoot,
    toolName = "repo_validate",
    bootstrapOverrides: Record<string, unknown> = {}
  ) {
    const fixture = await writeBootstrap(workspace, bootstrapOverrides);
    const { registerCatalogTool } = await import("../src/tools/define-tool.js");
    const { toolRegistry } = await import("../src/tools/registry.js");
    const handler = vi.fn(async () => ({
      structuredContent: { ok: true },
      content: [{ type: "text" as const, text: "validated" }]
    }));
    const catalogDefinition = toolRegistry.find((candidate) => candidate.name === toolName);
    if (!catalogDefinition) throw new Error(`Unknown test tool: ${toolName}`);
    const definition = { ...catalogDefinition, handler } as never;
    let invoke: ((args: unknown) => Promise<unknown>) | undefined;
    const server = {
      registerTool: (_name: string, _configuration: unknown, callback: (args: unknown) => Promise<unknown>) => {
        invoke = callback;
      }
    } as never;
    const context = {
      registry: {
        get(repoId: string) {
          return { repo_id: repoId, root: registeredRoot(fixture), display_name: "Fixture" };
        }
      }
    } as never;
    registerCatalogTool(server, context, definition);
    if (!invoke) throw new Error("Tool registration did not retain its handler.");
    return { fixture, handler, invoke };
  }

  test("uses the owner descriptor and live registry root while ignoring caller root fields", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-registration-seam-"));
    const previous = process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
    try {
      const { fixture, handler, invoke } = await setup(workspace);
      process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = fixture.bootstrapPath;
      const response = await invoke({ repo_id: "fixture-repo", profile: "test", dry_run: true });
      expect(handler).toHaveBeenCalledOnce();
      expect(response).toMatchObject({ structuredContent: { ok: true } });
      expect(await readdir(fixture.receiptDirectory)).toHaveLength(1);
    } finally {
      if (previous === undefined) delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      else process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = previous;
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("blocks work when the registered repo ID no longer maps to the enrolled root", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-registration-mismatch-"));
    const previous = process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
    try {
      const setupResult = await setup(workspace, (fixture) => fixture.primaryRoot);
      process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = setupResult.fixture.bootstrapPath;
      const response = await setupResult.invoke({ repo_id: "fixture-repo" }) as { isError?: boolean };
      expect(response.isError).toBe(true);
      expect(setupResult.handler).not.toHaveBeenCalled();
    } finally {
      if (previous === undefined) delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      else process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = previous;
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("completes enrolled patchset review without selecting unrelated V3 runs", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-patchset-review-no-run-selection-"));
    const previous = process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
    const runIds = ["2026-11-01T120501Z-patchset-first", "2026-11-01T120502Z-patchset-second"];
    try {
      const { fixture, handler, invoke } = await setup(
        workspace,
        undefined,
        "repo_review_patchset",
        { run_ids: runIds }
      );
      process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = fixture.bootstrapPath;

      const response = await invoke({ repo_id: "fixture-repo", patchset_id: "patchset-fixture" });

      expect(handler).toHaveBeenCalledOnce();
      expect(response).toMatchObject({ structuredContent: { ok: true } });
      const receiptFiles = await readdir(fixture.receiptDirectory);
      expect(receiptFiles).toHaveLength(1);
      const api = await import("../src/services/task-execution-boundary.js");
      await expect(api.readTaskExecutionReceipt(fixture.bootstrapPath, receiptFiles[0]!.replace(/\.json$/, "")))
        .resolves.toMatchObject({
          schema_version: 3,
          operation: "patchset_review",
          operation_outcome: "completed",
          run_ids: [],
          run_bindings: [],
          identity: { status: "verified" }
        });
    } finally {
      if (previous === undefined) delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      else process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = previous;
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("blocks enrolled patchset review when the registered root is wrong", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-patchset-review-wrong-root-"));
    const previous = process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
    try {
      const { fixture, handler, invoke } = await setup(
        workspace,
        (value) => value.primaryRoot,
        "repo_review_patchset",
        { run_ids: ["2026-11-01T120503Z-patchset-run"] }
      );
      process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = fixture.bootstrapPath;

      const response = await invoke({ repo_id: "fixture-repo", patchset_id: "patchset-fixture" }) as { isError?: boolean };

      expect(response.isError).toBe(true);
      expect(handler).not.toHaveBeenCalled();
    } finally {
      if (previous === undefined) delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      else process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = previous;
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("fails closed for repo_review_patchset when the owner bootstrap is malformed", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-patchset-review-"));
    const previous = process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
    try {
      const { fixture, handler, invoke } = await setup(workspace, undefined, "repo_review_patchset");
      await writeFile(fixture.bootstrapPath, "{");
      process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = fixture.bootstrapPath;

      const response = await invoke({ repo_id: "fixture-repo", patchset_id: "patchset-fixture" }) as { isError?: boolean };

      expect(response.isError).toBe(true);
      expect(handler).not.toHaveBeenCalled();
    } finally {
      if (previous === undefined) delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      else process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = previous;
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("keeps repo_review_patchset behavior ordinary when no owner bootstrap is enrolled", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-patchset-review-ordinary-"));
    const previous = process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
    try {
      const { handler, invoke } = await setup(workspace, undefined, "repo_review_patchset");
      delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;

      const response = await invoke({ repo_id: "fixture-repo", patchset_id: "patchset-fixture" });

      expect(handler).toHaveBeenCalledOnce();
      expect(response).toMatchObject({ structuredContent: { ok: true } });
    } finally {
      if (previous === undefined) delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      else process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = previous;
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("fails closed when the enrollment variable is present but empty", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-empty-bootstrap-path-"));
    const previous = process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
    try {
      const { handler, invoke } = await setup(workspace, undefined, "repo_review_patchset");
      process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = "";

      const response = await invoke({ repo_id: "fixture-repo", patchset_id: "patchset-fixture" }) as { isError?: boolean };

      expect(response.isError).toBe(true);
      expect(handler).not.toHaveBeenCalled();
    } finally {
      if (previous === undefined) delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      else process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = previous;
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("rejects an authorized source path with a Windows drive prefix after a POSIX separator", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-execution-path-validation-"));
    try {
      const primaryRoot = join(workspace, "primary");
      const executionRoot = join(workspace, "execution");
      await initRepo(primaryRoot);
      await initRepo(executionRoot);
      const fixture = await writeBootstrapForRoots(workspace, primaryRoot, executionRoot);
      await expect(loadTaskExecutionBootstrapAtPath(fixture.bootstrapPath)).resolves.toBeDefined();

      await writeFile(fixture.bootstrapPath, JSON.stringify({
        ...fixture.descriptor,
        authorized_source_paths: ["src/C:secret"]
      }), { mode: 0o600 });

      await expect(loadTaskExecutionBootstrapAtPath(fixture.bootstrapPath)).rejects.toThrow();

      await writeFile(fixture.bootstrapPath, JSON.stringify({
        ...fixture.descriptor,
        authorized_source_paths: ["src/readme:notes.md"]
      }), { mode: 0o600 });

      await expect(loadTaskExecutionBootstrapAtPath(fixture.bootstrapPath)).resolves.toBeDefined();
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("allows enrolled V3 task preparation without requiring persisted artifacts", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-prepare-seam-"));
    const previous = process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
    try {
      const { fixture, handler, invoke } = await setup(workspace, undefined, "repo_prepare_codex_task");
      process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = fixture.bootstrapPath;

      const response = await invoke({
        repo_id: "fixture-repo",
        title: "Boundary fixture task",
        task_kind: "technical_infrastructure",
        assignment: "Verify the task preparation seam.",
        outcome: {
          beneficiary: "repository maintainers",
          current_problem: "The fixture needs a complete task payload.",
          desired_outcome: "The handler receives schema-valid input.",
          why_now: "The registration seam validates before operation selection."
        },
        starting_points: [],
        authorization_scope: ["src/**"],
        forbidden_paths: [],
        hard_constraints: [],
        must_preserve: [],
        explicit_exclusions: [],
        technical_acceptance_criteria: ["A complete task payload reaches the handler."],
        technical_context: { enabling_value: "Reliable registration fixture." },
        runner: { mode: "manual" }
      });

      expect(handler).toHaveBeenCalledOnce();
      const handlerArgs = handler.mock.calls[0] as unknown as [Record<string, unknown>];
      expect(handlerArgs[0]).toMatchObject({ run_id: fixture.descriptor.run_ids[0] });
      expect(response).toMatchObject({ structuredContent: { ok: true } });
      expect(await readdir(fixture.receiptDirectory)).toHaveLength(1);
    } finally {
      if (previous === undefined) delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      else process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = previous;
      await rm(workspace, { recursive: true, force: true });
    }
  });
});

describe("symbol context task boundary", () => {
  async function registerSymbolContext(
    workspace: string,
    protectedPrimary = false,
    afterAnalyze?: (repo: { root: string }, primaryRoot: string) => void
  ) {
    const fixture = await writeBootstrap(workspace);
    const { CodeIntelligenceService } = await import("../src/services/code-intelligence-service.js");
    const { SymbolContextService } = await import("../src/services/symbol-context-service.js");
    const { registerCatalogTool } = await import("../src/tools/define-tool.js");
    const { toolRegistry } = await import("../src/tools/registry.js");
    const definition = toolRegistry.find((tool) => tool.name === "repo_symbol_context");
    if (!definition) throw new Error("Symbol context tool is not registered.");
    const factoryRoots: string[] = [];
    const factory = vi.fn(async (root: string) => {
      factoryRoots.push(root);
      return {
        call: async (tool: string) => tool === "list_projects"
          ? { projects: [{ name: "fixture-graph", root_path: fixture.executionRoot }] }
          : tool === "search_graph" ? { results: [] } : { callers: [], callees: [] },
        close: async () => undefined
      };
    });
    const codeIntelligence = new CodeIntelligenceService(factory, 5_000, 1_000);
    const repo = {
      repo_id: "fixture-repo",
      root: protectedPrimary ? fixture.primaryRoot : fixture.executionRoot,
      display_name: "Fixture"
    };
    const originalAnalyze = SymbolContextService.prototype.analyze;
    const analyze = vi.spyOn(SymbolContextService.prototype, "analyze");
    if (afterAnalyze) {
      analyze.mockImplementation(async function (this: InstanceType<typeof SymbolContextService>, input) {
        const result = await originalAnalyze.call(this, input);
        afterAnalyze(repo, fixture.primaryRoot);
        return result;
      });
    }
    const enrich = vi.spyOn(codeIntelligence, "enrich");
    let invoke: ((args: unknown) => Promise<unknown>) | undefined;
    const server = {
      registerTool: (_name: string, _configuration: unknown, callback: (args: unknown) => Promise<unknown>) => {
        invoke = callback;
      }
    } as never;
    registerCatalogTool(server, {
      registry: { get: () => repo },
      codeIntelligence
    } as unknown as RuntimeContext, definition);
    if (!invoke) throw new Error("Symbol context tool registration did not retain its handler.");
    return { fixture, invoke, factory, factoryRoots, analyze, enrich };
  }

  test("blocks symbol analysis and provider initialization for a protected-primary registration", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-symbol-context-wrong-root-"));
    const previous = process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
    let analyze: ReturnType<typeof vi.spyOn> | undefined;
    let enrich: ReturnType<typeof vi.spyOn> | undefined;
    try {
      const setup = await registerSymbolContext(workspace, true);
      analyze = setup.analyze;
      enrich = setup.enrich;
      process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = setup.fixture.bootstrapPath;

      const response = await setup.invoke({ repo_id: "fixture-repo", symbols: ["tracked"] }) as { isError?: boolean };

      expect(response.isError).toBe(true);
      expect(setup.analyze).not.toHaveBeenCalled();
      expect(setup.enrich).not.toHaveBeenCalled();
      expect(setup.factory).not.toHaveBeenCalled();
    } finally {
      if (previous === undefined) delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      else process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = previous;
      analyze?.mockRestore();
      enrich?.mockRestore();
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("analyzes and enriches symbol context on the registered execution checkout", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-symbol-context-execution-root-"));
    const previous = process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
    let analyze: ReturnType<typeof vi.spyOn> | undefined;
    let enrich: ReturnType<typeof vi.spyOn> | undefined;
    try {
      const setup = await registerSymbolContext(workspace);
      analyze = setup.analyze;
      enrich = setup.enrich;
      process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = setup.fixture.bootstrapPath;

      const response = await setup.invoke({ repo_id: "fixture-repo", symbols: ["tracked"] }) as {
        isError?: boolean;
        structuredContent?: { provider?: { status?: string } };
      };

      expect(response.isError).not.toBe(true);
      expect(setup.analyze).toHaveBeenCalledOnce();
      expect(setup.enrich).toHaveBeenCalledOnce();
      expect(setup.factory).toHaveBeenCalledOnce();
      expect(setup.factoryRoots).toEqual([setup.fixture.executionRoot]);
      expect(response.structuredContent?.provider?.status).toBe("ready");
      const receipts = await readdir(setup.fixture.receiptDirectory);
      expect(receipts).toHaveLength(1);
      const receiptApi = await import("../src/services/task-execution-boundary.js");
      await expect(receiptApi.readTaskExecutionReceipt(setup.fixture.bootstrapPath, receipts[0]!.replace(/\.json$/, "")))
        .resolves.toMatchObject({ operation: "index", operation_outcome: "completed", verdict: "NOT_PROVEN" });
    } finally {
      if (previous === undefined) delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      else process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = previous;
      analyze?.mockRestore();
      enrich?.mockRestore();
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("propagates provider revalidation failure after analysis and records a failed receipt", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "task-symbol-context-provider-revalidation-race-"));
    const previous = process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
    let analyze: ReturnType<typeof vi.spyOn> | undefined;
    let enrich: ReturnType<typeof vi.spyOn> | undefined;
    try {
      const setup = await registerSymbolContext(workspace, false, (repo, primaryRoot) => {
        repo.root = primaryRoot;
      });
      analyze = setup.analyze;
      enrich = setup.enrich;
      process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = setup.fixture.bootstrapPath;

      const response = await setup.invoke({ repo_id: "fixture-repo", symbols: ["tracked"] }) as { isError?: boolean };

      expect(response.isError).toBe(true);
      expect(setup.analyze).toHaveBeenCalledOnce();
      expect(setup.enrich).toHaveBeenCalledOnce();
      expect(setup.factory).not.toHaveBeenCalled();
      const receipts = await readdir(setup.fixture.receiptDirectory);
      expect(receipts).toHaveLength(1);
      const receiptApi = await import("../src/services/task-execution-boundary.js");
      await expect(receiptApi.readTaskExecutionReceipt(setup.fixture.bootstrapPath, receipts[0]!.replace(/\.json$/, "")))
        .resolves.toMatchObject({
          operation: "index",
          operation_outcome: "failed",
          failure_code: expect.any(String),
          verdict: "NOT_PROVEN"
        });
    } finally {
      if (previous === undefined) delete process.env.GPT_REPO_TASK_BOOTSTRAP_PATH;
      else process.env.GPT_REPO_TASK_BOOTSTRAP_PATH = previous;
      analyze?.mockRestore();
      enrich?.mockRestore();
      await rm(workspace, { recursive: true, force: true });
    }
  });
});
