import { execFile } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, test } from "vitest";
import { delegationBaselineSha256V3 } from "../src/services/delegation-v3-normalizer.js";
import { TaskExecutionBoundary, type TaskExecutionBootstrap } from "../src/services/task-execution-boundary.js";
import { buildTaskPreservationSidecar, collectTaskPreservationSnapshot } from "../src/services/task-preservation-observation.js";
import { taskExecutionPolicyFor } from "../src/tools/task-execution-policy.js";

const execFileAsync = promisify(execFile);

async function createRepository(root: string): Promise<string> {
  await mkdir(root, { recursive: true });
  await writeFile(join(root, "tracked.txt"), "working-file contents stay unread\n");
  await writeFile(join(root, ".gitignore"), "ignored-data/\n");
  await execFileAsync("git", ["init"], { cwd: root });
  await execFileAsync("git", ["config", "user.email", "fixture@example.test"], { cwd: root });
  await execFileAsync("git", ["config", "user.name", "Fixture"], { cwd: root });
  await execFileAsync("git", ["add", "--all"], { cwd: root });
  await execFileAsync("git", ["commit", "-m", "fixture"], { cwd: root });
  return (await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: root })).stdout.trim();
}

function bootstrap(protectedRoot: string, executionRoot: string, baseline: string): TaskExecutionBootstrap {
  const expectedBaseline = {
    head_sha: baseline,
    worktree_fingerprint: "fixture-fingerprint",
    initial_changed_paths: [],
    initial_path_states: []
  };
  return {
    schema: "gpt-repo-mcp.task-bootstrap",
    schema_version: 2,
    task_id: "fixture-preservation",
    run_ids: ["2026-11-01T120000Z-fixture-run"],
    repo_id: "fixture-repo",
    protected_root: protectedRoot,
    execution_root: executionRoot,
    expected_baseline: {
      ...expectedBaseline,
      baseline_sha256: delegationBaselineSha256V3(expectedBaseline)
    },
    protected_paths: ["private/config.json"],
    protected_state_inputs: ["HEAD", "refs", "index"],
    explicit_exclusions: ["working-file contents"],
    authorized_source_paths: ["src/**", "tests/**"],
    authorized_ref_transitions: [],
    receipt_directory: "/tmp/task-receipts",
    path_token_key: "b".repeat(64),
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
    }
  };
}

describe("preservation evidence collection", () => {
  test("records opaque metadata without reading file contents or exposing protected names", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "preservation-snapshot-"));
    try {
      const protectedRoot = join(workspace, "protected");
      const executionRoot = join(workspace, "execution");
      await createRepository(protectedRoot);
      await mkdir(join(protectedRoot, "private"), { recursive: true });
      await writeFile(join(protectedRoot, "private/config.json"), "do not include this content");
      await execFileAsync("git", ["add", "private/config.json"], { cwd: protectedRoot });
      await execFileAsync("git", ["commit", "-m", "protected fixture"], { cwd: protectedRoot });
      const executionHead = await createRepository(executionRoot);
      const protectedCanonical = await realpath(protectedRoot);
      const executionCanonical = await realpath(executionRoot);
      await mkdir(join(protectedRoot, "ignored-data"), { recursive: true });
      await writeFile(join(protectedRoot, "ignored-data/entry.txt"), "ignored");
      const descriptor = bootstrap(protectedCanonical, executionCanonical, executionHead);
      const sample = await collectTaskPreservationSnapshot({
        bootstrap: descriptor,
        repo_id: "fixture-repo",
        configured_root: executionCanonical,
        cwd: executionCanonical
      });
      const serialized = JSON.stringify(sample.snapshot);

      expect(sample.identity.execution_head).toBe(executionHead);
      expect(sample.snapshot.protected_metadata[0]?.path_token).toMatch(/^path:[a-f0-9]{64}$/);
      expect(serialized).not.toContain(protectedCanonical);
      expect(serialized).not.toContain("private/config.json");
      expect(serialized).not.toContain("do not include this content");
      expect(serialized).not.toContain("ignored-data/entry.txt");
      expect(sample.snapshot.untracked_count).toBe(0);
      expect(sample.collector_environment.git_commands).toContain("ls-files --others --exclude-standard -z");

      const sidecar = buildTaskPreservationSidecar({
        bootstrap: descriptor,
        operation: "validation",
        operation_outcome: "completed",
        operation_started_at_utc: "2026-11-01T12:00:00.000Z",
        operation_finished_at_utc: "2026-11-01T12:00:01.000Z",
        pre: sample,
        post: sample
      });
      expect(sidecar.serialized).not.toContain(protectedCanonical);
      expect(sidecar.serialized).not.toContain(executionCanonical);
      expect(sidecar.serialized).not.toContain("private/config.json");
      expect(sidecar.serialized).not.toContain("working-file contents stay unread");
      expect(sidecar.sidecar.identity).toHaveProperty("protected_root_token");
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("samples owner-selected files, detects endpoint changes, and omits explicit exclusions", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "preservation-selected-input-"));
    try {
      const protectedRoot = join(workspace, "protected");
      const executionRoot = join(workspace, "execution");
      await createRepository(protectedRoot);
      const executionHead = await createRepository(executionRoot);
      await writeFile(join(protectedRoot, "selected-state.json"), "before");
      await writeFile(join(protectedRoot, "excluded-state.json"), "excluded contents");
      const protectedCanonical = await realpath(protectedRoot);
      const executionCanonical = await realpath(executionRoot);
      const descriptor = bootstrap(protectedCanonical, executionCanonical, executionHead);
      descriptor.protected_state_inputs = [
        ...descriptor.protected_state_inputs,
        "selected-state.json",
        "excluded-state.json"
      ];
      descriptor.explicit_exclusions = ["working-file contents", "excluded-state.json"];

      const before = await collectTaskPreservationSnapshot({
        bootstrap: descriptor,
        repo_id: "fixture-repo",
        configured_root: executionCanonical,
        cwd: executionCanonical
      });
      await writeFile(join(protectedRoot, "selected-state.json"), "changed selected state");
      const after = await collectTaskPreservationSnapshot({
        bootstrap: descriptor,
        repo_id: "fixture-repo",
        configured_root: executionCanonical,
        cwd: executionCanonical
      });
      const beforeSelected = (before.snapshot as unknown as { owner_protected_metadata: Array<{ path_token: string; size?: string }> }).owner_protected_metadata;
      const afterSelected = (after.snapshot as unknown as { owner_protected_metadata: Array<{ path_token: string; size?: string }> }).owner_protected_metadata;
      const sidecar = buildTaskPreservationSidecar({
        bootstrap: descriptor,
        operation: "validation",
        operation_outcome: "completed",
        operation_started_at_utc: "2026-11-01T12:00:00.000Z",
        operation_finished_at_utc: "2026-11-01T12:00:01.000Z",
        pre: before,
        post: after
      });

      expect(beforeSelected).toHaveLength(1);
      expect(beforeSelected[0]?.path_token).toMatch(/^path:[a-f0-9]{64}$/);
      expect(afterSelected[0]?.size).not.toBe(beforeSelected[0]?.size);
      expect(sidecar.sidecar.collection.differences).toContainEqual({
        category: "unattributed",
        state: "owner_protected_input_metadata"
      });
      expect(sidecar.serialized).not.toContain("selected-state.json");
      expect(sidecar.serialized).not.toContain("excluded-state.json");
      expect(sidecar.serialized).not.toContain("before");
      expect(sidecar.serialized).not.toContain("changed selected state");
      expect(sidecar.serialized).not.toContain("excluded contents");
      expect(sidecar.serialized).not.toContain("working-file contents");
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("marks an unsupported owner-selected path incomplete", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "preservation-invalid-input-"));
    try {
      const protectedRoot = join(workspace, "protected");
      const executionRoot = join(workspace, "execution");
      await createRepository(protectedRoot);
      const executionHead = await createRepository(executionRoot);
      const protectedCanonical = await realpath(protectedRoot);
      const executionCanonical = await realpath(executionRoot);
      const descriptor = bootstrap(protectedCanonical, executionCanonical, executionHead);
      descriptor.protected_state_inputs = [...descriptor.protected_state_inputs, "../outside.txt"];

      const sample = await collectTaskPreservationSnapshot({
        bootstrap: descriptor,
        repo_id: "fixture-repo",
        configured_root: executionCanonical,
        cwd: executionCanonical
      });

      expect(sample.snapshot.inventory_complete).toBe(false);
      expect(sample.snapshot.errors.length).toBeGreaterThan(0);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("does not follow owner-selected symlinks and marks the sample incomplete", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "preservation-symlink-input-"));
    try {
      const protectedRoot = join(workspace, "protected");
      const executionRoot = join(workspace, "execution");
      await createRepository(protectedRoot);
      const executionHead = await createRepository(executionRoot);
      await writeFile(join(workspace, "outside-secret.txt"), "outside contents");
      await symlink(join(workspace, "outside-secret.txt"), join(protectedRoot, "selected-link"));
      const protectedCanonical = await realpath(protectedRoot);
      const executionCanonical = await realpath(executionRoot);
      const descriptor = bootstrap(protectedCanonical, executionCanonical, executionHead);
      descriptor.protected_state_inputs = [...descriptor.protected_state_inputs, "selected-link"];

      const sample = await collectTaskPreservationSnapshot({
        bootstrap: descriptor,
        repo_id: "fixture-repo",
        configured_root: executionCanonical,
        cwd: executionCanonical
      });

      expect(sample.snapshot.inventory_complete).toBe(false);
      expect(sample.snapshot.unsupported_layouts).toContain("owner_protected_input_unsupported_file_type");
      expect(JSON.stringify(sample.snapshot)).not.toContain("outside-secret.txt");
      expect(JSON.stringify(sample.snapshot)).not.toContain("outside contents");
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test.each(["repo_git_review", "repo_semantic_review"] as const)(
    "%s remains enrolled without requiring one selected run in a multi-run task",
    async (toolName) => {
      const workspace = await mkdtemp(join(tmpdir(), "preservation-runless-review-"));
      try {
        const protectedRoot = join(workspace, "protected");
        const executionRoot = join(workspace, "execution");
        await createRepository(protectedRoot);
        const executionHead = await createRepository(executionRoot);
        const protectedCanonical = await realpath(protectedRoot);
        const executionCanonical = await realpath(executionRoot);
        const descriptor = bootstrap(protectedCanonical, executionCanonical, executionHead);
        descriptor.run_ids = [
          "2026-11-01T120000Z-fixture-run",
          "2026-11-01T120100Z-fixture-run"
        ];
        const policy = taskExecutionPolicyFor(toolName);
        expect(policy).toBeDefined();
        const request = policy!({ repo_id: "fixture-repo" });
        expect(request.operation).toBe("repository_review");
        expect(request.run_id).toBeUndefined();
        expect(request.run_ids).toBeUndefined();

        const boundary = new TaskExecutionBoundary(
          { bootstrap: descriptor, descriptor_path: "", sha256: "" },
          { cwd: () => executionCanonical }
        );
        const session = await boundary.begin({
          repo_id: request.repo_id,
          root: executionCanonical,
          registered_repo: { repo_id: "fixture-repo", root: executionCanonical },
          operation: request.operation
        });

        expect(session.execution_root).toBe(executionCanonical);
      } finally {
        await rm(workspace, { recursive: true, force: true });
      }
    }
  );

  test("keeps the enrolled repository root bound for runless reviews", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "preservation-review-root-"));
    try {
      const protectedRoot = join(workspace, "protected");
      const executionRoot = join(workspace, "execution");
      await createRepository(protectedRoot);
      const executionHead = await createRepository(executionRoot);
      const protectedCanonical = await realpath(protectedRoot);
      const executionCanonical = await realpath(executionRoot);
      const descriptor = bootstrap(protectedCanonical, executionCanonical, executionHead);
      descriptor.run_ids = [
        "2026-11-01T120000Z-fixture-run",
        "2026-11-01T120100Z-fixture-run"
      ];
      const policy = taskExecutionPolicyFor("repo_git_review")!;
      const request = policy({ repo_id: "fixture-repo" });
      const boundary = new TaskExecutionBoundary(
        { bootstrap: descriptor, descriptor_path: "", sha256: "" },
        { cwd: () => protectedCanonical }
      );

      await expect(boundary.begin({
        repo_id: request.repo_id,
        root: protectedCanonical,
        registered_repo: { repo_id: "fixture-repo", root: protectedCanonical },
        operation: request.operation
      })).rejects.toMatchObject({ code: "RUNNER_POLICY_BLOCKED" });
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test("exposes the sole enrolled run for task creation input normalization", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "preservation-inferred-run-"));
    try {
      const protectedRoot = join(workspace, "protected");
      const executionRoot = join(workspace, "execution");
      await createRepository(protectedRoot);
      const executionHead = await createRepository(executionRoot);
      const protectedCanonical = await realpath(protectedRoot);
      const executionCanonical = await realpath(executionRoot);
      const descriptor = bootstrap(protectedCanonical, executionCanonical, executionHead);
      const boundary = new TaskExecutionBoundary(
        { bootstrap: descriptor, descriptor_path: "", sha256: "" },
        { cwd: () => executionCanonical }
      );

      const session = await boundary.begin({
        repo_id: "fixture-repo",
        root: executionCanonical,
        registered_repo: { repo_id: "fixture-repo", root: executionCanonical },
        operation: "prepare"
      });

      expect((session as unknown as { run_id?: string }).run_id).toBe(descriptor.run_ids[0]);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
});
