import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { createTaskExecutionBoundaryFromEnvironment } from "../src/services/task-execution-boundary.js";
import { TASK_EXECUTION_BOOTSTRAP_ENV } from "../src/services/task-execution-bootstrap.js";
import { taskExecutionPolicyFor } from "../src/tools/task-execution-policy.js";

describe("task execution tool policies", () => {
  test("repo_symbol_context uses the enrolled index boundary before analysis", () => {
    expect(taskExecutionPolicyFor("repo_symbol_context")?.({ repo_id: "fixture-repo" }))
      .toEqual({ repo_id: "fixture-repo", operation: "index" });
  });

  test.each(["repo_git_review", "repo_semantic_review"] as const)(
    "%s uses the enrolled repository-review policy without run selectors",
    (toolName) => {
      const request = taskExecutionPolicyFor(toolName)?.({ repo_id: "fixture-repo" });

      expect(request).toMatchObject({ repo_id: "fixture-repo", operation: "repository_review" });
      expect(request).not.toHaveProperty("run_id");
      expect(request).not.toHaveProperty("run_ids");
    }
  );

  test.each(["repo_prepare_codex_task", "repo_write_codex_task"] as const)(
    "%s forwards an inferred owner run id only when one is available",
    (toolName) => {
      const policy = taskExecutionPolicyFor(toolName);
      expect(policy).toBeDefined();
      const acceptInferredRun = policy as unknown as (
        input: { repo_id: string },
        inferredRunId?: string
      ) => { run_id?: string };

      expect(acceptInferredRun({ repo_id: "fixture-repo" }).run_id).toBeUndefined();
      expect(acceptInferredRun({ repo_id: "fixture-repo" }, "2026-11-01T120000Z-fixture-run").run_id)
        .toBe("2026-11-01T120000Z-fixture-run");
    }
  );

  test("keeps unenrolled calls outside the execution boundary", async () => {
    await expect(createTaskExecutionBoundaryFromEnvironment({}, { cwd: () => process.cwd() }))
      .resolves.toBeUndefined();
  });

  test("rejects a malformed enrollment descriptor", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "malformed-task-bootstrap-"));
    try {
      const descriptorPath = join(workspace, "bootstrap.json");
      await writeFile(descriptorPath, JSON.stringify({ schema: "invalid" }));

      await expect(createTaskExecutionBoundaryFromEnvironment({
        [TASK_EXECUTION_BOOTSTRAP_ENV]: descriptorPath
      }, { cwd: () => workspace })).rejects.toBeDefined();
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
});
