import type { TaskExecutionOperation } from "../services/task-execution-bootstrap.js";
import type { ToolName } from "./contracts.js";

export type TaskExecutionToolArgs = {
  repo_id: string;
  run_id?: string;
  run_ids?: readonly string[];
  dry_run?: boolean;
  runner?: { mode?: string };
};

export type TaskExecutionToolRequest = {
  repo_id: string;
  operation: TaskExecutionOperation;
  run_id?: string;
  run_ids?: readonly string[];
};

export type TaskExecutionToolMetadata = (input: TaskExecutionToolArgs, inferredRunId?: string) => TaskExecutionToolRequest;

export const TASK_EXECUTION_TOOL_NAMES = [
  "repo_symbol_context",
  "repo_prepare_codex_task",
  "repo_write_codex_task",
  "repo_write_agent_reply",
  "repo_codex_review",
  "repo_write_codex_review",
  "repo_write_integration_review",
  "repo_ship_review",
  "repo_git_review",
  "repo_validate",
  "repo_semantic_review",
  "repo_review_patchset"
] as const satisfies readonly ToolName[];

export type TaskExecutionToolName = typeof TASK_EXECUTION_TOOL_NAMES[number];

export const TASK_EXECUTION_POLICIES = {
  repo_symbol_context: (input) => ({ repo_id: input.repo_id, operation: "index" }),
  repo_prepare_codex_task: (input, inferredRunId) => ({
    repo_id: input.repo_id,
    operation: "prepare",
    ...((input.run_id ?? inferredRunId) ? { run_id: input.run_id ?? inferredRunId } : {})
  }),
  repo_write_codex_task: (input, inferredRunId) => ({
    repo_id: input.repo_id,
    operation: input.dry_run ? "prepare" : input.runner?.mode === "queued" ? "queue" : "registration",
    ...((input.run_id ?? inferredRunId) ? { run_id: input.run_id ?? inferredRunId } : {})
  }),
  repo_write_agent_reply: (input) => ({
    repo_id: input.repo_id,
    operation: "resume",
    ...(input.run_id ? { run_id: input.run_id } : {})
  }),
  repo_codex_review: (input) => ({
    repo_id: input.repo_id,
    operation: "review",
    ...(input.run_id ? { run_id: input.run_id } : {}),
    ...(input.run_ids ? { run_ids: input.run_ids } : {})
  }),
  repo_write_codex_review: (input) => ({
    repo_id: input.repo_id,
    operation: "review",
    ...(input.run_id ? { run_id: input.run_id } : {}),
    ...(input.run_ids ? { run_ids: input.run_ids } : {})
  }),
  repo_write_integration_review: (input) => ({
    repo_id: input.repo_id,
    operation: "review",
    ...(input.run_id ? { run_id: input.run_id } : {}),
    ...(input.run_ids ? { run_ids: input.run_ids } : {})
  }),
  repo_ship_review: (input) => ({
    repo_id: input.repo_id,
    operation: "review",
    ...(input.run_id ? { run_id: input.run_id } : {})
  }),
  repo_git_review: (input) => ({ repo_id: input.repo_id, operation: "repository_review" }),
  repo_validate: (input) => ({ repo_id: input.repo_id, operation: "validation" }),
  repo_semantic_review: (input) => ({ repo_id: input.repo_id, operation: "repository_review" }),
  repo_review_patchset: (input) => ({ repo_id: input.repo_id, operation: "patchset_review" })
} satisfies Record<TaskExecutionToolName, TaskExecutionToolMetadata>;

export function taskExecutionPolicyFor(name: ToolName): TaskExecutionToolMetadata | undefined {
  return Object.hasOwn(TASK_EXECUTION_POLICIES, name)
    ? TASK_EXECUTION_POLICIES[name as TaskExecutionToolName]
    : undefined;
}
