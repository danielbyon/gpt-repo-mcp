import { constants } from "node:fs";
import { createHash, createHmac, randomUUID } from "node:crypto";
import { lstat, open, realpath, link, unlink } from "node:fs/promises";
import { basename, join } from "node:path";
import { z } from "zod";
import { RepoReaderError } from "../runtime/errors.js";
import { buildTaskPreservationSidecar, opaquePath } from "./task-preservation-observation.js";
import {
  isOwnerControlledDirectory,
  isOwnerControlledFile,
  isWithin,
  loadTaskExecutionBootstrapAtPath,
  readOwnerControlledFile,
} from "./task-execution-bootstrap.js";
import { errorReason, taskExecutionError } from "./task-execution-errors.js";
import type {
  ExecutionIdentity,
  LoadedTaskExecutionBootstrap,
  TaskExecutionBootstrap,
  TaskExecutionOperation,
  TaskPreservationSample,
  VerifiedTaskRunBinding
} from "./task-execution-bootstrap.js";

const SHA256 = z.string().regex(/^[a-f0-9]{64}$/);
const TaskExecutionReceiptCore = {
  schema: z.literal("gpt-repo-mcp.preservation-receipt"),
  task_id: z.string().min(1),
  operation_id: z.string().uuid(),
  operation: z.enum(["prepare", "registration", "queue", "resume", "review", "repository_review", "patchset_review", "validation", "index", "async"]),
  operation_outcome: z.enum(["completed", "failed"]),
  failure_code: z.string().optional(),
  verdict: z.literal("NOT_PROVEN"),
  bootstrap_sha256: SHA256,
  created_at_utc: z.string().datetime(),
  identity: z.record(z.string(), z.unknown()),
  pre: z.unknown().nullable(),
  post: z.unknown().nullable(),
  comparison: z.object({
    stable_endpoints: z.boolean(),
    differences: z.array(z.object({
      category: z.enum(["owner_authorized", "unattributed"]),
      state_token: z.string().regex(/^state:[a-f0-9]{64}$/)
    }).strict()),
    attribution: z.object({
      owner_authorized_count: z.number().int().nonnegative(),
      unattributed_count: z.number().int().nonnegative(),
      not_proven: z.array(z.string())
    }).strict()
  }).strict(),
  limitations: z.array(z.string())
};
const ReceiptIntegritySchema = z.object({ algorithm: z.literal("sha256"), sha256: SHA256 }).strict();
const TaskExecutionReceiptV1Schema = z.object({
  ...TaskExecutionReceiptCore,
  schema_version: z.literal(1),
  run_id: z.string().min(1),
  integrity: ReceiptIntegritySchema
}).strict().superRefine((receipt, context) => {
  if (receipt.operation === "patchset_review" || receipt.operation === "repository_review") {
    context.addIssue({ code: "custom", path: ["operation"], message: "Runless review receipts must use the no-run receipt version." });
  }
});
const TaskExecutionReceiptV2Schema = z.object({
  ...TaskExecutionReceiptCore,
  schema_version: z.literal(2),
  run_id: z.string().min(1),
  run_ids: z.array(z.string().min(1)).min(1).max(64),
  run_bindings: z.array(z.object({
    run_id: z.string().min(1),
    baseline_sha256: SHA256,
    prompt_sha256: SHA256
  }).strict()).max(64),
  integrity: ReceiptIntegritySchema
}).strict().superRefine((receipt, context) => {
  if (receipt.operation === "patchset_review" || receipt.operation === "repository_review") {
    context.addIssue({ code: "custom", path: ["operation"], message: "Runless review receipts must use the no-run receipt version." });
  }
  if (receipt.run_ids[0] !== receipt.run_id || new Set(receipt.run_ids).size !== receipt.run_ids.length) {
    context.addIssue({ code: "custom", path: ["run_ids"], message: "Receipt run IDs must be unique and begin with the primary run ID." });
  }
  const bindingIds = receipt.run_bindings.map(({ run_id: runId }) => runId);
  if (new Set(bindingIds).size !== bindingIds.length || bindingIds.some((runId) => !receipt.run_ids.includes(runId))) {
    context.addIssue({ code: "custom", path: ["run_bindings"], message: "Receipt run bindings must be unique members of the selected run set." });
  }
  if (receipt.operation_outcome === "completed"
    && ["registration", "queue", "resume", "review"].includes(receipt.operation)
    && (bindingIds.length !== receipt.run_ids.length || bindingIds.some((runId, index) => runId !== receipt.run_ids[index]))) {
    context.addIssue({ code: "custom", path: ["run_bindings"], message: "Completed task operations must record every verified run binding." });
  }
});
const TaskExecutionReceiptV3Schema = z.object({
  ...TaskExecutionReceiptCore,
  schema_version: z.literal(3),
  run_ids: z.array(z.string().min(1)).max(64),
  run_bindings: z.array(z.object({
    run_id: z.string().min(1),
    baseline_sha256: SHA256,
    prompt_sha256: SHA256
  }).strict()).max(64),
  integrity: ReceiptIntegritySchema
}).strict().superRefine((receipt, context) => {
  if ((receipt.operation !== "patchset_review" && receipt.operation !== "repository_review")
    || receipt.run_ids.length !== 0 || receipt.run_bindings.length !== 0) {
    context.addIssue({ code: "custom", path: ["run_ids"], message: "Version 3 receipts are reserved for runless reviews with no V3 run selection." });
  }
});
const TaskExecutionReceiptSchema = z.union([TaskExecutionReceiptV1Schema, TaskExecutionReceiptV2Schema, TaskExecutionReceiptV3Schema]);

/** Reads and verifies one owner-controlled preservation receipt by operation ID. */
export async function readTaskExecutionReceipt(bootstrapPath: string, operationId: string): Promise<unknown> {
  if (!/^[0-9a-f-]{36}$/i.test(operationId)) throw taskExecutionError("receipt_id_invalid");
  const loaded = await loadTaskExecutionBootstrapAtPath(bootstrapPath);
  const receiptPath = join(loaded.bootstrap.receipt_directory, operationId + ".json");
  if (!isWithin(loaded.bootstrap.receipt_directory, receiptPath) || basename(receiptPath) !== operationId + ".json") {
    throw taskExecutionError("receipt_path_invalid");
  }
  const bytes = await readOwnerControlledFile(receiptPath, loaded.bootstrap.limits.receipt_bytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw taskExecutionError("receipt_json_invalid");
  }
  const result = TaskExecutionReceiptSchema.safeParse(parsed);
  if (!result.success) throw taskExecutionError("receipt_schema_invalid");
  const integrity = result.data.integrity;
  const core = Object.fromEntries(Object.entries(parsed as Record<string, unknown>).filter(([key]) => key !== "integrity"));
  const digest = createHash("sha256").update(JSON.stringify(core), "utf8").digest("hex");
  const receiptRunIds = "run_ids" in result.data ? result.data.run_ids : [result.data.run_id];
  if (digest !== integrity.sha256
    || result.data.operation_id !== operationId
    || result.data.task_id !== loaded.bootstrap.task_id
    || receiptRunIds.some((runId) => !loaded.bootstrap.run_ids.includes(runId))
    || result.data.bootstrap_sha256 !== loaded.sha256) {
    throw taskExecutionError("receipt_integrity_mismatch");
  }
  return result.data;
}

export async function writeTaskExecutionReceipt(input: {
    loaded: LoadedTaskExecutionBootstrap;
    operationId: string;
    runId?: string;
    runIds: readonly string[];
    runBindings: readonly VerifiedTaskRunBinding[];
    operation: TaskExecutionOperation;
    outcome: "completed" | "failed";
    failureCode?: string;
    identity?: ExecutionIdentity;
    pre: TaskPreservationSample | null | undefined;
    post: TaskPreservationSample | null;
    createdAt: string;
    now: () => Date;
  }): Promise<string> {
    const { loaded, operationId, runId, runIds, runBindings, operation, outcome, identity, pre, post } = input;
    const observation = pre ? buildTaskPreservationSidecar({
      bootstrap: loaded.bootstrap,
      operation,
      operation_outcome: outcome,
      operation_error_code: input.failureCode,
      operation_started_at_utc: input.createdAt,
      operation_finished_at_utc: input.now().toISOString(),
      pre,
      post
    }) : undefined;
    const differences = observation?.sidecar.collection.differences ?? [];
    const core = {
      schema: "gpt-repo-mcp.preservation-receipt" as const,
      ...(runIds.length === 0 ? {
        schema_version: 3 as const,
        run_ids: [] as string[],
        run_bindings: [] as Array<{ run_id: string; baseline_sha256: string; prompt_sha256: string }>
      } : {
        schema_version: 2 as const,
        run_id: runId,
        run_ids: [...runIds],
        run_bindings: runBindings.map((binding) => ({ ...binding }))
      }),
      task_id: loaded.bootstrap.task_id,
      operation_id: operationId,
      operation,
      operation_outcome: outcome,
      ...(input.failureCode ? { failure_code: input.failureCode } : {}),
      verdict: "NOT_PROVEN" as const,
      bootstrap_sha256: loaded.sha256,
      created_at_utc: input.now().toISOString(),
      identity: receiptIdentity(identity, loaded.bootstrap),
      pre: pre ? pre.snapshot : null,
      post: post ? post.snapshot : null,
      comparison: {
        stable_endpoints: observation?.sidecar.collection.stable_endpoints ?? false,
        differences: differences.map(({ category, state }) => ({
          category,
          state_token: "state:" + createHmac("sha256", Buffer.from(loaded.bootstrap.path_token_key, "hex")).update(state, "utf8").digest("hex")
        })),
        attribution: {
          owner_authorized_count: observation?.sidecar.collection.attribution_categories.owner_authorized.length ?? 0,
          unattributed_count: observation?.sidecar.collection.attribution_categories.unattributed.length ?? 0,
          not_proven: observation?.sidecar.collection.attribution_categories.not_proven ?? ["preflight_missing"]
        }
      },
      limitations: [
        "Endpoint equality does not rule out transient writes.",
        "Working-file content equivalence remains NOT_PROVEN.",
        "This local receipt does not attest server identity or machine-wide control."
      ]
    };
    const normalized = TaskExecutionReceiptSchema.parse({
      ...core,
      integrity: { algorithm: "sha256", sha256: "0".repeat(64) }
    });
    const normalizedCore = Object.fromEntries(Object.entries(normalized).filter(([key]) => key !== "integrity"));
    const integrityHash = createHash("sha256").update(JSON.stringify(normalizedCore), "utf8").digest("hex");
    const receipt = TaskExecutionReceiptSchema.parse({
      ...normalized,
      integrity: { algorithm: "sha256", sha256: integrityHash }
    });
    const bytes = Buffer.from(JSON.stringify(receipt, null, 2) + "\n", "utf8");
    if (bytes.byteLength > loaded.bootstrap.limits.receipt_bytes) throw taskExecutionError("receipt_size_limit_exceeded");
    await publishReceiptAtomically(loaded.bootstrap, operationId, bytes);
    return integrityHash;
  }
function receiptIdentity(identity: ExecutionIdentity | undefined, bootstrap: TaskExecutionBootstrap): Record<string, unknown> {
  const token = (path: string) => opaquePath(Buffer.from(path, "utf8"), bootstrap.path_token_key);
  return {
    status: identity ? "verified" : "NOT_PROVEN",
    protected_root_token: token(bootstrap.protected_root),
    execution_root_token: token(bootstrap.execution_root),
    ...(identity ? {
      protected_git_admin_token: token(identity.primary_common_dir),
      execution_git_admin_token: token(identity.execution_common_dir),
      shared_refs: identity.shared_refs,
      execution_linked_worktree: identity.execution_linked_worktree,
      shared_protected_admin_state: identity.shares_protected_admin
    } : {})
  };
}

async function publishReceiptAtomically(bootstrap: TaskExecutionBootstrap, operationId: string, bytes: Buffer): Promise<void> {
  const directory = bootstrap.receipt_directory;
  const info = await lstat(directory, { bigint: true });
  if (!isOwnerControlledDirectory(info) || await realpath(directory) !== directory
    || isWithin(bootstrap.protected_root, directory) || isWithin(bootstrap.execution_root, directory)) {
    throw taskExecutionError("receipt_directory_unsafe");
  }
  const finalPath = join(directory, operationId + ".json");
  const tempPath = join(directory, "." + operationId + "." + randomUUID() + ".tmp");
  if (!isWithin(directory, finalPath) || !isWithin(directory, tempPath)) throw taskExecutionError("receipt_path_invalid");
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(tempPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await link(tempPath, finalPath);
    await unlink(tempPath);
    const saved = await lstat(finalPath, { bigint: true });
    if (!isOwnerControlledFile(saved)) throw taskExecutionError("receipt_file_unsafe_after_publish");
    const directoryHandle = await open(directory, constants.O_RDONLY);
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  } catch (error) {
    if (handle) await handle.close().catch(() => undefined);
    await unlink(tempPath).catch(() => undefined);
    throw error instanceof RepoReaderError ? error : taskExecutionError(errorReason(error));
  }
}
