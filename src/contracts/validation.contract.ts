import { z } from "zod";
import { RepoInputSchema } from "./repo.contract.js";

export const ValidationProfileSchema = z.enum(["test", "build", "lint", "typecheck", "smoke", "all"]);
export const ValidationCommandStatusSchema = z.enum(["passed", "failed", "skipped"]);
export const NodeRuntimeSourceSchema = z.enum(["package.json#volta.node", ".node-version", ".nvmrc", "package.json#engines.node"]);
const NodeValidationRuntimeSchema = z.object({
  name: z.literal("node").describe("Selected project runtime name."),
  version: z.string().regex(/^\d+\.\d+\.\d+$/).describe("Exact selected Node.js version."),
  source: NodeRuntimeSourceSchema.describe("Repository metadata source that requested the Node.js version.")
});
const RustToolIdentitySchema = z.object({
  path_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  real_path_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  sha256: z.string().regex(/^[a-f0-9]{64}$/)
});
const RustValidationRuntimeSchema = z.object({
  name: z.literal("rust"),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  source: z.enum(["rust-toolchain", "rust-toolchain.toml"]),
  active_toolchain: z.string().min(1),
  rustup: RustToolIdentitySchema.optional(),
  cargo: RustToolIdentitySchema,
  rustc: RustToolIdentitySchema,
  cargo_home_path_sha256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  cargo_config_sha256: z.string().regex(/^[a-f0-9]{64}$/).optional()
});
export const ValidationRuntimeSchema = z.discriminatedUnion("name", [NodeValidationRuntimeSchema, RustValidationRuntimeSchema]);
export const ValidationExecutableIdentitySchema = z.object({
  path_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  real_path_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  size_bytes: z.number().int().nonnegative(),
  mode_bits: z.number().int().nonnegative(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/)
});
export const ValidationRecipeSchema = z.object({
  path: z.string().min(1),
  size_bytes: z.number().int().nonnegative(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/)
});

export const ValidateInputSchema = RepoInputSchema.extend({
  profile: ValidationProfileSchema.describe("Fixed allowlisted validation profile resolved first from a configured make or just target, then a matching npm script, then the detected pytest test fallback."),
  test_paths: z.array(z.string().min(1)).optional().describe("Optional focused test paths. Accepted only for profile test when configured validation_test_path_globs allow them and the selected runner supports focused paths; paths must pass repository path and sensitive-path checks."),
  dry_run: z.boolean().optional().describe("When true, resolve runners and verify any requested Node binary without executing project validation scripts."),
  timeout_ms: z.number().int().positive().max(900_000).optional().describe("Optional per-command timeout in milliseconds, capped at 900000; defaults to 900000.")
});

export const ValidateCommandResultSchema = z.object({
  profile: ValidationProfileSchema.describe("Validation profile represented by this command, including a repository-owned all profile."),
  script: z.string().min(1).describe("Selected validation runner name, such as an npm script name or pytest."),
  command: z.string().min(1).describe("Display-only command summary such as npm run test or .venv/bin/python -m pytest."),
  executable: z.string().min(1),
  executable_identity: ValidationExecutableIdentitySchema.optional(),
  runtime_executable_identity: ValidationExecutableIdentitySchema.optional(),
  recipe: ValidationRecipeSchema.optional(),
  runtime: ValidationRuntimeSchema.optional().describe("Selected runtime for the validation command."),
  status: ValidationCommandStatusSchema.describe("Validation command result status."),
  exit_code: z.number().int().optional().describe("Process exit code when the validation runner completed with an exit code."),
  duration_ms: z.number().int().nonnegative().optional().describe("Elapsed command duration in milliseconds when the command executed."),
  stdout_tail: z.string().optional().describe("Redacted bounded tail of stdout from the command."),
  stderr_tail: z.string().optional().describe("Redacted bounded tail of stderr from the command.")
});

export const ValidateResultSchema = z.object({
  ok: z.literal(true).describe("True when validation planning or execution completed."),
  repo_id: z.string().describe("Approved repository id that validation targeted."),
  validation_id: z.string().optional().describe("Stable id for the saved validation artifact when validation executed."),
  profile: ValidationProfileSchema.describe("Requested validation profile."),
  focused: z.boolean().optional().describe("Whether validation was scoped to explicit test paths."),
  test_paths: z.array(z.string()).optional().describe("Validated focused test paths when supplied."),
  dry_run: z.boolean().describe("Whether validation resolved commands without executing project validation scripts."),
  status: ValidationCommandStatusSchema.describe("Overall validation status across all selected commands."),
  commands: z.array(ValidateCommandResultSchema).describe("Validation commands selected and their results."),
  counts: z.object({
    total: z.number().int().nonnegative().describe("Total selected validation commands."),
    passed: z.number().int().nonnegative().describe("Number of validation commands that passed."),
    failed: z.number().int().nonnegative().describe("Number of validation commands that failed."),
    skipped: z.number().int().nonnegative().describe("Number of validation commands skipped by dry-run mode.")
  }).describe("Validation command counts by status."),
  warnings: z.array(z.string()).describe("Stable warning codes produced during validation."),
  validation_artifact: z.object({
    path: z.string().describe("Repo-relative path to the saved redacted validation artifact.")
  }).optional().describe("Saved validation artifact metadata when validation executed.")
});

const ValidationIndexEntrySchema = z.object({
  path: z.string().min(1).max(4_096),
  mode: z.string().regex(/^(?:100644|100755|120000)$/),
  object_id: z.string().regex(/^[a-f0-9]{40,64}$/),
  stage: z.number().int().min(0).max(3)
}).strict();

const ValidationSourceWorktreeSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("file"), mode_bits: z.number().int().nonnegative(), size_bytes: z.number().int().nonnegative(), content_sha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict(),
  z.object({ kind: z.literal("symlink"), mode_bits: z.number().int().nonnegative(), size_bytes: z.number().int().nonnegative(), content_sha256: z.string().regex(/^[a-f0-9]{64}$/), symlink_target: z.string() }).strict(),
  z.object({ kind: z.literal("missing"), mode_bits: z.null(), size_bytes: z.literal(0) }).strict()
]);

export const ValidationSourceSnapshotSchema = z.object({
  schema_version: z.literal(2),
  root: z.object({
    configured_path: z.string().min(1),
    real_path: z.string().min(1),
    device: z.string().min(1),
    inode: z.string().min(1),
    git_dir: z.string().min(1),
    git_common_dir: z.string().min(1)
  }).strict(),
  head_sha: z.string().regex(/^[a-f0-9]{40,64}$/),
  ref: z.string().min(1),
  index: z.object({ entries: z.array(ValidationIndexEntrySchema), sha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict(),
  files: z.array(z.object({
    path: z.string().min(1).max(4_096),
    head: z.object({ mode: z.string().regex(/^(?:100644|100755|120000)$/), object_id: z.string().regex(/^[a-f0-9]{40,64}$/) }).strict().optional(),
    index_entries: z.array(ValidationIndexEntrySchema),
    untracked: z.boolean(),
    worktree: ValidationSourceWorktreeSchema
  }).strict()),
  content_bytes: z.number().int().nonnegative(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/)
}).strict();

export const ValidationReceiptV2BaseSchema = z.object({
  schema_version: z.literal(2),
  evidence_contract_version: z.literal(2),
  validation_id: z.string().min(1),
  repo_id: z.string().min(1),
  profile: ValidationProfileSchema,
  focused: z.boolean(),
  test_paths: z.array(z.string()),
  status: ValidationCommandStatusSchema,
  eligibility: z.object({ status: z.enum(["eligible", "ineligible", "unverified"]), reasons: z.array(z.string().min(1)) }).strict(),
  head_sha: z.string().regex(/^[a-f0-9]{40,64}$/).optional(),
  worktree_fingerprint: z.string().min(1).optional(),
  timestamp: z.string().datetime({ offset: true }),
  artifact_path: z.string().min(1),
  effective_policy: z.object({
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    after_sha256: z.string().regex(/^[a-f0-9]{64}$/),
    value: z.unknown()
  }).strict(),
  source_evidence: z.object({
    before: ValidationSourceSnapshotSchema.optional(),
    before_error: z.string().optional(),
    after: ValidationSourceSnapshotSchema.optional(),
    after_error: z.string().optional(),
    observation: z.literal("endpoint_snapshots_only"),
    continuous_detection: z.literal(false),
    limitation: z.literal("Endpoint snapshots do not establish detection of transient change-and-revert activity.")
  }).strict(),
  runner_post_state: z.array(z.object({
    profile: ValidationProfileSchema,
    script: z.string().min(1),
    executable: z.string().min(1),
    status: z.enum(["verified", "unverified"]),
    reason: z.string().optional(),
    executable_identity: ValidationExecutableIdentitySchema.optional(),
    runtime_executable_identity: ValidationExecutableIdentitySchema.optional(),
    recipe: ValidationRecipeSchema.optional(),
    runtime: ValidationRuntimeSchema.optional()
  }).strict()),
  commands: z.array(ValidateCommandResultSchema),
  counts: ValidateResultSchema.shape.counts,
  warnings: z.array(z.string()),
  receipt_sha256: z.string().regex(/^[a-f0-9]{64}$/)
}).strict();
export const ValidationReceiptV2Schema = ValidationReceiptV2BaseSchema.superRefine((receipt, context) => {
  const commandCounts = {
    total: receipt.commands.length,
    passed: receipt.commands.filter((command) => command.status === "passed").length,
    failed: receipt.commands.filter((command) => command.status === "failed").length,
    skipped: receipt.commands.filter((command) => command.status === "skipped").length
  };
  if (receipt.counts.total !== commandCounts.total
      || receipt.counts.passed !== commandCounts.passed
      || receipt.counts.failed !== commandCounts.failed
      || receipt.counts.skipped !== commandCounts.skipped) {
    context.addIssue({
      code: "custom",
      path: ["counts"],
      message: "Validation command counts must match the recorded command outcomes."
    });
  }
  const expectedStatus = commandCounts.failed > 0
    ? "failed"
    : commandCounts.skipped > 0 || commandCounts.passed === 0
      ? "skipped"
      : "passed";
  if (receipt.status !== expectedStatus) {
    context.addIssue({
      code: "custom",
      path: ["status"],
      message: "Validation status must match the recorded command outcomes."
    });
  }
  receipt.commands.forEach((command, index) => {
    if (command.runtime?.name === "rust") requireCargoConfigIdentity(command.runtime, ["commands", index, "runtime"], context);
  });
  receipt.runner_post_state.forEach((runner, index) => {
    if (runner.runtime?.name === "rust") requireCargoConfigIdentity(runner.runtime, ["runner_post_state", index, "runtime"], context);
  });
});

export const ValidationLatestPointerV2Schema = z.object({
  schema_version: z.literal(2),
  evidence_contract_version: z.literal(2),
  validation_id: z.string().min(1),
  repo_id: z.string().min(1),
  profile: ValidationProfileSchema,
  focused: z.boolean(),
  test_paths: z.array(z.string()),
  status: ValidationCommandStatusSchema,
  eligibility: z.enum(["eligible", "ineligible", "unverified"]),
  head_sha: z.string().regex(/^[a-f0-9]{40,64}$/).optional(),
  worktree_fingerprint: z.string().min(1).optional(),
  artifact_path: z.string().min(1),
  timestamp: z.string().datetime({ offset: true }),
  receipt_sha256: z.string().regex(/^[a-f0-9]{64}$/)
}).strict();

function requireCargoConfigIdentity(
  runtime: z.infer<typeof RustValidationRuntimeSchema>,
  path: Array<string | number>,
  context: z.RefinementCtx
): void {
  for (const field of ["cargo_home_path_sha256", "cargo_config_sha256"] as const) {
    if (!runtime[field]) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "V2 Rust evidence must bind its Cargo home and configuration.",
        path: [...path, field]
      });
    }
  }
}

export type ValidateInput = z.infer<typeof ValidateInputSchema>;
export type ValidationProfile = z.infer<typeof ValidationProfileSchema>;
export type ValidateResult = z.infer<typeof ValidateResultSchema>;
export type ValidationReceiptV2 = z.infer<typeof ValidationReceiptV2Schema>;
export type ValidationLatestPointerV2 = z.infer<typeof ValidationLatestPointerV2Schema>;
export type ValidationRuntime = z.infer<typeof ValidationRuntimeSchema>;
