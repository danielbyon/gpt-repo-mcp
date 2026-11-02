import { constants, type BigIntStats } from "node:fs";
import { createHash } from "node:crypto";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { z } from "zod";
import { RepoReaderError } from "../runtime/errors.js";
import { delegationBaselineSha256V3, parseDelegationManifestV3 } from "./delegation-v3-normalizer.js";
import { errorReason, taskExecutionError } from "./task-execution-errors.js";

export const TASK_EXECUTION_BOOTSTRAP_ENV = "GPT_REPO_TASK_BOOTSTRAP_PATH";

const SHA1 = z.string().regex(/^[a-f0-9]{40}$/);
const SHA256 = z.string().regex(/^[a-f0-9]{64}$/);
const TaskLimitsSchema = z.object({
  bootstrap_bytes: z.number().int().min(1024).max(64 * 1024),
  receipt_bytes: z.number().int().min(4096).max(8 * 1024 * 1024),
  refs: z.number().int().min(1).max(4096),
  untracked_entries: z.number().int().min(1).max(1000),
  protected_paths: z.number().int().min(1).max(128),
  path_bytes: z.number().int().min(1).max(1024),
  inventory_bytes: z.number().int().min(1).max(8 * 1024 * 1024),
  index_bytes: z.number().int().min(1).max(8 * 1024 * 1024),
  sidecar_bytes: z.number().int().min(1).max(8 * 1024 * 1024),
  tracked_entries: z.number().int().min(1).max(100_000)
}).strict();

const TaskExecutionBootstrapSchema = z.object({
  schema: z.literal("gpt-repo-mcp.task-bootstrap"),
  schema_version: z.literal(2),
  task_id: z.string().min(1).max(128),
  run_ids: z.array(z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{6}Z-[a-z0-9][a-z0-9-]{0,79}$/)).min(1).max(64),
  repo_id: z.string().min(1).max(200),
  protected_root: z.string().min(1).max(4096),
  execution_root: z.string().min(1).max(4096),
  expected_baseline: z.object({
    head_sha: SHA1,
    worktree_fingerprint: z.string().min(1).max(128),
    baseline_sha256: SHA256
  }).strict(),
  protected_paths: z.array(z.string().min(1).max(1024)).max(128),
  protected_state_inputs: z.array(z.string().min(1).max(256)).max(32),
  explicit_exclusions: z.array(z.string().min(1).max(256)).max(64),
  authorized_source_paths: z.array(z.string().min(1).max(1024)).max(1000),
  authorized_ref_transitions: z.array(z.object({
    refname: z.string().regex(/^refs\/[A-Za-z0-9._/-]+$/).max(1024),
    before_oid: SHA1.nullable(),
    after_oid: SHA1.nullable()
  }).strict().refine((item) => item.before_oid !== item.after_oid, "A ref transition must change its endpoint.")).max(4096),
  receipt_directory: z.string().min(1).max(4096),
  path_token_key: SHA256,
  limits: TaskLimitsSchema
}).strict().superRefine((bootstrap, context) => {
  for (const [field, paths] of [
    ["protected_paths", bootstrap.protected_paths],
    ["authorized_source_paths", bootstrap.authorized_source_paths]
  ] as const) {
    if (new Set(paths).size !== paths.length) {
      context.addIssue({ code: "custom", path: [field], message: "Paths must be unique." });
    }
    paths.forEach((path, index) => {
      if (!isSafeRepoRelativePath(path)) {
        context.addIssue({ code: "custom", path: [field, index], message: "Expected a safe repo-relative POSIX path." });
      }
    });
  }
  if (new Set(bootstrap.run_ids).size !== bootstrap.run_ids.length) {
    context.addIssue({ code: "custom", path: ["run_ids"], message: "Run IDs must be unique." });
  }
  if (new Set(bootstrap.authorized_ref_transitions.map(({ refname }) => refname)).size !== bootstrap.authorized_ref_transitions.length) {
    context.addIssue({ code: "custom", path: ["authorized_ref_transitions"], message: "Ref transitions must have unique refnames." });
  }
});

export type TaskExecutionBootstrap = {
  schema: "gpt-repo-mcp.task-bootstrap";
  schema_version: 2;
  task_id: string;
  run_ids: readonly string[];
  repo_id: string;
  protected_root: string;
  execution_root: string;
  expected_baseline: { head_sha: string; worktree_fingerprint: string; baseline_sha256: string };
  protected_paths: readonly string[];
  protected_state_inputs: readonly string[];
  explicit_exclusions: readonly string[];
  authorized_source_paths: readonly string[];
  authorized_ref_transitions: readonly { refname: string; before_oid: string | null; after_oid: string | null }[];
  receipt_directory: string;
  path_token_key: string;
  limits: Readonly<{
    bootstrap_bytes: number;
    receipt_bytes: number;
    refs: number;
    untracked_entries: number;
    protected_paths: number;
    path_bytes: number;
    inventory_bytes: number;
    index_bytes: number;
    sidecar_bytes: number;
    tracked_entries: number;
  }>;
};

export type ExecutionIdentityInput = {
  bootstrap: TaskExecutionBootstrap;
  repo_id: string;
  configured_root: string;
  cwd: string;
};

export type ExecutionIdentity = {
  status: "verified";
  primary_root: string;
  execution_root: string;
  primary_git_dir: string;
  primary_common_dir: string;
  execution_git_dir: string;
  execution_common_dir: string;
  execution_head: string;
  execution_linked_worktree: boolean;
  shared_refs: boolean;
  shares_protected_admin: boolean;
};

export type TaskPreservationIdentityEvidence = {
  status: "verified";
  protected_root_token: string;
  execution_root_token: string;
  protected_git_admin_token: string;
  execution_git_admin_token: string;
  execution_head: string;
  execution_linked_worktree: boolean;
  shared_refs: boolean;
  shared_protected_admin_state: boolean;
};

export type PathMetadata = {
  path_token: string;
  present: boolean;
  kind?: "file" | "directory" | "symlink" | "other";
  mode?: number;
  size?: string;
  mtime_ns?: string;
  ctime_ns?: string;
  device?: string;
  inode?: string;
  links?: string;
};

export type TaskPreservationSnapshot = {
  collected_at_utc: string;
  head: { oid: string; symbolic_ref: string | null };
  refs: Record<string, string>;
  index: { path_token: string; sha256: string; size: string; mtime_ns: string; device: string; inode: string };
  staged_entries: Array<{ path_token: string; mode: string; oid: string; stage: number }>;
  tracked_metadata: PathMetadata[];
  protected_metadata: PathMetadata[];
  owner_protected_metadata: PathMetadata[];
  untracked_count: number;
  untracked_inventory_sha256: string;
  untracked_metadata: PathMetadata[];
  inventory_complete: boolean;
  unsupported_layouts: string[];
  errors: string[];
};

type Snapshot = TaskPreservationSnapshot;

export type TaskPreservationSidecar = {
  schema: "gpt-repo-mcp.preservation-observation.v1";
  task_id: string;
  verdict: "NOT_PROVEN";
  identity: TaskPreservationIdentityEvidence;
  limits: Readonly<Record<string, number>>;
  pre: Snapshot;
  post: Snapshot | null;
  collection: {
    operation: TaskExecutionOperation;
    operation_outcome: "completed" | "failed";
    operation_error_code?: string;
    operation_started_at_utc: string;
    operation_finished_at_utc: string;
    started_at_utc: string;
    finished_at_utc: string;
    stable_endpoints: boolean;
    differences: Array<{ category: "owner_authorized" | "unattributed"; state: string }>;
    attribution_categories: { owner_authorized: string[]; attributed_to_task: string[]; unattributed: string[]; not_proven: string[] };
    content_equivalence: "NOT_PROVEN";
    collector_environment: {
      git_env_allowlist: string[];
      git_overrides: string[];
      git_version: string;
      node_version: string;
      git_commands: string[];
    };
    limitations: string[];
  };
};

export type TaskPreservationSample = {
  identity: ExecutionIdentity;
  snapshot: Snapshot;
  collector_environment: TaskPreservationSidecar["collection"]["collector_environment"];
};

export type CollectTaskPreservationInput = {
  bootstrap: TaskExecutionBootstrap;
  repo_id: string;
  configured_root: string;
  cwd: string;
  now?: () => Date;
  run_git?: (root: string, args: string[], allowedExitCodes?: readonly number[]) => Promise<Buffer>;
};

export type TaskExecutionOperation = "prepare" | "registration" | "queue" | "resume" | "review" | "repository_review" | "patchset_review" | "validation" | "index" | "async";

export type TaskExecutionInput = {
  repo_id?: string;
  root?: string;
  registered_repo?: { repo_id: string; root: string };
  resolve_registered_repo?: () => { repo_id: string; root: string };
  operation: TaskExecutionOperation;
  run_id?: string;
  run_ids?: readonly string[];
  task_text?: string;
};

export type TaskExecutionEvidence = {
  operation_id: string;
  operation: TaskExecutionOperation;
  verdict: "NOT_PROVEN";
  receipt_sha256: string;
};

export type VerifiedTaskRunBinding = {
  run_id: string;
  baseline_sha256: string;
  prompt_sha256: string;
};

export type TaskExecutionRegistrationBaseline = {
  head_sha: string;
  worktree_fingerprint: string;
  baseline_sha256: string;
};

export type TaskExecutionBoundaryOptions = {
  cwd?: () => string;
  now?: () => Date;
  run_git?: CollectTaskPreservationInput["run_git"];
};

export type TaskExecutionProviderGuard = {
  /** The sole enrolled run selected by the owner, when this operation has one. */
  run_id?: string;
  revalidateBeforeProvider(): Promise<void>;
  bindTaskPrompt(
    prompt: string,
    repoId: string,
    runId: string,
    sourcePaths: readonly string[],
    env?: NodeJS.ProcessEnv,
    registrationBaseline?: TaskExecutionRegistrationBaseline
  ): Promise<string>;
};

export type TaskExecutionSession = {
  readonly execution_root: string;
  readonly run_id?: string;
  revalidateBeforeProvider(registeredRepo?: () => { repo_id: string; root: string }): Promise<void>;
  bindTaskPrompt(
    prompt: string,
    repoId: string,
    runId: string,
    sourcePaths: readonly string[],
    env?: NodeJS.ProcessEnv,
    registrationBaseline?: TaskExecutionRegistrationBaseline
  ): Promise<string>;
  finish(outcome?: { status?: "completed" | "failed"; error?: unknown }): Promise<TaskExecutionEvidence>;
};

export type LoadedTaskExecutionBootstrap = {
  bootstrap: TaskExecutionBootstrap;
  descriptor_path: string;
  sha256: string;
};

export function sameFileIdentity(left: Awaited<ReturnType<typeof lstat>>, right: Awaited<ReturnType<typeof lstat>>): boolean {
  const a = left as Awaited<ReturnType<typeof lstat>> & { dev: bigint; ino: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint };
  const b = right as Awaited<ReturnType<typeof lstat>> & { dev: bigint; ino: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint };
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
}

/** Loads owner enrollment from process context and rejects unsafe descriptor files. */
export async function loadTaskExecutionBootstrapFromEnvironment(
  env: NodeJS.ProcessEnv = process.env
): Promise<LoadedTaskExecutionBootstrap | undefined> {
  const configuredPath = env[TASK_EXECUTION_BOOTSTRAP_ENV];
  if (configuredPath === undefined) return undefined;
  if (configuredPath === "") throw taskExecutionError("bootstrap_path_empty");
  if (!isAbsolute(configuredPath) || resolve(configuredPath) !== configuredPath) {
    throw taskExecutionError("bootstrap_path_not_canonical");
  }

  const pathStat = await lstat(configuredPath, { bigint: true }).catch(() => undefined);
  if (!pathStat || !isOwnerControlledFile(pathStat)) throw taskExecutionError("bootstrap_file_unsafe");
  const canonicalPath = await realpath(configuredPath).catch(() => "");
  if (canonicalPath !== configuredPath) throw taskExecutionError("bootstrap_path_not_canonical");
  const bytes = await readOwnerControlledFile(configuredPath, 64 * 1024);
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw taskExecutionError("bootstrap_json_invalid");
  }
  const result = TaskExecutionBootstrapSchema.safeParse(parsed);
  if (!result.success) throw taskExecutionError("bootstrap_schema_invalid");
  const bootstrap = result.data;
  await validateBootstrapPaths(bootstrap, configuredPath);
  if (bytes.length > bootstrap.limits.bootstrap_bytes) throw taskExecutionError("bootstrap_size_limit_exceeded");
  return {
    bootstrap,
    descriptor_path: configuredPath,
    sha256: createHash("sha256").update(bytes).digest("hex")
  };
}

/** Checks the process registration, physical roots, Git metadata, and expected baseline. */
export async function verifyTaskV3RunBinding(input: {
  loaded: LoadedTaskExecutionBootstrap;
  registered_repo: { repo_id: string; root: string };
  run_id: string;
}): Promise<VerifiedTaskRunBinding> {
  const { bootstrap } = input.loaded;
  if (!bootstrap.run_ids.includes(input.run_id)
    || input.registered_repo.repo_id !== bootstrap.repo_id
    || input.registered_repo.root !== bootstrap.execution_root) {
    throw taskExecutionError("v3_run_identity_mismatch");
  }
  const runDirectory = join(bootstrap.execution_root, ".chatgpt", "codex-runs", input.run_id);
  await assertNoSymlinkPath(bootstrap.execution_root, runDirectory);
  const promptPath = join(runDirectory, "PROMPT.md");
  const manifestPath = join(runDirectory, "run.json");
  const [promptBytes, manifestBytes] = await Promise.all([
    readBoundedRegularFile(promptPath, bootstrap.limits.sidecar_bytes),
    readBoundedRegularFile(manifestPath, bootstrap.limits.sidecar_bytes)
  ]);
  let parsed: unknown;
  try {
    parsed = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw taskExecutionError("v3_manifest_invalid");
  }
  let manifest: ReturnType<typeof parseDelegationManifestV3>;
  try {
    manifest = parseDelegationManifestV3(parsed);
  } catch {
    throw taskExecutionError("v3_manifest_invalid");
  }
  const baselineDigest = delegationBaselineSha256V3(manifest.baseline);
  const prompt = promptBytes.toString("utf8");
  const requestedSources = [...new Set([
    ...manifest.task.starting_points,
    ...manifest.authorization.effective_scope,
    ...manifest.baseline.initial_changed_paths
  ])].sort();
  assertAuthorizedSourcePaths(bootstrap, requestedSources);
  const expectedPromptPath = ".chatgpt/codex-runs/" + input.run_id + "/PROMPT.md";
  const expectedResultPath = ".chatgpt/codex-runs/" + input.run_id + "/RESULT.json";
  const expectedManifestPath = ".chatgpt/codex-runs/" + input.run_id + "/run.json";
  if (
    manifest.repo_id !== bootstrap.repo_id
    || manifest.run_id !== input.run_id
    || manifest.prompt_path !== expectedPromptPath
    || manifest.result_json_path !== expectedResultPath
    || manifest.manifest_path !== expectedManifestPath
    || manifest.baseline.head_sha !== bootstrap.expected_baseline.head_sha
    || manifest.baseline.worktree_fingerprint !== bootstrap.expected_baseline.worktree_fingerprint
    || !hasCompleteNormalizedBaseline(manifest.baseline)
    || manifest.baseline_sha256 !== bootstrap.expected_baseline.baseline_sha256
    || baselineDigest !== bootstrap.expected_baseline.baseline_sha256
    || manifest.prompt_byte_count !== promptBytes.byteLength
    || manifest.prompt_sha256 !== createHash("sha256").update(promptBytes).digest("hex")
    || !hasValidPromptBinding(prompt, input.loaded, manifest.repo_id, input.run_id, requestedSources)
  ) {
    throw taskExecutionError("v3_run_binding_mismatch");
  }
  return {
    run_id: input.run_id,
    baseline_sha256: manifest.baseline_sha256,
    prompt_sha256: manifest.prompt_sha256
  };
}

function hasCompleteNormalizedBaseline(baseline: ReturnType<typeof parseDelegationManifestV3>["baseline"]): boolean {
  const states = baseline.initial_path_states;
  if (!states) return false;
  const normalizedPaths = [...new Set(baseline.initial_changed_paths)].sort((left, right) => left.localeCompare(right));
  const normalizedStates = [...states].sort((left, right) => left.path.localeCompare(right.path));
  return JSON.stringify(baseline.initial_changed_paths) === JSON.stringify(normalizedPaths)
    && JSON.stringify(states) === JSON.stringify(normalizedStates)
    && JSON.stringify(states.map(({ path }) => path)) === JSON.stringify(normalizedPaths);
}

export async function verifyTaskV3Runs(
  loaded: LoadedTaskExecutionBootstrap,
  registeredRepo: { repo_id: string; root: string },
  runIds: readonly string[]
): Promise<VerifiedTaskRunBinding[]> {
  const bindings: VerifiedTaskRunBinding[] = [];
  for (const runId of runIds) {
    bindings.push(await verifyTaskV3RunBinding({ loaded, registered_repo: registeredRepo, run_id: runId }));
  }
  return bindings;
}

/** Adds a structured owner binding without exposing source or protected path names. */
export function bindTaskPrompt(
  prompt: string,
  loaded: LoadedTaskExecutionBootstrap,
  repoId: string,
  runId: string,
  sourcePaths: readonly string[],
  registrationBaseline?: TaskExecutionRegistrationBaseline
): string {
  if (repoId !== loaded.bootstrap.repo_id || !loaded.bootstrap.run_ids.includes(runId)) {
    throw taskExecutionError("v3_run_identity_mismatch");
  }
  if (registrationBaseline && (
    registrationBaseline.head_sha !== loaded.bootstrap.expected_baseline.head_sha
    || registrationBaseline.worktree_fingerprint !== loaded.bootstrap.expected_baseline.worktree_fingerprint
    || registrationBaseline.baseline_sha256 !== loaded.bootstrap.expected_baseline.baseline_sha256
  )) {
    throw taskExecutionError("v3_registration_baseline_mismatch");
  }
  assertAuthorizedSourcePaths(loaded.bootstrap, sourcePaths);
  const binding = {
    schema: "gpt-repo-mcp.task-prompt-binding",
    schema_version: 1,
    task_id: loaded.bootstrap.task_id,
    run_id: runId,
    repo_id: repoId,
    bootstrap_sha256: loaded.sha256,
    source_path_set_sha256: digestSourcePaths(sourcePaths)
  };
  const encoded = Buffer.from(JSON.stringify(binding), "utf8").toString("base64url");
  return prompt.trimEnd() + "\n\n<!-- gpt-repo-mcp-task-binding " + encoded + " -->\n";
}

/** Adds owner prompt binding only when this process is enrolled for the task. */
export async function bindTaskPromptIfEnrolled(
  prompt: string,
  repoId: string,
  runId: string,
  sourcePaths: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
  registrationBaseline?: TaskExecutionRegistrationBaseline
): Promise<string> {
  const loaded = await loadTaskExecutionBootstrapFromEnvironment(env);
  return loaded ? bindTaskPrompt(prompt, loaded, repoId, runId, sourcePaths, registrationBaseline) : prompt;
}

async function readBoundedRegularFile(path: string, maxBytes: number): Promise<Buffer> {
  try {
    const before = await lstat(path, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.size > BigInt(maxBytes)) {
      throw taskExecutionError("bound_file_unsafe_or_over_limit");
    }
    const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const opened = await file.stat({ bigint: true });
      if (!sameFileIdentity(before, opened)) throw taskExecutionError("bound_file_changed_while_opening");
      const output: Buffer[] = [];
      let size = 0;
      const chunk = Buffer.alloc(64 * 1024);
      while (true) {
        const { bytesRead } = await file.read(chunk, 0, chunk.length, size);
        if (bytesRead === 0) break;
        size += bytesRead;
        if (size > maxBytes) throw taskExecutionError("bound_file_size_limit_exceeded");
        output.push(Buffer.from(chunk.subarray(0, bytesRead)));
      }
      const afterOpen = await file.stat({ bigint: true });
      const afterPath = await lstat(path, { bigint: true });
      if (!sameFileIdentity(before, afterOpen) || !sameFileIdentity(before, afterPath) || BigInt(size) !== before.size) {
        throw taskExecutionError("bound_file_changed_during_read");
      }
      return Buffer.concat(output);
    } finally {
      await file.close();
    }
  } catch (error) {
    if (error instanceof RepoReaderError) throw error;
    throw taskExecutionError(errorReason(error));
  }
}

export async function loadTaskExecutionBootstrapAtPath(path: string): Promise<LoadedTaskExecutionBootstrap> {
  const loaded = await loadTaskExecutionBootstrapFromEnvironment({ [TASK_EXECUTION_BOOTSTRAP_ENV]: path });
  if (!loaded) throw taskExecutionError("bootstrap_unavailable");
  return loaded;
}

export async function readOwnerControlledFile(path: string, maxBytes: number): Promise<Buffer> {
  try {
    const before = await lstat(path, { bigint: true });
    if (!isOwnerControlledFile(before) || before.size > BigInt(maxBytes)) throw taskExecutionError("owner_file_unsafe_or_over_limit");
    const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const opened = await file.stat({ bigint: true });
      if (!sameFileIdentity(before, opened)) throw taskExecutionError("owner_file_changed_while_opening");
      const chunks: Buffer[] = [];
      const chunk = Buffer.alloc(32 * 1024);
      let size = 0;
      while (true) {
        const { bytesRead } = await file.read(chunk, 0, chunk.length, size);
        if (bytesRead === 0) break;
        size += bytesRead;
        if (size > maxBytes) throw taskExecutionError("owner_file_size_limit_exceeded");
        chunks.push(Buffer.from(chunk.subarray(0, bytesRead)));
      }
      const afterOpen = await file.stat({ bigint: true });
      const afterPath = await lstat(path, { bigint: true });
      if (!sameFileIdentity(before, afterOpen) || !sameFileIdentity(before, afterPath) || BigInt(size) !== before.size) {
        throw taskExecutionError("owner_file_changed_during_read");
      }
      return Buffer.concat(chunks);
    } finally {
      await file.close();
    }
  } catch (error) {
    if (error instanceof RepoReaderError) throw error;
    throw taskExecutionError(errorReason(error));
  }
}

export function isOwnerControlledFile(stat: BigIntStats): boolean {
  const owner = typeof process.getuid === "function" ? BigInt(process.getuid()) : undefined;
  return stat.isFile()
    && !stat.isSymbolicLink()
    && (owner === undefined || stat.uid === owner)
    && Number(stat.mode & 0o777n) === 0o600
    && stat.nlink === 1n;
}

async function validateBootstrapPaths(bootstrap: TaskExecutionBootstrap, descriptorPath: string): Promise<void> {
  const paths = [bootstrap.protected_root, bootstrap.execution_root, bootstrap.receipt_directory, descriptorPath];
  for (const path of paths) {
    if (!isAbsolute(path) || resolve(path) !== path || await realpath(path).catch(() => "") !== path) {
      throw taskExecutionError("bootstrap_path_not_canonical");
    }
  }
  const [protectedInfo, executionInfo, receiptInfo] = await Promise.all([
    lstat(bootstrap.protected_root, { bigint: true }),
    lstat(bootstrap.execution_root, { bigint: true }),
    lstat(bootstrap.receipt_directory, { bigint: true })
  ]);
  if (!protectedInfo.isDirectory() || protectedInfo.isSymbolicLink()
    || !executionInfo.isDirectory() || executionInfo.isSymbolicLink()
    || !isOwnerControlledDirectory(receiptInfo)
    || rootsOverlap(bootstrap.protected_root, bootstrap.execution_root)
    || rootsOverlap(bootstrap.protected_root, bootstrap.receipt_directory)
    || rootsOverlap(bootstrap.execution_root, bootstrap.receipt_directory)
    || isWithin(bootstrap.protected_root, descriptorPath)
    || isWithin(bootstrap.execution_root, descriptorPath)) {
    throw taskExecutionError("bootstrap_path_policy_invalid");
  }
  if (bootstrap.protected_paths.length > bootstrap.limits.protected_paths) {
    throw taskExecutionError("protected_path_limit_exceeded");
  }
}

export function isOwnerControlledDirectory(stat: BigIntStats): boolean {
  const owner = typeof process.getuid === "function" ? BigInt(process.getuid()) : undefined;
  return stat.isDirectory()
    && !stat.isSymbolicLink()
    && (owner === undefined || stat.uid === owner)
    && (stat.mode & 0o077n) === 0n;
}

async function assertNoSymlinkPath(root: string, target: string): Promise<void> {
  const canonicalRoot = await realpath(root);
  if (!isWithin(canonicalRoot, target)) throw taskExecutionError("path_outside_execution_root");
  const relativePath = relative(canonicalRoot, resolve(target));
  let current = canonicalRoot;
  for (const component of relativePath.split(sep).filter(Boolean)) {
    current = join(current, component);
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw taskExecutionError("symlink_path_component");
  }
}

export function resolveRunIds(bootstrap: TaskExecutionBootstrap, input: TaskExecutionInput): string[] {
  if (input.operation === "patchset_review") {
    if (input.run_id !== undefined || (input.run_ids?.length ?? 0) > 0) {
      throw taskExecutionError("task_run_id_not_applicable");
    }
    return [];
  }
  const explicit = input.run_ids ? [...input.run_ids] : input.run_id ? [input.run_id] : [];
  const selected = explicit.length > 0
    ? explicit
    : bootstrap.run_ids.length === 1
      ? [bootstrap.run_ids[0]!]
      : ["index", "validation", "async", "repository_review"].includes(input.operation)
        ? [...bootstrap.run_ids]
        : [];
  if (selected.length === 0) throw taskExecutionError("task_run_id_required");
  if (["prepare", "registration", "queue", "resume"].includes(input.operation) && selected.length !== 1) {
    throw taskExecutionError("single_task_run_id_required");
  }
  if (selected.some((runId) => !isValidRunId(runId) || !bootstrap.run_ids.includes(runId))) {
    throw taskExecutionError("task_run_id_not_authorized");
  }
  if (new Set(selected).size !== selected.length) throw taskExecutionError("duplicate_run_id");
  return selected;
}

export function assertTaskInputPaths(bootstrap: TaskExecutionBootstrap, taskText: string | undefined): void {
  if (!taskText) return;
  let input: unknown;
  try {
    input = JSON.parse(taskText);
  } catch {
    throw taskExecutionError("task_input_invalid");
  }
  const paths: string[] = [];
  const pathKeys = new Set(["starting_points", "authorization_scope", "paths", "test_paths", "scope_paths"]);
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (typeof value !== "object" || value === null) return;
    for (const [key, nested] of Object.entries(value)) {
      if (pathKeys.has(key) && Array.isArray(nested)) {
        if (!nested.every((item): item is string => typeof item === "string")) throw taskExecutionError("task_path_input_invalid");
        paths.push(...nested);
      } else {
        visit(nested);
      }
    }
  };
  visit(input);
  assertAuthorizedSourcePaths(bootstrap, paths);
}

function assertAuthorizedSourcePaths(bootstrap: TaskExecutionBootstrap, paths: readonly string[]): void {
  const allowed = new Set(bootstrap.authorized_source_paths);
  for (const path of paths) {
    if (!isSafeRepoRelativePath(path) || !allowed.has(path)) throw taskExecutionError("source_path_not_authorized");
  }
}

function hasValidPromptBinding(
  prompt: string,
  loaded: LoadedTaskExecutionBootstrap,
  repoId: string,
  runId: string,
  sourcePaths: readonly string[]
): boolean {
  const markers = [...prompt.matchAll(/<!-- gpt-repo-mcp-task-binding ([A-Za-z0-9_-]+) -->/g)];
  if (markers.length !== 1) return false;
  try {
    const binding: unknown = JSON.parse(Buffer.from(markers[0]![1]!, "base64url").toString("utf8"));
    if (typeof binding !== "object" || binding === null || Array.isArray(binding)) return false;
    const value = binding as Record<string, unknown>;
    return value.schema === "gpt-repo-mcp.task-prompt-binding"
      && value.schema_version === 1
      && value.task_id === loaded.bootstrap.task_id
      && value.run_id === runId
      && value.repo_id === repoId
      && value.bootstrap_sha256 === loaded.sha256
      && value.source_path_set_sha256 === digestSourcePaths(sourcePaths)
      && Object.keys(value).length === 7;
  } catch {
    return false;
  }
}

function digestSourcePaths(paths: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify([...new Set(paths)].sort()), "utf8").digest("hex");
}

function isSafeRepoRelativePath(path: string): boolean {
  if (!path || path.startsWith("/") || path.includes(String.fromCharCode(92))) return false;
  return path.split("/").every((component) =>
    component !== ""
      && component !== "."
      && component !== ".."
      && !/^[A-Za-z]:/.test(component)
  );
}

function isValidRunId(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}T\d{6}Z-[a-z0-9][a-z0-9-]{0,79}$/.test(value);
}

function rootsOverlap(left: string, right: string): boolean {
  return isWithin(left, right) || isWithin(right, left);
}

export function isWithin(root: string, path: string): boolean {
  const rel = relative(resolve(root), resolve(path));
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== "..");
}
