import { spawn } from "node:child_process";
import { constants, type BigIntStats } from "node:fs";
import { createHash, createHmac } from "node:crypto";
import { lstat, open, realpath } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { RepoReaderError } from "../runtime/errors.js";
import { errorReason, taskExecutionError } from "./task-execution-errors.js";
import type {
  ExecutionIdentity,
  ExecutionIdentityInput,
  TaskPreservationSample,
  TaskPreservationSidecar,
  TaskPreservationSnapshot,
  CollectTaskPreservationInput,
  TaskPreservationIdentityEvidence,
  TaskExecutionBootstrap,
  TaskExecutionOperation,
  PathMetadata
} from "./task-execution-bootstrap.js";
import { sameFileIdentity } from "./task-execution-bootstrap.js";

const GIT_STDOUT_LIMIT = 8 * 1024 * 1024;
const GIT_STDERR_LIMIT = 128 * 1024;
const GIT_TIMEOUT_MS = 15_000;
const GIT_OPTIONS = [
  "-c", "core.fsmonitor=false",
  "-c", "maintenance.auto=false",
  "-c", "gc.auto=0",
  "-c", "diff.external=",
  "-c", "core.pager=cat",
  "-c", "core.hooksPath=/dev/null",
  "-c", "color.ui=false"
];
type Snapshot = TaskPreservationSnapshot;
const BUILT_IN_PROTECTED_STATE_INPUTS = new Set(["HEAD", "refs", "index"]);

export async function verifyExecutionIdentity(
  input: ExecutionIdentityInput
): Promise<ExecutionIdentity> {
  const { bootstrap } = input;
  if (input.repo_id !== bootstrap.repo_id) throw taskExecutionError("repository_id_mismatch");
  try {
    const [primaryReal, executionReal, configuredReal, cwdReal] = await Promise.all([
      realpath(bootstrap.protected_root),
      realpath(bootstrap.execution_root),
      realpath(input.configured_root),
      realpath(input.cwd)
    ]);
    if (
      primaryReal !== bootstrap.protected_root
      || executionReal !== bootstrap.execution_root
      || configuredReal !== input.configured_root
      || configuredReal !== bootstrap.execution_root
      || cwdReal !== bootstrap.execution_root
      || rootsOverlap(primaryReal, executionReal)
    ) {
      throw taskExecutionError("physical_root_or_cwd_mismatch");
    }

    const [primary, execution] = await Promise.all([
      readGitIdentity(primaryReal),
      readGitIdentity(executionReal)
    ]);
    const sharesProtectedAdmin = execution.commonDir === primary.commonDir;
    if (
      primary.top !== primaryReal
      || execution.top !== executionReal
      || !isWithin(primary.commonDir, primary.gitDir)
      || !isWithin(execution.commonDir, execution.gitDir)
      || (!sharesProtectedAdmin && rootsOverlap(primaryReal, execution.commonDir))
      || rootsOverlap(primary.commonDir, executionReal)
      || execution.head !== bootstrap.expected_baseline.head_sha
    ) {
      throw taskExecutionError("git_identity_mismatch");
    }

    const executionLinked = execution.gitDir !== execution.commonDir;
    if (executionLinked && !await isWorktreeRegistered(executionReal, execution)) {
      throw taskExecutionError("execution_worktree_registration_unverified");
    }
    if (sharesProtectedAdmin && !executionLinked) throw taskExecutionError("shared_git_admin_not_isolated");

    return {
      status: "verified",
      primary_root: primaryReal,
      execution_root: executionReal,
      primary_git_dir: primary.gitDir,
      primary_common_dir: primary.commonDir,
      execution_git_dir: execution.gitDir,
      execution_common_dir: execution.commonDir,
      execution_head: execution.head,
      execution_linked_worktree: executionLinked,
      shared_refs: sharesProtectedAdmin,
      shares_protected_admin: sharesProtectedAdmin
    };
  } catch (error) {
    if (error instanceof RepoReaderError) throw error;
    throw taskExecutionError(errorReason(error));
  }
}

/**
 * Records bounded Git metadata and owner-selected repo-relative file metadata.
 * Selected files are checked with no-follow metadata calls; their contents are never opened.
 */
export async function collectTaskPreservationSnapshot(
  input: CollectTaskPreservationInput
): Promise<TaskPreservationSample> {
  const identity = await verifyExecutionIdentity(input);
  const now = input.now ?? (() => new Date());
  const run = input.run_git ?? runGit;
  const snapshot = await collectSnapshot(input.bootstrap.protected_root, input.bootstrap, now, run);
  const collectorEnvironment = {
    git_env_allowlist: Object.keys(taskGitEnvironment()).sort(),
    git_overrides: GIT_OPTIONS.slice(),
    git_version: (await run(input.bootstrap.protected_root, ["--version"])).toString("utf8").trim(),
    node_version: process.version,
    git_commands: [
      "rev-parse --show-toplevel",
      "rev-parse --path-format=absolute --absolute-git-dir",
      "rev-parse --path-format=absolute --git-common-dir",
      "rev-parse --path-format=absolute --git-path index",
      "rev-parse --shared-index-path",
      "rev-parse --verify HEAD",
      "symbolic-ref --quiet HEAD",
      "for-each-ref --format=%(refname)%00%(objectname)",
      "ls-files --sparse --stage -z",
      "ls-files --others --exclude-standard -z",
      "--version"
    ]
  };
  return { identity, snapshot, collector_environment: collectorEnvironment };
}

export function buildTaskPreservationSidecar(input: {
  bootstrap: TaskExecutionBootstrap;
  operation: TaskExecutionOperation;
  operation_outcome: "completed" | "failed";
  operation_error_code?: string;
  operation_started_at_utc: string;
  operation_finished_at_utc: string;
  pre: TaskPreservationSample;
  post: TaskPreservationSample | null;
}): { verdict: "NOT_PROVEN"; sidecar: TaskPreservationSidecar; serialized: string; sha256: string } {
  const { bootstrap, pre, post } = input;
  const stable = post !== null && snapshotForComparison(pre.snapshot) === snapshotForComparison(post.snapshot);
  const differences = post
    ? compareSnapshots(pre.snapshot, post.snapshot, bootstrap.authorized_ref_transitions)
    : [];
  const notProven = new Set<string>();
  for (const reason of [
    ...pre.snapshot.errors,
    ...pre.snapshot.unsupported_layouts,
    ...(post?.snapshot.errors ?? []),
    ...(post?.snapshot.unsupported_layouts ?? [])
  ]) notProven.add(reason);
  if (!pre.snapshot.inventory_complete || (post !== null && !post.snapshot.inventory_complete)) notProven.add("inventory_incomplete");
  if (post === null) notProven.add("postflight_missing");
  if (input.operation_outcome === "failed") notProven.add("operation_failed");
  if (!stable) notProven.add("unstable_collection");
  notProven.add("content_equivalence_not_proven");

  const sidecar: TaskPreservationSidecar = {
    schema: "gpt-repo-mcp.preservation-observation.v1",
    task_id: bootstrap.task_id,
    verdict: "NOT_PROVEN",
    identity: identityEvidence(pre.identity, bootstrap.path_token_key),
    limits: bootstrap.limits,
    pre: pre.snapshot,
    post: post?.snapshot ?? null,
    collection: {
      operation: input.operation,
      operation_outcome: input.operation_outcome,
      ...(input.operation_error_code ? { operation_error_code: input.operation_error_code } : {}),
      operation_started_at_utc: input.operation_started_at_utc,
      operation_finished_at_utc: input.operation_finished_at_utc,
      started_at_utc: pre.snapshot.collected_at_utc,
      finished_at_utc: post?.snapshot.collected_at_utc ?? input.operation_finished_at_utc,
      stable_endpoints: stable,
      differences,
      attribution_categories: {
        owner_authorized: differences.filter((item) => item.category === "owner_authorized").map((item) => item.state),
        attributed_to_task: [],
        unattributed: differences.filter((item) => item.category === "unattributed").map((item) => item.state),
        not_proven: [...notProven].sort()
      },
      content_equivalence: "NOT_PROVEN",
      collector_environment: pre.collector_environment,
      limitations: [
        "Equal endpoint samples do not prove the absence of transient writes.",
        "Working-file content equivalence is NOT_PROVEN because file contents are never read or hashed.",
        "Direct ungoverned shell, MCP, and external agents remain outside this guard and NOT_PROVEN.",
        "No machine-wide enforcement is claimed.",
        "Same-device bind mounts may not be distinguishable by device metadata."
      ]
    }
  };
  const serialized = `${JSON.stringify(sidecar, null, 2)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > bootstrap.limits.sidecar_bytes) {
    throw taskExecutionError("sidecar_size_limit_exceeded");
  }
  return { verdict: "NOT_PROVEN", sidecar, serialized, sha256: createHash("sha256").update(serialized, "utf8").digest("hex") };
}

/** Verifies strict V3 artifacts against the owner descriptor and live registry entry. */
async function isWorktreeRegistered(root: string, identity: GitIdentity): Promise<boolean> {
  const adminWorktrees = join(identity.commonDir, "worktrees");
  if (!isWithin(adminWorktrees, identity.gitDir) || identity.gitDir === identity.commonDir) return false;
  const output = await runGit(root, ["worktree", "list", "--porcelain", "-z"]);
  const records: Array<{ path?: string; head?: string }> = [];
  let current: { path?: string; head?: string } = {};
  for (const field of output.toString("utf8").split("\0")) {
    if (field.startsWith("worktree ")) {
      if (current.path) records.push(current);
      current = { path: field.slice("worktree ".length) };
    } else if (field.startsWith("HEAD ")) {
      current.head = field.slice("HEAD ".length);
    } else if (field === "" && current.path) {
      records.push(current);
      current = {};
    }
  }
  if (current.path) records.push(current);
  return records.some((record) => record.path === root && record.head === identity.head);
}

type GitIdentity = { top: string; gitDir: string; commonDir: string; head: string };

async function readGitIdentity(root: string): Promise<GitIdentity> {
  const [top, gitDir, commonDir, head] = await Promise.all([
    gitText(root, ["rev-parse", "--show-toplevel"]),
    gitText(root, ["rev-parse", "--path-format=absolute", "--absolute-git-dir"]),
    gitText(root, ["rev-parse", "--path-format=absolute", "--git-common-dir"]),
    gitText(root, ["rev-parse", "--verify", "HEAD"])
  ]);
  return {
    top: await realpath(top),
    gitDir: await realpath(gitDir),
    commonDir: await realpath(commonDir),
    head
  };
}

async function collectSnapshot(
  root: string,
  bootstrap: TaskExecutionBootstrap,
  now: () => Date,
  run: (root: string, args: string[], allowedExitCodes?: readonly number[]) => Promise<Buffer>
): Promise<Snapshot> {
  const errors: string[] = [];
  const unsupported: string[] = [];
  let head: Snapshot["head"] = { oid: "", symbolic_ref: null };
  let refMap: Record<string, string> = {};
  let index: Snapshot["index"] = { path_token: "", sha256: "", size: "0", mtime_ns: "0", device: "0", inode: "0" };
  let stagedEntries: Snapshot["staged_entries"] = [];
  let trackedMetadata: PathMetadata[] = [];
  let protectedMetadata: PathMetadata[] = [];
  let ownerProtectedMetadata: PathMetadata[] = [];
  let untrackedCount = 0;
  let untrackedDigest = "";
  let untrackedMetadata: PathMetadata[] = [];
  let inventoryComplete = true;
  let ownerProtectedPaths: Buffer[] = [];
  try {
    ownerProtectedPaths = ownerProtectedPathBuffers(bootstrap);
  } catch (error) {
    errors.push(errorReason(error));
    inventoryComplete = false;
  }

  try {
    const oid = (await run(root, ["rev-parse", "--verify", "HEAD"])).toString("ascii").trim();
    const symbolicOutput = (await run(root, ["symbolic-ref", "--quiet", "HEAD"], [0, 1])).toString("utf8").trim();
    head = { oid, symbolic_ref: symbolicOutput || null };
  } catch (error) {
    errors.push(errorReason(error));
    inventoryComplete = false;
  }

  try {
    refMap = await readRefs(root, bootstrap.limits.refs, bootstrap.limits.inventory_bytes, run);
  } catch (error) {
    errors.push(errorReason(error));
    inventoryComplete = false;
  }

  try {
    const sharedIndex = (await run(root, ["rev-parse", "--shared-index-path"])).toString("utf8").trim();
    if (sharedIndex) {
      unsupported.push("split_or_shared_index");
      inventoryComplete = false;
    }
  } catch (error) {
    errors.push(errorReason(error));
    inventoryComplete = false;
  }

  try {
    index = await readIndex(root, bootstrap, run);
  } catch (error) {
    errors.push(errorReason(error));
    inventoryComplete = false;
  }

  try {
    const stageOutput = await run(root, ["ls-files", "--sparse", "--stage", "-z"]);
    const stageRows = parseNulRecords(stageOutput, bootstrap.limits.inventory_bytes);
    if (stageRows.length > bootstrap.limits.tracked_entries) throw limitError("tracked_entry_limit_exceeded");
    stagedEntries = stageRows.map((row) => parseStageEntry(row, bootstrap));
    if (stagedEntries.some((entry) => entry.mode === "040000" || entry.mode === "40000")) {
      unsupported.push("sparse_index");
      inventoryComplete = false;
    }
    const trackedPathMap = new Map<string, Buffer>();
    for (const row of stageRows) {
      const path = parseStagePath(row);
      trackedPathMap.set(path.toString("base64"), path);
    }
    trackedMetadata = await collectPathMetadata(root, [...trackedPathMap.values()], bootstrap);
  } catch (error) {
    errors.push(errorReason(error));
    inventoryComplete = false;
  }

  try {
    const untrackedOutput = await run(root, ["ls-files", "--others", "--exclude-standard", "-z"]);
    const untrackedPaths = parseNulRecords(untrackedOutput, bootstrap.limits.inventory_bytes);
    untrackedCount = untrackedPaths.length;
    untrackedDigest = createHmac("sha256", bootstrap.path_token_key).update(untrackedOutput).digest("hex");
    if (untrackedPaths.length > bootstrap.limits.untracked_entries) {
      inventoryComplete = false;
      errors.push("untracked_entry_limit_exceeded");
    } else {
      untrackedMetadata = await collectPathMetadata(root, untrackedPaths, bootstrap);
    }
  } catch (error) {
    inventoryComplete = false;
    errors.push(errorReason(error));
  }

  try {
    const protectedPaths = protectedPathBuffers(bootstrap);
    protectedMetadata = await collectPathMetadata(root, protectedPaths, bootstrap);
    if (protectedMetadata.some((metadata) => metadata.kind === "symlink")) {
      unsupported.push("protected_path_is_symlink");
      inventoryComplete = false;
    }
  } catch (error) {
    inventoryComplete = false;
    errors.push(errorReason(error));
  }

  if (ownerProtectedPaths.length > 0) {
    try {
      ownerProtectedMetadata = await collectPathMetadata(root, ownerProtectedPaths, bootstrap);
      if (ownerProtectedMetadata.some((metadata) => metadata.present && metadata.kind !== "file")) {
        unsupported.push("owner_protected_input_unsupported_file_type");
        inventoryComplete = false;
      }
    } catch (error) {
      inventoryComplete = false;
      errors.push(errorReason(error));
    }
  }

  return {
    collected_at_utc: now().toISOString(),
    head,
    refs: refMap,
    index,
    staged_entries: stagedEntries,
    tracked_metadata: trackedMetadata,
    protected_metadata: protectedMetadata,
    owner_protected_metadata: ownerProtectedMetadata,
    untracked_count: untrackedCount,
    untracked_inventory_sha256: untrackedDigest,
    untracked_metadata: untrackedMetadata,
    inventory_complete: inventoryComplete,
    unsupported_layouts: [...new Set(unsupported)].sort(),
    errors: [...new Set(errors)].sort()
  };
}

async function readRefs(
  root: string,
  maxRefs: number,
  maxBytes: number,
  run: (root: string, args: string[], allowedExitCodes?: readonly number[]) => Promise<Buffer>
): Promise<Record<string, string>> {
  const output = await run(root, ["for-each-ref", "--format=%(refname)%00%(objectname)"]);
  if (output.length > maxBytes) throw limitError("inventory_output_limit_exceeded");
  const refs: Record<string, string> = {};
  for (const line of output.toString("utf8").split("\n")) {
    if (!line) continue;
    const separator = line.indexOf("\0");
    if (separator <= 0) throw limitError("invalid_ref_inventory");
    refs[line.slice(0, separator)] = line.slice(separator + 1);
  }
  if (Object.keys(refs).length > maxRefs) throw limitError("ref_limit_exceeded");
  return Object.fromEntries(Object.entries(refs).sort(([left], [right]) => left.localeCompare(right)));
}

async function readIndex(
  root: string,
  bootstrap: TaskExecutionBootstrap,
  run: (root: string, args: string[], allowedExitCodes?: readonly number[]) => Promise<Buffer>
): Promise<Snapshot["index"]> {
  const indexPath = (await run(root, ["rev-parse", "--path-format=absolute", "--git-path", "index"])).toString("utf8").trim();
  const before = await lstat(indexPath, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) throw limitError("index_not_regular");
  if (before.size > BigInt(bootstrap.limits.index_bytes)) throw limitError("index_size_limit_exceeded");

  const file = await open(indexPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await file.stat({ bigint: true });
    if (!sameFileIdentity(before, opened)) throw limitError("index_changed_while_opening");
    const digest = createHash("sha256");
    let position = 0;
    const buffer = Buffer.alloc(64 * 1024);
    while (true) {
      const { bytesRead } = await file.read(buffer, 0, buffer.length, position);
      if (bytesRead === 0) break;
      position += bytesRead;
      if (position > bootstrap.limits.index_bytes) throw limitError("index_size_limit_exceeded");
      digest.update(buffer.subarray(0, bytesRead));
    }
    const afterOpen = await file.stat({ bigint: true });
    const afterPath = await lstat(indexPath, { bigint: true });
    if (!sameFileIdentity(before, afterOpen) || !sameFileIdentity(before, afterPath) || BigInt(position) !== before.size) {
      throw limitError("index_changed_during_collection");
    }
    return {
      path_token: opaquePath(Buffer.from(indexPath, "utf8"), bootstrap.path_token_key),
      sha256: digest.digest("hex"),
      size: before.size.toString(),
      mtime_ns: before.mtimeNs.toString(),
      device: before.dev.toString(),
      inode: before.ino.toString()
    };
  } finally {
    await file.close();
  }
}

async function collectPathMetadata(root: string, paths: Buffer[], bootstrap: TaskExecutionBootstrap): Promise<PathMetadata[]> {
  const rootInfo = await lstat(root, { bigint: true });
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw limitError("root_not_physical_directory");
  const output: PathMetadata[] = [];
  for (const rawPath of paths) {
    output.push(await pathMetadata(root, rawPath, rootInfo.dev, bootstrap.limits.path_bytes, bootstrap.path_token_key));
  }
  return output;
}

function protectedPathBuffers(bootstrap: TaskExecutionBootstrap): Buffer[] {
  if (bootstrap.protected_paths.length > bootstrap.limits.protected_paths) throw limitError("protected_path_limit_exceeded");
  return bootstrap.protected_paths.map((path) => {
    const bytes = Buffer.from(path, "utf8");
    if (bytes.length === 0 || bytes.length > bootstrap.limits.path_bytes || Buffer.from(bytes.toString("utf8"), "utf8").compare(bytes) !== 0) {
      throw limitError("protected_path_shape_or_size_invalid");
    }
    return bytes;
  });
}

/**
 * Accepts the built-in Git selectors and exact safe repo-relative file paths.
 * Explicitly excluded selectors are omitted; path traversal and unsupported path shapes fail closed.
 */
function ownerProtectedPathBuffers(bootstrap: TaskExecutionBootstrap): Buffer[] {
  const selectors = bootstrap.protected_state_inputs;
  const exclusions = bootstrap.explicit_exclusions;
  if (
    !Array.isArray(selectors)
    || selectors.length > 32
    || new Set(selectors).size !== selectors.length
    || !Array.isArray(exclusions)
    || exclusions.some((value) => typeof value !== "string" || value.length === 0 || value.length > 256)
  ) {
    throw limitError("protected_state_input_shape_or_count_invalid");
  }
  const excluded = new Set(exclusions);
  const paths: Buffer[] = [];
  for (const selector of selectors) {
    if (typeof selector !== "string" || selector.length === 0 || selector.length > 256 || selector.includes("\0")) {
      throw limitError("protected_state_input_shape_or_count_invalid");
    }
    if (BUILT_IN_PROTECTED_STATE_INPUTS.has(selector) || excluded.has(selector)) continue;
    const bytes = Buffer.from(selector, "utf8");
    const components = selector.split("/");
    if (
      bytes.length > Math.min(256, bootstrap.limits.path_bytes)
      || selector.startsWith("/")
      || /^[A-Za-z]:/.test(selector)
      || selector.includes("\\")
      || components.some((component) => component.length === 0 || component === "." || component === "..")
      || Buffer.from(bytes.toString("utf8"), "utf8").compare(bytes) !== 0
    ) {
      throw limitError("protected_state_input_path_invalid");
    }
    paths.push(bytes);
  }
  return paths;
}

async function pathMetadata(
  root: string,
  rawPath: Buffer,
  rootDevice: bigint,
  maxPathBytes: number,
  pathTokenKey: string
): Promise<PathMetadata> {
  if (rawPath.length === 0 || rawPath.length > maxPathBytes || rawPath.includes(0) || rawPath[0] === 47) {
    throw limitError("path_length_or_shape_invalid");
  }
  const relativePath = rawPath.toString("utf8");
  if (!Buffer.from(relativePath, "utf8").equals(rawPath)) throw limitError("non_utf8_path_not_supported");
  const components = relativePath.split("/");
  if (components.some((component) => component === "" || component === "." || component === "..")) {
    throw limitError("path_escape_rejected");
  }
  let current = root;
  let finalInfo: BigIntStats | undefined;
  for (const [index, component] of components.entries()) {
    current = resolve(current, component);
    if (!isWithin(root, current)) throw limitError("path_escape_rejected");
    try {
      finalInfo = await lstat(current, { bigint: true });
    } catch (error) {
      if (isMissing(error)) return { path_token: opaquePath(rawPath, pathTokenKey), present: false };
      throw error;
    }
    if (finalInfo.dev !== rootDevice) throw limitError("filesystem_boundary_crossed");
    if (index < components.length - 1 && (!finalInfo.isDirectory() || finalInfo.isSymbolicLink())) {
      throw limitError("symlink_or_non_directory_parent");
    }
  }
  if (!finalInfo) throw limitError("empty_inventory_path");
  const kind = finalInfo.isFile() ? "file" : finalInfo.isDirectory() ? "directory" : finalInfo.isSymbolicLink() ? "symlink" : "other";
  return {
    path_token: opaquePath(rawPath, pathTokenKey),
    present: true,
    kind,
    mode: Number(finalInfo.mode),
    size: finalInfo.size.toString(),
    mtime_ns: finalInfo.mtimeNs.toString(),
    ctime_ns: finalInfo.ctimeNs.toString(),
    device: finalInfo.dev.toString(),
    inode: finalInfo.ino.toString(),
    links: finalInfo.nlink.toString()
  };
}

function parseNulRecords(output: Buffer, maxBytes = GIT_STDOUT_LIMIT): Buffer[] {
  if (output.length > Math.min(maxBytes, GIT_STDOUT_LIMIT)) throw limitError("inventory_output_limit_exceeded");
  if (output.length === 0) return [];
  if (output[output.length - 1] !== 0) throw limitError("incomplete_nul_inventory");
  return output.subarray(0, -1).toString("binary").split("\0").map((value) => Buffer.from(value, "binary"));
}

function parseStagePath(record: Buffer): Buffer {
  const separator = record.indexOf(9);
  if (separator < 0) throw limitError("invalid_stage_entry");
  return record.subarray(separator + 1);
}

function parseStageEntry(record: Buffer, bootstrap: TaskExecutionBootstrap): Snapshot["staged_entries"][number] {
  const separator = record.indexOf(9);
  if (separator < 0) throw limitError("invalid_stage_entry");
  const header = record.subarray(0, separator).toString("ascii").split(" ");
  const path = record.subarray(separator + 1);
  if (header.length !== 3 || path.length === 0 || path.length > bootstrap.limits.path_bytes) {
    throw limitError("invalid_stage_entry");
  }
  return {
    path_token: opaquePath(path, bootstrap.path_token_key),
    mode: header[0],
    oid: header[1],
    stage: Number(header[2])
  };
}

export function opaquePath(path: Buffer, pathTokenKey: string): string {
  return `path:${createHmac("sha256", pathTokenKey).update(path).digest("hex")}`;
}

function identityEvidence(identity: ExecutionIdentity, pathTokenKey: string): TaskPreservationIdentityEvidence {
  const token = (path: string) => opaquePath(Buffer.from(path, "utf8"), pathTokenKey);
  return {
    status: "verified",
    protected_root_token: token(identity.primary_root),
    execution_root_token: token(identity.execution_root),
    protected_git_admin_token: token(identity.primary_common_dir),
    execution_git_admin_token: token(identity.execution_common_dir),
    execution_head: identity.execution_head,
    execution_linked_worktree: identity.execution_linked_worktree,
    shared_refs: identity.shared_refs,
    shared_protected_admin_state: identity.shares_protected_admin
  };
}

function snapshotForComparison(snapshot: Snapshot): string {
  return JSON.stringify(Object.fromEntries(Object.entries(snapshot).filter(([key]) => key !== "collected_at_utc")));
}

export function compareRefTransitions(
  before: Record<string, string>,
  after: Record<string, string>,
  authorizedTransitions: readonly { refname: string; before_oid: string | null; after_oid: string | null }[]
): Array<{ category: "owner_authorized" | "unattributed"; state: string }> {
  const changes: Array<{ category: "owner_authorized" | "unattributed"; state: string }> = [];
  for (const refname of new Set([...Object.keys(before), ...Object.keys(after)])) {
    const beforeOid = before[refname] ?? null;
    const afterOid = after[refname] ?? null;
    if (beforeOid === afterOid) continue;
    const exact = authorizedTransitions.some((transition) =>
      transition.refname === refname
      && transition.before_oid === beforeOid
      && transition.after_oid === afterOid
    );
    changes.push({ category: exact ? "owner_authorized" : "unattributed", state: `ref:${refname}` });
  }
  return changes.sort((left, right) => left.state.localeCompare(right.state));
}

function compareSnapshots(
  before: Snapshot,
  after: Snapshot,
  authorizedRefTransitions: readonly { refname: string; before_oid: string | null; after_oid: string | null }[]
): TaskPreservationSidecar["collection"]["differences"] {
  const differences: TaskPreservationSidecar["collection"]["differences"] = [];
  if (before.head.oid !== after.head.oid || before.head.symbolic_ref !== after.head.symbolic_ref) {
    differences.push({ category: "unattributed", state: "HEAD" });
  }
  differences.push(...compareRefTransitions(before.refs, after.refs, authorizedRefTransitions));
  if (
    before.index.sha256 !== after.index.sha256
    || before.index.size !== after.index.size
    || before.index.mtime_ns !== after.index.mtime_ns
    || before.index.device !== after.index.device
    || before.index.inode !== after.index.inode
  ) {
    differences.push({ category: "unattributed", state: "index" });
  }
  if (JSON.stringify(before.staged_entries) !== JSON.stringify(after.staged_entries)) {
    differences.push({ category: "unattributed", state: "staged_index_entries" });
  }
  if (
    before.untracked_inventory_sha256 !== after.untracked_inventory_sha256
    || JSON.stringify(before.tracked_metadata) !== JSON.stringify(after.tracked_metadata)
    || JSON.stringify(before.untracked_metadata) !== JSON.stringify(after.untracked_metadata)
  ) {
    differences.push({ category: "unattributed", state: "working_tree_metadata" });
  }
  if (JSON.stringify(before.protected_metadata) !== JSON.stringify(after.protected_metadata)) {
    differences.push({ category: "unattributed", state: "protected_path_metadata" });
  }
  if (JSON.stringify(before.owner_protected_metadata) !== JSON.stringify(after.owner_protected_metadata)) {
    differences.push({ category: "unattributed", state: "owner_protected_input_metadata" });
  }
  return differences;
}

function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function limitError(reason: string): RepoReaderError {
  return new RepoReaderError("SIZE_LIMIT_EXCEEDED", "Preservation evidence is incomplete within the configured limits.", {
    diagnostics: { reason }
  });
}

async function gitText(root: string, args: string[], allowedExitCodes: readonly number[] = [0]): Promise<string> {
  const output = await runGit(root, args, allowedExitCodes);
  return output.toString("utf8").trim();
}

function runGit(root: string, args: string[], allowedExitCodes: readonly number[] = [0]): Promise<Buffer> {
  return new Promise((resolveOutput, rejectOutput) => {
    const child = spawn("git", [...GIT_OPTIONS, ...args], {
      cwd: root,
      env: taskGitEnvironment(),
      stdio: ["ignore", "pipe", "pipe"]
    });
    const stdout: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let stderrTruncated = false;
    let settled = false;
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      fail("git_timeout");
    }, GIT_TIMEOUT_MS);

    const fail = (reason: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      child.kill("SIGTERM");
      rejectOutput(taskExecutionError(reason));
    };

    child.stdout!.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > GIT_STDOUT_LIMIT) {
        fail("git_output_limit_exceeded");
        return;
      }
      stdout.push(chunk);
    });
    child.stderr!.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stderrBytes > GIT_STDERR_LIMIT) stderrTruncated = true;
    });
    child.on("error", () => fail("git_process_unavailable"));
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (!allowedExitCodes.includes(code ?? 1)) {
        rejectOutput(taskExecutionError(stderrTruncated ? "git_failed_stderr_truncated" : "git_command_failed"));
        return;
      }
      resolveOutput(Buffer.concat(stdout));
    });
  });
}

function taskGitEnvironment(): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH ?? "/usr/bin:/bin:/usr/sbin:/sbin",
    LANG: "C",
    LC_ALL: "C",
    TZ: "UTC",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_PAGER: "cat",
    PAGER: "cat",
    GIT_ALLOW_PROTOCOL: "none"
  };
}

function rootsOverlap(left: string, right: string): boolean {
  return isWithin(left, right) || isWithin(right, left);
}

function isWithin(root: string, path: string): boolean {
  const rel = relative(resolve(root), resolve(path));
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== "..");
}
