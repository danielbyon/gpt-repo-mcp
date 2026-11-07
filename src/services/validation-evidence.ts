import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { access, lstat, open, readlink, realpath } from "node:fs/promises";
import { delimiter, isAbsolute, join, relative, resolve, sep } from "node:path";
import { gitOperationEnv } from "./git-operation-safety.js";
import { isDelegationControlArtifact } from "../policies/delegation-control-artifacts.js";
import { RepoReaderError } from "../runtime/errors.js";

const DEFAULT_MAX_ENTRIES = 20_000;
const DEFAULT_MAX_CONTENT_BYTES = 256 * 1024 * 1024;
const DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_GIT_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_GIT_ERROR_BYTES = 16 * 1024;
const GIT_COMMAND_TIMEOUT_MS = 15_000;
const MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024;

export type ValidationIndexEntry = {
  path: string;
  mode: string;
  object_id: string;
  stage: number;
};

export type ValidationSourceFile = {
  path: string;
  head?: { mode: string; object_id: string };
  index_entries: ValidationIndexEntry[];
  untracked: boolean;
  worktree: {
    kind: "file" | "symlink" | "missing";
    mode_bits: number | null;
    size_bytes: number;
    content_sha256?: string;
    symlink_target?: string;
  };
};

export type ValidationSourceSnapshot = {
  schema_version: 2;
  root: {
    configured_path: string;
    real_path: string;
    device: string;
    inode: string;
    git_dir: string;
    git_common_dir: string;
  };
  head_sha: string;
  ref: string;
  index: { entries: ValidationIndexEntry[]; sha256: string };
  files: ValidationSourceFile[];
  content_bytes: number;
  sha256: string;
};

export type ValidationEvidenceLimits = {
  max_entries?: number;
  max_content_bytes?: number;
  max_file_bytes?: number;
};

export type ValidationExecutableIdentity = {
  path_sha256: string;
  real_path_sha256: string;
  size_bytes: number;
  mode_bits: number;
  sha256: string;
};

type HeadEntry = { mode: string; object_id: string };
type PathRecord = { head?: HeadEntry; index_entries: ValidationIndexEntry[]; untracked: boolean; requiredRecipeSource?: boolean };

/** Captures a bounded, content-addressed view of a configured Git checkout. */
export class ValidationEvidenceService {
  private readonly limits: Required<ValidationEvidenceLimits>;

  constructor(
    private readonly root: string,
    options: { limits?: ValidationEvidenceLimits } = {}
  ) {
    this.limits = {
      max_entries: options.limits?.max_entries ?? DEFAULT_MAX_ENTRIES,
      max_content_bytes: options.limits?.max_content_bytes ?? DEFAULT_MAX_CONTENT_BYTES,
      max_file_bytes: options.limits?.max_file_bytes ?? DEFAULT_MAX_FILE_BYTES
    };
  }

  /** Reads Git source state and the caller's bounded Make or Just recipe source graph. */
  async captureSourceSnapshot(signal?: AbortSignal, recipeSourcePaths: string[] = []): Promise<ValidationSourceSnapshot> {
    signal?.throwIfAborted();
    const configuredPath = resolve(this.root);
    const realPath = await realpath(configuredPath);
    const rootInfo = await lstat(configuredPath);
    if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
      throw unverified("The configured validation root is not a regular directory.");
    }

    const [headSha, ref, gitDirText, gitCommonDirText, headOutput, indexOutput, untrackedOutput] = await Promise.all([
      gitText(this.root, ["rev-parse", "--verify", "HEAD"], signal),
      gitText(this.root, ["rev-parse", "--abbrev-ref", "HEAD"], signal),
      gitText(this.root, ["rev-parse", "--absolute-git-dir"], signal),
      gitText(this.root, ["rev-parse", "--git-common-dir"], signal),
      gitBytes(this.root, ["ls-tree", "-r", "-z", "--full-tree", "HEAD"], signal),
      gitBytes(this.root, ["ls-files", "--stage", "-z"], signal),
      gitBytes(this.root, ["ls-files", "--others", "--exclude-standard", "-z"], signal)
    ]);
    signal?.throwIfAborted();

    const headEntries = parseHeadEntries(headOutput);
    const indexEntries = parseIndexEntries(indexOutput);
    const untrackedPaths = parsePaths(untrackedOutput)
      .filter((path) => !path.startsWith(".chatgpt/validation/"))
      .filter((path) => !isDelegationControlArtifact(path, { includeResultJson: true }));
    const pathRecords = new Map<string, PathRecord>();
    for (const [path, entry] of headEntries) pathRecords.set(path, { head: entry, index_entries: [], untracked: false });
    for (const entry of indexEntries) {
      const record = pathRecords.get(entry.path) ?? { index_entries: [], untracked: false };
      record.index_entries.push(entry);
      pathRecords.set(entry.path, record);
    }
    for (const path of untrackedPaths) {
      const record = pathRecords.get(path) ?? { index_entries: [], untracked: false };
      record.untracked = true;
      pathRecords.set(path, record);
    }
    for (const path of recipeSourcePaths) {
      const normalizedPath = validateRecipeSourcePath(path);
      const record = pathRecords.get(normalizedPath) ?? { index_entries: [], untracked: false };
      record.requiredRecipeSource = true;
      pathRecords.set(normalizedPath, record);
    }

    const paths = [...pathRecords.keys()].sort(comparePath);
    if (paths.length > this.limits.max_entries || indexEntries.length > this.limits.max_entries) {
      throw unverified("The checkout source inventory exceeded its entry bound.");
    }

    const files: ValidationSourceFile[] = [];
    let contentBytes = 0;
    for (const path of paths) {
      signal?.throwIfAborted();
      const record = pathRecords.get(path)!;
      const worktree = await readWorktreePath(this.root, path, record.untracked || record.requiredRecipeSource === true, this.limits, this.limits.max_content_bytes - contentBytes);
      if (record.requiredRecipeSource && worktree.kind !== "file") {
        throw unverified("A discovered Make or Just recipe source is not a regular file in the checkout.");
      }
      contentBytes += worktree.size_bytes;
      record.index_entries.sort((left, right) => left.stage - right.stage || comparePath(left.path, right.path));
      files.push({
        path,
        ...(record.head ? { head: record.head } : {}),
        index_entries: record.index_entries,
        untracked: record.untracked,
        worktree
      });
    }
    signal?.throwIfAborted();

    const gitDir = await realpath(resolve(this.root, gitDirText.trim()));
    const gitCommonDir = await realpath(resolve(this.root, gitCommonDirText.trim()));
    const rootAfter = await lstat(configuredPath);
    if (!sameIdentity(rootInfo, rootAfter) || await realpath(configuredPath) !== realPath) {
      throw unverified("The configured checkout root changed while evidence was being captured.");
    }

    const index = { entries: indexEntries.sort((a, b) => comparePath(a.path, b.path) || a.stage - b.stage), sha256: "" };
    index.sha256 = canonicalSha256(index.entries);
    const unsigned = {
      schema_version: 2 as const,
      root: {
        configured_path: configuredPath,
        real_path: realPath,
        device: String(rootInfo.dev),
        inode: String(rootInfo.ino),
        git_dir: gitDir,
        git_common_dir: gitCommonDir
      },
      head_sha: headSha.trim(),
      ref: ref.trim(),
      index,
      files,
      content_bytes: contentBytes
    };
    return { ...unsigned, sha256: canonicalSha256(unsigned) };
  }
}

function validateRecipeSourcePath(path: string): string {
  const components = path.split("/");
  if (!path || path.includes("\\") || components.some((part) => !part || part === "." || part === "..") || isAbsolute(path)) {
    throw unverified("A discovered Make or Just recipe path is not a safe repository-relative path.");
  }
  return path;
}

/** Hashes JSON values with recursively sorted object keys and stable array order. */
export function canonicalSha256(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(canonicalize(value))).digest("hex");
}

/** Reads a bounded regular file after checking each repository path component for symlinks. */
export async function readContainedRegularFile(root: string, relativePath: string, maxBytes: number): Promise<Buffer> {
  const components = relativePath.split("/");
  if (!relativePath || relativePath.includes("\\") || components.some((part) => !part || part === "." || part === "..") || isAbsolute(relativePath)) {
    throw unverified("The validation artifact path is not a safe repository-relative path.");
  }
  const configuredRoot = resolve(root);
  const rootInfo = await lstat(configuredRoot);
  const rootRealPath = await realpath(configuredRoot);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw unverified("The configured validation root is not a regular directory.");
  const filePath = resolve(configuredRoot, ...components);
  if (!isWithin(configuredRoot, filePath)) throw unverified("The validation artifact path resolves outside the configured checkout.");
  const parents = await readParentIdentities(configuredRoot, relativePath);
  if (!parents) throw unverified("A validation artifact parent directory is missing.");
  let before;
  try {
    before = await lstat(filePath);
  } catch {
    throw unverified("The validation artifact is missing or cannot be inspected.");
  }
  if (!before.isFile() || before.isSymbolicLink() || before.size > maxBytes) throw unverified("The validation artifact is not a bounded regular file.");
  let handle;
  try {
    const realFilePath = await realpath(filePath);
    if (!isWithin(rootRealPath, realFilePath)) throw new Error("outside root");
    handle = await open(filePath, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!sameIdentity(before, opened)) throw new Error("changed before read");
    const contents = await handle.readFile();
    const after = await handle.stat();
    const pathAfter = await lstat(filePath);
    if (!sameIdentity(opened, after) || !sameIdentity(before, pathAfter) || contents.length !== after.size) throw new Error("changed while reading");
    await verifyParentIdentities(configuredRoot, relativePath, parents);
    const rootAfter = await lstat(configuredRoot);
    if (!sameIdentity(rootInfo, rootAfter) || await realpath(configuredRoot) !== rootRealPath) throw new Error("checkout root changed while reading");
    return contents;
  } catch {
    throw unverified("The validation artifact changed or could not be read safely.");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** Resolves and hashes the executable that a validation command will find on its PATH. */
export async function captureExecutableIdentity(
  root: string,
  executable: string,
  pathValue: string,
  platform: NodeJS.Platform = process.platform
): Promise<ValidationExecutableIdentity> {
  const candidates = executable.includes("/") || executable.includes("\\")
    ? [isAbsolute(executable) ? executable : resolve(root, executable)]
    : pathValue.split(delimiter).filter(Boolean).flatMap((directory) => executableNames(executable).map((name) => join(isAbsolute(directory) ? directory : resolve(root, directory), name)));
  for (const candidate of candidates) {
    let pathInfo;
    try {
      pathInfo = await lstat(candidate);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT" || (error as NodeJS.ErrnoException).code === "ENOTDIR") continue;
      throw unverified("A validation executable could not be inspected safely.");
    }
    let realPath: string;
    let handle;
    try {
      realPath = await realpath(candidate);
      handle = await open(realPath, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
      const before = await handle.stat();
      if (!before.isFile() || (platform !== "win32" && (before.mode & 0o111) === 0) || before.size > MAX_EXECUTABLE_BYTES) {
        throw new Error("unbounded or non-executable file");
      }
      if (platform !== "win32") await access(realPath, fsConstants.X_OK);
      const bytes = await handle.readFile();
      const after = await handle.stat();
      const pathAfter = await lstat(candidate);
      if (!sameIdentity(before, after) || !sameIdentity(pathInfo, pathAfter) || bytes.length !== after.size || pathInfo.isSymbolicLink() && await realpath(candidate) !== realPath) {
        throw new Error("executable changed while being read");
      }
      return {
        path_sha256: createHash("sha256").update(resolve(candidate)).digest("hex"),
        real_path_sha256: createHash("sha256").update(realPath).digest("hex"),
        size_bytes: bytes.length,
        mode_bits: after.mode & 0o7777,
        sha256: createHash("sha256").update(bytes).digest("hex")
      };
    } catch {
      throw unverified("A validation executable changed or could not be verified.");
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }
  throw unverified(`The selected validation executable ${executable} was not found on its execution PATH.`);
}

function executableNames(name: string): string[] {
  if (process.platform !== "win32" || /\.[a-z0-9]+$/i.test(name)) return [name];
  const extensions = (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean);
  return [name, ...extensions.map((extension) => `${name}${extension.toLowerCase()}`), ...extensions.map((extension) => `${name}${extension.toUpperCase()}`)];
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => comparePath(left, right))
      .map(([key, item]) => [key, canonicalize(item)]));
  }
  return value;
}

function parseHeadEntries(bytes: Buffer): Map<string, HeadEntry> {
  const result = new Map<string, HeadEntry>();
  for (const record of splitNul(bytes)) {
    const separator = record.indexOf(9);
    if (separator < 0) throw unverified("Git returned an invalid HEAD tree entry.");
    const metadata = record.subarray(0, separator).toString("ascii").split(" ");
    const path = decodePath(record.subarray(separator + 1));
    if (metadata.length !== 3 || !/^(?:100644|100755|120000|160000)$/.test(metadata[0]!) || !/^[a-f0-9]{40,64}$/.test(metadata[2]!)) {
      throw unverified("Git returned an unsupported HEAD tree entry.");
    }
    if (metadata[0] === "160000") throw unverified("Submodule working trees are not included in validation evidence.");
    result.set(path, { mode: metadata[0]!, object_id: metadata[2]! });
  }
  return result;
}

function parseIndexEntries(bytes: Buffer): ValidationIndexEntry[] {
  const result: ValidationIndexEntry[] = [];
  for (const record of splitNul(bytes)) {
    const separator = record.indexOf(9);
    if (separator < 0) throw unverified("Git returned an invalid logical index entry.");
    const metadata = record.subarray(0, separator).toString("ascii").split(" ");
    const path = decodePath(record.subarray(separator + 1));
    const stage = Number(metadata[2]);
    if (metadata.length !== 3 || !/^(?:100644|100755|120000)$/.test(metadata[0]!) || !/^[a-f0-9]{40,64}$/.test(metadata[1]!) || !Number.isInteger(stage) || stage < 0 || stage > 3) {
      throw unverified("Git returned an unsupported logical index entry.");
    }
    result.push({ path, mode: metadata[0]!, object_id: metadata[1]!, stage });
  }
  return result;
}

function parsePaths(bytes: Buffer): string[] {
  return splitNul(bytes).map(decodePath);
}

function splitNul(bytes: Buffer): Buffer[] {
  if (bytes.length === 0) return [];
  if (bytes[bytes.length - 1] !== 0) throw unverified("Git inventory output was truncated.");
  const records: Buffer[] = [];
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] === 0) {
      records.push(bytes.subarray(start, index));
      start = index + 1;
    }
  }
  return records;
}

function decodePath(bytes: Buffer): string {
  try {
    const path = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const parts = path.split("/");
    if (!path || path.includes("\0") || isAbsolute(path) || parts.some((part) => !part || part === "." || part === "..")) {
      throw new Error("invalid relative path");
    }
    return path;
  } catch {
    throw unverified("A source path cannot be represented safely as UTF-8.");
  }
}

async function readWorktreePath(
  root: string,
  path: string,
  untracked: boolean,
  limits: Required<ValidationEvidenceLimits>,
  remainingBytes: number
): Promise<ValidationSourceFile["worktree"]> {
  const absolute = resolve(root, ...path.split("/"));
  if (!isWithin(resolve(root), absolute)) throw unverified("A source path resolves outside the configured checkout.");
  const parentIdentities = await readParentIdentities(root, path);
  if (!parentIdentities) {
    if (untracked) throw unverified("An untracked source parent disappeared during inventory.");
    return { kind: "missing", mode_bits: null, size_bytes: 0 };
  }

  let before;
  try {
    before = await lstat(absolute);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      if (untracked) throw unverified("An untracked source disappeared during inventory.");
      return { kind: "missing", mode_bits: null, size_bytes: 0 };
    }
    throw unverified("A source path could not be inspected safely.");
  }

  if (before.isSymbolicLink()) {
    let target: Buffer;
    try {
      target = await readlink(absolute, { encoding: "buffer" });
      const after = await lstat(absolute);
      if (!sameIdentity(before, after) || !after.isSymbolicLink()) throw new Error("symlink changed");
      await verifyParentIdentities(root, path, parentIdentities);
    } catch {
      throw unverified("A symlink changed or could not be read during inventory.");
    }
    if (target.length > limits.max_file_bytes || target.length > remainingBytes) {
      throw unverified("The checkout source inventory exceeded its content bound.");
    }
    const targetText = decodePathTarget(target);
    return {
      kind: "symlink",
      mode_bits: before.mode & 0o7777,
      size_bytes: target.length,
      content_sha256: createHash("sha256").update(target).digest("hex"),
      symlink_target: targetText
    };
  }

  if (!before.isFile()) throw unverified("A source entry is not a regular file or symlink.");
  if (before.size > limits.max_file_bytes || before.size > remainingBytes) {
    throw unverified("The checkout source inventory exceeded its content bound.");
  }

  let handle;
  try {
    handle = await open(absolute, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || !sameIdentity(before, opened)) throw new Error("source changed before reading");
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!sameIdentity(opened, after) || bytes.length !== after.size) throw new Error("source changed while reading");
    await verifyParentIdentities(root, path, parentIdentities);
    return {
      kind: "file",
      mode_bits: after.mode & 0o7777,
      size_bytes: bytes.length,
      content_sha256: createHash("sha256").update(bytes).digest("hex")
    };
  } catch {
    throw unverified("A source file changed or could not be read during inventory.");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

type ParentIdentity = { path: string; dev: number; ino: number; mode: number; mtimeMs: number; ctimeMs: number };

async function readParentIdentities(root: string, path: string): Promise<ParentIdentity[] | undefined> {
  const components = path.split("/");
  const parents: ParentIdentity[] = [];
  let current = resolve(root);
  for (const component of components.slice(0, -1)) {
    current = join(current, component);
    try {
      const info = await lstat(current);
      if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("source parent is not a directory");
      parents.push({ path: current, dev: info.dev, ino: info.ino, mode: info.mode, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw unverified("A source parent directory changed or could not be inspected safely.");
    }
  }
  return parents;
}

async function verifyParentIdentities(root: string, path: string, expected: ParentIdentity[]): Promise<void> {
  const current = await readParentIdentities(root, path);
  if (!current || current.length !== expected.length || current.some((entry, index) => {
    const original = expected[index]!;
    return entry.path !== original.path || entry.dev !== original.dev || entry.ino !== original.ino || entry.mode !== original.mode || entry.mtimeMs !== original.mtimeMs || entry.ctimeMs !== original.ctimeMs;
  })) {
    throw unverified("A source parent directory changed while evidence was being captured.");
  }
}

function decodePathTarget(bytes: Buffer): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw unverified("A symlink target cannot be represented safely as UTF-8.");
  }
}

function sameIdentity(
  left: { dev: number; ino: number; mode: number; size: number; mtimeMs: number; ctimeMs: number },
  right: { dev: number; ino: number; mode: number; size: number; mtimeMs: number; ctimeMs: number }
): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode && left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function isWithin(root: string, candidate: string): boolean {
  const fromRoot = relative(root, candidate);
  return fromRoot === "" || (fromRoot !== ".." && !fromRoot.startsWith(`..${sep}`) && !isAbsolute(fromRoot));
}

function comparePath(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function unverified(message: string): RepoReaderError {
  return new RepoReaderError("VALIDATION_EVIDENCE_UNVERIFIED", message);
}

async function gitText(root: string, args: string[], signal?: AbortSignal): Promise<string> {
  const bytes = await gitBytes(root, args, signal, 1024 * 1024);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw unverified("Git returned output that could not be decoded safely.");
  }
}

async function gitBytes(root: string, args: string[], signal?: AbortSignal, maxBytes = MAX_GIT_OUTPUT_BYTES): Promise<Buffer> {
  signal?.throwIfAborted();
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn("git", args, {
      cwd: root,
      env: gitOperationEnv(),
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;
    let settled = false;
    const settleReject = (error: unknown) => {
      if (settled) return;
      settled = true;
      rejectPromise(error);
    };
    const timer = setTimeout(() => {
      overflow = true;
      child.kill("SIGKILL");
    }, GIT_COMMAND_TIMEOUT_MS);
    const abort = () => child.kill("SIGTERM");
    signal?.addEventListener("abort", abort, { once: true });

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > maxBytes) {
        overflow = true;
        child.kill("SIGKILL");
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (stderrBytes >= MAX_GIT_ERROR_BYTES) return;
      const accepted = chunk.subarray(0, MAX_GIT_ERROR_BYTES - stderrBytes);
      stderr.push(accepted);
      stderrBytes += accepted.length;
    });
    child.once("error", (error) => settleReject(unverified(`Git could not be started: ${error.message}`)));
    child.once("close", (code, childSignal) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (signal?.aborted) {
        settleReject(signal.reason ?? new DOMException("Validation evidence capture cancelled.", "AbortError"));
        return;
      }
      if (overflow) {
        settleReject(unverified("Git inventory exceeded its output or time bound."));
        return;
      }
      if (code !== 0) {
        settleReject(unverified(Buffer.concat(stderr).toString("utf8").trim() || `Git inventory exited with ${code ?? childSignal ?? "unknown"}.`));
        return;
      }
      if (settled) return;
      settled = true;
      resolvePromise(Buffer.concat(stdout));
    });
  });
}
