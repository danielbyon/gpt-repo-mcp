import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import process from "node:process";
import { execFileSync, spawnSync } from "node:child_process";
import { constants, existsSync } from "node:fs";
import { lstat, mkdir, open, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_PATCH_BYTES = 16 * 1024 * 1024;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_UNTRACKED_FILES = 256;
const MAX_UNTRACKED_BYTES = 16 * 1024 * 1024;
const MAX_REFERENCE_FILES = 16;
const MAX_REFERENCE_BYTES = 16 * 1024 * 1024;
const MAX_ENUMERATED_PATHS = 8_192;
const MISSING_TRACKED_MODE = "000000";
const REGULAR_TRACKED_MODES = new Set(["100644", "100755"]);
const IGNORED_INVENTORY_ROOTS = Object.freeze([
  "src/", "tests/", "scripts/", "docs/", "native/", ".github/workflows/",
  "Makefile", "Justfile", "package.json", "Cargo.toml"
]);
const READ_FLAGS = constants.O_RDONLY |
  (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0);
const DEFAULT_REFERENCES = [
  "CONTRIBUTING.md",
  "docs/QUALITY.md",
  "docs/SECURITY.md",
  "docs/ARCHITECTURE.md"
];
const ROOT_FILES = new Set([
  "README.md", "CONTRIBUTING.md", "SECURITY.md", "AGENTS.md",
  "CLAUDE.md", "GLOSSARY.md", "Makefile", "Justfile", "package.json",
  "package-lock.json", "Cargo.toml", "Cargo.lock"
]);
const SOURCE_EXTENSIONS = /\.(?:ts|tsx|mts|cts|js|mjs|cjs|json|md|txt|yaml|yml|toml|rs|py|c|h|cpp|hpp|sh|bash|zsh|css|html|swift|kt|java|gradle|xml)$/i;
const RESTRICTED_SEGMENTS = new Set([
  ".git", ".chatgpt", ".codex", ".serena", ".codegraph", "node_modules",
  "target", "dist", "build", "coverage", "test-results", ".cache",
  ".pytest_cache", "__pycache__", ".venv", "venv"
]);

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function git(root, args, options = {}) {
  return execFileSync("git", args, {
    cwd: root,
    windowsHide: true,
    maxBuffer: options.maxBuffer ?? 32 * 1024 * 1024,
    timeout: 30_000,
    stdio: ["ignore", "pipe", "pipe"]
  });
}

function gitText(root, args) {
  return git(root, args).toString("utf8").trim();
}

function nulFields(bytes) {
  const text = bytes.toString("utf8");
  if (text.includes("\uFFFD")) throw new Error("Git emitted a path that is not valid UTF-8.");
  if (text.length === 0) return [];
  if (!text.endsWith("\0")) throw new Error("Git emitted malformed NUL-delimited metadata.");
  return text.slice(0, -1).split("\0");
}

function nulPaths(bytes) {
  return nulFields(bytes).filter(Boolean).sort();
}

function isSafeRelative(path) {
  return typeof path === "string" && path.length > 0 &&
    !path.includes("\\") && !path.includes("\0") &&
    !path.startsWith("/") && !/^[A-Za-z]:/.test(path) &&
    path.split("/").every((part) => part.length > 0 && part !== "." && part !== ".." &&
      !part.endsWith(" ") && !part.endsWith("."));
}

function restricted(path) {
  if (!isSafeRelative(path)) return true;
  const parts = path.toLowerCase().split("/");
  return parts.some((part) => RESTRICTED_SEGMENTS.has(part) ||
    part === ".env" || part.startsWith(".env.") ||
    part === "config.local.json" || part.endsWith(".local.json") ||
    /\.(?:pem|key|p12|pfx|kdbx)$/.test(part)) ||
    parts[0] === "security";
}

function eligibleUntracked(path) {
  if (restricted(path)) return false;
  if (ROOT_FILES.has(path)) return true;
  if (path.startsWith(".github/workflows/")) return /\.(?:yml|yaml)$/.test(path);
  return /^(?:src|tests|scripts|docs|native)\//.test(path) && SOURCE_EXTENSIONS.test(path);
}

function isWithin(root, candidate) {
  const rel = relative(root, candidate);
  return rel === "" || (rel !== ".." && !rel.startsWith(".." + sep) && !isAbsolute(rel));
}

async function readBoundFile(root, path, maxBytes = MAX_FILE_BYTES) {
  if (!isSafeRelative(path)) throw new Error("Unsafe review-bundle path.");
  const parts = path.split("/");
  let parent = root;
  for (const part of parts.slice(0, -1)) {
    parent = join(parent, part);
    const info = await lstat(parent);
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error("Review source has a symlinked or non-directory ancestor: " + path);
    }
  }
  const absolute = join(root, path);
  const before = await lstat(absolute);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 ||
      before.size > maxBytes) {
    throw new Error("Review source is not a bounded, singly linked regular file: " + path);
  }
  const handle = await open(absolute, READ_FLAGS);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 ||
        opened.dev !== before.dev || opened.ino !== before.ino ||
        opened.size !== before.size || opened.size > maxBytes) {
      throw new Error("Review source changed before read: " + path);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (after.dev !== opened.dev || after.ino !== opened.ino ||
        after.size !== opened.size || bytes.byteLength !== after.size) {
      throw new Error("Review source changed during read: " + path);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function writeBundleFile(output, path, bytes) {
  if (!isSafeRelative(path)) throw new Error("Unsafe review-bundle output path.");
  const dest = join(output, path);
  await mkdir(dirname(dest), { recursive: true, mode: 0o700 });
  await writeFile(dest, bytes, { flag: "wx", mode: 0o600 });
}

function trackedDiff(root, baseSha) {
  return git(root, ["-c", "color.ui=false", "diff", "--binary", "--full-index",
    "--no-ext-diff", "--no-textconv", baseSha, "--"], { maxBuffer: MAX_PATCH_BYTES + 4096 });
}

function changedPaths(root, baseSha) {
  return nulPaths(git(root, ["diff", "--name-only", "-z", baseSha, "--"]));
}

function rawTrackedChanges(root, diffArgs) {
  const fields = nulFields(git(root, [
    "diff", "--raw", "--no-abbrev", "--no-renames", "-z", ...diffArgs, "--"
  ], { maxBuffer: MAX_PATCH_BYTES * 2 }));
  if (fields.length % 2 !== 0) throw new Error("Git emitted incomplete tracked-file metadata.");

  const changes = [];
  for (let index = 0; index < fields.length; index += 2) {
    const match = /^:(\d{6}) (\d{6}) \S+ \S+ ([A-Z])$/.exec(fields[index]);
    const path = fields[index + 1];
    if (!match || !isSafeRelative(path)) {
      throw new Error("Git emitted malformed tracked-file metadata.");
    }
    changes.push({
      path,
      old_mode: match[1],
      new_mode: match[2],
      status: match[3]
    });
  }
  return changes;
}

function trackedDiffMetadata(root, baseSha, headSha) {
  return {
    committed: rawTrackedChanges(root, [baseSha, headSha]),
    index: rawTrackedChanges(root, ["--cached", baseSha]),
    worktree: rawTrackedChanges(root, [baseSha])
  };
}

function assertTrackedModes(metadata) {
  for (const change of Object.values(metadata).flat()) {
    if (!["A", "D", "M", "T"].includes(change.status)) {
      throw new Error("Tracked change has unsupported Git status: " + change.path);
    }
    for (const mode of [change.old_mode, change.new_mode]) {
      if (mode !== MISSING_TRACKED_MODE && !REGULAR_TRACKED_MODES.has(mode)) {
        throw new Error("Tracked change uses prohibited Git file mode " + mode + ": " + change.path);
      }
    }
  }
}

function trackedBaseModes(metadata) {
  const modes = new Map();
  for (const change of Object.values(metadata).flat()) {
    const prior = modes.get(change.path);
    if (prior !== undefined && prior !== change.old_mode) {
      throw new Error("Git tracked-file metadata disagrees on the selected base: " + change.path);
    }
    modes.set(change.path, change.old_mode);
  }
  return modes;
}

function trackedWorktreeChanges(metadata) {
  return new Map(metadata.worktree.map((change) => [change.path, change]));
}

async function trackedPathState(root, path, baseMode, worktreeChange, affectedPaths) {
  function missingState() {
    if (worktreeChange?.status === "D" &&
        worktreeChange.new_mode === MISSING_TRACKED_MODE &&
        worktreeChange.old_mode !== MISSING_TRACKED_MODE) {
      return { path, kind: "git-deletion" };
    }
    if (!worktreeChange && baseMode === MISSING_TRACKED_MODE) {
      return { path, kind: "absent-from-selected-base-and-worktree" };
    }
    throw new Error("Tracked source is missing without a Git-recorded deletion: " + path);
  }

  let parent = root;
  const parts = path.split("/");
  for (const part of parts.slice(0, -1)) {
    parent = join(parent, part);
    let info;
    try {
      info = await lstat(parent);
    } catch (error) {
      if (error.code === "ENOENT") return missingState();
      throw error;
    }
    if (info.isSymbolicLink()) {
      throw new Error("Tracked source has a symlinked ancestor: " + path);
    }
    if (!info.isDirectory()) {
      if (info.isFile()) return missingState();
      throw new Error("Tracked source has an unsupported ancestor file type: " + path);
    }
  }

  let info;
  try {
    info = await lstat(join(root, path));
  } catch (error) {
    if (error.code === "ENOENT") return missingState();
    throw error;
  }
  if (info.isSymbolicLink()) throw new Error("Tracked source is a symlink: " + path);
  if (info.isFile()) {
    if (info.nlink !== 1) {
      throw new Error("Tracked source is not a singly linked regular file: " + path);
    }
    return {
      path,
      kind: "regular-file",
      device: info.dev,
      inode: info.ino,
      mode: info.mode,
      links: info.nlink,
      size: info.size
    };
  }
  if (info.isDirectory() && worktreeChange?.new_mode === MISSING_TRACKED_MODE &&
      affectedPaths.some((candidate) => candidate !== path && candidate.startsWith(path + "/"))) {
    return {
      path,
      kind: "synthetic-directory-ancestor",
      device: info.dev,
      inode: info.ino,
      mode: info.mode,
      links: info.nlink
    };
  }
  throw new Error("Tracked source is not a regular file: " + path);
}

async function trackedSourceSnapshot(root, baseSha, headSha, changed) {
  const metadata = trackedDiffMetadata(root, baseSha, headSha);
  assertTrackedModes(metadata);
  const baseModes = trackedBaseModes(metadata);
  const affectedPaths = [...new Set([
    ...changed,
    ...Object.values(metadata).flat().map((change) => change.path)
  ])].sort();
  const worktreeChanges = trackedWorktreeChanges(metadata);
  const sources = [];
  for (const path of affectedPaths) {
    if (!baseModes.has(path)) {
      throw new Error("Git tracked-file metadata omitted the selected base mode: " + path);
    }
    sources.push(await trackedPathState(
      root, path, baseModes.get(path), worktreeChanges.get(path), affectedPaths
    ));
  }
  return { metadata, sources };
}

function validCommitIdentity(value) {
  return typeof value === "string" && /^(?:[a-f\d]{40}|[a-f\d]{64})$/i.test(value) &&
    !/^0+$/.test(value);
}

function assertCommitIdentities(manifest) {
  const baseSha = manifest?.base_sha;
  const headSha = manifest?.head_sha;
  if (!validCommitIdentity(baseSha) || !validCommitIdentity(headSha) ||
      baseSha.length !== headSha.length) {
    throw new Error("Review-bundle commit identities must be full, nonzero hexadecimal Git object IDs of the same format.");
  }
}

function boundedPaths(bytes) {
  const entries = nulPaths(bytes);
  if (entries.length > MAX_ENUMERATED_PATHS) {
    throw new Error("Review-bundle candidate inventory exceeds the path-count limit.");
  }
  return entries;
}

function untrackedPaths(root) {
  return boundedPaths(git(root, ["ls-files", "--others", "--exclude-standard", "-z", "--"],
    { maxBuffer: 1024 * 1024 }));
}

/**
 * Git's --directory inventory can include traversal ancestors that are not
 * themselves ignored. Classify its bounded candidates with Git check-ignore;
 * only genuinely ignored paths may affect exclusions or fail-closed checks.
 * Neither command descends into collapsed ignored build/dependency trees.
 */
function ignoredPaths(root) {
  const candidates = boundedPaths(git(root, [
    "ls-files", "--others", "--ignored", "--exclude-standard", "--directory",
    "-z", "--", ...IGNORED_INVENTORY_ROOTS
  ], { maxBuffer: 1024 * 1024 }));
  if (candidates.length === 0) return [];

  const input = Buffer.from(candidates.join("\0") + "\0", "utf8");
  if (input.byteLength > 1024 * 1024) {
    throw new Error("Review-bundle ignored-source inventory exceeds its byte limit.");
  }
  const checked = spawnSync("git", ["check-ignore", "-z", "--stdin"], {
    cwd: root, windowsHide: true, input, timeout: 30_000, maxBuffer: 1024 * 1024,
    stdio: ["pipe", "pipe", "pipe"]
  });
  if (checked.error) throw checked.error;
  if (checked.signal || (checked.status !== 0 && checked.status !== 1)) {
    throw new Error("Git ignored-source classification failed.");
  }
  const ignored = boundedPaths(checked.stdout);
  const candidateSet = new Set(candidates);
  if ((checked.status === 1 && ignored.length !== 0) ||
      ignored.some((path) => !candidateSet.has(path))) {
    throw new Error("Git ignored-source classification returned inconsistent paths.");
  }
  return ignored;
}

function relevantIgnoredSource(path) {
  if (path.endsWith("/")) return !restricted(path.slice(0, -1));
  return eligibleUntracked(path);
}

function assertIgnoredInventory(paths) {
  for (const path of paths) {
    if (!isSafeRelative(path.endsWith("/") ? path.slice(0, -1) : path)) {
      throw new Error("Unsafe path in scoped ignored-source inventory.");
    }
    if (relevantIgnoredSource(path)) {
      throw new Error("Relevant ignored source cannot be omitted from review evidence: " + path);
    }
  }
}

async function validateSnapshot(root, baseSha, snapshot) {
  if (gitText(root, ["rev-parse", "--verify", "HEAD"]) !== snapshot.head_sha) {
    throw new Error("HEAD changed during review-bundle capture.");
  }
  const currentPaths = changedPaths(root, baseSha);
  const currentTrackedSources = await trackedSourceSnapshot(
    root, baseSha, snapshot.head_sha, currentPaths
  );
  if (JSON.stringify(currentTrackedSources) !== JSON.stringify(snapshot.tracked_source_snapshot)) {
    throw new Error("Tracked source state changed during review-bundle capture.");
  }
  if (sha256(trackedDiff(root, baseSha)) !== snapshot.tracked_patch.sha256 ||
      JSON.stringify(currentPaths) !== JSON.stringify(snapshot.tracked_changed_paths) ||
      JSON.stringify(untrackedPaths(root)) !== JSON.stringify(snapshot.all_untracked_paths) ||
      JSON.stringify(ignoredPaths(root)) !== JSON.stringify(snapshot.all_ignored_paths)) {
    throw new Error("Git worktree changed during review-bundle capture.");
  }
  for (const entry of [...snapshot.untracked_files, ...snapshot.references]) {
    if (sha256(await readBoundFile(root, entry.source_path)) !== entry.sha256) {
      throw new Error("Source changed during review-bundle capture: " + entry.source_path);
    }
  }
}

/**
 * Captures a content-addressed, read-only Git worktree review snapshot.
 * The output is outside the checkout; this operation never stages or edits it.
 * Endpoint verification cannot detect a concurrent writer that changes and
 * restores identical bytes between observations.
 */
export async function createReviewBundle({
  cwd = process.cwd(), base, output, references = [], issues = [],
  beforeFinalSnapshot

} = {}) {
  if (typeof base !== "string" || !/^[A-Za-z0-9._/-]{1,120}$/.test(base)) {
    throw new Error("Provide a safe base commit or ref using --base.");
  }
  if (typeof output !== "string" || !isAbsolute(output)) {
    throw new Error("Provide an absolute, new output directory outside the checkout.");
  }

  const root = await realpath(gitText(cwd, ["rev-parse", "--show-toplevel"]));
  const outputDirectory = resolve(output);
  const parent = await realpath(dirname(outputDirectory));
  if (isWithin(root, parent) || isWithin(root, outputDirectory)) {
    throw new Error("Review bundle output must be outside the source checkout.");
  }
  if (existsSync(outputDirectory)) {
    throw new Error("Review bundle output directory already exists.");
  }

  const baseSha = gitText(root, ["rev-parse", "--verify", "--end-of-options", base + "^{commit}"]);
  git(root, ["merge-base", "--is-ancestor", baseSha, "HEAD"]);
  const headSha = gitText(root, ["rev-parse", "--verify", "HEAD"]);
  const paths = changedPaths(root, baseSha);
  for (const path of paths) {
    if (restricted(path)) throw new Error("Tracked change crosses the review safety boundary: " + path);
  }
  const trackedSources = await trackedSourceSnapshot(root, baseSha, headSha, paths);
  const allUntracked = untrackedPaths(root);
  for (const path of allUntracked) {
    if (!isSafeRelative(path)) throw new Error("Git worktree contains unsafe untracked path syntax.");
  }
  const allIgnored = ignoredPaths(root);
  assertIgnoredInventory(allIgnored);
  const excludedIgnored = allIgnored.filter((path) =>
    !restricted(path.endsWith("/") ? path.slice(0, -1) : path));
  const redactedIgnoredCount = allIgnored.length - excludedIgnored.length;
  const selectedUntracked = allUntracked.filter(eligibleUntracked);
  if (selectedUntracked.length > MAX_UNTRACKED_FILES) {
    throw new Error("Review bundle exceeds the untracked-source file count limit.");
  }
  const patch = trackedDiff(root, baseSha);
  if (patch.byteLength > MAX_PATCH_BYTES) throw new Error("Review patch exceeds its byte limit.");
  if (paths.length === 0 && selectedUntracked.length === 0) {
    throw new Error("No tracked changes or eligible untracked source files to review.");
  }

  const requestedReferences = [...new Set([...DEFAULT_REFERENCES, ...references])].sort();
  for (const path of requestedReferences) {
    if (restricted(path) || !/\.(?:md|txt)$/i.test(path)) {
      throw new Error("Review reference must be a safe text document: " + String(path));
    }
  }
  const issueReferences = [...new Set(issues.map((issue) => {
    if (typeof issue !== "string" || !/^#?[1-9]\d*$/.test(issue)) {
      throw new Error("Issue references must be issue numbers, e.g. #50.");
    }
    return "#" + issue.replace(/^#/, "");
  }))].sort();

  await mkdir(outputDirectory, { mode: 0o700 });
  try {
    await writeBundleFile(outputDirectory, "tracked.patch", patch);
    const manifest = {
      schema_version: 2,
      base_sha: baseSha,
      head_sha: headSha,
      tracked_changed_paths: paths,
      tracked_patch: { path: "tracked.patch", bytes: patch.byteLength, sha256: sha256(patch) },
      untracked_files: [],
      references: [],
      excluded_untracked_paths: allUntracked.filter((path) => !eligibleUntracked(path)),
      ignored_inventory_roots: [...IGNORED_INVENTORY_ROOTS],
      excluded_ignored_paths: excludedIgnored,
      redacted_ignored_count: redactedIgnoredCount,
      issue_references: issueReferences
    };
    let untrackedBytes = 0;
    for (const path of selectedUntracked) {
      const content = await readBoundFile(root, path);
      untrackedBytes += content.byteLength;
      if (untrackedBytes > MAX_UNTRACKED_BYTES) {
        throw new Error("Review bundle exceeds the total untracked-source byte limit.");
      }
      const bundlePath = "untracked/" + path;
      await writeBundleFile(outputDirectory, bundlePath, content);
      manifest.untracked_files.push({
        source_path: path, path: bundlePath, bytes: content.byteLength, sha256: sha256(content)
      });
    }
    let referenceBytes = 0;
    for (const path of requestedReferences) {
      if (!existsSync(join(root, path)) && DEFAULT_REFERENCES.includes(path) &&
          !references.includes(path)) continue;
      if (manifest.references.length >= MAX_REFERENCE_FILES) {
        throw new Error("Review bundle exceeds the reference file count limit.");
      }
      const content = await readBoundFile(root, path);
      referenceBytes += content.byteLength;
      if (referenceBytes > MAX_REFERENCE_BYTES) {
        throw new Error("Review bundle exceeds the total reference byte limit.");
      }
      const bundlePath = "references/" + path;
      await writeBundleFile(outputDirectory, bundlePath, content);
      manifest.references.push({
        source_path: path, path: bundlePath, bytes: content.byteLength, sha256: sha256(content)
      });
    }

    if (beforeFinalSnapshot) await beforeFinalSnapshot(root);
    await validateSnapshot(root, baseSha, {
      ...manifest,
      tracked_source_snapshot: trackedSources,
      all_untracked_paths: allUntracked,
      all_ignored_paths: allIgnored
    });
    const contentDigest = sha256(JSON.stringify(manifest));
    const encoded = Buffer.from(JSON.stringify({
      ...manifest, content_digest_sha256: contentDigest
    }, null, 2) + "\n", "utf8");
    await writeBundleFile(outputDirectory, "manifest.json", encoded);
    const manifestSha256 = sha256(encoded);
    await verifyReviewBundle(outputDirectory, manifestSha256);
    return {
      output: outputDirectory,
      manifest_sha256: manifestSha256,
      content_digest_sha256: contentDigest,
      tracked_path_count: paths.length,
      untracked_path_count: selectedUntracked.length,
      excluded_untracked_count: manifest.excluded_untracked_paths.length,
      excluded_ignored_count: excludedIgnored.length,
      redacted_ignored_count: redactedIgnoredCount
    };
  } catch (error) {
    await rm(outputDirectory, { recursive: true, force: true });
    throw error;
  }
}

async function allBundleFiles(root, prefix = "") {
  const entries = await readdir(join(root, prefix), { withFileTypes: true });
  const found = [];
  for (const entry of entries) {
    const path = prefix ? prefix + "/" + entry.name : entry.name;
    if (entry.isSymbolicLink()) throw new Error("Review bundle contains a symlink: " + path);
    if (entry.isDirectory()) found.push(...await allBundleFiles(root, path));
    else if (entry.isFile()) found.push(path);
    else throw new Error("Review bundle contains an unsupported file type.");
  }
  return found.sort();
}

export async function verifyReviewBundle(directory, expectedManifestSha256) {
  if (typeof expectedManifestSha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(expectedManifestSha256)) {
    throw new Error("Verification requires the externally recorded manifest SHA-256.");
  }
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error("Review bundle root must be a real directory.");
  }
  const root = await realpath(directory);
  const manifestBytes = await readBoundFile(root, "manifest.json");
  if (sha256(manifestBytes) !== expectedManifestSha256) {
    throw new Error("Review bundle manifest digest mismatch.");
  }
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  assertCommitIdentities(manifest);
  if (manifest.schema_version !== 2 || !Array.isArray(manifest.tracked_changed_paths) ||
      !Array.isArray(manifest.untracked_files) || !Array.isArray(manifest.references) ||
      !Array.isArray(manifest.excluded_untracked_paths) ||
      !Array.isArray(manifest.excluded_ignored_paths) ||
      JSON.stringify(manifest.ignored_inventory_roots) !==
        JSON.stringify(IGNORED_INVENTORY_ROOTS) ||
      !Number.isSafeInteger(manifest.redacted_ignored_count) ||
      manifest.redacted_ignored_count < 0) {
    throw new Error("Unsupported review-bundle manifest.");
  }
  if (manifest.references.length > MAX_REFERENCE_FILES) {
    throw new Error("Review bundle exceeds the reference file count limit.");
  }
  if (manifest.untracked_files.length > MAX_UNTRACKED_FILES) {
    throw new Error("Review bundle exceeds the untracked-source file count limit.");
  }
  const { content_digest_sha256: digest, ...unsigned } = manifest;
  if (sha256(JSON.stringify(unsigned)) !== digest) {
    throw new Error("Review bundle content manifest digest mismatch.");
  }
  if (new Set(manifest.tracked_changed_paths).size !== manifest.tracked_changed_paths.length ||
      manifest.tracked_changed_paths.some(restricted) ||
      new Set(manifest.excluded_untracked_paths).size !== manifest.excluded_untracked_paths.length ||
      manifest.excluded_untracked_paths.some((path) => !isSafeRelative(path)) ||
      new Set(manifest.excluded_ignored_paths).size !== manifest.excluded_ignored_paths.length ||
      manifest.excluded_ignored_paths.some((path) =>
        restricted(path.endsWith("/") ? path.slice(0, -1) : path))) {
    throw new Error("Review-bundle inventory is inconsistent or includes restricted paths.");
  }
  const expected = ["manifest.json"];
  if (manifest.tracked_patch?.path !== "tracked.patch") {
    throw new Error("Review-bundle tracked patch path is inconsistent.");
  }
  for (const entry of manifest.untracked_files) {
    if (!eligibleUntracked(entry?.source_path) ||
        entry.path !== "untracked/" + entry.source_path) {
      throw new Error("Review-bundle untracked entry is inconsistent.");
    }
  }
  for (const entry of manifest.references) {
    if (restricted(entry?.source_path) || !/\.(?:md|txt)$/i.test(entry.source_path) ||
        entry.path !== "references/" + entry.source_path) {
      throw new Error("Review-bundle reference entry is inconsistent.");
    }
  }
  const entries = [manifest.tracked_patch, ...manifest.untracked_files, ...manifest.references];
  let untrackedBytes = 0;
  let referenceBytes = 0;
  for (const entry of entries) {
    if (!entry || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 ||
        !isSafeRelative(entry.path) || restricted(entry.path) ||
        (entry !== manifest.tracked_patch &&
          !entry.path.startsWith("untracked/") && !entry.path.startsWith("references/"))) {
      throw new Error("Invalid review-bundle manifest entry.");
    }
    const maxBytes = entry === manifest.tracked_patch ? MAX_PATCH_BYTES : MAX_FILE_BYTES;
    const bytes = await readBoundFile(root, entry.path, maxBytes);
    if (manifest.untracked_files.includes(entry)) {
      untrackedBytes += bytes.byteLength;
      if (untrackedBytes > MAX_UNTRACKED_BYTES) {
        throw new Error("Review bundle exceeds the total untracked-source byte limit.");
      }
    }
    if (manifest.references.includes(entry)) {
      referenceBytes += bytes.byteLength;
      if (referenceBytes > MAX_REFERENCE_BYTES) {
        throw new Error("Review bundle exceeds the total reference byte limit.");
      }
    }
    if (bytes.byteLength !== entry.bytes || sha256(bytes) !== entry.sha256) {
      throw new Error("Review-bundle content mismatch: " + entry.path);
    }
    expected.push(entry.path);
  }
  if (new Set(expected).size !== expected.length ||
      JSON.stringify(expected.sort()) !== JSON.stringify(await allBundleFiles(root))) {
    throw new Error("Review bundle includes missing, duplicate, or unexpected files.");
  }
  return { verified: true, manifest_sha256: expectedManifestSha256,
    base_sha: manifest.base_sha, head_sha: manifest.head_sha };
}

function argumentsFor(command, args) {
  const result = { references: [], issues: [] };
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i];
    const value = args[i + 1];
    if (!flag?.startsWith("--") || value === undefined) throw new Error("Invalid review-bundle arguments.");
    const key = flag.slice(2);
    if (command === "create" && key === "reference") result.references.push(value);
    else if (command === "create" && key === "issue") result.issues.push(value);
    else if (["base", "output", "bundle", "expected-manifest-sha256"].includes(key) && !result[key]) {
      result[key] = value;
    } else throw new Error("Unsupported or duplicate review-bundle argument: " + flag);
  }
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const usage = "Usage:\n" +
    "  node scripts/create-review-bundle.mjs create --base <ref> --output <absolute-new-dir>" +
    " [--reference <repo-relative-doc>] [--issue <#number>]\n" +
    "  node scripts/create-review-bundle.mjs verify --bundle <dir>" +
    " --expected-manifest-sha256 <64-hex>\n";
  const [command, ...args] = process.argv.slice(2);
  if (command === "--help" || command === undefined) {
    process.stdout.write(usage);
  } else {
    try {
      const opts = argumentsFor(command, args);
      let result;
      if (command === "create") {
        result = await createReviewBundle({
          base: opts.base, output: opts.output, references: opts.references, issues: opts.issues
        });
      } else if (command === "verify") {
        result = await verifyReviewBundle(opts.bundle, opts["expected-manifest-sha256"]);
      } else throw new Error("Unknown review-bundle command.");
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } catch (error) {
      process.stderr.write((error instanceof Error ? error.message : String(error)) + "\n");
      process.exitCode = 1;
    }
  }
}
