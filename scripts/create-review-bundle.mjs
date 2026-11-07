import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import process from "node:process";
import { execFileSync } from "node:child_process";
import { constants, existsSync } from "node:fs";
import { lstat, mkdir, open, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, URL } from "node:url";

const MAX_PATCH_BYTES = 16 * 1024 * 1024;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_UNTRACKED_FILES = 256;
const MAX_UNTRACKED_BYTES = 16 * 1024 * 1024;
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

function nulPaths(bytes) {
  const text = bytes.toString("utf8");
  if (text.includes("\uFFFD")) throw new Error("Git emitted a path that is not valid UTF-8.");
  return text.split("\0").filter(Boolean).sort();
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

function untrackedPaths(root) {
  return nulPaths(git(root, ["ls-files", "--others", "--exclude-standard", "-z", "--"]));
}

async function validateSnapshot(root, baseSha, snapshot) {
  if (gitText(root, ["rev-parse", "--verify", "HEAD"]) !== snapshot.head_sha) {
    throw new Error("HEAD changed during review-bundle capture.");
  }
  if (sha256(trackedDiff(root, baseSha)) !== snapshot.tracked_patch.sha256 ||
      JSON.stringify(changedPaths(root, baseSha)) !== JSON.stringify(snapshot.tracked_changed_paths) ||
      JSON.stringify(untrackedPaths(root)) !== JSON.stringify(snapshot.all_untracked_paths)) {
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
  cwd = process.cwd(), base, output, references = [], issues = []
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
  const allUntracked = untrackedPaths(root);
  for (const path of allUntracked) {
    if (!isSafeRelative(path)) throw new Error("Git worktree contains unsafe untracked path syntax.");
  }
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
      schema_version: 1,
      base_sha: baseSha,
      head_sha: headSha,
      tracked_changed_paths: paths,
      tracked_patch: { path: "tracked.patch", bytes: patch.byteLength, sha256: sha256(patch) },
      untracked_files: [],
      references: [],
      excluded_untracked_paths: allUntracked.filter((path) => !eligibleUntracked(path)),
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
    for (const path of requestedReferences) {
      if (!existsSync(join(root, path)) && DEFAULT_REFERENCES.includes(path) &&
          !references.includes(path)) continue;
      const content = await readBoundFile(root, path);
      const bundlePath = "references/" + path;
      await writeBundleFile(outputDirectory, bundlePath, content);
      manifest.references.push({
        source_path: path, path: bundlePath, bytes: content.byteLength, sha256: sha256(content)
      });
    }

    await validateSnapshot(root, baseSha, {
      ...manifest, all_untracked_paths: allUntracked
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
      excluded_untracked_count: manifest.excluded_untracked_paths.length
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
  if (manifest.schema_version !== 1 || !Array.isArray(manifest.tracked_changed_paths) ||
      !Array.isArray(manifest.untracked_files) || !Array.isArray(manifest.references)) {
    throw new Error("Unsupported review-bundle manifest.");
  }
  const { content_digest_sha256: digest, ...unsigned } = manifest;
  if (sha256(JSON.stringify(unsigned)) !== digest) {
    throw new Error("Review bundle content manifest digest mismatch.");
  }
  const expected = ["manifest.json"];
  const entries = [manifest.tracked_patch, ...manifest.untracked_files, ...manifest.references];
  for (const entry of entries) {
    if (!entry || !isSafeRelative(entry.path) || restricted(entry.path) ||
        (entry !== manifest.tracked_patch &&
          !entry.path.startsWith("untracked/") && !entry.path.startsWith("references/"))) {
      throw new Error("Invalid review-bundle manifest entry.");
    }
    const bytes = await readBoundFile(root, entry.path, MAX_PATCH_BYTES);
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
