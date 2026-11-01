import { execFileSync } from "node:child_process";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  hasRestrictedPolicyPathSuffix,
  hasUnsupportedWindowsPathAlias
} from "./restricted-policy-path.mjs";

const WINDOWS_DRIVE_PATH = /^[A-Za-z]:/;

const forbiddenTrackedArtifacts = {
  exact: new Set([
    ".ds_store",
    "config.local.json"
  ]),
  prefixes: [
    ".chatgpt/"
  ],
  patterns: [
    {
      regex: /(?:^|\/)[^/]+\.local\.json(?:\.[^/]+)?$/i,
      label: "local config or local config backup"
    }
  ]
};

const scanRoots = [
  "README.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "LICENSE",
  "package.json",
  "config.example.json",
  ".gitleaks.toml",
  ".gitleaksignore",
  ".gitignore",
  ".npmignore",
  "docs/",
  "security/",
  "src/",
  "scripts/",
  "tools/",
  "AGENTS.md"
];

const excludedScanPaths = [
  "security/oss-security-policy.json",
  "node_modules/",
  "dist/",
  "coverage/",
  "package-lock.json"
];

// Keep the obsolete description explicit so the public check can flag it.
// The checker allows that one marker in its own source.
const obsoleteProductDescription = "read-only TypeScript MCP server";

const blockedMarkers = [
  "/Us" + "ers/",
  "Do not add " + "write tools",
  "No " + "write tools",
  obsoleteProductDescription,
  "Prom" + "ptiva"
];

const allowlistedMarkerHits = new Set([
  `LICENSE::${blockedMarkers[4]}`,
  `scripts/check-public.mjs::${obsoleteProductDescription}`
]);

function gitRepositoryRoot(startingDirectory) {
  if (hasUnsupportedWindowsPathAlias(startingDirectory)) {
    throw new Error("Starting directory uses unsupported Windows path alias syntax.");
  }
  const resolvedStartingDirectory = resolve(startingDirectory);
  if (!hasSafeDirectoryPath(resolvedStartingDirectory, lstatSync)) {
    throw new Error("Starting directory must be a real directory without symlinked ancestors.");
  }
  const output = execFileSync(
    "git",
    ["-C", resolvedStartingDirectory, "rev-parse", "--show-toplevel"],
    { encoding: "utf8" }
  );
  const root = resolve(output.trim());
  if (hasUnsupportedWindowsPathAlias(root)) {
    throw new Error("Git repository root uses unsupported Windows path alias syntax.");
  }
  if (!hasSafeDirectoryPath(root, lstatSync)) {
    throw new Error("Git repository root must be a real directory without symlinked ancestors.");
  }
  const relativeStartingDirectory = relative(root, resolvedStartingDirectory);
  if (relativeStartingDirectory === ".." ||
      relativeStartingDirectory.startsWith(`..${sep}`) ||
      isAbsolute(relativeStartingDirectory)) {
    throw new Error("Starting directory is outside the discovered Git root.");
  }
  return root;
}

function gitLsFiles(root) {
  const output = execFileSync("git", ["-C", root, "ls-files", "-z"], {
    encoding: "buffer"
  });
  return output.toString("utf8").split("\0").filter(Boolean);
}

function noFollowReadFlags() {
  if (typeof constants.O_NOFOLLOW !== "number") {
    throw new Error("No-follow file opens are not supported on this platform.");
  }
  return constants.O_RDONLY | constants.O_NOFOLLOW;
}

function isSafeRepoRelativePath(path) {
  if (typeof path !== "string" || path.length === 0 || isAbsolute(path) ||
      WINDOWS_DRIVE_PATH.test(path) || path.includes("\\") || path.includes("\0")) {
    return false;
  }
  return path.split("/").every((component) =>
    component.length > 0 && component !== "." && component !== ".."
  );
}

function hasSafeDirectoryPath(path, lstat) {
  if (!isAbsolute(path)) return false;
  const absolutePath = resolve(path);
  const filesystemRoot = parse(absolutePath).root;
  const components = relative(filesystemRoot, absolutePath)
    .split(sep)
    .filter(Boolean);
  let current = filesystemRoot;
  const rootInfo = lstat(current);
  if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) return false;
  for (const component of components) {
    current = join(current, component);
    const info = lstat(current);
    if (info.isSymbolicLink() || !info.isDirectory()) return false;
  }
  return true;
}

function hasSafeParentDirectories(root, file, lstat) {
  let parent = "";
  for (const component of file.split("/").slice(0, -1)) {
    parent = parent.length === 0 ? component : `${parent}/${component}`;
    const info = lstat(join(root, parent));
    if (info.isSymbolicLink() || !info.isDirectory()) return false;
  }
  return true;
}

function assertWithinApprovedRoot(root, absolutePath, label) {
  const pathFromRoot = relative(root, absolutePath);
  if (!pathFromRoot || pathFromRoot === ".." || pathFromRoot.startsWith(`..${sep}`) ||
      isAbsolute(pathFromRoot)) {
    throw new Error(`${label} is outside the approved root.`);
  }
  return pathFromRoot;
}

function assertNoSymlinkedParents(root, pathFromRoot, lstat, label) {
  const components = pathFromRoot.split(sep);
  let parent = "";
  for (const component of components.slice(0, -1)) {
    parent = parent.length === 0 ? component : `${parent}${sep}${component}`;
    const info = lstat(join(root, parent));
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new Error(`${label} has a symlinked or non-directory parent.`);
    }
  }
}

/**
 * Reads an explicit source manifest after lexical restricted-path and
 * root-containment checks. The approved root is realpath-canonicalized; the
 * manifest target is then built lexically within that root and checked for
 * static parent symlinks before its metadata or contents are accessed. Win32
 * trailing-dot/space and 8.3-looking path syntax is rejected before filesystem
 * access rather than resolved to a target.
 */
export function manifestFiles(manifestPath, {
  root = process.cwd(),
  lstat = lstatSync,
  open = openSync,
  fstat = fstatSync,
  readFile = readFileSync,
  close = closeSync,
  realpath = realpathSync,
  platform = process.platform
} = {}) {
  if (typeof manifestPath !== "string") {
    throw new Error("Source manifest path must be a string.");
  }
  if (hasUnsupportedWindowsPathAlias(manifestPath, platform)) {
    throw new Error("Source manifest path uses unsupported Windows path alias syntax.");
  }
  if (hasUnsupportedWindowsPathAlias(root, platform)) {
    throw new Error("Approved source root uses unsupported Windows path alias syntax.");
  }
  if (hasRestrictedPolicyPathSuffix(manifestPath, platform)) {
    throw new Error("Restricted policy manifest path is forbidden.");
  }
  if (!isAbsolute(manifestPath)) {
    throw new Error("Source manifest path must be absolute.");
  }
  const resolvedPath = resolve(manifestPath);
  if (hasRestrictedPolicyPathSuffix(resolvedPath, platform)) {
    throw new Error("Restricted policy manifest path is forbidden.");
  }

  const resolvedRoot = resolve(root);
  const pathFromRoot = assertWithinApprovedRoot(
    resolvedRoot,
    resolvedPath,
    "Source manifest path"
  );
  if (!hasSafeDirectoryPath(resolvedRoot, lstat)) {
    throw new Error("Approved source root must be a real directory without symlinked ancestors.");
  }
  const canonicalRoot = resolve(realpath(resolvedRoot));
  const canonicalPath = resolve(canonicalRoot, pathFromRoot);
  if (hasUnsupportedWindowsPathAlias(canonicalRoot, platform) ||
      hasUnsupportedWindowsPathAlias(canonicalPath, platform)) {
    throw new Error("Source manifest path uses unsupported Windows path alias syntax.");
  }
  assertWithinApprovedRoot(
    canonicalRoot,
    canonicalPath,
    "Source manifest path"
  );
  if (hasRestrictedPolicyPathSuffix(canonicalRoot, platform) ||
      hasRestrictedPolicyPathSuffix(canonicalPath, platform)) {
    throw new Error("Restricted policy manifest path is forbidden.");
  }
  assertNoSymlinkedParents(
    canonicalRoot,
    pathFromRoot,
    lstat,
    "Source manifest path"
  );

  const before = lstat(canonicalPath);
  if (before.isSymbolicLink()) {
    throw new Error("Source manifest must not be a symbolic link.");
  }
  if (!before.isFile() || before.nlink !== 1) {
    throw new Error("Source manifest must be a singly-linked regular file.");
  }

  const descriptor = open(canonicalPath, noFollowReadFlags());
  let manifest;
  try {
    const opened = fstat(descriptor);
    if (!opened.isFile() || opened.nlink !== 1 ||
        opened.dev !== before.dev || opened.ino !== before.ino) {
      throw new Error("Source manifest changed or is not a singly-linked regular file.");
    }
    manifest = JSON.parse(readFile(descriptor, "utf8"));
  } finally {
    close(descriptor);
  }
  if (!manifest || !Array.isArray(manifest.entries)) {
    throw new Error("Source manifest must contain an entries array.");
  }
  if (manifest.entries.length === 0) {
    throw new Error("Source manifest must contain at least one entry.");
  }

  const files = [];
  const seen = new Set();
  for (const entry of manifest.entries) {
    const file = entry?.path;
    if (!isSafeRepoRelativePath(file)) {
      throw new Error("Source manifest contains an unsafe relative path.");
    }
    if (seen.has(file)) {
      throw new Error(`Source manifest contains a duplicate path: ${file}`);
    }
    seen.add(file);
    files.push(file);
  }
  return files;
}

function sourceInventory() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    const root = gitRepositoryRoot(process.cwd());
    return { root, files: gitLsFiles(root) };
  }
  if (args.length === 2 && args[0] === "--manifest") {
    const root = resolve(process.cwd());
    return { root, files: manifestFiles(args[1], { root }) };
  }
  throw new Error("Usage: check-public.mjs [--manifest <absolute-path>]");
}

/** Normalizes a relative scan path before root and exclusion comparisons. */
function normalizeScanPath(file) {
  return file.replaceAll("\\", "/").replace(/\/+/g, "/");
}

function isUnderScanRoot(file) {
  const normalizedFile = normalizeScanPath(file).toLowerCase();
  return scanRoots.some((root) => {
    const normalizedRoot = normalizeScanPath(root).toLowerCase();
    return normalizedRoot.endsWith("/")
      ? normalizedFile.startsWith(normalizedRoot)
      : normalizedFile === normalizedRoot;
  });
}

function isExcluded(file) {
  const normalizedPath = normalizeScanPath(file).replace(/\/+$/, "");
  const normalizedFile = normalizedPath.toLowerCase();
  return excludedScanPaths.some((path) => {
    const normalizedPath = normalizeScanPath(path).toLowerCase();
    if (path === "security/oss-security-policy.json") {
      return file === path;
    }
    return normalizedPath.endsWith("/")
      ? normalizedFile.startsWith(normalizedPath)
      : normalizedFile === normalizedPath;
  });
}

function isForbiddenTrackedArtifact(file) {
  const normalized = file.toLowerCase();
  if (
    forbiddenTrackedArtifacts.exact.has(normalized) ||
    normalized.endsWith(".ds_store")
  ) {
    return true;
  }
  if (forbiddenTrackedArtifacts.prefixes.some((prefix) => normalized.startsWith(prefix))) {
    return true;
  }
  return forbiddenTrackedArtifacts.patterns.some(({ regex }) => regex.test(normalized));
}

function forbiddenArtifactLabel(file) {
  const normalized = file.toLowerCase();
  const pattern = forbiddenTrackedArtifacts.patterns.find(({ regex }) => regex.test(normalized));
  return pattern?.label ?? file;
}

/**
 * Reads a regular scan candidate after checking relative-path syntax and then
 * applying scan exclusions. Unsafe syntax is therefore never classified as an
 * intentional exclusion. Win32 trailing-dot/space and 8.3-looking path syntax
 * is reported as unsafe before the candidate is excluded or inspected.
 * Restricted paths are excluded before filesystem access. A static lstat walk
 * validates the approved root and every candidate parent before the final
 * component is checked and opened without following a symlink.
 * These checks reject symlinks present during inspection. A malicious process
 * with the same UID can replace a checked parent before open; the trusted-local
 * operator model accepts that residual TOCTOU window.
 *
 * @param {string} file Repository-relative scan candidate.
 * @param {object} [fileAccess] Optional root and filesystem callbacks used by regression fixtures.
 * @returns {{status: "excluded"} | {status: "unsafe", reason: string} |
 *   {status: "scanned", text: string}} Discriminated scan outcome. Unsafe
 *   in-scope entries are reported to the caller rather than treated as skips.
 */
export function readScannableText(file, {
  root = process.cwd(),
  lstat = lstatSync,
  open = openSync,
  fstat = fstatSync,
  readFile = readFileSync,
  close = closeSync,
  platform = process.platform
} = {}) {
  if (typeof file !== "string") {
    throw new Error("Public scan path must be a string.");
  }
  if (!isSafeRepoRelativePath(file)) {
    return { status: "unsafe", reason: "unsafe relative path" };
  }
  if (hasUnsupportedWindowsPathAlias(file, platform) ||
      hasUnsupportedWindowsPathAlias(root, platform)) {
    return { status: "unsafe", reason: "unsupported Windows path alias syntax" };
  }
  if (hasRestrictedPolicyPathSuffix(file, platform)) {
    return file === "security/oss-security-policy.json"
      ? { status: "excluded" }
      : { status: "unsafe", reason: "restricted policy path alias" };
  }
  if (isExcluded(file) || !isUnderScanRoot(file)) {
    return { status: "excluded" };
  }
  const absoluteRoot = resolve(root);
  if (!hasSafeDirectoryPath(absoluteRoot, lstat)) {
    return { status: "unsafe", reason: "symlinked or non-directory approved root" };
  }
  if (!hasSafeParentDirectories(absoluteRoot, file, lstat)) {
    return { status: "unsafe", reason: "symlinked or non-directory parent" };
  }
  const absolutePath = join(absoluteRoot, file);
  const before = lstat(absolutePath);
  if (before.isSymbolicLink()) return { status: "unsafe", reason: "symbolic link" };
  if (!before.isFile()) return { status: "unsafe", reason: "non-regular file" };
  if (before.nlink !== 1) return { status: "unsafe", reason: "multiple hard links" };
  const descriptor = open(absolutePath, noFollowReadFlags());
  try {
    const opened = fstat(descriptor);
    if (opened.isSymbolicLink?.()) return { status: "unsafe", reason: "symbolic link" };
    if (!opened.isFile()) return { status: "unsafe", reason: "non-regular file" };
    if (opened.nlink !== 1) {
      return { status: "unsafe", reason: "multiple hard links" };
    }
    if (opened.dev !== before.dev || opened.ino !== before.ino) {
      return { status: "unsafe", reason: "file changed during inspection" };
    }
    return { status: "scanned", text: readFile(descriptor, "utf8") };
  } finally {
    close(descriptor);
  }
}

function main() {
  const { root, files: trackedFiles } = sourceInventory();
  const failures = [];
  let scannedCount = 0;
  if (trackedFiles.length === 0) {
    failures.push("Source inventory is empty.");
  }

  for (const file of trackedFiles) {
    if (isForbiddenTrackedArtifact(file)) {
      failures.push(`${file}: tracked local-only/private artifact is forbidden (${forbiddenArtifactLabel(file)}).`);
    }
  }

  for (const file of trackedFiles) {
    const outcome = readScannableText(file, { root });
    if (outcome.status === "excluded") continue;
    if (outcome.status === "unsafe") {
      failures.push(`${file}: unsafe public scan entry (${outcome.reason}).`);
      continue;
    }
    if (outcome.status !== "scanned") {
      failures.push(`${file}: public scan returned an invalid outcome.`);
      continue;
    }
    scannedCount += 1;
    for (const marker of blockedMarkers) {
      if (outcome.text.includes(marker) &&
          !allowlistedMarkerHits.has(`${file}::${marker}`)) {
        failures.push(`${file}: blocked public-release marker found: ${marker}`);
      }
    }
  }

  if (scannedCount === 0) {
    failures.push("Source inventory contained no public files to scan.");
  }

  if (failures.length > 0) {
    process.stderr.write("Public hygiene check failed:\n");
    for (const failure of failures) {
      process.stderr.write(`- ${failure}\n`);
    }
    process.exit(1);
  }

  process.stdout.write("Public hygiene check passed.\n");
}

if (process.argv[1] &&
    await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url))) {
  main();
}
