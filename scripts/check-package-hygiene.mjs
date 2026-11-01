import { Buffer } from "node:buffer";
import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { lstat, open, readFile, readdir, realpath } from "node:fs/promises";
import process from "node:process";
import { isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  hasRestrictedPolicyPathSuffix,
  hasUnsupportedWindowsPathAlias
} from "./restricted-policy-path.mjs";

const execFileAsync = promisify(execFile);
const NPM_PACK_TIMEOUT_MS = 120_000;

const FORBIDDEN_EXACT = new Set(["config.local.json", ".ds_store"]);
const FORBIDDEN_PREFIXES = new Set([
  "security/",
  "node_modules/",
  ".chatgpt/",
  ".git/",
  "coverage/",
  "test-results/",
  ".serena/",
  ".codegraph/",
  ".tokensave/"
]);
const FORBIDDEN_PATTERNS = [/(?:^|\/)[^/]*\.local\.[^/]*$/i];
const ENVIRONMENT_TEMPLATE = ".env.example";
const WINDOWS_DRIVE_PATH = /^[A-Za-z]:/;
const WINDOWS_UNC_PATH = /^\/\//;
// Account roots are assembled from parts because the public hygiene gate
// rejects that literal path anywhere in tracked source, including here.
const USERS_ROOT = ["", "Users", ""].join("/");
const HOME_ROOT = ["", "home", ""].join("/");
const ACCOUNT_ROOTS = [USERS_ROOT, HOME_ROOT];
const INSPECT_CHUNK_BYTES = 64 * 1024;
const PACKAGE_READ_FLAGS = constants.O_RDONLY |
  (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0);
// Keep a full root in the carry so a root ending exactly on a chunk boundary
// can still pair with an account component in the next chunk.
const INSPECT_CARRY_BYTES = Math.max(...ACCOUNT_ROOTS.map((root) => root.length));
// One account component must follow the root before a path identifies a user.
// Quotes, brackets and angle brackets mark placeholders rather than accounts.
const ACCOUNT_SEGMENT_PATTERN = /^[^/\s"'\x60<>()[\]{},;]+/;

/**
 * Reports the normalized home-directory markers found in a text sample. The
 * returned values never include the account name or the surrounding text. A
 * bare account root describes a directory layout but names no account, and a
 * placeholder root names no account either, so only roots followed by an
 * account component are reported.
 */
export function findHomePathLeaks(text) {
  const normalized = text.replaceAll("\\", "/");
  const markers = [];
  for (const root of ACCOUNT_ROOTS) {
    let index = normalized.indexOf(root);
    while (index !== -1) {
      const remainder = normalized.slice(index + root.length);
      if (ACCOUNT_SEGMENT_PATTERN.test(remainder)) {
        markers.push(root + "<user>/");
        break;
      }
      index = normalized.indexOf(root, index + root.length);
    }
  }
  return markers;
}

/**
 * Reports whether a package path crosses the public package boundary. The
 * environment-file rule is deliberately based on the case-folded basename so
 * a private file cannot be shipped by changing case or by nesting it below an
 * allowed directory. The exact template file is the only environment file
 * intended for publication. Forbidden basenames and directory names are
 * compared case-insensitively; directory names are checked at every path
 * segment, so moving one below an allowed directory does not bypass the
 * package boundary. On Windows, trailing-dot/space and 8.3-looking components
 * are also rejected because this string-only check cannot safely resolve them.
 */
// Restricted suffixes and ambiguous Win32 alias syntax fail before metadata inspection.
export function isForbiddenPackagePath(path, platform = process.platform) {
  if (typeof path !== "string") return false;
  if (hasUnsupportedWindowsPathAlias(path, platform)) return true;
  const normalized = path
    .replaceAll("\\", "/")
    .replace(/\/+/g, "/")
    .replace(/\/+$/, "");
  const basename = normalized.slice(normalized.lastIndexOf("/") + 1);
  const foldedBasename = basename.toLowerCase();
  if (
    foldedBasename === ".env" ||
    (foldedBasename.startsWith(".env.") && basename !== ENVIRONMENT_TEMPLATE)
  ) {
    return true;
  }
  if (hasRestrictedPolicyPathSuffix(normalized, platform)) return true;
  if (FORBIDDEN_EXACT.has(foldedBasename) || foldedBasename.endsWith(".ds_store")) {
    return true;
  }
  if (
    normalized
      .split("/")
      .some((segment) => FORBIDDEN_PREFIXES.has(segment.toLowerCase() + "/"))
  ) {
    return true;
  }
  return FORBIDDEN_PATTERNS.some((pattern) => pattern.test(normalized));
}

/**
 * Reports whether an archive or package path is unsafe to resolve. Windows
 * drive paths, UNC paths, absolute paths, parent traversal, and backslashes
 * are rejected before any filesystem or archive access.
 */
function isUnsafePath(path) {
  if (typeof path !== "string" || path.length === 0) return true;
  const normalized = path.replaceAll("\\", "/");
  return (
    isAbsolute(path) ||
    WINDOWS_DRIVE_PATH.test(normalized) ||
    WINDOWS_UNC_PATH.test(normalized) ||
    path.startsWith("./") ||
    path.split("/").includes("..") ||
    path.includes("\\")
  );
}

/**
 * Reports whether a path contains a NUL byte. Filesystem and archive APIs
 * treat NUL as a string terminator, so a path containing one cannot be
 * resolved consistently. The package boundary rejects it before file access.
 */
function containsNulByte(path) {
  return path.includes("\u0000");
}

function declaredEntryPoints(manifest) {
  const declared = [];
  if (typeof manifest?.main === "string") declared.push(manifest.main);
  for (const target of Object.values(manifest?.bin ?? {})) {
    if (typeof target === "string") declared.push(target);
  }
  return [...new Set(declared.map((value) => value.replace(/^\.\//, "")))];
}

/**
 * Compares the entries npm would publish against the package manifest. Only
 * path metadata is inspected, so the caller can decide which files to read.
 * NUL bytes are rejected before normalization because downstream filesystem
 * calls would otherwise fail only after the package boundary accepted the
 * entry.
 */
export function evaluatePackageBoundary({ entries, manifest, platform = process.platform }) {
  const blockers = [];
  const normalized = [];
  for (const entry of entries) {
    const path = typeof entry === "string" ? entry : entry?.path;
    if (typeof path === "string" && containsNulByte(path)) {
      blockers.push("NUL byte in package path: " + JSON.stringify(path));
      continue;
    }
    if (isUnsafePath(path)) {
      blockers.push("unsafe package path: " + String(path));
      continue;
    }
    if (hasUnsupportedWindowsPathAlias(path, platform)) {
      blockers.push("unsupported Windows path alias syntax: " + path);
      continue;
    }
    if (isForbiddenPackagePath(path, platform)) {
      blockers.push("forbidden package path: " + path);
      continue;
    }
    normalized.push(path);
  }
  for (const declared of declaredEntryPoints(manifest)) {
    if (containsNulByte(declared)) {
      blockers.push("NUL byte in declared entry point: " + JSON.stringify(declared));
      continue;
    }
    if (!normalized.includes(declared)) {
      blockers.push("declared entry point missing from package: " + declared);
    }
  }
  return {
    ok: blockers.length === 0,
    entries: normalized,
    entry_count: normalized.length,
    declared_entry_points: declaredEntryPoints(manifest),
    blockers
  };
}

/**
 * Opens a checked file and verifies the descriptor still identifies the same
 * singly linked regular file before reading. It then streams fixed-size chunks
 * and reports home-directory markers. The carry keeps the longest account root
 * intact across a chunk boundary. A NUL byte marks content that cannot be
 * inspected as text; the caller rejects such files instead of skipping the
 * remaining chunks. Every chunk is still searched so a NUL byte cannot hide a
 * path in the same file.
 */
async function inspectPackedFileText(absolute, relativePath, expected, openPath = open) {
  const handle = await openPath(absolute, PACKAGE_READ_FLAGS);
  const found = new Set();
  let hasNul = false;
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 ||
        opened.dev !== expected.dev || opened.ino !== expected.ino) {
      throw new Error(
        "Package file changed or is multiply linked during inspection: " + relativePath
      );
    }
    const buffer = Buffer.alloc(INSPECT_CHUNK_BYTES);
    let carry = "";
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) return { markers: [...found], has_nul: hasNul };
      const chunk = buffer.subarray(0, bytesRead);
      if (chunk.includes(0)) hasNul = true;
      const window = carry + chunk.toString("latin1");
      for (const marker of findHomePathLeaks(window)) found.add(marker);
      carry = window.slice(-INSPECT_CARRY_BYTES);
    }
  } finally {
    await handle.close();
  }
}

/**
 * Reads one published file and reports path-shaped problems. Restricted policy
 * and private configuration paths never reach this function because the caller
 * filters them out first.
 */
async function inspectPackedFile(root, path, blockers, openPath = open) {
  const absolute = join(root, path);
  const info = await lstat(absolute);
  if (info.isSymbolicLink()) {
    blockers.push("symlink in package: " + path);
    return;
  }
  if (!info.isFile()) {
    blockers.push("non-regular file in package: " + path);
    return;
  }
  if (info.nlink !== 1) {
    blockers.push("multiple hard links in package: " + path);
    return;
  }
  // Stream the whole file so a large packed text file cannot hide a leak. A
  // file containing NUL bytes is rejected because its text cannot be fully
  // inspected for personal paths.
  const inspection = await inspectPackedFileText(absolute, path, info, openPath);
  for (const marker of inspection.markers) {
    blockers.push("home-directory path " + marker + " in package file: " + path);
  }
  if (inspection.has_nul) {
    blockers.push("NUL-byte content in package file: " + path);
  }
}

/**
 * Accepts only literal ASCII package paths. Npm's files field supports glob
 * families that this metadata-only preflight cannot safely expand, including
 * braces, extglobs, wildcards, character classes, and escape syntax.
 */
function hasUnsupportedPackagePathSyntax(path) {
  return !/^[A-Za-z0-9._/-]+$/.test(path);
}

function packageOutput(manifest, blockers, entryCount = 0) {
  return {
    schema_version: 1,
    package: { name: manifest.name, version: manifest.version },
    entry_count: entryCount,
    declared_entry_points: declaredEntryPoints(manifest),
    files_allowlist: Array.isArray(manifest.files) ? manifest.files : null,
    blockers,
    ok: blockers.length === 0
  };
}

async function packageParentBlocker(root, relativePath, lstatPath) {
  const absoluteRoot = resolve(root);
  const absolutePath = resolve(absoluteRoot, relativePath);
  const pathFromRoot = relative(absoluteRoot, absolutePath);
  if (!pathFromRoot || pathFromRoot === ".." ||
      pathFromRoot.startsWith(`..${sep}`) || isAbsolute(pathFromRoot)) {
    return `unsafe package path outside package root: ${relativePath}`;
  }

  const components = pathFromRoot.split(sep);
  let current = root;
  let parentPath = "";
  for (const component of components.slice(0, -1)) {
    current = join(current, component);
    parentPath = parentPath ? `${parentPath}/${component}` : component;
    let info;
    try {
      info = await lstatPath(current);
    } catch (error) {
      if (error?.code === "ENOENT" || error?.code === "ENOTDIR") {
        return `package preflight could not inspect ${relativePath}: ` +
          (error instanceof Error ? error.message : String(error));
      }
      throw error;
    }
    if (info.isSymbolicLink()) return `symlink in package: ${parentPath}`;
    if (!info.isDirectory()) {
      return `package preflight could not inspect ${relativePath}: parent is not a directory`;
    }
  }
  return null;
}

/**
 * Checks package-included path names before npm enumerates package files.
 * Literal file and directory roots are walked with Dirent entries; symlinks and
 * multiply linked regular files present during inspection are rejected before
 * their contents are read or npm enumerates package files. Parent components
 * are checked before final path metadata or directory enumeration. On Windows,
 * trailing-dot/space and 8.3-looking path syntax is rejected before package
 * path metadata is inspected because this static preflight cannot safely
 * identify those filesystem targets.
 * A same-UID process can replace a checked parent before a later filesystem
 * operation; that residual race is accepted by the trusted-local-operator
 * model. Only literal ASCII path characters are accepted because a name-only
 * preflight cannot safely expand npm glob or escape syntax.
 */
async function preflightPackagePaths(root, files, {
  lstatPath = lstat,
  readDirectory = readdir,
  additionalPaths = [],
  platform = process.platform
} = {}) {
  const blockers = [];
  const roots = [];

  async function walkDirectory(relativeDirectory) {
    const absoluteDirectory = join(root, relativeDirectory);
    let children;
    try {
      children = await readDirectory(absoluteDirectory, { withFileTypes: true });
    } catch (error) {
      blockers.push(
        `package preflight could not enumerate ${relativeDirectory}: ` +
          (error instanceof Error ? error.message : String(error))
      );
      return;
    }

    for (const child of children) {
      const relativePath = `${relativeDirectory}/${child.name}`;
      if (hasUnsupportedWindowsPathAlias(relativePath, platform)) {
        blockers.push(`unsupported Windows path alias syntax: ${relativePath}`);
        continue;
      }
      if (isForbiddenPackagePath(relativePath, platform)) {
        blockers.push(`forbidden package path: ${relativePath}`);
        continue;
      }
      if (child.isSymbolicLink()) {
        blockers.push(`symlink in package: ${relativePath}`);
        continue;
      }
      const isDirectory = child.isDirectory();
      if (isDirectory) {
        const absolutePath = join(root, relativePath);
        const info = await lstatPath(absolutePath);
        if (info.isSymbolicLink() || !info.isDirectory()) {
          blockers.push(`unsafe package directory: ${relativePath}`);
          continue;
        }
        await walkDirectory(relativePath);
        continue;
      }
      if (!child.isFile()) {
        blockers.push(`unrecognized package entry type: ${relativePath}`);
        continue;
      }
      const absolutePath = join(root, relativePath);
      const info = await lstatPath(absolutePath);
      if (info.isSymbolicLink() || !info.isFile()) {
        blockers.push(`unsafe package file: ${relativePath}`);
        continue;
      }
      if (info.nlink !== 1) {
        blockers.push(`multiple hard links in package: ${relativePath}`);
      }
    }
  }

  if (!Array.isArray(files) || files.length === 0) {
    return ["package.json must declare a files allowlist"];
  }

  const pathEntries = [
    ...files.map((path) => ({ path, kind: "files" })),
    ...additionalPaths.map((path) => ({ path, kind: "entry point" }))
  ];
  const seenRoots = new Set();
  for (const { path, kind } of pathEntries) {
    if (typeof path !== "string" || path.length === 0) {
      const label = kind === "files" ? "package files entry" : "declared entry point";
      blockers.push(`invalid ${label}: ${String(path)}`);
      continue;
    }
    const label = kind === "files" ? "package files entry" : "declared entry point";
    if (containsNulByte(path)) {
      const subject = kind === "files" ? "package path" : "declared entry point";
      blockers.push(`NUL byte in ${subject}: ${JSON.stringify(path)}`);
      continue;
    }
    if (hasUnsupportedWindowsPathAlias(path, platform)) {
      blockers.push(`unsupported Windows path alias syntax: ${path}`);
      continue;
    }
    if (isForbiddenPackagePath(path, platform)) {
      blockers.push(`forbidden package path: ${path}`);
      continue;
    }
    if (isUnsafePath(path)) {
      blockers.push(`unsafe ${label}: ${String(path)}`);
      continue;
    }
    if (hasUnsupportedPackagePathSyntax(path)) {
      blockers.push(`unsupported package path syntax before pack: ${path}`);
      continue;
    }
    const relativePath = path.replace(/\/+$/, "");
    if (!relativePath || relativePath.split("/").some((segment) => segment === "" || segment === "." || segment === "..")) {
      const label = kind === "files" ? "package files entry" : "declared entry point";
      blockers.push(`unsafe ${label}: ${path}`);
      continue;
    }
    if (!seenRoots.has(relativePath)) {
      seenRoots.add(relativePath);
      roots.push(relativePath);
    }
  }

  // Validate every manifest path before inspecting metadata for any package root.
  if (blockers.length > 0) return blockers;

  for (const relativePath of roots) {
    const parentBlocker = await packageParentBlocker(root, relativePath, lstatPath);
    if (parentBlocker) {
      blockers.push(parentBlocker);
      continue;
    }
    let info;
    try {
      info = await lstatPath(join(root, relativePath));
    } catch (error) {
      if (error?.code === "ENOENT" || error?.code === "ENOTDIR") {
        blockers.push(
          `package preflight could not inspect ${relativePath}: ` +
            (error instanceof Error ? error.message : String(error))
        );
        continue;
      }
      throw error;
    }
    if (info.isSymbolicLink()) {
      blockers.push(`symlink in package: ${relativePath}`);
      continue;
    }
    if (info.isDirectory()) {
      await walkDirectory(relativePath);
    } else if (!info.isFile()) {
      blockers.push(`non-regular package root: ${relativePath}`);
    } else if (info.nlink !== 1) {
      blockers.push(`multiple hard links in package: ${relativePath}`);
    }
  }

  return blockers;
}

async function runNpmPackDryRun(root, execFilePath = execFileAsync) {
  return execFilePath(
    "npm",
    ["pack", "--json", "--dry-run", "--ignore-scripts"],
    {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      timeout: NPM_PACK_TIMEOUT_MS
    }
  );
}

/**
 * Rejects a preexisting symlink or non-directory anywhere along the absolute
 * path to the package root. This static component walk does not prevent a
 * same-UID process from replacing a checked parent before a later operation.
 */
async function assertPackageRootIsRealDirectory(root, lstatPath) {
  const absoluteRoot = resolve(root);
  const filesystemRoot = parse(absoluteRoot).root;
  const components = relative(filesystemRoot, absoluteRoot)
    .split(sep)
    .filter(Boolean);
  let current = filesystemRoot;
  const rootInfo = await lstatPath(current);
  if (rootInfo.isSymbolicLink()) {
    throw new Error("symlink in package root path: filesystem root");
  }
  if (!rootInfo.isDirectory()) {
    const error = new Error("package root path is not a directory.");
    error.code = "ENOTDIR";
    throw error;
  }

  for (const component of components) {
    current = join(current, component);
    const info = await lstatPath(current);
    if (info.isSymbolicLink()) {
      const relativePath = relative(filesystemRoot, current) || ".";
      throw new Error(`symlink in package root path: ${relativePath}`);
    }
    if (!info.isDirectory()) {
      const error = new Error(`package root path is not a directory: ${current}`);
      error.code = "ENOTDIR";
      throw error;
    }
  }
}

export async function checkPackageHygiene({
  root = process.cwd(),
  platform = process.platform,
  lstatPath = lstat,
  readFilePath = readFile,
  readDirectory = readdir,
  openPath = open,
  execFilePath = execFileAsync,
  packPackage = (packageRoot) => runNpmPackDryRun(packageRoot, execFilePath)
} = {}) {
  if (hasUnsupportedWindowsPathAlias(root, platform)) {
    throw new Error("Package root uses unsupported Windows path alias syntax.");
  }
  root = resolve(root);
  await assertPackageRootIsRealDirectory(root, lstatPath);
  const manifestPath = join(root, "package.json");
  const manifestInfo = await lstatPath(manifestPath);
  if (manifestInfo.isSymbolicLink()) {
    throw new Error("package.json must not be a symbolic link.");
  }
  if (!manifestInfo.isFile()) throw new Error("package.json is not a file.");
  if (manifestInfo.nlink !== 1) {
    throw new Error("package.json must not have multiple hard links.");
  }
  const manifest = JSON.parse(await readFilePath(manifestPath, {
    encoding: "utf8",
    flag: PACKAGE_READ_FLAGS
  }));
  const preflightBlockers = await preflightPackagePaths(root, manifest.files, {
    lstatPath,
    readDirectory,
    additionalPaths: declaredEntryPoints(manifest),
    platform
  });
  if (preflightBlockers.length > 0) {
    return packageOutput(manifest, preflightBlockers);
  }

  const listed = await packPackage(root);
  const report = JSON.parse(listed.stdout)[0];
  const result = evaluatePackageBoundary({
    entries: report.files ?? [],
    manifest,
    platform
  });
  const blockers = [...result.blockers];
  for (const path of result.entries) {
    await inspectPackedFile(root, path, blockers, openPath);
  }
  return packageOutput(manifest, blockers, result.entry_count);
}

async function main() {
  const output = await checkPackageHygiene();
  process.stdout.write(JSON.stringify(output, null, 2) + "\n");
  if (!output.ok) process.exitCode = 1;
}

if (process.argv[1] &&
    await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    process.stderr.write(
      "Package hygiene check failed: " +
        (error instanceof Error ? error.message : String(error)) +
        "\n"
    );
    process.exitCode = 1;
  });
}
