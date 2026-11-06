import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import process from "node:process";
import { basename, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL, URL } from "node:url";
import { promisify } from "node:util";
import { gunzipSync } from "node:zlib";

const execFileAsync = promisify(execFile);
const COMMAND_TIMEOUT_MS = 120_000;
const OUTPUT_LIMIT_BYTES = 1_048_576;
const COMMON_ENTRIES = [
  "package/LICENSE",
  "package/README.md",
  "package/dist/cli/connect-gpt.js",
  "package/dist/server.js",
  "package/package.json"
];
const WINDOWS_HELPER_ENTRY = "package/dist/windows-process-host.exe";
const projectRoot = resolve(fileURLToPath(new URL("../", import.meta.url)));

export function verifyPackageArchiveInventory(entries, platform = process.platform) {
  const expected = [...COMMON_ENTRIES, ...(platform === "win32" ? [WINDOWS_HELPER_ENTRY] : [])].sort();
  const expectedSet = new Set(expected);
  const actual = [...entries].sort();
  const seen = new Set();
  const missing = expected.filter((entry) => !actual.includes(entry));
  const unexpected = [];
  const duplicates = [];

  for (const entry of actual) {
    if (!expectedSet.has(entry)) unexpected.push(entry);
    if (seen.has(entry)) duplicates.push(entry);
    seen.add(entry);
  }

  if (missing.length || unexpected.length || duplicates.length) {
    throw new Error([
      missing.length ? `Missing package entries: ${missing.join(", ")}.` : "",
      unexpected.length ? `Unexpected package entries: ${unexpected.join(", ")}.` : "",
      duplicates.length ? `Duplicate package entries: ${duplicates.join(", ")}.` : ""
    ].filter(Boolean).join(" "));
  }
}

async function verifyPackageArchive() {
  const npmCliPath = process.env.npm_execpath;
  if (!npmCliPath || !isAbsolute(npmCliPath) || basename(npmCliPath).toLowerCase() !== "npm-cli.js") {
    throw new Error("Run this check as an npm script so it can use the active Node executable and npm CLI.");
  }

  const packageDirectory = await mkdtemp(join(tmpdir(), "gpt-repo-mcp-package-"));
  let verificationError;

  try {
    const npmCliInfo = await lstat(npmCliPath);
    if (!npmCliInfo.isFile() || npmCliInfo.isSymbolicLink()) {
      throw new Error("The active npm CLI must be a regular, non-symlink file.");
    }

    const packResult = await execFileAsync(
      process.execPath,
      [npmCliPath, "pack", "--json", "--pack-destination", packageDirectory],
      {
        cwd: projectRoot,
        encoding: "utf8",
        timeout: COMMAND_TIMEOUT_MS,
        maxBuffer: OUTPUT_LIMIT_BYTES,
        windowsHide: true
      }
    );
    let packMetadata;
    try {
      packMetadata = JSON.parse(packResult.stdout);
    } catch (error) {
      throw new Error("npm pack --json returned invalid JSON.", { cause: error });
    }
    if (!Array.isArray(packMetadata) || packMetadata.length !== 1) {
      throw new Error("npm pack --json must report exactly one package archive.");
    }

    const [packageMetadata] = packMetadata;
    if (
      typeof packageMetadata.filename !== "string" ||
      !packageMetadata.filename.endsWith(".tgz") ||
      basename(packageMetadata.filename) !== packageMetadata.filename
    ) {
      throw new Error("npm pack --json returned an unsafe archive filename.");
    }

    const archivePath = resolve(packageDirectory, packageMetadata.filename);
    if (!archivePath.startsWith(`${resolve(packageDirectory)}${process.platform === "win32" ? "\\" : "/"}`)) {
      throw new Error("npm pack returned an archive outside its temporary directory.");
    }
    const archiveInfo = await lstat(archivePath);
    if (!archiveInfo.isFile() || archiveInfo.isSymbolicLink() || archiveInfo.nlink !== 1) {
      throw new Error("npm pack did not create a singly linked regular archive file.");
    }

    const archive = await readFile(archivePath);
    const entries = readTarGzip(archive);
    verifyPackageArchiveInventory(entries.map(({ path }) => path));

    let helperDigest;
    if (process.platform === "win32") {
      const buildHostPath = join(projectRoot, "dist", "windows-process-host.exe");
      const buildHost = await readFile(buildHostPath);
      if (buildHost.byteLength === 0) {
        throw new Error("The built Windows process host is empty.");
      }

      const packedHost = entries.find(({ path }) => path === WINDOWS_HELPER_ENTRY)?.contents;
      if (!packedHost || packedHost.byteLength === 0) {
        throw new Error(`${WINDOWS_HELPER_ENTRY} is missing or empty in the npm archive.`);
      }

      const buildHostSha256 = sha256(buildHost);
      helperDigest = sha256(packedHost);
      if (helperDigest !== buildHostSha256) {
        throw new Error(
          `Packaged Windows process host hash mismatch: built=${buildHostSha256}, packed=${helperDigest}.`
        );
      }
    }

    const packageFiles = entries.map(({ path }) => path.slice("package/".length)).sort();
    process.stdout.write([
      `Verified ${packageMetadata.name}@${packageMetadata.version}:`,
      `  files: ${packageFiles.join(", ")}`,
      ...(helperDigest ? [`  Windows process host: SHA-256 ${helperDigest}`] : [])
    ].join("\n") + "\n");
  } catch (error) {
    verificationError = error;
  }

  try {
    await rm(packageDirectory, { recursive: true, force: true });
  } catch (cleanupError) {
    if (verificationError) {
      throw new AggregateError([verificationError, cleanupError], "Package verification and cleanup failed.");
    }
    throw cleanupError;
  }

  if (verificationError) throw verificationError;
}

function readTarGzip(compressedArchive) {
  const archive = gunzipSync(compressedArchive);
  const entries = [];
  let offset = 0;
  let foundEndMarker = false;

  while (offset + 512 <= archive.byteLength) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      foundEndMarker = true;
      break;
    }

    const name = readTarString(header, 0, 100);
    const prefix = readTarString(header, 345, 155);
    const path = prefix ? `${prefix}/${name}` : name;
    const sizeText = readTarString(header, 124, 12).trim();
    if (!path || !/^[0-7]+$/.test(sizeText)) {
      throw new Error("The npm archive contains an invalid tar header.");
    }

    const size = Number.parseInt(sizeText, 8);
    if (!Number.isSafeInteger(size)) {
      throw new Error(`The npm archive contains an invalid size for ${path}.`);
    }

    const typeFlag = header[156];
    if (typeFlag !== 0 && typeFlag !== 48) {
      throw new Error(`The npm archive contains a non-file entry: ${path}.`);
    }

    const contentStart = offset + 512;
    const contentEnd = contentStart + size;
    if (contentEnd > archive.byteLength) {
      throw new Error(`The npm archive contains a truncated entry: ${path}.`);
    }

    entries.push({ path, contents: archive.subarray(contentStart, contentEnd) });
    offset = contentStart + Math.ceil(size / 512) * 512;
  }

  if (!foundEndMarker) {
    throw new Error("The npm archive is missing its tar end marker.");
  }
  return entries;
}

function readTarString(header, start, length) {
  const field = header.subarray(start, start + length);
  const end = field.indexOf(0);
  return field.subarray(0, end === -1 ? field.byteLength : end).toString("utf8");
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await verifyPackageArchive().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
