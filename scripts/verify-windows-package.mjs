import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import process from "node:process";
import { basename, join, resolve } from "node:path";
import { fileURLToPath, URL } from "node:url";
import { gunzipSync } from "node:zlib";

const require = createRequire(import.meta.url);
const { sync: spawnSync } = require("cross-spawn");

const expectedFiles = [
  "package/LICENSE",
  "package/README.md",
  "package/dist/cli/connect-gpt.js",
  "package/dist/server.js",
  "package/dist/windows-process-host.exe",
  "package/package.json"
];
const windowsHostPath = "package/dist/windows-process-host.exe";
const projectRoot = resolve(fileURLToPath(new URL("../", import.meta.url)));

try {
  await verifyWindowsPackage();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
}

async function verifyWindowsPackage() {
  const buildHostPath = join(projectRoot, "dist", "windows-process-host.exe");
  const buildHost = await readFile(buildHostPath);
  if (buildHost.byteLength === 0) {
    throw new Error("The built Windows process host is empty.");
  }
  const buildHostSha256 = sha256(buildHost);
  const packageDirectory = await mkdtemp(join(tmpdir(), "gpt-repo-mcp-windows-package-"));
  let verificationError;

  try {
    const packResult = spawnSync(
      "npm",
      ["pack", "--json", "--pack-destination", packageDirectory],
      { cwd: projectRoot, encoding: "utf8", windowsHide: true }
    );
    if (packResult.error) throw packResult.error;
    if (packResult.status !== 0) {
      throw new Error(
        `npm pack --json failed with status ${String(packResult.status)}: ${packResult.stderr.trim()}`
      );
    }

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

    const archivePath = join(packageDirectory, packageMetadata.filename);
    const archive = await readFile(archivePath);
    const entries = readTarGzip(archive);
    assertExpectedInventory(entries);

    const packedHost = entries.find(({ path }) => path === windowsHostPath)?.contents;
    if (!packedHost || packedHost.byteLength === 0) {
      throw new Error(`${windowsHostPath} is missing or empty in the npm archive.`);
    }

    const packedHostSha256 = sha256(packedHost);
    if (packedHostSha256 !== buildHostSha256) {
      throw new Error(
        `Packaged Windows process host hash mismatch: built=${buildHostSha256}, packed=${packedHostSha256}.`
      );
    }

    const packageFiles = entries.map(({ path }) => path.slice("package/".length)).sort();
    process.stdout.write([
      `Verified ${packageMetadata.name}@${packageMetadata.version}:`,
      `  files: ${packageFiles.join(", ")}`,
      `  Windows process host: ${packedHost.byteLength} bytes SHA-256 ${packedHostSha256}`
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

function assertExpectedInventory(entries) {
  const actualFiles = entries.map(({ path }) => path).sort();
  const expected = [...expectedFiles].sort();
  const expectedSet = new Set(expected);
  const seen = new Set();
  const missing = expected.filter((path) => !actualFiles.includes(path));
  const extra = [];
  for (const path of actualFiles) {
    if (!expectedSet.has(path) || seen.has(path)) extra.push(path);
    seen.add(path);
  }
  if (missing.length > 0 || extra.length > 0 || actualFiles.length !== expected.length) {
    throw new Error(
      `npm archive inventory mismatch; missing=[${missing.join(", ")}], extra=[${extra.join(", ")}].`
    );
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
