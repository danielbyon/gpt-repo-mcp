import { execFileSync } from "node:child_process";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, sep, resolve } from "node:path";
import process from "node:process";
import { URL } from "node:url";
import { promisify } from "node:util";
import { describe, expect, test, vi } from "vitest";

async function createSyntheticDependencyAudit(root) {
  const executablePath = join(root, "npm-audit-fixture");
  const executableBody = `#!/bin/sh
if [ "$1" = "--version" ]; then echo synthetic-audit-fixture/1; exit 0; fi
if [ "$1" = "audit" ]; then printf '%s\\n' '${syntheticDependencyAuditOutput()}'; exit 0; fi
exit 2
`;
  await writeFile(executablePath, executableBody, { mode: 0o700 });
  return {
    executablePath,
    policy: {
      executable_path: executablePath,
      executable_sha256: sha256(executableBody),
      registry: "https://registry.npmjs.org/",
      timeout_ms: 30_000
    }
  };
}

function isSyntheticDependencyAuditCommand(command) {
  return typeof command === "string" && command.endsWith("/dependency-audit-executable");
}

function syntheticDependencyAuditOutput() {
  return JSON.stringify({
    auditReportVersion: 2,
    vulnerabilities: {},
    metadata: {
      vulnerabilities: {
        info: 0,
        low: 0,
        moderate: 0,
        high: 0,
        critical: 0,
        total: 0
      },
      dependencies: {
        prod: 1,
        dev: 0,
        optional: 0,
        peer: 0,
        peerOptional: 0,
        total: 1
      }
    }
  });
}

const {
  execFileMock,
  openMock,
  pathOperationMock,
  readMock,
  readFileMock
} = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  openMock: vi.fn(),
  pathOperationMock: vi.fn(),
  readMock: vi.fn(),
  readFileMock: vi.fn()
}));

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, execFile: execFileMock };
});

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    lstat: async (path, ...args) => {
      pathOperationMock("lstat", path);
      const override = active?.lstatOverrides?.get(resolve(String(path)));
      if (override) return override;
      return actual.lstat(path, ...args);
    },
    mkdir: async (path, ...args) => {
      pathOperationMock("mkdir", path);
      return actual.mkdir(path, ...args);
    },
    open: async (path, ...args) => {
      openMock(path, ...args);
      const handle = await actual.open(path, ...args);
      return new Proxy(handle, {
        get(target, property) {
          if (property === "read") {
            return (...readArgs) => {
              readMock(path, ...readArgs);
              return target.read(...readArgs);
            };
          }
          if (property === "readFile") {
            return (...readArgs) => {
              readFileMock(path, ...readArgs);
              return target.readFile(...readArgs);
            };
          }
          const value = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    },
    readlink: async (path, ...args) => {
      pathOperationMock("readlink", path);
      return actual.readlink(path, ...args);
    },
    realpath: async (path, ...args) => {
      pathOperationMock("realpath", path);
      const override = active?.realpathOverrides?.get(resolve(String(path)));
      if (override) return override;
      return actual.realpath(path, ...args);
    },
    stat: async (path, ...args) => {
      pathOperationMock("stat", path);
      return actual.stat(path, ...args);
    },
    writeFile: async (path, ...args) => {
      pathOperationMock("writeFile", path);
      return actual.writeFile(path, ...args);
    }
  };
});

let active = null;
const SCAN_INPUT_BYTE_LIMIT = 5 * 1024 * 1024;

function dispatch(command, args, options) {
  active?.processCalls?.push({ command, args: [...args] });
  if (command === "git") {
    active?.gitCalls?.push([...args]);
    const encoding = options?.encoding === "buffer" ? "buffer" : "utf8";
    const stdout = execFileSync("git", args, {
      cwd: options?.cwd,
      env: options?.env,
      encoding,
      maxBuffer: 64 * 1024 * 1024
    });
    return {
      stdout: active?.gitOutputTransform?.(args, stdout) ?? stdout,
      stderr: ""
    };
  }
  if (isSyntheticDependencyAuditCommand(command)) {
    if (args[0] === "--version") return { stdout: "synthetic-audit-fixture/1\n", stderr: "" };
    return { stdout: syntheticDependencyAuditOutput(), stderr: "" };
  }
  if (
    command.endsWith("/gitleaks-fixture") ||
    command.endsWith("/gitleaks-bin")
  ) {
    if (args[0] === "version") {
      return { stdout: "8.30.1\n", stderr: "" };
    }
    if (args[0] === "git" && active?.onHistoryScan) {
      active.onHistoryScan(args);
    }
    const reportPath = args[args.indexOf("--report-path") + 1];
    writeFileSync(reportPath, "[]");
    if (args[0] === "dir" && active?.onCandidateScan) active.onCandidateScan();
    return { stdout: "", stderr: "" };
  }
  throw new Error("unexpected command: " + command + " " + args.join(" "));
}

execFileMock[promisify.custom] = async (command, args, options) => {
  return dispatch(command, args, options);
};

execFileMock.mockImplementation((command, args, options, callback) => {
  try {
    const result = dispatch(command, args, options);
    callback(null, result.stdout, result.stderr);
  } catch (error) {
    callback(error, "", "");
  }
});

const {
  candidateEmailOccurrences,
  historyEmailOccurrences,
  runSecurityScan,
  runSecurityScanRequest
} = await import("../scripts/oss-security-scan.mjs");
const { resolvePublicationRefSet } = await import("../scripts/publication-ref-set.mjs");

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function exportTree(files) {
  const digest = createHash("sha256");
  for (const entry of [...files].sort((left, right) =>
    left.path.localeCompare(right.path)
  )) {
    digest.update(entry.path);
    digest.update("\0");
    digest.update(entry.sha256);
    digest.update("\0");
    digest.update(String(entry.bytes));
    digest.update("\n");
  }
  return digest.digest("hex");
}

function git(root, args, environment = {}) {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, ...environment }
  }).trim();
}

function gitSubcommandIndex(args, subcommand) {
  const changeDirectoryIndex = args.indexOf("-C");
  const commandIndex = changeDirectoryIndex < 0 ? 0 : changeDirectoryIndex + 2;
  return args[commandIndex] === subcommand ? commandIndex : -1;
}

function appendSyntheticHistoryObject(
  args,
  stdout,
  path,
  objectId = "neutral-denied-sentinel-object"
) {
  const commandIndex = gitSubcommandIndex(args, "rev-list");
  if (commandIndex < 0 || args[commandIndex + 1] !== "--objects") return stdout;
  const record = `${objectId} ${path}\n`;
  if (Buffer.isBuffer(stdout)) {
    const separator = stdout.length === 0 || stdout.at(-1) === 0x0a ? "" : "\n";
    return Buffer.concat([stdout, Buffer.from(`${separator}${record}`, "utf8")]);
  }
  const separator = stdout.endsWith("\n") ? "" : "\n";
  return `${stdout}${separator}${record}`;
}

function appendSyntheticTreeEntry(args, stdout, path) {
  const commandIndex = gitSubcommandIndex(args, "ls-tree");
  if (commandIndex < 0 || !args.slice(commandIndex).includes("--")) return stdout;
  const record = Buffer.from(
    `100644 blob neutral-denied-sentinel-object\t${path}\0`,
    "utf8"
  );
  return Buffer.isBuffer(stdout)
    ? Buffer.concat([stdout, record])
    : `${stdout}${record.toString("utf8")}`;
}

function isHistoryTreeCall(args) {
  const commandIndex = gitSubcommandIndex(args, "ls-tree");
  return commandIndex >= 0 &&
    args[commandIndex + 1] === "-r" &&
    !args.slice(commandIndex).includes("--");
}

function appendSyntheticHistoryTreeEntries(args, stdout, entries) {
  if (!isHistoryTreeCall(args)) return stdout;
  const commandIndex = gitSubcommandIndex(args, "ls-tree");
  const namesOnly = args.slice(commandIndex).includes("--name-only");
  const records = entries.map(({ objectId, path }) => namesOnly
    ? `${path}\0`
    : `100644 blob ${objectId}\t${path}\0`
  ).join("");
  const recordBytes = Buffer.from(records, "utf8");
  return Buffer.isBuffer(stdout)
    ? Buffer.concat([stdout, recordBytes])
    : `${stdout}${records}`;
}

function appendSyntheticHistoryTreeEntry(
  args,
  stdout,
  path,
  objectId = "neutral-denied-sentinel-object"
) {
  return appendSyntheticHistoryTreeEntries(args, stdout, [{ objectId, path }]);
}

async function commit(root, message) {
  git(root, ["add", "--all"]);
  git(root, ["commit", "-qm", message], {
    GIT_AUTHOR_EMAIL: "fixture@example.com",
    GIT_COMMITTER_EMAIL: "fixture@example.com"
  });
  return git(root, ["rev-parse", "HEAD"]);
}

async function createFixture(options = {}) {
  const root = await mkdtemp(join(await realpath(tmpdir()), "gpt-repo-post-scan-"));
  try {
    return await createFixtureWithRoot(root, options);
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function createFixtureWithRoot(root, {
  historyBinary = false,
  historyBlobSize,
  sourceEntryPath,
  sourceEntryContent = "neutral denied sentinel\n",
  exportSourceEntry = false,
  moveRef = false,
  setupFailure
} = {}) {
  const dependencyAudit = await createSyntheticDependencyAudit(root);
  await setupFailure?.(root);
  const repo = join(root, "repo");
  const candidate = join(root, "candidate");
  const scanner = join(root, "gitleaks-fixture");
  const exportReportPath = join(root, "export.json");
  let historyBlobCommit;
  await mkdir(repo);
  await mkdir(join(candidate, "node_modules"), { recursive: true });
  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Fixture"]);
  git(repo, ["config", "user.email", "fixture@example.invalid"]);
  const content = "candidate\n";
  const packageJson = JSON.stringify({ name: "fixture", version: "1.0.0" }) + "\n";
  const packageLock =
    JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: { "": { name: "fixture", version: "1.0.0" } }
    }) + "\n";
  await writeFile(join(repo, "README.md"), content);
  await writeFile(join(repo, "package.json"), packageJson);
  await writeFile(join(repo, "package-lock.json"), packageLock);
  if (sourceEntryPath) {
    await mkdir(dirname(join(repo, sourceEntryPath)), { recursive: true });
    await writeFile(join(repo, sourceEntryPath), sourceEntryContent);
  }
  if (historyBinary) {
    await writeFile(join(repo, "binary.dat"), "binary\u0000content");
  }
  await commit(repo, "source");
  if (historyBinary) {
    await rm(join(repo, "binary.dat"));
    await commit(repo, "remove binary");
  }
  let sourceCommit = git(repo, ["rev-parse", "HEAD"]);
  let historyBlobBytes;
  if (historyBlobSize !== undefined) {
    const prefix = Buffer.from("boundary@example.com\n");
    historyBlobBytes = Buffer.concat([prefix, Buffer.alloc(historyBlobSize - prefix.length, 0x78)]);
    await writeFile(join(repo, "history-boundary.txt"), historyBlobBytes);
    historyBlobCommit = await commit(repo, "history email boundary");
    sourceCommit = historyBlobCommit;
  }
  await writeFile(join(repo, "outside.txt"), "outside\n");
  const outside = await commit(repo, "outside");
  git(repo, ["update-ref", "refs/heads/outside", outside]);
  git(repo, ["reset", "-q", "--hard", sourceCommit]);

  await writeFile(join(candidate, "README.md"), content);
  await writeFile(join(candidate, "package.json"), packageJson);
  await writeFile(join(candidate, "package-lock.json"), packageLock);
  if (sourceEntryPath && exportSourceEntry) {
    await mkdir(dirname(join(candidate, sourceEntryPath)), { recursive: true });
    await writeFile(join(candidate, sourceEntryPath), sourceEntryContent);
  }
  if (historyBlobBytes) {
    await writeFile(join(candidate, "history-boundary.txt"), historyBlobBytes);
  }
  await writeFile(scanner, "fixture scanner\n");
  const trustedConfig = join(root, "trusted-gitleaks.toml");
  const trustedIgnore = join(root, "trusted-gitleaksignore");
  const trustedConfigBody = "title = \"post-scan fixture\"\n";
  const trustedIgnoreBody = "";
  await writeFile(trustedConfig, trustedConfigBody);
  await writeFile(trustedIgnore, trustedIgnoreBody);
  const files = [
    { path: "README.md", bytes: Buffer.byteLength(content), sha256: sha256(content) },
    {
      path: "package.json",
      bytes: Buffer.byteLength(packageJson),
      sha256: sha256(packageJson)
    },
    {
      path: "package-lock.json",
      bytes: Buffer.byteLength(packageLock),
      sha256: sha256(packageLock)
    }
  ];
  if (historyBlobBytes) {
    files.push({
      path: "history-boundary.txt",
      bytes: historyBlobBytes.byteLength,
      sha256: sha256(historyBlobBytes)
    });
  }
  if (sourceEntryPath && exportSourceEntry) {
    files.push({
      path: sourceEntryPath,
      bytes: Buffer.byteLength(sourceEntryContent),
      sha256: sha256(sourceEntryContent)
    });
  }
  await writeFile(
    exportReportPath,
    JSON.stringify({ source_commit: sourceCommit, files, tree_sha256: exportTree(files) })
  );

  const policy = {
    schema_version: 1,
    policy_version: "fixture",
    gitleaks: {
      version: "8.30.1",
      assets: {
        [`${process.platform}_${process.arch}`]: {
          binary_sha256: sha256("fixture scanner\n")
        }
      }
    },
    email: {
      allowed_domains: ["example.com"],
      allowed_addresses: [],
      reviewed_public_history_locations: []
    },
    licenses: { allowed: [] },
    dependency_audit: dependencyAudit.policy,
    known_development_advisories: []
  };
  const publication = await resolvePublicationRefSet({
    repoRoot: repo,
    candidate: { kind: "ref", ref: "refs/heads/main" },
    target: { kind: "ref", ref: "refs/heads/main" }
  });

  active = {
    gitCalls: [],
    processCalls: [],
    onCandidateScan: moveRef
      ? () => git(repo, ["update-ref", "refs/heads/main", outside])
      : undefined
  };

  const scan = async (overrides = {}, scanOptions = {}) => runSecurityScan({
    candidateRoot: candidate,
    exportReportPath,
    publicRepo: repo,
    gitleaksBin: scanner,
    gitleaksConfig: {
      path: trustedConfig,
      sha256: sha256(trustedConfigBody)
    },
    gitleaksIgnore: {
      path: trustedIgnore,
      sha256: sha256(trustedIgnoreBody)
    },
    policy,
    policyProvenance: { kind: "synthetic_fixture", fixture_id: "post-scan-guard", policy_sha256: sha256(JSON.stringify(policy)) },
    publication,
    ...overrides
  }, scanOptions);

  return {
    root,
    repo,
    candidate,
    exportReportPath,
    policy,
    historyBlobCommit,
    runRaw: scan,
    run: async () => {
      const result = await scan();
      if (result.status === "INCOMPLETE") {
        const error = new Error(result.reason);
        error.code = result.cause_code;
        throw error;
      }
      return result;
    }
  };
}

async function writeSyntheticScanRequest(
  root,
  publicRepo,
  policyPath,
  filename,
  requestOverrides = {}
) {
  const candidateRef = "refs/heads/main";
  const requestPath = join(root, filename);
  await writeFile(
    requestPath,
    JSON.stringify({
      schema_version: 2,
      public_repo: publicRepo,
      candidate_root: join(root, "candidate"),
      export_report_path: join(root, "export.json"),
      gitleaks_bin: join(root, "gitleaks-fixture"),
      gitleaks_config: {
        path: join(root, "trusted-gitleaks.toml"),
        sha256: sha256("title = \"post-scan fixture\"\n")
      },
      gitleaks_ignore: {
        path: join(root, "trusted-gitleaksignore"),
        sha256: sha256("")
      },
      candidate_ref: candidateRef,
      target_ref: candidateRef,
      policy_path: policyPath,
      policy_source: {
        kind: "synthetic_fixture",
        fixture_id: "guard-test"
      },
      publication: {
        candidate: { kind: "ref", ref: candidateRef },
        target: { kind: "ref", ref: candidateRef }
      },
      ...requestOverrides
    })
  );
  return requestPath;
}

function clearScanIoMocks() {
  openMock.mockClear();
  pathOperationMock.mockClear();
  readMock.mockClear();
  readFileMock.mockClear();
  execFileMock.mockClear();
  if (active?.processCalls) active.processCalls.length = 0;
}

function expectNoFileOperationsFor(path) {
  const expectedPath = resolve(path);
  expect(openMock.mock.calls.some(([observedPath]) =>
    resolve(observedPath) === expectedPath
  )).toBe(false);
  expect(readMock.mock.calls.some(([observedPath]) =>
    resolve(observedPath) === expectedPath
  )).toBe(false);
  expect(readFileMock.mock.calls.some(([observedPath]) =>
    resolve(observedPath) === expectedPath
  )).toBe(false);
  expect(pathOperationMock.mock.calls.some(([, observedPath]) =>
    typeof observedPath === "string" && resolve(observedPath) === expectedPath
  )).toBe(false);
}

describe("post-scan publication guard", () => {
  test("bounds and verifies tag metadata snapshot revalidation", () => {
    const scannerSource = readFileSync(
      new URL("../scripts/oss-security-scan.mjs", import.meta.url),
      "utf8"
    );
    const captureSource = readFileSync(
      new URL("../scripts/publication-ref-set.mjs", import.meta.url),
      "utf8"
    );
    const captureBound = captureSource.match(
      /const MAX_TAG_OBJECT_BYTES = [^;]+;/
    )?.[0];
    const scannerBound = scannerSource.match(
      /const MAX_SCANNER_INPUT_BYTES = [^;]+;/
    )?.[0]?.replace("MAX_SCANNER_INPUT_BYTES", "MAX_TAG_OBJECT_BYTES");
    expect(captureBound).toBeDefined();
    expect(scannerBound).toBe(captureBound);

    const revalidationStart = scannerSource.indexOf(
      "const snapshotBytes = await readSnapshotBytes("
    );
    const revalidationEnd = scannerSource.indexOf(
      "const after = await readPublicationTagMetadata(repoRoot, tagObjects);",
      revalidationStart
    );
    expect(revalidationStart).toBeGreaterThanOrEqual(0);
    expect(revalidationEnd).toBeGreaterThan(revalidationStart);
    const revalidation = scannerSource.slice(revalidationStart, revalidationEnd);
    expect(revalidation).toContain("MAX_SCANNER_INPUT_BYTES");
    expect(revalidation).not.toContain("Number.MAX_SAFE_INTEGER");
    expect(revalidation).toMatch(
      /if \(!snapshotBytes\.equals\(entry\.bytes\)\) \{\s*throw new Error\(/
    );

    const snapshotReadStart = scannerSource.indexOf(
      "async function readSnapshotBytes("
    );
    const snapshotReadEnd = scannerSource.indexOf(
      "async function writeTaskLocalSnapshot(",
      snapshotReadStart
    );
    const snapshotRead = scannerSource.slice(snapshotReadStart, snapshotReadEnd);
    expect(snapshotRead).toContain(
      "readBoundedHandleBytes(handle, label, maxBytes)"
    );
    expect(snapshotRead).toMatch(
      /if \(info\.size > maxBytes\) \{\s*throw new Error\(/
    );
    expect(snapshotRead).toMatch(
      /if \(bytes\.byteLength !== info\.size\) \{\s*throw new Error\(/
    );
    expect(snapshotRead).not.toContain("handle.readFile()");

    const boundedReadStart = scannerSource.indexOf(
      "async function readBoundedHandleBytes("
    );
    const boundedReadEnd = scannerSource.indexOf(
      "async function readSnapshotBytes(",
      boundedReadStart
    );
    const boundedRead = scannerSource.slice(boundedReadStart, boundedReadEnd);
    expect(boundedRead).toContain("Buffer.allocUnsafe(maxBytes + 1)");
    expect(boundedRead).toMatch(
      /if \(offset > maxBytes\) \{\s*throw new Error\(/
    );

    expect(captureSource).toContain("tagSize > MAX_TAG_OBJECT_BYTES");
    expect(captureSource).toContain(
      '["cat-file", "tag", tag.object_sha]'
    );
    expect(captureSource).toContain("bytes.byteLength !== tagSize");
    expect(captureSource).toContain("outputBytes > MAX_GIT_OUTPUT_BYTES");
  });

  test("removes the temp root when fixture setup throws before returning a handle", async () => {
    let fixtureRoot;
    let fixture;
    try {
      await expect(
        createFixture({
          setupFailure: (root) => {
            fixtureRoot = root;
            throw new Error("injected fixture setup failure");
          }
        }).then((created) => {
          fixture = created;
          return created;
        })
      ).rejects.toThrow("injected fixture setup failure");
      expect(fixtureRoot).toBeDefined();
      expect(existsSync(fixtureRoot)).toBe(false);
    } finally {
      if (fixture) await rm(fixture.root, { recursive: true, force: true });
    }
  });


  test("scans a history email blob at the exact 5 MiB limit", async () => {
    const fixture = await createFixture({ historyBlobSize: 5 * 1024 * 1024 });
    try {
      const blob = git(fixture.repo, [
        "rev-parse",
        `${fixture.historyBlobCommit}:history-boundary.txt`
      ]);
      expect(Number(git(fixture.repo, ["cat-file", "-s", blob]))).toBe(5 * 1024 * 1024);
      const coverage = {};
      const occurrences = await historyEmailOccurrences(fixture.repo, {
        commits: [fixture.historyBlobCommit]
      }, { coverage });
      expect(occurrences.some((entry) =>
        entry.location.source === "git_blob" && entry.address === "boundary@example.com"
      )).toBe(true);
      expect(coverage.blobs_skipped_large).toBe(0);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  }, 30_000);

  test("returns NOT_RUN before any process call when dependency_audit policy is missing", async () => {
    const fixture = await createFixture();
    try {
      const policy = { ...fixture.policy };
      delete policy.dependency_audit;
      execFileMock.mockClear();
      active.processCalls.length = 0;
      const result = await fixture.runRaw({
        policy,
        policyProvenance: {
          kind: "synthetic_fixture",
          fixture_id: "post-scan-guard",
          policy_sha256: sha256(JSON.stringify(policy))
        }
      });

      expect(result).toMatchObject({
        status: "NOT_RUN",
        scanner_invoked: false,
        scanner_clean: false,
        publication_eligible: false,
        ok: false
      });
      expect(execFileMock).not.toHaveBeenCalled();
      expect(active.processCalls).toEqual([]);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("bounds request JSON before parsing and returns sanitized NOT_RUN", async () => {
    const fixture = await createFixture();
    try {
      const requestPath = join(fixture.root, "oversized-request.json");
      await writeFile(
        requestPath,
        Buffer.alloc(SCAN_INPUT_BYTE_LIMIT + 1, 0x20)
      );
      openMock.mockClear();
      readMock.mockClear();
      readFileMock.mockClear();
      execFileMock.mockClear();
      active.processCalls.length = 0;

      const result = await runSecurityScanRequest(requestPath);

      expect(result).toMatchObject({
        status: "NOT_RUN",
        scanner_invoked: false,
        ok: false
      });
      expect(result.reason).toBe(
        "The scan request could not be validated or required inputs were unavailable."
      );
      expect(JSON.stringify(result)).not.toContain(requestPath);
      expect(readMock.mock.calls.some(([path]) => resolve(path) === resolve(requestPath))).toBe(false);
      expect(readFileMock.mock.calls.some(([path]) => resolve(path) === resolve(requestPath))).toBe(false);
      expect(execFileMock).not.toHaveBeenCalled();
      expect(active.processCalls).toEqual([]);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("bounds synthetic policy JSON before parsing and returns sanitized NOT_RUN", async () => {
    const fixture = await createFixture();
    try {
      const policyPath = join(fixture.root, "oversized-policy.json");
      await writeFile(
        policyPath,
        Buffer.alloc(SCAN_INPUT_BYTE_LIMIT + 1, 0x20)
      );
      const requestPath = await writeSyntheticScanRequest(
        fixture.root,
        fixture.repo,
        policyPath,
        "oversized-policy-request.json"
      );
      openMock.mockClear();
      readMock.mockClear();
      readFileMock.mockClear();
      execFileMock.mockClear();
      active.processCalls.length = 0;

      const result = await runSecurityScanRequest(requestPath);
      const openedPaths = openMock.mock.calls.map(([path]) => resolve(path));

      expect(result).toMatchObject({
        status: "NOT_RUN",
        scanner_invoked: false,
        ok: false
      });
      expect(result.reason).toBe(
        "The scan request could not be validated or required inputs were unavailable."
      );
      expect(JSON.stringify(result)).not.toContain(policyPath);
      expect(openedPaths).toContain(resolve(await realpath(policyPath)));
      expect(readMock.mock.calls.some(([path]) => resolve(path) === resolve(policyPath))).toBe(false);
      expect(readFileMock.mock.calls.some(([path]) => resolve(path) === resolve(policyPath))).toBe(false);
      expect(execFileMock).not.toHaveBeenCalled();
      expect(active.processCalls).toEqual([]);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects the restricted policy path as a request before opening or reading it", async () => {
    const fixture = await createFixture();
    try {
      const restrictedPath = join(
        fixture.root,
        "path-fixtures",
        "security",
        "oss-security-policy.json"
      );
      clearScanIoMocks();

      const result = await runSecurityScanRequest(restrictedPath);

      expect(result).toMatchObject({
        status: "NOT_RUN",
        scanner_invoked: false,
        ok: false
      });
      expectNoFileOperationsFor(restrictedPath);
      expect(JSON.stringify(result)).not.toContain(restrictedPath);
      expect(execFileMock).not.toHaveBeenCalled();
      expect(active.processCalls).toEqual([]);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects an ASCII case-variant restricted policy path before opening or reading it", async () => {
    const fixture = await createFixture();
    try {
      const caseVariantPath = join(
        fixture.root,
        "path-fixtures",
        "Security",
        "OSS-SECURITY-POLICY.JSON"
      );
      clearScanIoMocks();

      const result = await runSecurityScanRequest(caseVariantPath);

      expect(result).toMatchObject({
        status: "NOT_RUN",
        scanner_invoked: false,
        ok: false
      });
      expectNoFileOperationsFor(caseVariantPath);
      expect(JSON.stringify(result)).not.toContain(caseVariantPath);
      expect(execFileMock).not.toHaveBeenCalled();
      expect(active.processCalls).toEqual([]);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  const restrictedRequestPathFields = [
    ["candidate_root", (path) => ({ candidate_root: path })],
    ["export_report_path", (path) => ({ export_report_path: path })],
    ["public_repo", (path) => ({ public_repo: path })],
    ["gitleaks binary path", (path) => ({ gitleaks_bin: path })],
    ["gitleaks_config.path", (path) => ({
      gitleaks_config: { path, sha256: "0".repeat(64) }
    })],
    ["gitleaks_ignore.path", (path) => ({
      gitleaks_ignore: { path, sha256: "0".repeat(64) }
    })],
    ["policy_path", (path) => ({ policy_path: path })]
  ];

  for (const [index, [label, requestOverride]] of restrictedRequestPathFields.entries()) {
    test(`rejects restricted ${label} before file access`, async () => {
      const fixture = await createFixture();
      try {
        const restrictedPath = join(
          fixture.root,
          "path-fixtures",
          "Security",
          "OSS-SECURITY-POLICY.JSON"
        );
        const requestPath = await writeSyntheticScanRequest(
          fixture.root,
          fixture.repo,
          join(fixture.root, "unused-synthetic-policy.json"),
          `restricted-request-field-${index}.json`,
          requestOverride(restrictedPath)
        );
        clearScanIoMocks();

        const result = await runSecurityScanRequest(requestPath);

        expect(result).toMatchObject({
          status: "NOT_RUN",
          scanner_invoked: false,
          ok: false
        });
        expectNoFileOperationsFor(restrictedPath);
        expect(JSON.stringify(result)).not.toContain(restrictedPath);
        expect(execFileMock).not.toHaveBeenCalled();
        expect(active.processCalls).toEqual([]);
      } finally {
        active = null;
        await rm(fixture.root, { recursive: true, force: true });
      }
    });
  }

  test("rejects an export report reached through a restricted parent alias before file access", async () => {
    const fixture = await createFixture();
    try {
      const securityDirectory = join(fixture.repo, "security");
      const restrictedPath = join(
        securityDirectory,
        "oss-security-policy.json"
      );
      const aliasDirectory = join(fixture.root, "policy-alias");
      const aliasPath = join(aliasDirectory, "oss-security-policy.json");
      await mkdir(aliasDirectory);
      active.realpathOverrides = new Map([
        [resolve(aliasDirectory), securityDirectory]
      ]);
      const requestPath = await writeSyntheticScanRequest(
        fixture.root,
        fixture.repo,
        join(fixture.root, "unused-synthetic-policy.json"),
        "restricted-export-alias-request.json",
        { export_report_path: aliasPath }
      );
      clearScanIoMocks();

      const result = await runSecurityScanRequest(requestPath);

      expect(result).toMatchObject({
        status: "NOT_RUN",
        scanner_invoked: false,
        ok: false
      });
      expectNoFileOperationsFor(aliasPath);
      expectNoFileOperationsFor(restrictedPath);
      expect(execFileMock).not.toHaveBeenCalled();
      expect(active.processCalls).toEqual([]);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects a case-variant candidate policy path before file access", async () => {
    const fixture = await createFixture();
    try {
      const caseVariantPath = "SeCuRiTy/OSS-SECURITY-POLICY.JSON";
      const syntheticBlob = "f".repeat(40);
      const originalReport = JSON.parse(
        readFileSync(fixture.exportReportPath, "utf8")
      );
      const files = [
        ...originalReport.files,
        { path: caseVariantPath, bytes: 0, sha256: sha256("") }
      ];
      const reportPath = join(fixture.root, "case-variant-export.json");
      await writeFile(reportPath, JSON.stringify({
        ...originalReport,
        files,
        tree_sha256: exportTree(files)
      }));
      active.gitOutputTransform = (args, stdout) => {
        if (gitSubcommandIndex(args, "ls-tree") < 0) return stdout;
        const tree = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
        const entry = Buffer.from(args.includes("--name-only")
          ? `${caseVariantPath}\0`
          : `100644 blob ${syntheticBlob}\t${caseVariantPath}\0`
        );
        return Buffer.concat([tree, entry]);
      };
      clearScanIoMocks();

      const result = await fixture.runRaw({ exportReportPath: reportPath });
      const candidateAlias = join(
        fixture.candidate,
        ...caseVariantPath.split("/")
      );

      expect(result).toMatchObject({
        status: "INCOMPLETE",
        scanner_invoked: true,
        code: "MANDATORY_SCAN_INCOMPLETE"
      });
      expectNoFileOperationsFor(join(fixture.candidate, "SeCuRiTy"));
      expectNoFileOperationsFor(candidateAlias);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects normalized and symlinked synthetic policy paths before opening them", async () => {
    const fixture = await createFixture();
    try {
      const restrictedPath = join(
        fixture.repo,
        "security",
        "oss-security-policy.json"
      );
      const normalizedPath =
        fixture.repo + sep + "security" + sep + "extra" + sep + ".." +
        sep + "oss-security-policy.json";
      const aliasPath = join(fixture.root, "policy-alias.json");
      active.lstatOverrides = new Map([
        [resolve(aliasPath), {
          isSymbolicLink: () => true,
          isFile: () => false,
          isDirectory: () => false,
          nlink: 1,
          dev: 1,
          ino: 2,
          size: 0
        }]
      ]);

      for (const [index, policyPath] of [normalizedPath, aliasPath].entries()) {
        const requestPath = await writeSyntheticScanRequest(
          fixture.root,
          fixture.repo,
          policyPath,
          "restricted-policy-request-" + index + ".json"
        );
        openMock.mockClear();
        readMock.mockClear();
        readFileMock.mockClear();
        execFileMock.mockClear();
        active.processCalls.length = 0;

        const result = await runSecurityScanRequest(requestPath);
        const openedPaths = openMock.mock.calls.map(([path]) => resolve(path));

        expect(result).toMatchObject({
          status: "NOT_RUN",
          scanner_invoked: false,
          ok: false
        });
        expect(result.reason).toBe(
          "The scan request could not be validated or required inputs were unavailable."
        );
        expect(JSON.stringify(result)).not.toContain(restrictedPath);
        expect(openedPaths).toContain(resolve(await realpath(requestPath)));
        expect(openedPaths).not.toContain(resolve(restrictedPath));
        expect(openedPaths).not.toContain(resolve(aliasPath));
        expect(readMock.mock.calls.some(([path]) =>
          resolve(path) === resolve(restrictedPath) || resolve(path) === resolve(aliasPath)
        )).toBe(false);
        expect(readFileMock.mock.calls.some(([path]) =>
          resolve(path) === resolve(restrictedPath) || resolve(path) === resolve(aliasPath)
        )).toBe(false);
        expect(execFileMock).not.toHaveBeenCalled();
        expect(active.processCalls).toEqual([]);
      }
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects hard-linked synthetic policy aliases before opening or reading them", async () => {
    const fixture = await createFixture();
    try {
      const restrictedPath = join(
        fixture.repo,
        "security",
        "oss-security-policy.json"
      );
      const aliasPath = join(fixture.root, "policy-hardlink.json");
      active.lstatOverrides = new Map([
        [resolve(aliasPath), {
          isSymbolicLink: () => false,
          isFile: () => true,
          isDirectory: () => false,
          nlink: 2,
          dev: 1,
          ino: 2,
          size: 1
        }]
      ]);
      const requestPath = await writeSyntheticScanRequest(
        fixture.root,
        fixture.repo,
        aliasPath,
        "hard-linked-policy-request.json"
      );
      openMock.mockClear();
      readMock.mockClear();
      readFileMock.mockClear();
      execFileMock.mockClear();
      active.processCalls.length = 0;

      const result = await runSecurityScanRequest(requestPath);
      const openedPaths = openMock.mock.calls.map(([path]) => resolve(path));

      expect(result).toMatchObject({
        status: "NOT_RUN",
        scanner_invoked: false,
        ok: false
      });
      expect(openedPaths).toContain(resolve(await realpath(requestPath)));
      expect(openedPaths).not.toContain(resolve(aliasPath));
      expect(readMock.mock.calls.some(([path]) =>
        resolve(path) === resolve(aliasPath)
      )).toBe(false);
      expect(readFileMock.mock.calls.some(([path]) =>
        resolve(path) === resolve(aliasPath)
      )).toBe(false);
      expect(JSON.stringify(result)).not.toContain(restrictedPath);
      expect(execFileMock).not.toHaveBeenCalled();
      expect(active.processCalls).toEqual([]);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("skips a synthetic canonical policy tree entry before any blob read", async () => {
    const fixture = await createFixture({
      sourceEntryPath: "security/other.txt",
      sourceEntryContent: "history-visible@example.com\n"
    });
    try {
      const commitId = git(fixture.repo, ["rev-parse", "HEAD"]);
      const policyPath = "security/oss-security-policy.json";
      const syntheticPolicyObject = "neutral-policy-sentinel-object";
      active.gitOutputTransform = (args, stdout) => {
        const treeOutput = appendSyntheticHistoryTreeEntry(
          args,
          stdout,
          policyPath,
          syntheticPolicyObject
        );
        return appendSyntheticHistoryObject(
          args,
          treeOutput,
          policyPath,
          syntheticPolicyObject
        );
      };
      active.gitCalls.length = 0;
      const occurrences = await historyEmailOccurrences(fixture.repo, {
        commits: [commitId]
      });

      expect(occurrences.some((entry) =>
        entry.address === "history-visible@example.com" &&
        entry.location.source === "git_blob" &&
        entry.location.path === "security/other.txt"
      )).toBe(true);
      expect(active.gitCalls.filter((args) =>
        gitSubcommandIndex(args, "cat-file") >= 0 &&
        args.includes(syntheticPolicyObject)
      )).toEqual([]);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("blocks a case-variant history policy path before any blob read", async () => {
    const caseVariantPath = "Security/OSS-SECURITY-POLICY.JSON";
    const fixture = await createFixture();
    try {
      const commitId = git(fixture.repo, ["rev-parse", "HEAD"]);
      active.gitOutputTransform = (args, stdout) =>
        appendSyntheticHistoryTreeEntry(args, stdout, caseVariantPath);
      active.gitCalls.length = 0;

      await expect(historyEmailOccurrences(fixture.repo, {
        commits: [commitId]
      })).rejects.toMatchObject({ code: "RESTRICTED_POLICY_ALIAS_UNSUPPORTED" });

      expect(active.gitCalls.some((args) =>
        gitSubcommandIndex(args, "cat-file") >= 0
      )).toBe(false);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  }, 30_000);

  test.each([
    ["Unicode normalization", "security/oss-security-policy.jso\u0301n", "RESTRICTED_POLICY_ALIAS_UNSUPPORTED"],
    ["lowercase backslash spelling", "security\\oss-security-policy.json", "RESTRICTED_POLICY_ALIAS_UNSUPPORTED"],
    ["mixed-separator lowercase spelling", "nested\\security/oss-security-policy.json", "RESTRICTED_POLICY_ALIAS_UNSUPPORTED"],
    ["Win32 trailing dot", "docs/neutral-denied-sentinel.txt.", "WINDOWS_PATH_ALIAS_UNSUPPORTED"],
    ["Win32 trailing space", "docs/neutral-denied-sentinel.txt ", "WINDOWS_PATH_ALIAS_UNSUPPORTED"],
    ["Win32 8.3 component", "docs/NEUTRA~1/neutral-denied-sentinel.txt", "WINDOWS_PATH_ALIAS_UNSUPPORTED"]
  ])("blocks %s history entries before any blob read", async (_label, path, code) => {
    const fixture = await createFixture();
    try {
      const commitId = git(fixture.repo, ["rev-parse", "HEAD"]);
      active.gitOutputTransform = (args, stdout) =>
        appendSyntheticHistoryTreeEntry(args, stdout, path);
      active.gitCalls.length = 0;

      await expect(historyEmailOccurrences(fixture.repo, {
        commits: [commitId]
      }, { platform: "win32" })).rejects.toMatchObject({ code });

      expect(active.gitCalls.some((args) =>
        gitSubcommandIndex(args, "cat-file") >= 0
      )).toBe(false);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("finds an alias path after a safe path even when both tree entries share one blob", async () => {
    const fixture = await createFixture();
    try {
      const reachableTreeIds = git(fixture.repo, ["rev-list", "--all"])
        .split("\n")
        .filter(Boolean)
        .map((commit) => git(fixture.repo, ["rev-parse", `${commit}^{tree}`]));
      const sharedObject = "neutral-shared-sentinel-object";
      const returnedEntries = [
        { objectId: sharedObject, path: "docs/neutral-control.txt" },
        { objectId: sharedObject, path: "security\\oss-security-policy.json" }
      ];
      const historyScans = [];
      active.gitOutputTransform = (args, stdout) =>
        appendSyntheticHistoryTreeEntries(args, stdout, returnedEntries);
      active.onHistoryScan = (args) => historyScans.push(args);

      const result = await fixture.runRaw({}, { platform: "win32" });

      expect(returnedEntries).toEqual([
        { objectId: sharedObject, path: "docs/neutral-control.txt" },
        { objectId: sharedObject, path: "security\\oss-security-policy.json" }
      ]);
      expect(result).toMatchObject({
        status: "INCOMPLETE",
        ok: false,
        cause_code: "RESTRICTED_POLICY_ALIAS_UNSUPPORTED"
      });
      expect(historyScans).toEqual([]);
      expect(active.gitCalls.some((args) =>
        isHistoryTreeCall(args) && reachableTreeIds.includes(args.at(-1))
      )).toBe(true);
      expect(active.gitCalls.some((args) =>
        gitSubcommandIndex(args, "cat-file") >= 0 && args.includes(sharedObject)
      )).toBe(false);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  }, 30_000);

  test("keeps a literal 8.3-shaped history name usable on POSIX", async () => {
    const fixture = await createFixture({
      sourceEntryPath: "docs/NEUTRA~1/neutral-denied-sentinel.txt",
      sourceEntryContent: "posix-control@example.invalid\n"
    });
    try {
      const commitId = git(fixture.repo, ["rev-parse", "HEAD"]);
      const occurrences = await historyEmailOccurrences(fixture.repo, {
        commits: [commitId]
      }, { platform: "darwin" });

      expect(occurrences).toContainEqual(expect.objectContaining({
        address: "posix-control@example.invalid",
        location: expect.objectContaining({
          source: "git_blob",
          path: "docs/NEUTRA~1/neutral-denied-sentinel.txt"
        })
      }));
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test.each([
    ["Unicode restricted-path spelling", "Security/oss-security-policy.jso\u0301n", "darwin"],
    ["lowercase backslash spelling", "security\\oss-security-policy.json", "win32"],
    ["mixed-separator lowercase spelling", "nested\\security/oss-security-policy.json", "win32"]
  ])("rejects a %s in candidate email scanning before file access", async (_label, path, platform) => {
    const fixture = await createFixture();
    try {
      openMock.mockClear();

      await expect(candidateEmailOccurrences(fixture.candidate, [{
        path,
        bytes: 1,
        sha256: sha256("neutral denied sentinel")
      }], { platform })).rejects.toMatchObject({
        code: "RESTRICTED_POLICY_ALIAS_UNSUPPORTED"
      });

      expect(openMock).not.toHaveBeenCalled();
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("shares canonical path exclusions between Gitleaks and history email scans", async () => {
    const fixture = await createFixture({
      sourceEntryPath: "security/other.txt",
      sourceEntryContent: "history-visible@example.com\n"
    });
    try {
      const policyPath = "security/oss-security-policy.json";
      const syntheticPolicyObject = "neutral-policy-sentinel-object";
      active.gitOutputTransform = (args, stdout) => {
        const treeOutput = appendSyntheticHistoryTreeEntry(
          args,
          stdout,
          policyPath,
          syntheticPolicyObject
        );
        return appendSyntheticHistoryObject(
          args,
          treeOutput,
          policyPath,
          syntheticPolicyObject
        );
      };
      const historyInputs = [];
      active.onHistoryScan = (args) => {
        const logOptions = args[args.indexOf("--log-opts") + 1];
        const output = git(fixture.repo, [
          "log",
          "-p",
          "-U0",
          ...logOptions.split(" ")
        ]);
        historyInputs.push({ logOptions, output });
      };

      const result = await fixture.runRaw();

      expect(result.status).toBe("SYNTHETIC_PASSED");
      expect(result.scanner_clean).toBe(true);
      expect(result.blockers).toEqual([]);
      expect(historyInputs).toHaveLength(1);
      expect(historyInputs[0].logOptions.split(" ")).toEqual(
        expect.arrayContaining([
          "--",
          ".",
          ":(top,exclude,glob,icase)**/security/oss-security-policy.json",
          ":(top,exclude,glob,icase)**/security\\\\oss-security-policy.json",
          ":(top,exclude,glob,icase)**/*\\\\security/oss-security-policy.json",
          ":(top,exclude,glob,icase)**/*\\\\security\\\\oss-security-policy.json",
          ":(top,exclude,glob,icase)security\\\\oss-security-policy.json"
        ])
      );
      expect(historyInputs[0].output).toContain("history-visible@example.com");
      expect(historyInputs[0].output).not.toContain("security/oss-security-policy.json");
      expect(active.gitCalls.some((args) =>
        gitSubcommandIndex(args, "cat-file") >= 0 &&
        args.includes(syntheticPolicyObject)
      )).toBe(false);
      const win32Occurrences = await historyEmailOccurrences(fixture.repo, {
        commits: [git(fixture.repo, ["rev-parse", "HEAD"])]
      }, { platform: "win32" });
      expect(win32Occurrences.some((entry) =>
        entry.address === "history-visible@example.com" &&
        entry.location.path === "security/other.txt"
      )).toBe(true);
      const historyPathListIndex = active.processCalls.findIndex(({ command, args }) =>
        command === "git" && isHistoryTreeCall(args)
      );
      const historyScannerIndex = active.processCalls.findIndex(({ command, args }) =>
        command.endsWith("/gitleaks-bin") && args[0] === "git"
      );
      expect(historyPathListIndex).toBeGreaterThanOrEqual(0);
      expect(historyScannerIndex).toBeGreaterThan(historyPathListIndex);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  }, 30_000);

  test.each([
    ["Unicode restricted suffix", "security/oss-security-policy.jso\u0301n", "RESTRICTED_POLICY_ALIAS_UNSUPPORTED"],
    ["lowercase backslash suffix", "security\\oss-security-policy.json", "RESTRICTED_POLICY_ALIAS_UNSUPPORTED"],
    ["mixed-separator lowercase suffix", "nested\\security/oss-security-policy.json", "RESTRICTED_POLICY_ALIAS_UNSUPPORTED"],
    ["Win32 trailing dot", "docs/neutral-denied-sentinel.txt.", "WINDOWS_PATH_ALIAS_UNSUPPORTED"],
    ["Win32 trailing space", "docs/neutral-denied-sentinel.txt ", "WINDOWS_PATH_ALIAS_UNSUPPORTED"],
    ["Win32 8.3 component", "docs/NEUTRA~1/neutral-denied-sentinel.txt", "WINDOWS_PATH_ALIAS_UNSUPPORTED"]
  ])("blocks %s before Gitleaks receives a history pathspec", async (_label, path, code) => {
    const fixture = await createFixture();
    try {
      const syntheticBlob = "neutral-denied-sentinel-blob";
      const historyScans = [];
      active.gitOutputTransform = (args, stdout) => {
        return appendSyntheticHistoryTreeEntry(args, stdout, path, syntheticBlob);
      };
      active.onHistoryScan = (args) => historyScans.push(args);

      const result = await fixture.runRaw({}, { platform: "win32" });

      expect(result).toMatchObject({
        status: "INCOMPLETE",
        ok: false,
        cause_code: code
      });
      expect(historyScans).toEqual([]);
      expect(active.gitCalls.some((args) => isHistoryTreeCall(args))).toBe(true);
      expect(active.gitCalls.some((args) =>
        gitSubcommandIndex(args, "cat-file") >= 0 && args.includes(syntheticBlob)
      )).toBe(false);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  }, 30_000);

  test.each([
    ["Win32 8.3 component", "docs/NEUTRA~1/neutral-denied-sentinel.txt", "win32", "WINDOWS_PATH_ALIAS_UNSUPPORTED"],
    ["Win32 trailing dot", "docs/neutral-denied-sentinel.txt.", "win32", "WINDOWS_PATH_ALIAS_UNSUPPORTED"],
    ["Win32 trailing space", "docs/neutral-denied-sentinel.txt ", "win32", "WINDOWS_PATH_ALIAS_UNSUPPORTED"],
    ["lowercase backslash restricted-path spelling", "security\\oss-security-policy.json", "win32", "RESTRICTED_POLICY_ALIAS_UNSUPPORTED"],
    ["Unicode restricted-path spelling", "Security/oss-security-policy.jso\u0301n", "darwin", "RESTRICTED_POLICY_ALIAS_UNSUPPORTED"]
  ])("blocks an omitted %s source entry before candidate file reads", async (_label, sourceEntryPath, platform, code) => {
    const fixture = await createFixture();
    try {
      const sourceBlob = "neutral-denied-sentinel-object";
      active.gitOutputTransform = (args, stdout) =>
        appendSyntheticTreeEntry(args, stdout, sourceEntryPath);
      active.gitCalls.length = 0;
      let candidateScanRan = false;
      active.onCandidateScan = () => {
        candidateScanRan = true;
      };

      const result = await fixture.runRaw({}, { platform });

      expect(result).toMatchObject({
        status: "INCOMPLETE",
        ok: false,
        cause_code: code
      });
      expect(candidateScanRan).toBe(false);
      expect(active.gitCalls.some((args) =>
        gitSubcommandIndex(args, "cat-file") >= 0 && args.includes(sourceBlob)
      )).toBe(false);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  }, 30_000);

  test("keeps ordinary source entries in export parity under injected Win32 rules", async () => {
    const sourceEntryPath = "docs/neutral/private-sentinel.txt";
    const fixture = await createFixture({
      sourceEntryPath,
      sourceEntryContent: "ordinary Win32 path control\n",
      exportSourceEntry: true
    });
    try {
      let candidateScanRan = false;
      active.onCandidateScan = () => {
        candidateScanRan = true;
      };
      const result = await fixture.runRaw({}, { platform: "win32" });

      expect(candidateScanRan).toBe(true);
      expect(result.cause_code).not.toBe("WINDOWS_PATH_ALIAS_UNSUPPORTED");
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  }, 30_000);

  test("reports missing Gitleaks inputs as NOT_RUN before invoking a scanner", async () => {
    const fixture = await createFixture();
    try {
      const result = await fixture.runRaw({
        gitleaksConfig: {
          path: join(fixture.root, "missing-gitleaks.toml"),
          sha256: sha256("missing")
        }
      });

      expect(result).toMatchObject({
        status: "NOT_RUN",
        code: "SCAN_INPUT_INVALID_OR_UNAVAILABLE",
        reason: "Required scan inputs could not be validated; no scanner was invoked.",
        scanner_invoked: false
      });
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("does not expose a rejected scanner input path in the result", async () => {
    const fixture = await createFixture();
    try {
      const suppliedPath = join(fixture.root, "candidate", "gitleaks.toml");
      const result = await fixture.runRaw({
        gitleaksConfig: { path: suppliedPath, sha256: sha256("fixture") }
      });

      expect(result.status).toBe("NOT_RUN");
      expect(result.reason).toBe(
        "Required scan inputs could not be validated; no scanner was invoked."
      );
      expect(JSON.stringify(result)).not.toContain(suppliedPath);
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects a scanner input whose bytes do not match the selected digest", async () => {
    const fixture = await createFixture();
    try {
      const result = await fixture.runRaw({
        gitleaksConfig: {
          path: join(fixture.root, "trusted-gitleaks.toml"),
          sha256: sha256("different config bytes")
        }
      });

      expect(result).toMatchObject({
        status: "NOT_RUN",
        scanner_invoked: false,
        code: "SCAN_INPUT_INVALID_OR_UNAVAILABLE"
      });
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("reports a stable scanner identifier instead of its temporary absolute path", async () => {
    const fixture = await createFixture();
    try {
      const result = await fixture.runRaw();
      const versionStage = result.mandatory_checks.find(
        (stage) => stage.name === "gitleaks_version"
      );

      expect(versionStage).toMatchObject({
        status: "complete",
        executable: "gitleaks-bin"
      });
      expect(result.scanner).toMatchObject({
        name: "gitleaks",
        version: "8.30.1",
        platform: `${process.platform}_${process.arch}`,
        binary_sha256: sha256("fixture scanner\n"),
        config_sha256: sha256('title = "post-scan fixture"\n'),
        ignore_sha256: sha256("")
      });
      expect(JSON.stringify(result)).not.toContain("gpt-repo-security-scan.");
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("redacts raw scanner errors and codes from INCOMPLETE result evidence", async () => {
    const fixture = await createFixture();
    try {
      const suppliedPath = join(fixture.root, "private-scanner-input.toml");
      active.onCandidateScan = () => {
        const error = new Error(`scanner failed while reading ${suppliedPath}`);
        error.code = suppliedPath;
        throw error;
      };
      const result = await fixture.runRaw();
      const candidateStage = result.mandatory_checks.find(
        (stage) => stage.name === "candidate_gitleaks"
      );

      expect(result).toMatchObject({
        status: "INCOMPLETE",
        code: "MANDATORY_SCAN_INCOMPLETE",
        reason: "A mandatory security check did not complete successfully.",
        cause_code: null,
        scanner_invoked: true
      });
      expect(candidateStage).toMatchObject({
        status: "failed",
        reason: "A mandatory security check did not complete successfully."
      });
      expect(JSON.stringify(result)).not.toContain(suppliedPath);
      expect(JSON.stringify(result)).not.toContain("scanner failed while reading");
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("skips a history email blob one byte above the 5 MiB limit", async () => {
    const fixture = await createFixture({ historyBlobSize: 5 * 1024 * 1024 + 1 });
    try {
      const blob = git(fixture.repo, [
        "rev-parse",
        `${fixture.historyBlobCommit}:history-boundary.txt`
      ]);
      expect(Number(git(fixture.repo, ["cat-file", "-s", blob]))).toBe(5 * 1024 * 1024 + 1);
      const coverage = {};
      const occurrences = await historyEmailOccurrences(fixture.repo, {
        commits: [fixture.historyBlobCommit]
      }, { coverage });
      expect(occurrences.some((entry) =>
        entry.location.source === "git_blob" && entry.address === "boundary@example.com"
      )).toBe(false);
      expect(coverage.blobs_skipped_large).toBe(1);

      const result = await fixture.runRaw();
      expect(result.status).toBe("INCOMPLETE");
      expect(result.ok).toBe(false);
      expect(result.blockers).toContain("email_coverage_incomplete");
      expect(result.mandatory_checks.find(
        (stage) => stage.name === "public_history_email_classification"
      )).toMatchObject({ skipped: { blobs_skipped_large: 1 } });
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  }, 30_000);
  test("fails when a selected ref moves while the scan is running", async () => {
    const fixture = await createFixture({ moveRef: true });
    try {
      await expect(fixture.run()).rejects.toMatchObject({
        code: "PUBLICATION_SELECTION_CHANGED"
      });
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("fails when history email coverage skips a NUL blob", async () => {
    const fixture = await createFixture({ historyBinary: true });
    try {
      const result = await fixture.runRaw();
      expect(result.ok).toBe(false);
      expect(result.blockers).toContain("email_coverage_incomplete");
    } finally {
      active = null;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
});
