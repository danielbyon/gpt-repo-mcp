import { Buffer } from "node:buffer";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  symlink,
  truncate,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, URL } from "node:url";
import process from "node:process";
import { promisify } from "node:util";
import { describe, expect, test, vi } from "vitest";
import { resolvePublicationRefSet } from "../scripts/publication-ref-set.mjs";

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

const race = vi.hoisted(() => ({
  enabled: false,
  swapped: false,
  candidateReadme: "",
  candidatePackageLock: "",
  outside: "",
  capturedCandidate: null,
  substitutedCandidate: null,
  reportBody: null,
  scannerVersion: "8.30.1",
  tagScanContent: [],
  tagFinding: false,
  addCandidateExtraFile: false,
  tamperCandidateSnapshot: false,
  tamperTagSnapshot: false,
  tamperConfigSnapshot: false,
  tamperScannerSnapshot: false,
  missingReport: false,
  mutateCandidateDependency: false,
  restoreCandidateSnapshot: false,
  inflateReadPath: "",
  growReadPath: "",
  growReadBytes: 0,
  growReadLimit: 0,
  swapOnScanner: false,
  configSnapshots: [],
  ignoreSnapshots: [],
  scannerCalls: 0,
  scannerCommands: [],
  scannerSnapshotHashes: [],
  npmAuditLocks: [],
  npmAuditExitCode: 0,
  trackFilesystemAttempts: false,
  filesystemAttempts: []
}));

const { execFileMock } = vi.hoisted(() => ({ execFileMock: vi.fn() }));

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, execFile: execFileMock };
});

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    open: async (path, flags, mode) => {
    if (race.trackFilesystemAttempts) {
      race.filesystemAttempts.push({ operation: "open", path: String(path) });
    }
    const handle = await actual.open(path, flags, mode);
    if (
      race.enabled &&
      race.inflateReadPath &&
      String(path) === race.inflateReadPath
    ) {
      const readFromHandle = handle.read.bind(handle);
      let injected = false;
      handle.read = async (buffer, offset, length, position) => {
        const result = await readFromHandle(buffer, offset, length, position);
        if (result.bytesRead === 0 && !injected) {
          injected = true;
          buffer[offset] = 0x78;
          return { bytesRead: 1, buffer };
        }
        return result;
      };
    }
    if (race.enabled && race.growReadPath) {
      const resolvedPath = await realpath(String(path)).catch(() =>
        String(path)
      );
      if (
        String(path) === race.growReadPath ||
        resolvedPath === race.growReadPath
      ) {
        handle.read = async (buffer, offset, length) => {
          const remaining = race.growReadLimit - race.growReadBytes;
          const want = Math.max(0, Math.min(length, remaining));
          if (want === 0) {
            return { bytesRead: 0, buffer };
          }
          buffer.fill(0x30, offset, offset + want);
          race.growReadBytes += want;
          return { bytesRead: want, buffer };
        };
      }
    }
    return handle;
    },
    readFile: async (path, ...args) => {
      if (race.trackFilesystemAttempts) {
        race.filesystemAttempts.push({ operation: "readFile", path: String(path) });
      }
      return actual.readFile(path, ...args);
    },
    writeFile: async (path, ...args) => {
      if (race.trackFilesystemAttempts) {
        race.filesystemAttempts.push({ operation: "writeFile", path: String(path) });
      }
      return actual.writeFile(path, ...args);
    }
  };
});

let activeScanner = "";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function expectMandatoryScanFailure(result, stageName) {
  expect(result).toMatchObject({
    status: "INCOMPLETE",
    code: "MANDATORY_SCAN_INCOMPLETE",
    scanner_invoked: true,
    production_eligible: false,
    scanner_clean: false,
    publication_eligible: false,
    owner_approval_required: true
  });
  expect(result.mandatory_checks).toContainEqual(
    expect.objectContaining({ name: stageName, status: "failed" })
  );
  return result;
}

function expectScanNotRun(result) {
  expect(result).toMatchObject({
    status: "NOT_RUN",
    scanner_invoked: false,
    production_eligible: false,
    scanner_clean: false,
    publication_eligible: false,
    owner_approval_required: true
  });
  return result;
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

function git(root, args) {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, GIT_AUTHOR_EMAIL: "fixture@example.invalid" }
  }).trim();
}

async function dispatch(command, args, options) {
  if (command === "git") {
    return {
      stdout: execFileSync("git", args, {
        cwd: options?.cwd,
        env: options?.env,
        encoding: options?.encoding === "buffer" ? "buffer" : "utf8",
        maxBuffer: 64 * 1024 * 1024
      }),
      stderr: ""
    };
  }
  if (isSyntheticDependencyAuditCommand(command)) {
    if (args[0] === "--version") return { stdout: "synthetic-audit-fixture/1\n", stderr: "" };
    if (args[0] === "audit") {
      race.npmAuditLocks.push(
        await readFile(join(options.cwd, "package-lock.json"), "utf8")
      );
    }
    return {
      stdout: syntheticDependencyAuditOutput(),
      stderr: "",
      exitCode: args[0] === "audit" ? race.npmAuditExitCode : 0
    };
  }
  if (
    command === activeScanner ||
    command.endsWith("/gitleaks-fixture") ||
    command.endsWith("/gitleaks-bin")
  ) {
    if (command.endsWith("/gitleaks-bin")) {
      race.scannerCommands.push(command);
      race.scannerSnapshotHashes.push(sha256(await readFile(command)));
    }
    race.scannerCalls += 1;
    if (args[0] === "version") {
      return { stdout: `${race.scannerVersion}\n`, stderr: "" };
    }
    const configPath = args[args.indexOf("--config") + 1];
    const ignorePath = args[args.indexOf("--gitleaks-ignore-path") + 1];
    race.configSnapshots.push(await readFile(configPath, "utf8"));
    race.ignoreSnapshots.push(await readFile(ignorePath, "utf8"));
      if (race.tamperConfigSnapshot) {
        race.tamperConfigSnapshot = false;
        await chmod(configPath, 0o600);
        await writeFile(configPath, 'title = "tampered snapshot rules"\n');
      }
      if (race.tamperScannerSnapshot) {
        race.tamperScannerSnapshot = false;
        await chmod(command, 0o700);
        await writeFile(command, "tampered scanner snapshot\n");
      }
    if (args[0] === "dir") {
      const target = args[1];
      const names = await readdir(target);
      if (names.includes("README.md")) {
        if (race.swapOnScanner) {
          race.swapOnScanner = false;
          race.swapped = true;
          await rm(race.candidateReadme);
          await symlink(race.outside, race.candidateReadme);
        }
        if (race.mutateCandidateDependency) {
          await writeFile(
            race.candidatePackageLock,
            JSON.stringify({
              lockfileVersion: 3,
              packages: {
                "": { name: "fixture", version: "1.0.0" },
                "node_modules/evil": {
                  name: "evil",
                  version: "1.0.0",
                  license: "GPL-3.0"
                }
              }
            }) + "\n"
          );
        }
        if (race.restoreCandidateSnapshot) {
          const readme = join(target, "README.md");
          const original = await readFile(readme, "utf8");
          await chmod(readme, 0o600);
          await writeFile(readme, "substituted snapshot bytes\n");
          race.substitutedCandidate = await readFile(readme, "utf8");
          await writeFile(readme, original);
        }
        if (!race.restoreCandidateSnapshot) {
          race.capturedCandidate = await readFile(
            join(target, "README.md"),
            "utf8"
          );
        }
        if (race.addCandidateExtraFile) {
          await writeFile(join(target, "injected.txt"), "injected scan input\n");
        }
        if (race.tamperCandidateSnapshot) {
          await chmod(join(target, "README.md"), 0o600);
          await writeFile(join(target, "README.md"), "tampered snapshot bytes\n");
        }
      } else {
        const contents = [];
        for (const name of names.sort()) {
          contents.push(await readFile(join(target, name), "utf8"));
        }
        race.tagScanContent = contents;
        if (race.tamperTagSnapshot) {
          const name = names.find((entry) => entry.endsWith(".txt"));
          await chmod(join(target, name), 0o600);
          await writeFile(join(target, name), "tampered tag metadata\n");
        }
      }
    }
    const reportPath = args[args.indexOf("--report-path") + 1];
    const isCandidateScan =
      args[0] === "dir" && (await readdir(args[1])).includes("README.md");
    if (race.reportBody !== null) {
      writeFileSync(reportPath, race.reportBody);
    } else if (!race.missingReport) {
      writeFileSync(
        reportPath,
        isCandidateScan || !race.tagFinding
          ? "[]"
          : JSON.stringify([{ RuleID: "tag-rule", StartLine: 1 }])
      );
    }
    return {
      stdout: "",
      stderr: "",
      exitCode:
        race.reportBody !== null || (!isCandidateScan && race.tagFinding) ? 1 : 0
    };
  }
  throw new Error(`unexpected command: ${command} ${args.join(" ")}`);
}

execFileMock[promisify.custom] = async (command, args, options) =>
  dispatch(command, args, options);

execFileMock.mockImplementation((command, args, options, callback) => {
  Promise.resolve(dispatch(command, args, options)).then(
    (result) => {
      if (result.exitCode) {
        callback(
          Object.assign(new Error("command failed"), { code: result.exitCode }),
          result.stdout,
          result.stderr
        );
        return;
      }
      callback(null, result.stdout, result.stderr);
    },
    (error) => callback(error)
  );
});

const { runSecurityScan } = await import("../scripts/oss-security-scan.mjs");

async function createFixture(options = {}) {
  const root = await mkdtemp(join(await realpath(tmpdir()), "gpt-repo-security-boundary-"));
  try {
    return await createFixtureWithRoot(root, options);
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function createFixtureWithRoot(root, {
  candidateConfig = 'title = "candidate controlled"\n',
  includeTags = false,
  tagEmail = "fixture@example.invalid",
  scannerBody = "fixture scanner\n",
  setupFailure
} = {}) {
  const dependencyAudit = await createSyntheticDependencyAudit(root);
  await setupFailure?.(root);
  const repo = join(root, "repo");
  const candidate = join(root, "candidate");
  const scanner = join(root, "gitleaks-fixture");
  const exportReportPath = join(root, "export.json");
  const trustedConfigPath = join(root, "trusted-gitleaks.toml");
  const trustedIgnorePath = join(root, "trusted-gitleaksignore");
  const trustedConfigBody = 'title = "trusted owner rules"\n';
  const trustedIgnoreBody = "synthetic-trusted-ignore\n";
  const sourceContent = "source bytes\n";
  const nestedContent = "nested source bytes\n";
const packageJson = JSON.stringify({ name: "fixture", version: "1.0.0" }) + "\n";
const packageLock =
  JSON.stringify({
    name: "fixture",
    version: "1.0.0",
    lockfileVersion: 3,
    requires: true,
    packages: { "": { name: "fixture", version: "1.0.0" } }
  }) + "\n";
  const outsidePath = join(root, "outside-secret.txt");

  await mkdir(repo);
  await mkdir(join(candidate, "node_modules"), { recursive: true });
  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Fixture"]);
  git(repo, ["config", "user.email", "fixture@example.invalid"]);
  await writeFile(join(repo, "README.md"), sourceContent);
  await mkdir(join(repo, "nested"));
  await writeFile(join(repo, "nested", "README.md"), nestedContent);
await writeFile(join(repo, "package.json"), packageJson);
await writeFile(join(repo, "package-lock.json"), packageLock);
  git(repo, ["add", "--all"]);
  git(repo, ["commit", "-qm", "source"]);
  const sourceCommit = git(repo, ["rev-parse", "HEAD"]);

  if (includeTags) {
    git(repo, [
      "-c",
      `user.email=${tagEmail}`,
      "tag",
      "-a",
      "inner",
      "-m",
      "synthetic inner tag marker",
      sourceCommit
    ]);
    git(repo, [
      "-c",
      "advice.nestedTag=false",
      "-c",
      `user.email=${tagEmail}`,
      "tag",
      "-a",
      "outer",
      "-m",
      "synthetic outer tag marker",
      "inner"
    ]);
  }

  await writeFile(join(candidate, "README.md"), sourceContent);
  await mkdir(join(candidate, "nested"));
  await writeFile(join(candidate, "nested", "README.md"), nestedContent);
await writeFile(join(candidate, "package.json"), packageJson);
await writeFile(join(candidate, "package-lock.json"), packageLock);
  await writeFile(join(candidate, ".gitleaks.toml"), candidateConfig);
  await writeFile(join(candidate, ".gitleaksignore"), "candidate-ignore\n");
  await writeFile(join(root, "outside-secret.txt"), "outside secret bytes\n");
  await writeFile(scanner, scannerBody);
  await writeFile(trustedConfigPath, trustedConfigBody);
  await writeFile(trustedIgnorePath, trustedIgnoreBody);

  const files = [
    {
      path: "README.md",
      bytes: Buffer.byteLength(sourceContent),
      sha256: sha256(sourceContent)
  },
  {
    path: "package.json",
    bytes: Buffer.byteLength(packageJson),
    sha256: sha256(packageJson)
  },
  {
    path: "package-lock.json",
    bytes: Buffer.byteLength(packageLock),
    sha256: sha256(packageLock)
  },
  {
    path: "nested/README.md",
    bytes: Buffer.byteLength(nestedContent),
    sha256: sha256(nestedContent)
    }
  ];
  await writeFile(
    exportReportPath,
    JSON.stringify({
      source_commit: sourceCommit,
      files,
      tree_sha256: exportTree(files)
    })
  );

  activeScanner = scanner;
  const publication = await resolvePublicationRefSet({
    repoRoot: repo,
    candidate: { kind: "ref", ref: "refs/heads/main" },
    target: { kind: "ref", ref: "refs/heads/main" },
    additionalRefs: includeTags
      ? [{ kind: "ref", ref: "refs/tags/outer" }]
      : []
  });
  const policy = {
    schema_version: 1,
    policy_version: "fixture",
    gitleaks: {
      version: "8.30.1",
      assets: {
        [`${process.platform}_${process.arch}`]: {
          binary_sha256: sha256(scannerBody)
        }
      }
    },
    email: {
      allowed_domains: ["example.invalid"],
      allowed_addresses: [],
      reviewed_public_history_locations: []
    },
    licenses: { allowed: [] },
    dependency_audit: dependencyAudit.policy,
    known_development_advisories: []
  };
  const syntheticPolicyProvenance = {
    kind: "synthetic_fixture",
    fixture_id: "oss-security-security-boundary",
    policy_sha256: sha256(JSON.stringify(policy))
  };
  const trustedConfig = {
    path: trustedConfigPath,
    sha256: sha256(trustedConfigBody)
  };
  const trustedIgnore = {
    path: trustedIgnorePath,
    sha256: sha256(trustedIgnoreBody)
  };

  return {
    root,
    candidate,
    repo,
    exportReportPath,
    publication,
    scanner,
    dependencyAudit,
    sourceCommit,
    outsidePath,
    trustedConfigPath,
    trustedConfigBody,
    trustedConfig,
    trustedIgnore,
    policy,
    syntheticPolicyProvenance,
    run: async (overrides = {}) => {
      const result = await runSecurityScan({
        candidateRoot: candidate,
        exportReportPath,
        publicRepo: repo,
        gitleaksBin: scanner,
        gitleaksConfig: trustedConfig,
        gitleaksIgnore: trustedIgnore,
        policy,
        policyProvenance: syntheticPolicyProvenance,
        publication,
        ...overrides
      });
      return result;
    }
  };
}

function resetRaceState() {
  race.enabled = false;
  race.swapped = false;
  race.candidateReadme = "";
  race.outside = "";
  race.capturedCandidate = null;
  race.substitutedCandidate = null;
  race.reportBody = null;
  race.scannerVersion = "8.30.1";
  race.tagScanContent = [];
  race.tagFinding = false;
  race.addCandidateExtraFile = false;
  race.tamperCandidateSnapshot = false;
  race.tamperTagSnapshot = false;
  race.tamperConfigSnapshot = false;
  race.tamperScannerSnapshot = false;
  race.missingReport = false;
  race.swapOnScanner = false;
  race.configSnapshots = [];
  race.ignoreSnapshots = [];
  race.scannerCalls = 0;
  race.scannerCommands = [];
  race.scannerSnapshotHashes = [];
  race.npmAuditLocks = [];
  race.npmAuditExitCode = 0;
  race.mutateCandidateDependency = false;
  race.restoreCandidateSnapshot = false;
  race.inflateReadPath = "";
  race.growReadPath = "";
  race.growReadBytes = 0;
  race.growReadLimit = 0;
  race.candidatePackageLock = "";
  race.trackFilesystemAttempts = false;
  race.filesystemAttempts = [];
}

async function createDirectPathFixture() {
  const root = await mkdtemp(join(await realpath(tmpdir()), "gpt-repo-direct-path-boundary-"));
  const candidateRoot = join(root, "candidate");
  const publicRepo = join(root, "public");
  await mkdir(candidateRoot);
  await mkdir(publicRepo);
  const policy = {};
  const options = {
    candidateRoot,
    exportReportPath: join(root, "export-report.json"),
    publicRepo,
    gitleaksBin: join(root, "gitleaks-fixture"),
    gitleaksConfig: { path: join(root, "gitleaks.toml"), sha256: "0".repeat(64) },
    gitleaksIgnore: { path: join(root, "gitleaksignore"), sha256: "0".repeat(64) },
    policy,
    policyProvenance: {
      kind: "synthetic_fixture",
      fixture_id: "direct-path-boundary",
      policy_sha256: sha256(JSON.stringify(policy))
    },
    publication: {
      candidate: { kind: "ref", ref: "refs/heads/main" },
      target: { kind: "ref", ref: "refs/heads/main" }
    }
  };
  return {
    root,
    options,
    run: (overrides = {}) => runSecurityScan({ ...options, ...overrides })
  };
}

describe("OSS security scan trust boundaries", () => {
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


  test("npm audit exit 1 with zero reported advisories is incomplete", async () => {
    resetRaceState();
    const fixture = await createFixture();
    try {
      race.npmAuditExitCode = 1;
      expectMandatoryScanFailure(
        await fixture.run(),
        "production_dependency_vulnerability_audit"
      );
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("CLI keeps a synthetic policy file out of production authorization", async () => {
    resetRaceState();
    const fixture = await createFixture();
    try {
      const scannerBody = `#!/bin/sh
if [ "$1" = "version" ]; then echo 8.30.1; exit 0; fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then shift; report="$1"; fi
  shift
done
printf '[]' > "$report"
`;
      const npmBody = `#!/bin/sh
if [ "$1" = "--version" ]; then echo synthetic-audit-fixture/1; exit 0; fi
if [ "$1" = "audit" ]; then printf '%s\\n' '${syntheticDependencyAuditOutput()}'; exit 0; fi
exit 2
`;
      await writeFile(fixture.scanner, scannerBody, { mode: 0o700 });
      await chmod(fixture.scanner, 0o700);
      fixture.policy.gitleaks.assets[`${process.platform}_${process.arch}`].binary_sha256 = sha256(scannerBody);
      await writeFile(fixture.dependencyAudit.executablePath, npmBody, { mode: 0o700 });
      await chmod(fixture.dependencyAudit.executablePath, 0o700);
      fixture.policy.dependency_audit.executable_sha256 = sha256(npmBody);

      const policyPath = join(fixture.root, "synthetic-policy.json");
      const requestPath = join(fixture.root, "scan-request.json");
      await writeFile(policyPath, JSON.stringify(fixture.policy));
      const request = {
        schema_version: 2,
        candidate_root: fixture.candidate,
        export_report_path: fixture.exportReportPath,
        public_repo: fixture.repo,
        candidate_ref: "refs/heads/main",
        target_ref: "refs/heads/main",
        gitleaks_bin: fixture.scanner,
        gitleaks_config: fixture.trustedConfig,
        gitleaks_ignore: fixture.trustedIgnore,
        policy_path: policyPath,
        policy_source: { kind: "synthetic_fixture", fixture_id: "cli-synthetic" },
        publication: fixture.publication
      };
      await writeFile(requestPath, JSON.stringify(request));

      const script = fileURLToPath(new URL("../scripts/oss-security-scan.mjs", import.meta.url));
      const result = spawnSync(process.execPath, [script, "--request", requestPath], {
        cwd: fixture.root,
        encoding: "utf8"
      });

      expect(result.status).toBe(78);
      expect(JSON.parse(result.stdout)).toMatchObject({
        status: "SYNTHETIC_PASSED",
        policy_provenance: { kind: "synthetic_fixture", fixture_id: "cli-synthetic" },
        production_eligible: false,
        publication_eligible: false
      });

      request.policy_source = { kind: "owner_authorized_policy_file" };
      await writeFile(requestPath, JSON.stringify(request));
      const mislabeledResult = spawnSync(process.execPath, [script, "--request", requestPath], {
        cwd: fixture.root,
        encoding: "utf8"
      });
      expect(mislabeledResult.status).toBe(78);
      expect(JSON.parse(mislabeledResult.stdout)).toMatchObject({
        status: "NOT_RUN",
        code: "PRODUCTION_POLICY_UNAVAILABLE",
        scanner_invoked: false,
        production_eligible: false,
        publication_eligible: false
      });
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("scanner consumes the pinned candidate snapshot after source path changes", async () => {
    resetRaceState();
    const fixture = await createFixture();
    try {
      race.enabled = true;
      race.swapOnScanner = true;
      race.candidateReadme = await realpath(join(fixture.candidate, "README.md"));
      race.outside = await realpath(fixture.outsidePath);
      const result = await fixture.run();
      expect(race.swapped).toBe(true);
      expect(race.capturedCandidate).toBe("source bytes\n");
      expect(result.status).toBe("SYNTHETIC_PASSED");
      expect(result.ok).toBe(false);
      expect(result.scanner_clean).toBe(true);
      expect(result.publication_eligible).toBe(false);
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("candidate Gitleaks files cannot replace external scanner rules", async () => {
    resetRaceState();
    const fixture = await createFixture({
      candidateConfig: 'title = "candidate permissive rules"\n'
    });
    try {
      await fixture.run();
      expect(race.scannerCalls).toBeGreaterThan(1);
      expect(new Set(race.configSnapshots)).toEqual(
        new Set([fixture.trustedConfigBody])
      );
      expect(new Set(race.ignoreSnapshots)).toEqual(
        new Set(["synthetic-trusted-ignore\n"])
      );
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("missing or inconsistent Gitleaks input digests fail before scan", async () => {
    resetRaceState();
    const fixture = await createFixture();
    try {
      const missingConfigDigest = { ...fixture.trustedConfig };
      delete missingConfigDigest.sha256;
      expectScanNotRun(
        await fixture.run({ gitleaksConfig: missingConfigDigest })
      );
      expectScanNotRun(await fixture.run({
        gitleaksIgnore: {
          ...fixture.trustedIgnore,
          sha256: "0".repeat(64)
        }
      }));
      expect(race.scannerCalls).toBe(0);
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("missing trusted Gitleaks inputs fail before scanner execution", async () => {
    resetRaceState();
    const fixture = await createFixture();
    try {
      expectScanNotRun(await fixture.run({ gitleaksConfig: undefined }));
      expectScanNotRun(await fixture.run({ gitleaksIgnore: undefined }));
      expect(race.scannerCalls).toBe(0);
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("tampered trusted Gitleaks input fails before scanner execution", async () => {
    resetRaceState();
    const fixture = await createFixture();
    try {
      await writeFile(
        fixture.trustedConfigPath,
        'title = "tampered rules"\n'
      );
      expectScanNotRun(await fixture.run());
      expect(race.scannerCalls).toBe(0);
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("trusted Gitleaks input symlink fails before scanner execution", async () => {
    resetRaceState();
    const fixture = await createFixture();
    try {
      const linkedConfig = join(fixture.root, "linked-gitleaks.toml");
      await symlink(fixture.trustedConfigPath, linkedConfig);
      expectScanNotRun(await fixture.run({
        gitleaksConfig: {
          path: linkedConfig,
          sha256: sha256(fixture.trustedConfigBody)
        }
      }));
      expect(race.scannerCalls).toBe(0);
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("missing scanner report fails closed", async () => {
    resetRaceState();
    const fixture = await createFixture();
    try {
      race.missingReport = true;
      expectMandatoryScanFailure(await fixture.run(), "candidate_gitleaks");
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

test("malformed or non-array scanner reports fail closed", async () => {
  for (const body of ["{", '[{"RuleID":"x"', "{}", '"[]"']) {
    resetRaceState();
    const fixture = await createFixture();
    try {
      race.reportBody = body;
      expectMandatoryScanFailure(await fixture.run(), "candidate_gitleaks");
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("unexpected scanner version fails before any scan", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    race.scannerVersion = "8.30.0";
    const result = await fixture.run();
    expectMandatoryScanFailure(result, "candidate_source_snapshot");
    expect(result.mandatory_checks).toContainEqual(
      expect.objectContaining({
        name: "gitleaks_version",
        status: "complete",
        version: "8.30.0",
        exit_code: 0
      })
    );
    expect(race.scannerCalls).toBe(1);
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("executes the verified private scanner snapshot", async () => {
    resetRaceState();
    const fixture = await createFixture();
    try {
      const result = await fixture.run();
      expect(result.status).toBe("SYNTHETIC_PASSED");
      expect(result.ok).toBe(false);
      expect(result.scanner_clean).toBe(true);
      expect(result.scanner).toEqual({
        name: "gitleaks",
        version: "8.30.1",
        platform: `${process.platform}_${process.arch}`,
        binary_sha256: sha256("fixture scanner\n"),
        config_sha256: sha256(fixture.trustedConfigBody),
        ignore_sha256: sha256("synthetic-trusted-ignore\n")
      });
      expect(result.publication_eligible).toBe(false);
      expect(result.mandatory_checks.map(({ name }) => name)).toEqual([
        "publication_ref_identity",
        "candidate_source_snapshot",
        "gitleaks_version",
        "candidate_gitleaks",
        "publication_tag_scanners",
        "public_history_gitleaks",
        "candidate_email_classification",
        "public_history_email_classification",
        "dependency_license_classification",
        "production_dependency_vulnerability_audit",
        "final_source_consistency"
      ]);
      expect(result.mandatory_checks.every(({ status }) => status === "complete")).toBe(true);
      expect(result.status).not.toBe("PASSED");
      expect(result.policy_provenance).toMatchObject({
        kind: "synthetic_fixture",
        fixture_id: "oss-security-security-boundary",
        policy_sha256: sha256(JSON.stringify(fixture.policy))
      });
      expect(result.production_eligible).toBe(false);
      expect(result.candidate.gitleaks.scan.exit_code).toBe(0);
      expect(result.public_history.tag_metadata.scan.status).toBe("NOT_RUN");
      expect(result.public_history.gitleaks.scan_batches.every((batch) => batch.exit_code === 0)).toBe(true);
      expect(result.dependencies.audit.evidence.executable_version).toBe("synthetic-audit-fixture/1");
      expect(race.scannerCommands.length).toBeGreaterThan(1);
      expect(
        race.scannerCommands.every((command) =>
          command.endsWith("/gitleaks-bin")
        )
      ).toBe(true);
      expect(new Set(race.scannerSnapshotHashes)).toEqual(
        new Set([sha256("fixture scanner\n")])
      );
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

test("trusted config snapshot tampering fails post-scan verification", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    race.tamperConfigSnapshot = true;
    expectMandatoryScanFailure(await fixture.run(), "public_history_gitleaks");
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("synthetic policy provenance cannot qualify a production scan", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    const result = await fixture.run({ policyProvenance: fixture.syntheticPolicyProvenance });
    expect(result.status).toBe("SYNTHETIC_PASSED");
    expect(result.ok).toBe(false);
    expect(result.scanner_clean).toBe(true);
    expect(result.policy_provenance.kind).toBe("synthetic_fixture");
    expect(result.production_eligible).toBe(false);
    expect(result.publication_eligible).toBe(false);
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("missing policy provenance returns NOT_RUN before any scanner is invoked", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    const result = await fixture.run({ policyProvenance: undefined });
    expect(result).toMatchObject({ status: "NOT_RUN", code: "POLICY_PROVENANCE_REQUIRED", scanner_invoked: false });
    expect(race.scannerCalls).toBe(0);
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test.each([
  ["synthetic digest mismatch", { kind: "synthetic_fixture", fixture_id: "forged", policy_sha256: "0".repeat(64) }],
  ["forged production assertion", { kind: "owner_authorized_policy_file", policy_sha256: "0".repeat(64), source_sha256: "1".repeat(64), request_sha256: "2".repeat(64) }]
])("%s provenance returns NOT_RUN before scanning", async (_label, policyProvenance) => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    const forged = policyProvenance.kind === "owner_authorized_policy_file"
      ? { ...policyProvenance, policy_sha256: sha256(JSON.stringify(fixture.policy)) }
      : policyProvenance;
    const result = await fixture.run({ policyProvenance: forged });
    expect(result).toMatchObject({ status: "NOT_RUN", code: "POLICY_PROVENANCE_INVALID", scanner_invoked: false });
    expect(race.scannerCalls).toBe(0);
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("hard-linked candidate files are rejected using a disposable fixture", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    await link(join(fixture.candidate, "README.md"), join(fixture.candidate, "README-link.md"));
    expectMandatoryScanFailure(
      await fixture.run({ policyProvenance: fixture.syntheticPolicyProvenance }),
      "candidate_source_snapshot"
    );
    expect(race.scannerCalls).toBe(1); // The pinned version check runs before candidate-file verification.
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("scanner binary snapshot tampering fails post-scan verification", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    race.tamperScannerSnapshot = true;
    expectMandatoryScanFailure(await fixture.run(), "public_history_gitleaks");
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("task-local scanner snapshots support binaries larger than 5 MiB", async () => {
  resetRaceState();
  const scannerBody = Buffer.alloc(6 * 1024 * 1024, 0x61);
  const fixture = await createFixture({ scannerBody });
  try {
    const result = await fixture.run();
    expect(result.status).toBe("SYNTHETIC_PASSED");
    expect(result.ok).toBe(false);
    expect(result.scanner_clean).toBe(true);
    expect(race.scannerSnapshotHashes.length).toBeGreaterThan(0);
    expect(
      race.scannerSnapshotHashes.every((hash) => hash === sha256(scannerBody))
    ).toBe(true);
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("audit and license inputs are bound to the source commit", async () => {
    resetRaceState();
    const fixture = await createFixture();
    try {
      const sourceLock = await readFile(
        join(fixture.repo, "package-lock.json"),
        "utf8"
      );
      race.mutateCandidateDependency = true;
      race.candidatePackageLock = join(fixture.candidate, "package-lock.json");
      const result = await fixture.run();
    expect(race.npmAuditLocks).toEqual([sourceLock, sourceLock]);
      expect(result.dependencies.package_lock_sha256).toBe(sha256(sourceLock));
      expect(result.dependencies.licenses.package_count).toBe(0);
      expect(await readFile(race.candidatePackageLock, "utf8")).toContain(
        "GPL-3.0"
      );
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("scans every object in a selected nested annotated-tag chain", async () => {
    resetRaceState();
    const fixture = await createFixture({ includeTags: true });
    try {
      const result = await fixture.run();
    expect(result.public_history.tag_metadata).toMatchObject({
        finding_count: 0,
      rule_counts: {},
      scan: { status: "COMPLETE", exit_code: 0 },
      email: {
        occurrence_count: 2,
        allowed_count: 2,
        reviewed_history_count: 0,
        unclassified: []
      }
      });
      expect(race.tagScanContent).toHaveLength(2);
      expect(race.tagScanContent.join("\n")).toContain("synthetic outer tag marker");
      expect(race.tagScanContent.join("\n")).toContain("synthetic inner tag marker");
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("tag metadata findings block the scan", async () => {
    resetRaceState();
    const fixture = await createFixture({ includeTags: true });
    try {
      race.tagFinding = true;
      const result = await fixture.run();
      expect(result.ok).toBe(false);
      expect(result.blockers).toContain("publication_tag_gitleaks_findings");
    expect(result.public_history.tag_metadata).toMatchObject({
        finding_count: 1,
      rule_counts: { "tag-rule": 1 },
      scan: { status: "COMPLETE", exit_code: 1 },
      email: {
        occurrence_count: 2,
        allowed_count: 2,
        reviewed_history_count: 0,
        unclassified: []
      }
      });
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("annotated tagger email outside policy blocks the scan", async () => {
    resetRaceState();
    const fixture = await createFixture({
      includeTags: true,
      tagEmail: "outside@personal.invalid"
    });
    try {
      const result = await fixture.run();
      expect(result.ok).toBe(false);
      expect(result.blockers).toContain("publication_tag_email_findings");
      expect(result.public_history.tag_metadata.email.unclassified).toHaveLength(2);
      expect(
        result.public_history.tag_metadata.email.unclassified.every(
          (entry) =>
            entry.source === "annotated_tag" &&
            entry.ref === "refs/tags/outer"
        )
      ).toBe(true);
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  }, 15_000);

  test("tag metadata snapshot tampering fails post-scan verification", async () => {
    resetRaceState();
    const fixture = await createFixture({ includeTags: true });
    try {
      race.tamperTagSnapshot = true;
    expectMandatoryScanFailure(await fixture.run(), "publication_tag_scanners");
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("extra file in candidate snapshot fails post-scan verification", async () => {
    resetRaceState();
    const fixture = await createFixture();
    try {
      race.addCandidateExtraFile = true;
    expectMandatoryScanFailure(await fixture.run(), "public_history_gitleaks");
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("snapshot bytes changed during scan fail post-scan source verification", async () => {
    resetRaceState();
    const fixture = await createFixture();
    try {
      race.tamperCandidateSnapshot = true;
    expectMandatoryScanFailure(await fixture.run(), "public_history_gitleaks");
    } finally {
      resetRaceState();
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
});

test("trusted config inside the candidate root is rejected", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    const inside = join(fixture.candidate, "candidate-rules.toml");
    await writeFile(inside, "rules\n");
    expectScanNotRun(await fixture.run({
      gitleaksConfig: { path: inside, sha256: sha256("rules\n") }
    }));
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted ignore file inside the candidate root is rejected", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    const inside = join(fixture.candidate, "candidate-ignore");
    await writeFile(inside, "fingerprint\n");
    expectScanNotRun(await fixture.run({
      gitleaksIgnore: { path: inside, sha256: sha256("fingerprint\n") }
    }));
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("oversized candidate export report fails before parsing", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    const oversized = join(fixture.root, "oversized-export.json");
    await writeFile(oversized, "");
    await truncate(oversized, 16 * 1024 * 1024 + 1);
    expectScanNotRun(await fixture.run({ exportReportPath: oversized }));
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("oversized candidate file fails before digest comparison", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    await truncate(join(fixture.candidate, "README.md"), 16 * 1024 * 1024 + 1);
    expectMandatoryScanFailure(await fixture.run(), "candidate_source_snapshot");
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted input growing during its read fails closed", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    race.enabled = true;
    race.inflateReadPath = await realpath(fixture.trustedConfigPath);
    expectScanNotRun(await fixture.run());
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("growing export report fails closed at the snapshot bound", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    const reportPath = join(fixture.root, "growing-export.json");
    await writeFile(reportPath, "{}");
    race.enabled = true;
    race.growReadPath = await realpath(reportPath);
    race.growReadLimit = 2 * 16 * 1024 * 1024 + 2;
    expectScanNotRun(await fixture.run({ exportReportPath: reportPath }));
    expect(race.growReadBytes).toBe(16 * 1024 * 1024 + 1);
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("growing candidate file fails closed at the snapshot bound", async () => {
  resetRaceState();
  const fixture = await createFixture();
  try {
    race.enabled = true;
    race.growReadPath = await realpath(join(fixture.candidate, "README.md"));
    race.growReadLimit = 2 * 16 * 1024 * 1024 + 2;
    expectMandatoryScanFailure(await fixture.run(), "candidate_source_snapshot");
    expect(race.growReadBytes).toBe(16 * 1024 * 1024 + 1);
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test.each([
  ["candidateRoot", (fixture, path) => ({ candidateRoot: path })],
  ["exportReportPath", (fixture, path) => ({ exportReportPath: path })],
  ["publicRepo", (fixture, path) => ({ publicRepo: path })],
  ["gitleaksBin", (fixture, path) => ({ gitleaksBin: path })],
  ["gitleaksConfig.path", (fixture, path) => ({
    gitleaksConfig: { ...fixture.options.gitleaksConfig, path }
  })],
  ["gitleaksIgnore.path", (fixture, path) => ({
    gitleaksIgnore: { ...fixture.options.gitleaksIgnore, path }
  })]
])("direct scan rejects a symlinked parent in %s before file access", async (_label, overrideFor) => {
  resetRaceState();
  const fixture = await createDirectPathFixture();
  try {
    const sentinelDirectory = join(fixture.root, "denied-parent");
    const aliasDirectory = join(fixture.root, "denied-parent-alias");
    const deniedSentinel = join(sentinelDirectory, "denied-sentinel.json");
    const aliasFilePath = join(aliasDirectory, "denied-sentinel.json");
    await mkdir(sentinelDirectory);
    await writeFile(deniedSentinel, "neutral denied sentinel\n");
    await symlink(sentinelDirectory, aliasDirectory, "dir");
    const aliasPath = ["candidateRoot", "publicRepo"].includes(_label)
      ? aliasDirectory
      : aliasFilePath;

    race.trackFilesystemAttempts = true;
    const result = await fixture.run(overrideFor(fixture, aliasPath));

    expectScanNotRun(result);
    expect(race.scannerCalls).toBe(0);
    expect(race.filesystemAttempts.filter((attempt) =>
      attempt.operation === "open" || attempt.operation === "readFile"
    )).toEqual([]);
    expect(await readFile(deniedSentinel, "utf8")).toBe("neutral denied sentinel\n");
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test.each([
  ["candidateRoot", (fixture, path) => ({ candidateRoot: path })],
  ["exportReportPath", (fixture, path) => ({ exportReportPath: path })],
  ["publicRepo", (fixture, path) => ({ publicRepo: path })],
  ["gitleaksBin", (fixture, path) => ({ gitleaksBin: path })],
  ["gitleaksConfig.path", (fixture, path) => ({
    gitleaksConfig: { ...fixture.options.gitleaksConfig, path }
  })],
  ["gitleaksIgnore.path", (fixture, path) => ({
    gitleaksIgnore: { ...fixture.options.gitleaksIgnore, path }
  })]
])("direct scan rejects an exact restricted path in %s before file access", async (_label, overrideFor) => {
  resetRaceState();
  const fixture = await createDirectPathFixture();
  try {
    const restrictedPath = join(
      fixture.root,
      ["sec", "urity"].join(""),
      ["oss", "-security", "-policy", ".json"].join("")
    );

    race.trackFilesystemAttempts = true;
    const result = await fixture.run(overrideFor(fixture, restrictedPath));

    expectScanNotRun(result);
    expect(race.scannerCalls).toBe(0);
    expect(race.filesystemAttempts).toEqual([]);
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test.each([
  ["sharp-s case fold", "security/Oß-SECURITY-POLICY.JSON"],
  ["decomposed normalization", "nested/securi\u0301ty/oß-security-policy.json"],
  ["compatibility normalization", "nested/Ｓecurity/OSS-SECURITY-POLICY.JSON"]
])("direct scan rejects %s restricted path aliases before filesystem access", async (_label, suffix) => {
  resetRaceState();
  const fixture = await createDirectPathFixture();
  try {
    const aliasPath = join(fixture.root, suffix);

    race.trackFilesystemAttempts = true;
    const result = await fixture.run({
      gitleaksConfig: { ...fixture.options.gitleaksConfig, path: aliasPath }
    });

    expectScanNotRun(result);
    expect(race.scannerCalls).toBe(0);
    expect(race.filesystemAttempts).toEqual([]);
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("direct scan rejects preexisting symlinked path parents before opening inputs", async () => {
  resetRaceState();
  const fixture = await createDirectPathFixture();
  try {
    const aliasDirectory = join(fixture.root, "safe-parent-alias");
    const exportAlias = join(aliasDirectory, "export.json");
    const scannerAlias = join(aliasDirectory, "gitleaks-fixture");
    const configAlias = join(aliasDirectory, "trusted-gitleaks.toml");
    const ignoreAlias = join(aliasDirectory, "trusted-gitleaksignore");
    await symlink(fixture.root, aliasDirectory, "dir");

    race.trackFilesystemAttempts = true;
    const result = await fixture.run({
      exportReportPath: exportAlias,
      gitleaksBin: scannerAlias,
      gitleaksConfig: { ...fixture.options.gitleaksConfig, path: configAlias },
      gitleaksIgnore: { ...fixture.options.gitleaksIgnore, path: ignoreAlias }
    });

    expectScanNotRun(result);
    expect(result.scanner_invoked).toBe(false);
    expect(race.scannerCalls).toBe(0);
    expect(race.filesystemAttempts.filter((attempt) => attempt.operation === "open")).toEqual([]);
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("direct scan rejects a final symlink before reading its neutral denied sentinel", async () => {
  resetRaceState();
  const fixture = await createDirectPathFixture();
  try {
    const sentinelPath = join(fixture.root, "denied-sentinel-target.toml");
    const aliasPath = join(fixture.root, "denied-sentinel-config.toml");
    await writeFile(sentinelPath, "neutral denied sentinel\n");
    await symlink(sentinelPath, aliasPath, "file");

    race.trackFilesystemAttempts = true;
    const result = await fixture.run({
      gitleaksConfig: { ...fixture.options.gitleaksConfig, path: aliasPath }
    });

    expectScanNotRun(result);
    expect(race.scannerCalls).toBe(0);
    expect(race.filesystemAttempts.filter((attempt) =>
      attempt.operation === "open" || attempt.operation === "readFile"
    )).toEqual([]);
    expect(await readFile(sentinelPath, "utf8")).toBe("neutral denied sentinel\n");
  } finally {
    resetRaceState();
    await rm(fixture.root, { recursive: true, force: true });
  }
});
