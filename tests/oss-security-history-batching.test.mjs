import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
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

const { execFileMock, guardMock, historyBatches, historyLogOpts, historyReportPaths } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  guardMock: vi.fn(async () => ({ fingerprint: "fixture" })),
  historyBatches: [],
  historyLogOpts: [],
  historyReportPaths: []
}));

vi.mock("node:child_process", () => ({ execFile: execFileMock }));
vi.mock("../scripts/publication-ref-set.mjs", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, assertPublicationRefSetUnchanged: guardMock };
});

let dispatch = () => {
  throw new Error("child-process dispatch was not configured");
};

execFileMock[promisify.custom] = async (command, args) => {
  const result = dispatch(command, args);
  if (result.exitCode) {
    throw Object.assign(new Error("command failed"), {
      code: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr
    });
  }
  return { stdout: result.stdout, stderr: result.stderr };
};

execFileMock.mockImplementation((command, args, _options, callback) => {
  const result = dispatch(command, args);
  if (result.exitCode) {
    callback(
      Object.assign(new Error("command failed"), { code: result.exitCode }),
      result.stdout,
      result.stderr
    );
    return;
  }
  callback(null, result.stdout, result.stderr);
});

const scannerModule = await import("../scripts/oss-security-scan.mjs");
const { runSecurityScan } = scannerModule;

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

function gitBlobEntry(path, content) {
  return Buffer.from(
    "100644 blob " + sha256(content).slice(0, 40) + "\t" + path + "\0"
  );
}

describe("OSS security scan history batching", () => {
  test("keeps batching helpers private to match the declared scanner API", () => {
    expect(scannerModule.partitionCommitBatches).toBeUndefined();
    expect(scannerModule.scanGitleaksHistoryBatches).toBeUndefined();
  });

  test("scans every selected commit through bounded public-API batches", async () => {
    const root = await mkdtemp(join(await realpath(tmpdir()), "gpt-repo-history-batches-"));
    const dependencyAudit = await createSyntheticDependencyAudit(root);
    const candidate = join(root, "candidate");
    const publicRepo = join(root, "public");
    const scanner = join(root, "gitleaks-fixture");
    const exportReportPath = join(root, "export.json");
    const commits = Array.from({ length: 6_000 }, (_, index) =>
      index.toString(16).padStart(40, "0")
    );
    const target = commits.at(-1);
    const originalCommits = [...commits];
    const selectedCommitSet = new Set(commits);
    const selectedTree = "a".repeat(40);
    const unselectedRefCommit = "f".repeat(40);
    const unselectedTree = "e".repeat(40);
    const unsupportedAliasPath = "Security/OSS-SECURITY-POLICY.JSON";
    const treeBindings = [];
    const preflightTreeTargets = [];
    const historyScanTrace = [];
    const allRefsRequests = [];

    try {
      await mkdir(join(candidate, "node_modules"), { recursive: true });
      await mkdir(publicRepo, { recursive: true });
      const candidateFile = "fixture\n";
      const packageJson = JSON.stringify({ name: "fixture", version: "1.0.0" }) + "\n";
      const packageLock =
        JSON.stringify({
          name: "fixture",
          version: "1.0.0",
          lockfileVersion: 3,
          requires: true,
          packages: { "": { name: "fixture", version: "1.0.0" } }
        }) + "\n";
      await writeFile(join(candidate, "README.md"), candidateFile);
      await writeFile(join(candidate, "package.json"), packageJson);
      await writeFile(join(candidate, "package-lock.json"), packageLock);
      await writeFile(join(candidate, ".gitleaks.toml"), "");
      await writeFile(join(candidate, ".gitleaksignore"), "");
      await writeFile(scanner, "fixture scanner\n");
      const trustedConfig = join(root, "trusted-gitleaks.toml");
      const trustedIgnore = join(root, "trusted-gitleaksignore");
      const trustedConfigBody = "title = \"history batching fixture\"\n";
      const trustedIgnoreBody = "";
      await writeFile(trustedConfig, trustedConfigBody);
      await writeFile(trustedIgnore, trustedIgnoreBody);

      const sourceFiles = {
        "README.md": candidateFile,
        "package.json": packageJson,
        "package-lock.json": packageLock,
        ".gitleaks.toml": "",
        ".gitleaksignore": ""
      };
      const sourcePaths = Object.keys(sourceFiles);
      const pathsByTree = new Map([
        [selectedTree, sourcePaths],
        [unselectedTree, [unsupportedAliasPath]]
      ]);
      const files = Object.entries(sourceFiles).map(([path, content]) => ({
        path,
        bytes: Buffer.byteLength(content),
        sha256: sha256(content)
      }));
      await writeFile(
        exportReportPath,
        JSON.stringify({ source_commit: target, files, tree_sha256: exportTree(files) })
      );

      historyBatches.length = 0;
      historyLogOpts.length = 0;
      historyReportPaths.length = 0;
      guardMock.mockClear();
      dispatch = (command, args) => {
        if (isSyntheticDependencyAuditCommand(command)) {
    if (args[0] === "--version") return { stdout: "synthetic-audit-fixture/1\n", stderr: "" };
          return { stdout: syntheticDependencyAuditOutput(), stderr: "" };
        }
        if (
          command === scanner ||
          command.endsWith("/gitleaks-fixture") ||
          command.endsWith("/gitleaks-bin")
        ) {
          if (args[0] === "version") {
            return { stdout: "8.30.1\n", stderr: "" };
          }
          const reportPath = args[args.indexOf("--report-path") + 1];
          historyReportPaths.push(reportPath);
          if (args[0] === "dir") {
            writeFileSync(reportPath, "[]");
          } else {
            historyScanTrace.push("gitleaks-history");
            const logOpts = args[args.indexOf("--log-opts") + 1];
            const tokens = logOpts.split(" ");
            const pathspecStart = tokens.indexOf("--");
            const end = pathspecStart === -1 ? tokens.length : pathspecStart;
            const batch = tokens[0] === "--no-walk"
              ? tokens.slice(1, end)
              : tokens.slice(0, end);
            historyBatches.push(batch);
            historyLogOpts.push(logOpts);
            writeFileSync(
              reportPath,
              JSON.stringify([
                { RuleID: "shared", StartLine: 1 },
                { RuleID: "batch", Commit: batch[0], StartLine: 1 }
              ])
            );
          }
          return {
            stdout: "",
            stderr: "",
            exitCode: args[0] === "git" ? 1 : 0
          };
        }
        if (command === "git") {
          const gitArgs = args.slice(2);
          if (gitArgs[0] === "rev-parse") {
            const operand = gitArgs.at(-1);
            if (operand === "--show-toplevel") {
              return { stdout: `${publicRepo}\n`, stderr: "" };
            }
            if (operand === "HEAD") {
              return { stdout: `${target}\n`, stderr: "" };
            }
            if (operand === "--is-shallow-repository") {
              return { stdout: "false\n", stderr: "" };
            }
            if (operand === "refs/heads/main" && gitArgs.includes("--verify")) {
              return { stdout: `${target}\n`, stderr: "" };
            }
            if (operand === "refs/heads/main^{commit}") {
              return { stdout: `${target}\n`, stderr: "" };
            }
            if (operand.endsWith("^{tree}")) {
              const commit = operand.slice(0, -7);
              const tree = selectedCommitSet.has(commit)
                ? selectedTree
                : commit === unselectedRefCommit
                  ? unselectedTree
                  : null;
              treeBindings.push({ commit, tree });
              return tree
                ? { stdout: `${tree}\n`, stderr: "" }
                : { exitCode: 128, stdout: "", stderr: "unknown revision" };
            }
            if (operand.endsWith("^{commit}")) {
              const commit = operand.slice(0, -9);
              if (selectedCommitSet.has(commit)) {
                return { stdout: `${commit}\n`, stderr: "" };
              }
            }
            if (selectedCommitSet.has(operand)) {
              return { stdout: `${operand}\n`, stderr: "" };
            }
            return { exitCode: 128, stdout: "", stderr: "unknown revision" };
          }
          if (gitArgs[0] === "rev-list" && gitArgs[1] === "--all") {
            allRefsRequests.push(gitArgs);
            return {
              stdout: `${[...commits, unselectedRefCommit].join("\n")}\n`,
              stderr: ""
            };
          }
          if (gitArgs[0] === "ls-tree" && gitArgs.includes("--name-only")) {
            const tree = gitArgs.at(-1);
            preflightTreeTargets.push(tree);
            historyScanTrace.push(`preflight-tree:${tree}`);
            const paths = pathsByTree.get(tree) ?? sourcePaths;
            return {
              stdout: Buffer.from(paths.join("\0") + "\0"),
              stderr: ""
            };
          }
          if (gitArgs[0] === "ls-tree") {
          return {
            stdout: Buffer.concat(
              Object.entries(sourceFiles).map(([path, content]) =>
                gitBlobEntry(path, content)
              )
            ),
            stderr: ""
          };
        }
        if (gitArgs[0] === "cat-file" && gitArgs[1] === "-t") {
          return { stdout: "commit\n", stderr: "" };
        }
        if (gitArgs[0] === "cat-file" && gitArgs[1] === "blob") {
          const object = gitArgs[2];
          const path = Object.keys(sourceFiles).find(
            (candidatePath) =>
              sha256(sourceFiles[candidatePath]).slice(0, 40) === object
          );
          return { stdout: Buffer.from(sourceFiles[path]), stderr: "" };
        }
          if (gitArgs[0] === "rev-list" && gitArgs[1] === "--topo-order") {
            return { stdout: `${commits.join("\n")}\n`, stderr: "" };
          }
          if (gitArgs[0] === "log" || gitArgs[0] === "rev-list") {
            return { stdout: "", stderr: "" };
          }
        }
        return { exitCode: 1, stdout: "", stderr: "unexpected command" };
      };

      const policy = {
        schema_version: 1,
        policy_version: "fixture",
        gitleaks: {
          version: "8.30.1",
          assets: {
            [`${process.platform}_${process.arch}`]: {
              binary_sha256: sha256(await readFile(scanner))
            }
          }
        },
        email: {
          allowed_domains: [],
          allowed_addresses: [],
          reviewed_public_history_locations: []
        },
        licenses: { allowed: [] },
        dependency_audit: dependencyAudit.policy,
        known_development_advisories: []
      };
      const publication = {
        fingerprint: "fixture",
        candidate: { kind: "ref", ref: "refs/heads/main" },
        target: { kind: "ref", ref: "refs/heads/main" },
        refs: [{ ref: "refs/heads/main", commit_sha: target }],
        commits,
        pinned_commits: [target],
        commit_count: commits.length
      };
      const runScan = () => runSecurityScan({
        candidateRoot: candidate,
        exportReportPath,
        publicRepo,
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
        policyProvenance: { kind: "synthetic_fixture", fixture_id: "history-batching", policy_sha256: sha256(JSON.stringify(policy)) },
        publication
      });
      const result = await runScan();
      const firstSelectedTreeBindings = treeBindings.slice(0, commits.length);
      expect(firstSelectedTreeBindings).toHaveLength(commits.length);
      expect(
        sha256(
          firstSelectedTreeBindings
            .map(({ commit, tree }) => `${commit}\0${tree}`)
            .join("\n")
        )
      ).toBe(
        sha256(commits.map((commit) => `${commit}\0${selectedTree}`).join("\n"))
      );
      expect(preflightTreeTargets[0]).toBe(selectedTree);
      expect(preflightTreeTargets).not.toContain(unselectedTree);
      expect(treeBindings.some(({ commit }) => commit === unselectedRefCommit)).toBe(false);
      expect(allRefsRequests).toHaveLength(0);
      expect(publication.commits).toEqual(originalCommits);
      const selectedTreePreflightIndex = historyScanTrace.indexOf(
        `preflight-tree:${selectedTree}`
      );
      const firstGitleaksHistoryIndex = historyScanTrace.indexOf("gitleaks-history");
      expect(selectedTreePreflightIndex).toBeGreaterThanOrEqual(0);
      expect(firstGitleaksHistoryIndex).toBeGreaterThan(selectedTreePreflightIndex);

      expect(result.status, JSON.stringify(result)).toBe("FAILED");
      expect(result.blockers).toContain("public_history_gitleaks_findings");
      expect(guardMock).toHaveBeenCalledTimes(1);

      expect(historyBatches.length).toBeGreaterThan(1);
      expect(historyBatches.flat()).toEqual(commits);
      expect(new Set(historyBatches.flat()).size).toBe(commits.length);
      expect(historyLogOpts.length).toBe(historyBatches.length);
      expect(historyReportPaths.length).toBe(historyBatches.length + 1);
      expect(new Set(historyReportPaths).size).toBe(historyReportPaths.length);
      expect(
        historyLogOpts.every((logOpts) => logOpts.startsWith("--no-walk "))
      ).toBe(true);
      for (const batch of historyBatches) {
        expect(Buffer.byteLength(batch.join(" "))).toBeLessThanOrEqual(16 * 1024);
      }
      // Separate batches already contain disjoint selected commits. A report
      // object's JSON shape is not a global identity, so matching fields from
      // different batches must not discard one of the findings.
  expect(result.public_history.gitleaks).toMatchObject({
        finding_count: historyBatches.length * 2,
        rule_counts: {
          batch: historyBatches.length,
          shared: historyBatches.length
    }
      });
  expect(result.public_history.gitleaks.scan_batches).toHaveLength(historyBatches.length);
  expect(result.public_history.gitleaks.scan_batches.every((batch) =>
    batch.exit_code === 1 && /^[a-f0-9]{64}$/.test(batch.report_sha256)
  )).toBe(true);

      pathsByTree.set(selectedTree, [...sourcePaths, unsupportedAliasPath]);
      treeBindings.length = 0;
      preflightTreeTargets.length = 0;
      historyScanTrace.length = 0;
      allRefsRequests.length = 0;
      historyBatches.length = 0;
      historyLogOpts.length = 0;
      historyReportPaths.length = 0;
      guardMock.mockClear();

      const selectedAliasResult = await runScan();
      expect(selectedAliasResult.status).toBe("INCOMPLETE");
      expect(selectedAliasResult.cause_code).toBe("RESTRICTED_POLICY_ALIAS_UNSUPPORTED");
      expect(preflightTreeTargets).toEqual([selectedTree]);
      expect(historyBatches).toHaveLength(0);
      expect(historyLogOpts).toHaveLength(0);
      expect(historyScanTrace).not.toContain("gitleaks-history");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
