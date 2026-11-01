import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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

const { execFileMock, guardMock, lstatMock, readFileMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  guardMock: vi.fn(async () => ({ fingerprint: "fixture" })),
  lstatMock: vi.fn(),
  readFileMock: vi.fn()
}));

vi.mock("node:child_process", () => ({ execFile: execFileMock }));
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal();
  lstatMock.mockImplementation(actual.lstat);
  readFileMock.mockImplementation(actual.readFile);
  return { ...actual, lstat: lstatMock, readFile: readFileMock };
});
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

const { runSecurityScan } = await import("../scripts/oss-security-scan.mjs");

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

function blobEntry(path, content) {
  return Buffer.from("100644 blob " + sha256(content).slice(0, 40) + "\t" + path + "\0");
}

async function createFixture(options) {
  const root = await mkdtemp(join(await realpath(tmpdir()), "gpt-repo-export-completeness-"));
  try {
    return await createFixtureWithRoot(root, options);
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function createFixtureWithRoot(root, {
  candidateFiles,
  sourceFiles,
  reportFiles,
  publication,
  setupFailure
}) {
  const dependencyAudit = await createSyntheticDependencyAudit(root);
  await setupFailure?.(root);
  const candidate = join(root, "candidate");
  const publicRepo = join(root, "public");
  const scanner = join(root, "gitleaks-fixture");
  const exportReportPath = join(root, "export.json");
  const commit = "a".repeat(40);
  const dependencyFiles = {
    "package.json": JSON.stringify({ name: "fixture", version: "1.0.0" }) + "\n",
    "package-lock.json":
      JSON.stringify({
        name: "fixture",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: { "": { name: "fixture", version: "1.0.0" } }
      }) + "\n"
  };
  const dependencyReportFiles = Object.entries(dependencyFiles).map(
    ([path, content]) => ({
      path,
      bytes: Buffer.byteLength(content),
      sha256: sha256(content)
    })
  );
  candidateFiles = { ...dependencyFiles, ...candidateFiles };
  sourceFiles = { ...dependencyFiles, ...sourceFiles };
  reportFiles = [
    ...dependencyReportFiles,
    ...reportFiles.filter((entry) => !(entry.path in dependencyFiles))
  ];
  await mkdir(join(candidate, "node_modules"), { recursive: true });
  await mkdir(publicRepo, { recursive: true });
  for (const [path, content] of Object.entries(candidateFiles)) {
    await mkdir(dirname(join(candidate, path)), { recursive: true });
    await writeFile(join(candidate, path), content);
  }
  await writeFile(scanner, "fixture scanner\n");
  const trustedConfig = join(root, "trusted-gitleaks.toml");
  const trustedIgnore = join(root, "trusted-gitleaksignore");
  const trustedConfigBody = "title = \"export completeness fixture\"\n";
  const trustedIgnoreBody = "";
  await writeFile(trustedConfig, trustedConfigBody);
  await writeFile(trustedIgnore, trustedIgnoreBody);
  await writeFile(
    exportReportPath,
    JSON.stringify({
      source_commit: commit,
      files: reportFiles,
      tree_sha256: exportTree(reportFiles)
    })
  );

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
      if (args[0] === "version") return { stdout: "8.30.1\n", stderr: "" };
      const reportPath = args[args.indexOf("--report-path") + 1];
      writeFileSync(reportPath, "[]");
      return { stdout: "", stderr: "" };
    }
    if (command === "git") {
      const rest = args.slice(2);
      if (rest[0] === "rev-parse" && rest[1] === "--show-toplevel") {
        return { stdout: publicRepo + "\n", stderr: "" };
      }
      if (rest[0] === "rev-parse" && rest[1] === "HEAD") {
        return { stdout: commit + "\n", stderr: "" };
      }
      if (rest[0] === "rev-parse") {
        return { stdout: commit + "\n", stderr: "" };
      }
      if (rest[0] === "rev-list" && rest[1] === "--all") {
        return { stdout: commit + "\n", stderr: "" };
      }
      if (rest[0] === "rev-list" && rest[1] === "--topo-order") {
        return { stdout: commit + "\n", stderr: "" };
      }
      if (rest[0] === "ls-tree" && rest.includes("--name-only")) {
        return {
          stdout: Buffer.from(Object.keys(sourceFiles).join("\0") + "\0"),
          stderr: ""
        };
      }
      if (rest[0] === "ls-tree") {
        return {
          stdout: Buffer.concat(
            Object.entries(sourceFiles).map(([path, content]) => blobEntry(path, content))
          ),
          stderr: ""
        };
      }
      if (rest[0] === "cat-file" && rest[1] === "-t") {
        return { stdout: "commit\n", stderr: "" };
      }
      if (rest[0] === "cat-file" && rest[1] === "blob") {
        const target = rest[2];
        const path = target.includes(":") ? target.slice(commit.length + 1) : undefined;
        const content = path
          ? sourceFiles[path]
          : sourceFiles[
              Object.keys(sourceFiles).find(
                (candidatePath) =>
                  sha256(sourceFiles[candidatePath]).slice(0, 40) === target
              )
            ];
        return { stdout: Buffer.from(content), stderr: "" };
      }
      if (rest[0] === "log") {
        return { stdout: commit + "\tfixture@example.com\tfixture@example.com\n", stderr: "" };
      }
      if (rest[0] === "rev-list" && rest[1] === "--objects") {
        return { stdout: "", stderr: "" };
      }
    }
    throw new Error("unexpected command: " + command + " " + args.join(" "));
  };

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
    licenses: { allowed: ["MIT"] },
    dependency_audit: dependencyAudit.policy,
    known_development_advisories: []
  };

  return {
    root,
    run: async () => {
      const result = await runSecurityScan({
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
        policyProvenance: { kind: "synthetic_fixture", fixture_id: "export-completeness", policy_sha256: sha256(JSON.stringify(policy)) },
    publication: publication ?? {
          fingerprint: "fixture",
          candidate: { kind: "ref", ref: "refs/heads/main" },
          target: { kind: "ref", ref: "refs/heads/main" },
          refs: [{ ref: "refs/heads/main", commit_sha: commit }],
          pinned_commits: [commit],
          commits: [commit],
          commit_count: 1
        }
      });
      return result;
    }
  };
}

describe("candidate export completeness", () => {
  test("removes the temp root when fixture setup throws before returning a handle", async () => {
    let fixtureRoot;
    let fixture;
    try {
      await expect(
        createFixture({
          candidateFiles: { "README.md": "candidate\n" },
          sourceFiles: { "README.md": "candidate\n" },
          reportFiles: [],
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


  test("rejects an empty export report", async () => {
    const fixture = await createFixture({
      candidateFiles: { "README.md": "candidate\n" },
      sourceFiles: { "README.md": "candidate\n" },
      reportFiles: []
    });
    try {
      expectMandatoryScanFailure(await fixture.run(), "candidate_source_snapshot");
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects a partial export report", async () => {
    const fixture = await createFixture({
      candidateFiles: { "README.md": "candidate\n", "src/app.js": "export {};\n" },
      sourceFiles: { "README.md": "candidate\n", "src/app.js": "export {};\n" },
      reportFiles: [
        {
          path: "README.md",
          bytes: Buffer.byteLength("candidate\n"),
          sha256: sha256("candidate\n")
        }
      ]
    });
    try {
      expectMandatoryScanFailure(await fixture.run(), "candidate_source_snapshot");
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects an export entry absent from the source commit", async () => {
    const fixture = await createFixture({
      candidateFiles: { "README.md": "candidate\n", "extra.js": "extra\n" },
      sourceFiles: { "README.md": "candidate\n" },
      reportFiles: [
        {
          path: "README.md",
          bytes: Buffer.byteLength("candidate\n"),
          sha256: sha256("candidate\n")
        },
        {
          path: "extra.js",
          bytes: Buffer.byteLength("extra\n"),
          sha256: sha256("extra\n")
        }
      ]
    });
    try {
      lstatMock.mockClear();
      readFileMock.mockClear();
      const result = await fixture.run();
      const touchedPaths = [
        ...lstatMock.mock.calls,
        ...readFileMock.mock.calls
      ].map(([path]) => String(path));
      expect(touchedPaths.some((path) => path.endsWith("extra.js"))).toBe(false);
      expectMandatoryScanFailure(result, "candidate_source_snapshot");
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects a forbidden export path before reading it", async () => {
    const forbiddenPath = "security/synthetic-export-policy.json";
    const forbiddenContent = "synthetic fixture content, not a policy document\n";
    const fixture = await createFixture({
      candidateFiles: {
        "README.md": "candidate\n",
        [forbiddenPath]: forbiddenContent
      },
      sourceFiles: { "README.md": "candidate\n" },
      reportFiles: [
        {
          path: "README.md",
          bytes: Buffer.byteLength("candidate\n"),
          sha256: sha256("candidate\n")
        },
        {
          path: forbiddenPath,
          bytes: Buffer.byteLength(forbiddenContent),
          sha256: sha256(forbiddenContent)
        }
      ]
    });
    try {
      lstatMock.mockClear();
      readFileMock.mockClear();
      const result = await fixture.run();
      const statPaths = lstatMock.mock.calls.map(([path]) => String(path));
      const readPaths = readFileMock.mock.calls.map(([path]) => String(path));
      expect(statPaths.some((path) => path.endsWith(forbiddenPath))).toBe(false);
      expect(readPaths.some((path) => path.endsWith(forbiddenPath))).toBe(false);
      expectMandatoryScanFailure(result, "candidate_source_snapshot");
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects symlinked export parents before reading external bytes", async () => {
    const externalContent = "synthetic external file bytes\n";
    const fixture = await createFixture({
      candidateFiles: { "README.md": "candidate\n" },
      sourceFiles: {
        "README.md": "candidate\n",
        "leak/secret.txt": externalContent
      },
      reportFiles: [
        {
          path: "README.md",
          bytes: Buffer.byteLength("candidate\n"),
          sha256: sha256("candidate\n")
        },
        {
          path: "leak/secret.txt",
          bytes: Buffer.byteLength(externalContent),
          sha256: sha256(externalContent)
        }
      ]
    });
    try {
      const externalRoot = join(fixture.root, "external");
      const externalFile = join(externalRoot, "secret.txt");
      await mkdir(externalRoot, { recursive: true });
      await writeFile(externalFile, externalContent);
      await symlink(
        externalRoot,
        join(fixture.root, "candidate", "leak"),
        "dir"
      );
      lstatMock.mockClear();
      readFileMock.mockClear();
      const result = await fixture.run();
      const readPaths = readFileMock.mock.calls.map(([path]) => String(path));
      expect(
        readPaths.some(
          (path) =>
            path === externalFile ||
            path.endsWith(join("leak", "secret.txt"))
        )
      ).toBe(false);
      expectMandatoryScanFailure(result, "candidate_source_snapshot");
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects non-directory export parents before reading", async () => {
    const fixture = await createFixture({
      candidateFiles: {
        "README.md": "candidate\n",
        leak: "not a directory\n"
      },
      sourceFiles: {
        "README.md": "candidate\n",
        "leak/secret.txt": "synthetic nested bytes\n"
      },
      reportFiles: [
        {
          path: "README.md",
          bytes: Buffer.byteLength("candidate\n"),
          sha256: sha256("candidate\n")
        },
        {
          path: "leak/secret.txt",
          bytes: Buffer.byteLength("synthetic nested bytes\n"),
          sha256: sha256("synthetic nested bytes\n")
        }
      ]
    });
    try {
      lstatMock.mockClear();
      readFileMock.mockClear();
      const result = await fixture.run();
      const readPaths = readFileMock.mock.calls.map(([path]) => String(path));
      expect(
        readPaths.some((path) => path.endsWith(join("leak", "secret.txt")))
      ).toBe(false);
      expectMandatoryScanFailure(result, "candidate_source_snapshot");
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects embedded annotated-tag bytes supplied by publication metadata", async () => {
    const commit = "a".repeat(40);
    const tagObject = "b".repeat(40);
    const marker = "synthetic-annotated-tag-marker@example.invalid";
    const fixture = await createFixture({
      candidateFiles: { "README.md": "candidate\n" },
      sourceFiles: { "README.md": "candidate\n" },
      reportFiles: [
        {
          path: "README.md",
          bytes: Buffer.byteLength("candidate\n"),
          sha256: sha256("candidate\n")
        }
      ],
      publication: {
        fingerprint: "annotated-tag-fixture",
        candidate: { kind: "ref", ref: "refs/heads/main" },
        target: { kind: "ref", ref: "refs/heads/main" },
        refs: [
          {
            ref: "refs/heads/main",
            object_type: "commit",
            commit_sha: commit
          },
          {
            ref: "refs/tags/annotated",
            object_type: "tag",
            object_sha: tagObject,
            tag_object_sha: tagObject,
            tag_object_shas: [tagObject],
            commit_sha: commit
          }
        ],
        tag_objects: [
          {
            ref: "refs/tags/annotated",
            object_sha: tagObject,
            commit_sha: commit,
            body: marker
          }
        ],
        pinned_commits: [commit],
        commits: [commit],
        commit_count: 1
      }
    });
    try {
      expectScanNotRun(await fixture.run());
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("rejects export bytes that differ from the source commit blob", async () => {
    const fixture = await createFixture({
      candidateFiles: { "README.md": "candidate\n" },
      sourceFiles: { "README.md": "source\n" },
      reportFiles: [
        {
          path: "README.md",
          bytes: Buffer.byteLength("candidate\n"),
          sha256: sha256("candidate\n")
        }
      ]
    });
    try {
      expectMandatoryScanFailure(await fixture.run(), "candidate_source_snapshot");
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("reports incomplete email coverage for NUL candidate content", async () => {
    const binary = "binary\u0000content";
    const fixture = await createFixture({
      candidateFiles: { "README.md": "candidate\n", "binary.dat": binary },
      sourceFiles: { "README.md": "candidate\n", "binary.dat": binary },
      reportFiles: [
        {
          path: "README.md",
          bytes: Buffer.byteLength("candidate\n"),
          sha256: sha256("candidate\n")
        },
        {
          path: "binary.dat",
          bytes: Buffer.byteLength(binary),
          sha256: sha256(binary)
        }
      ]
    });
    try {
      const result = await fixture.run();
      expect(result).toMatchObject({
        status: "INCOMPLETE",
        scanner_invoked: true,
        scanner_clean: false,
        publication_eligible: false,
        blockers: ["email_coverage_incomplete"]
      });
      expect(result.code).toBeUndefined();
      expect(result.mandatory_checks.every(({ status }) => status === "complete")).toBe(true);
      expect(result.blockers).toContain("email_coverage_incomplete");
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
});
