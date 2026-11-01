import { Buffer } from "node:buffer";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import process from "node:process";
import { expect, test, vi } from "vitest";

const openedPaths = vi.hoisted(() => []);
const inspectedPaths = vi.hoisted(() => []);

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    lstat: async (path, ...args) => {
      inspectedPaths.push(String(path));
      return actual.lstat(path, ...args);
    },
    open: async (path, ...args) => {
      openedPaths.push(String(path));
      return actual.open(path, ...args);
    }
  };
});

const {
  candidateEmailOccurrences,
  hasRestrictedPolicyPathSuffix,
  runSecurityScan,
  runSecurityScanRequest
} = await import("../scripts/oss-security-scan.mjs");
const { hasUnsupportedWindowsPathAlias } = await import(
  "../scripts/restricted-policy-path.mjs"
);

async function createTaskLocalDirectory() {
  return mkdtemp(join(process.cwd(), ".tmp-oss-security-request-"));
}

test.each([
  ["default data stream", "/fixture/security/oss-security-policy.json::$DATA"],
  ["named stream", "/fixture/neutral-sentinel.txt:metadata"]
])("rejects Win32 %s colon spelling", (_label, path) => {
  expect(hasUnsupportedWindowsPathAlias(path, "win32")).toBe(true);
});

test.each([
  ["slash separator", "C:/fixture/neutral-sentinel.txt"],
  ["backslash separator", "C:\\fixture\\neutral-sentinel.txt"]
])("allows an absolute Win32 drive colon with a %s", (_label, path) => {
  expect(hasUnsupportedWindowsPathAlias(path, "win32")).toBe(false);
});

test("does not treat a POSIX colon filename as a Windows stream alias", () => {
  expect(
    hasUnsupportedWindowsPathAlias("docs/neutral:stream-control.txt", "darwin")
  ).toBe(false);
});

function requestWithPaths(root, overrides = {}) {
  return {
    schema_version: 2,
    candidate_root: join(root, "candidate"),
    export_report_path: join(root, "export-report.json"),
    public_repo: join(root, "public"),
    candidate_ref: "refs/heads/main",
    target_ref: "refs/heads/main",
    gitleaks_bin: join(root, "gitleaks-fixture"),
    gitleaks_config: { path: join(root, "gitleaks.toml"), sha256: "0".repeat(64) },
    gitleaks_ignore: { path: join(root, "gitleaksignore"), sha256: "0".repeat(64) },
    policy_path: join(root, "denied-sentinel.json"),
    policy_source: { kind: "synthetic_fixture", fixture_id: "path-check" },
    publication: {
      candidate: { kind: "ref", ref: "refs/heads/main" },
      target: { kind: "ref", ref: "refs/heads/main" }
    },
    ...overrides
  };
}

test("rejects a request reached through a symlinked parent before opening its neutral sentinel", async () => {
  openedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const sentinelDirectory = join(root, "sentinels");
    const aliasDirectory = join(root, "request-alias");
    const sentinelPath = join(sentinelDirectory, "denied-sentinel.json");
    const aliasedRequestPath = join(aliasDirectory, "denied-sentinel.json");
    await mkdir(sentinelDirectory);
    await writeFile(sentinelPath, "neutral denied sentinel\n");
    await symlink(sentinelDirectory, aliasDirectory, "dir");

    const result = await runSecurityScanRequest(aliasedRequestPath);

    expect(result).toMatchObject({
      status: "NOT_RUN",
      code: "SCAN_INPUT_INVALID_OR_UNAVAILABLE",
      scanner_invoked: false,
      publication_eligible: false
    });
    expect(openedPaths).toEqual([]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("still opens a request from an allowed direct path", async () => {
  openedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const requestPath = join(root, "scan-request.json");
    await writeFile(requestPath, "{}");

    const result = await runSecurityScanRequest(requestPath);

    expect(result).toMatchObject({
      status: "NOT_RUN",
      scanner_invoked: false,
      publication_eligible: false
    });
    expect(openedPaths).toEqual([requestPath]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects an ADS request spelling before inspecting or opening it", async () => {
  openedPaths.length = 0;
  inspectedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const requestPath = join(root, "scan-request.json::$DATA");
    const result = await runSecurityScanRequest(requestPath, { platform: "win32" });

    expect(result).toMatchObject({
      status: "NOT_RUN",
      code: "WINDOWS_PATH_ALIAS_UNSUPPORTED",
      scanner_invoked: false
    });
    expect(openedPaths).toEqual([]);
    expect(inspectedPaths).toEqual([]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects a candidate email stream spelling before file access", async () => {
  openedPaths.length = 0;
  inspectedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const content = "ordinary@example.invalid\n";
    await writeFile(join(root, "neutral-sentinel.txt"), content);

    await expect(candidateEmailOccurrences(root, [{
      path: "neutral-sentinel.txt:metadata",
      bytes: Buffer.byteLength(content),
      sha256: createHash("sha256").update(content).digest("hex")
    }], { platform: "win32" })).rejects.toMatchObject({
      code: "WINDOWS_PATH_ALIAS_UNSUPPORTED"
    });
    expect(openedPaths).toEqual([]);
    expect(inspectedPaths).toEqual([]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("reads a legitimate POSIX colon filename under POSIX rules", async () => {
  const root = await createTaskLocalDirectory();
  try {
    const relativePath = "docs/neutral:stream-control.txt";
    const content = "posix-control@example.invalid\n";
    await mkdir(join(root, "docs"));
    await writeFile(join(root, relativePath), content);

    const result = await candidateEmailOccurrences(root, [{
      path: relativePath,
      bytes: Buffer.byteLength(content),
      sha256: createHash("sha256").update(content).digest("hex")
    }], { platform: "darwin" });

    expect(result.occurrences).toContainEqual(expect.objectContaining({
      address: "posix-control@example.invalid",
      location: { source: "candidate", path: relativePath, line: 1 }
    }));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test.each([
  ["trailing dot", "neutral-denied-sentinel.json."],
  ["trailing space", "neutral-denied-sentinel.json "],
  ["short-name shape", "NEUTRA~1/neutral-denied-sentinel.json"]
])("rejects Win32 alias-shaped request inputs before opening the neutral sentinel: %s", async (_label, relativePath) => {
  openedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    await mkdir(join(root, "candidate"));
    await mkdir(join(root, "public"));
    const sentinelPath = join(root, relativePath);
    await mkdir(dirname(sentinelPath), { recursive: true });
    await writeFile(sentinelPath, "neutral denied sentinel\n");

    const requestPath = join(root, "scan-request.json");
    await writeFile(requestPath, JSON.stringify(requestWithPaths(root, {
      policy_path: sentinelPath
    })));

    const result = await runSecurityScanRequest(requestPath, { platform: "win32" });

    expect(result).toMatchObject({
      status: "NOT_RUN",
      code: "WINDOWS_PATH_ALIAS_UNSUPPORTED",
      scanner_invoked: false,
      publication_eligible: false
    });
    expect(openedPaths).toEqual([requestPath]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("keeps an ordinary Win32 path spelling eligible for the neutral sentinel read", async () => {
  openedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    await mkdir(join(root, "candidate"));
    await mkdir(join(root, "public"));
    const sentinelPath = join(root, "neutral-denied-sentinel.json");
    await writeFile(sentinelPath, "not JSON\n");
    const requestPath = join(root, "scan-request.json");
    await writeFile(requestPath, JSON.stringify(requestWithPaths(root, {
      policy_path: sentinelPath
    })));

    const result = await runSecurityScanRequest(requestPath, { platform: "win32" });

    expect(result).toMatchObject({ status: "NOT_RUN", scanner_invoked: false });
    expect(openedPaths).toEqual([requestPath, sentinelPath]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test.each([
  ["trailing dot", "neutral-denied-sentinel.txt."],
  ["trailing space", "neutral-denied-sentinel.txt "],
  ["short-name shape", "NEUTRA~1/neutral-denied-sentinel.txt"]
])("rejects candidate email aliases before metadata or content access: %s", async (_label, relativePath) => {
  openedPaths.length = 0;
  inspectedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const sentinelPath = join(root, relativePath);
    await mkdir(dirname(sentinelPath), { recursive: true });
    const content = "ordinary@example.com\n";
    await writeFile(sentinelPath, content);

    await expect(candidateEmailOccurrences(root, [{
      path: relativePath,
      bytes: Buffer.byteLength(content),
      sha256: createHash("sha256").update(content).digest("hex")
    }], { platform: "win32" })).rejects.toMatchObject({
      code: "WINDOWS_PATH_ALIAS_UNSUPPORTED"
    });
    expect(inspectedPaths).toEqual([]);
    expect(openedPaths).toEqual([]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("candidate email classification reads a literal Win32-safe path", async () => {
  openedPaths.length = 0;
  inspectedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const relativePath = "neutral-denied-sentinel.txt";
    const sentinelPath = join(root, relativePath);
    const content = "ordinary@example.com\n";
    await writeFile(sentinelPath, content);

    const result = await candidateEmailOccurrences(root, [{
      path: relativePath,
      bytes: Buffer.byteLength(content),
      sha256: createHash("sha256").update(content).digest("hex")
    }], { platform: "win32" });

    expect(result.occurrences).toHaveLength(1);
    expect(result.occurrences[0]).toMatchObject({
      location: { source: "candidate", path: relativePath }
    });
    expect(inspectedPaths).toEqual([sentinelPath]);
    expect(openedPaths).toEqual([sentinelPath]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test.each([
  ["case-fold", `/${["SECURITY", ["OSS", "-SECURITY", "-POLICY", ".JSON"].join("")].join("/")}`],
  ["composed mark-fold", `/securíty/${["oß", "-security-policy.json"].join("")}`],
  ["decomposed mark-fold", `/securi\u0301ty/${["oß", "-security-policy.json"].join("")}`],
  ["compatibility-fold", `/Ｓecurity/${["OSS", "-SECURITY", "-POLICY", ".JSON"].join("")}`],
  ["sharp-s full fold", `/security/${["oß", "-security-policy.json"].join("")}`]
])("rejects %s restricted path aliases before source reads", async (_label, suffix) => {
  openedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const requestPath = join(root, "scan-request.json");
    const aliasPath = `${root}${suffix}`;
    expect(hasRestrictedPolicyPathSuffix(aliasPath)).toBe(true);
    await writeFile(requestPath, JSON.stringify({ policy_path: aliasPath }));

    const result = await runSecurityScanRequest(requestPath);

    expect(result).toMatchObject({
      status: "NOT_RUN",
      scanner_invoked: false,
      publication_eligible: false
    });
    expect(openedPaths).toEqual([requestPath]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects a symlinked public repository root before policy or scanner inputs are opened", async () => {
  openedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const actualPublicRoot = join(root, "public-root");
    const publicRootAlias = join(root, "public-root-alias");
    const candidateRoot = join(root, "candidate");
    const requestPath = join(root, "scan-request.json");
    await mkdir(actualPublicRoot);
    await mkdir(candidateRoot);
    await symlink(actualPublicRoot, publicRootAlias, "dir");
    const request = requestWithPaths(root, { public_repo: publicRootAlias });
    await writeFile(requestPath, JSON.stringify(request));

    const result = await runSecurityScanRequest(requestPath);

    expect(result).toMatchObject({ status: "NOT_RUN", scanner_invoked: false });
    expect(openedPaths).toEqual([requestPath]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects a symlinked candidate-root ancestor before policy or scanner inputs are opened", async () => {
  openedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const physicalParent = join(root, "physical-parent");
    const linkedParent = join(root, "linked-parent");
    const actualCandidateRoot = join(physicalParent, "candidate");
    const candidateRootAlias = join(linkedParent, "candidate");
    const requestPath = join(root, "scan-request.json");
    await mkdir(actualCandidateRoot, { recursive: true });
    await mkdir(join(root, "public"));
    await symlink(physicalParent, linkedParent, "dir");
    const request = requestWithPaths(root, { candidate_root: candidateRootAlias });
    await writeFile(requestPath, JSON.stringify(request));

    const result = await runSecurityScanRequest(requestPath);

    expect(result).toMatchObject({ status: "NOT_RUN", scanner_invoked: false });
    expect(openedPaths).toEqual([requestPath]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects a symlinked scanner-input parent before policy or scanner input reads", async () => {
  openedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const actualConfigDirectory = join(root, "actual-config");
    const configAlias = join(root, "config-alias");
    const candidateRoot = join(root, "candidate");
    const publicRoot = join(root, "public");
    const requestPath = join(root, "scan-request.json");
    await mkdir(actualConfigDirectory);
    await mkdir(candidateRoot);
    await mkdir(publicRoot);
    await writeFile(join(actualConfigDirectory, "gitleaks.toml"), "neutral config sentinel\n");
    await symlink(actualConfigDirectory, configAlias, "dir");
    const request = requestWithPaths(root, {
      gitleaks_config: {
        path: join(configAlias, "gitleaks.toml"),
        sha256: "0".repeat(64)
      }
    });
    await writeFile(requestPath, JSON.stringify(request));

    const result = await runSecurityScanRequest(requestPath);

    expect(result).toMatchObject({ status: "NOT_RUN", scanner_invoked: false });
    expect(openedPaths).toEqual([requestPath]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects a symlinked policy parent before opening its neutral denied sentinel", async () => {
  openedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const actualPolicyDirectory = join(root, "actual-policies");
    const policyAlias = join(root, "policy-alias");
    const requestPath = join(root, "scan-request.json");
    await mkdir(actualPolicyDirectory);
    await mkdir(join(root, "candidate"));
    await mkdir(join(root, "public"));
    const sentinelPath = join(actualPolicyDirectory, "denied-sentinel.json");
    await writeFile(sentinelPath, "neutral denied sentinel\n");
    await symlink(actualPolicyDirectory, policyAlias, "dir");
    const request = requestWithPaths(root, {
      policy_path: join(policyAlias, "denied-sentinel.json")
    });
    await writeFile(requestPath, JSON.stringify(request));

    const result = await runSecurityScanRequest(requestPath);

    expect(result).toMatchObject({ status: "NOT_RUN", scanner_invoked: false });
    expect(openedPaths).toEqual([requestPath]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("direct scan rejects a symlinked root before opening scanner or source inputs", async () => {
  openedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const actualCandidateRoot = join(root, "actual-candidate");
    const candidateRootAlias = join(root, "candidate-alias");
    const publicRoot = join(root, "public");
    await mkdir(actualCandidateRoot);
    await mkdir(publicRoot);
    await symlink(actualCandidateRoot, candidateRootAlias, "dir");
    const policy = {};
    const result = await runSecurityScan({
      candidateRoot: candidateRootAlias,
      exportReportPath: join(root, "export-report.json"),
      publicRepo: publicRoot,
      gitleaksBin: join(root, "gitleaks-fixture"),
      gitleaksConfig: { path: join(root, "gitleaks.toml"), sha256: "0".repeat(64) },
      gitleaksIgnore: { path: join(root, "gitleaksignore"), sha256: "0".repeat(64) },
      policy,
      policyProvenance: {
        kind: "synthetic_fixture",
        fixture_id: "direct-path-check",
        policy_sha256: createHash("sha256").update(JSON.stringify(policy)).digest("hex")
      },
      publication: {
        candidate: { kind: "ref", ref: "refs/heads/main" },
        target: { kind: "ref", ref: "refs/heads/main" }
      }
    });

    expect(result).toMatchObject({
      status: "NOT_RUN",
      scanner_invoked: false,
      publication_eligible: false
    });
    expect(openedPaths).toEqual([]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("direct scan rejects Win32 trailing-dot root spelling before opening source inputs", async () => {
  openedPaths.length = 0;
  const root = await createTaskLocalDirectory();
  try {
    const candidateRoot = join(root, "candidate");
    const publicRoot = join(root, "public");
    await mkdir(candidateRoot);
    await mkdir(publicRoot);
    const policy = {};
    const result = await runSecurityScan({
      candidateRoot: `${candidateRoot}.`,
      exportReportPath: join(root, "export-report.json"),
      publicRepo: publicRoot,
      gitleaksBin: join(root, "gitleaks-fixture"),
      gitleaksConfig: { path: join(root, "gitleaks.toml"), sha256: "0".repeat(64) },
      gitleaksIgnore: { path: join(root, "gitleaksignore"), sha256: "0".repeat(64) },
      policy,
      policyProvenance: {
        kind: "synthetic_fixture",
        fixture_id: "direct-windows-alias-check",
        policy_sha256: createHash("sha256").update(JSON.stringify(policy)).digest("hex")
      },
      publication: {
        candidate: { kind: "ref", ref: "refs/heads/main" },
        target: { kind: "ref", ref: "refs/heads/main" }
      }
    }, { platform: "win32" });

    expect(result).toMatchObject({
      status: "NOT_RUN",
      cause_code: "WINDOWS_PATH_ALIAS_UNSUPPORTED",
      scanner_invoked: false,
      publication_eligible: false
    });
    expect(openedPaths).toEqual([]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
