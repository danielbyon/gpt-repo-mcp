import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";
import { runSecurityScan, runSecurityScanRequest } from "../scripts/oss-security-scan.mjs";

const sourceRoot = dirname(dirname(fileURLToPath(import.meta.url)));

const fixturePolicy = {
  schema_version: 1,
  policy_version: "synthetic-integration-fixture",
  gitleaks: { version: "fixture", assets: {} },
  email: {
    allowed_domains: [],
    allowed_addresses: [],
    reviewed_public_history_locations: []
  },
  licenses: { allowed: [] },
  known_development_advisories: []
};

async function withTemporaryRoot(run) {
  const root = await mkdtemp(join(process.cwd(), ".tmp-r12-integration."));
  try {
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function digestFile(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function writeOwnerRequest(root, overrides = {}) {
  const candidateRoot = join(root, "candidate");
  const publicRepo = join(root, "public");
  const configPath = join(sourceRoot, ".gitleaks.toml");
  const ignorePath = join(sourceRoot, ".gitleaksignore");
  await mkdir(candidateRoot);
  await mkdir(publicRepo);

  const request = {
    schema_version: 2,
    candidate_root: candidateRoot,
    export_report_path: join(root, "export-report.json"),
    public_repo: publicRepo,
    candidate_ref: "refs/heads/candidate",
    target_ref: "refs/heads/main",
    gitleaks_bin: join(root, "gitleaks-fixture"),
    gitleaks_config: { path: configPath, sha256: await digestFile(configPath) },
    gitleaks_ignore: { path: ignorePath, sha256: await digestFile(ignorePath) },
    policy_source: { kind: "owner_authorized_policy_file" },
    publication: {
      candidate: { kind: "ref", ref: "refs/heads/candidate" },
      target: { kind: "ref", ref: "refs/heads/main" }
    },
    ...overrides
  };
  const requestPath = join(root, "scan-request.json");
  await writeFile(requestPath, JSON.stringify(request));
  return { request, requestPath };
}

test("candidate email scanner is available as a runtime export", async () => {
  const scanner = await import("../scripts/oss-security-scan.mjs");

  expect(typeof scanner.candidateEmailOccurrences).toBe("function");
});

test("production policy selection fails closed when its trusted digest is unavailable", async () => {
  await withTemporaryRoot(async (root) => {
    const { requestPath } = await writeOwnerRequest(root);

    const result = await runSecurityScanRequest(requestPath);

    expect(result).toMatchObject({
      status: "NOT_RUN",
      code: "PRODUCTION_POLICY_UNAVAILABLE",
      scanner_invoked: false,
      production_eligible: false,
      publication_eligible: false,
      ok: false
    });
  });
});

test("production policy selection ignores request-supplied policy files", async () => {
  await withTemporaryRoot(async (root) => {
    const requestPolicyPath = join(root, "request-policy.json");
    await writeFile(requestPolicyPath, "not a trusted policy");
    const { request } = await writeOwnerRequest(root, { policy_path: requestPolicyPath });
    const requestPath = join(root, "scan-request.json");
    await writeFile(requestPath, JSON.stringify(request));

    const result = await runSecurityScanRequest(requestPath);

    expect(result).toMatchObject({
      status: "NOT_RUN",
      code: "PRODUCTION_POLICY_UNAVAILABLE",
      scanner_invoked: false,
      production_eligible: false,
      publication_eligible: false,
      ok: false
    });
  });
});

test.each(["gitleaks_config", "gitleaks_ignore"])(
  "production requests reject self-consistent request-selected %s inputs",
  async (inputName) => {
    await withTemporaryRoot(async (root) => {
      const { request } = await writeOwnerRequest(root);
      const fixturePath = join(root, `${inputName}.fixture`);
      const fixtureBytes = `synthetic ${inputName} fixture\n`;
      await writeFile(fixturePath, fixtureBytes);
      request[inputName] = {
        path: fixturePath,
        sha256: createHash("sha256").update(fixtureBytes).digest("hex")
      };
      const requestPath = join(root, "scan-request.json");
      await writeFile(requestPath, JSON.stringify(request));

      const result = await runSecurityScanRequest(requestPath);

      expect(result).toMatchObject({
        status: "NOT_RUN",
        scanner_invoked: false,
        publication_eligible: false,
        ok: false
      });
      expect(result.code).not.toBe("PRODUCTION_POLICY_UNAVAILABLE");
    });
  }
);

test("production scan rejects a mismatched pinned scanner-input digest", async () => {
  await withTemporaryRoot(async (root) => {
    const { request } = await writeOwnerRequest(root);
    request.gitleaks_config.sha256 = "0".repeat(64);
    const requestPath = join(root, "scan-request.json");
    await writeFile(requestPath, JSON.stringify(request));

    const result = await runSecurityScanRequest(requestPath);

    expect(result).toMatchObject({
      status: "NOT_RUN",
      scanner_invoked: false,
      publication_eligible: false,
      ok: false
    });
    expect(result.code).not.toBe("PRODUCTION_POLICY_UNAVAILABLE");
  });
});

test("production scan rejects publication refs that differ from explicit refs", async () => {
  await withTemporaryRoot(async (root) => {
    const { request } = await writeOwnerRequest(root);
    request.publication.candidate.ref = "refs/heads/other";
    const requestPath = join(root, "scan-request.json");
    await writeFile(requestPath, JSON.stringify(request));

    const result = await runSecurityScanRequest(requestPath);

    expect(result).toMatchObject({
      status: "NOT_RUN",
      scanner_invoked: false,
      publication_eligible: false,
      ok: false
    });
    expect(result.code).not.toBe("PRODUCTION_POLICY_UNAVAILABLE");
  });
});

test("security scan rejects a candidate beneath a symlinked parent", async () => {
  await withTemporaryRoot(async (root) => {
    const realParent = join(root, "real-parent");
    const candidate = join(realParent, "candidate");
    const symlinkParent = join(root, "linked-parent");
    await mkdir(candidate, { recursive: true });
    await symlink(realParent, symlinkParent);

    const result = await runSecurityScan({
      candidateRoot: join(symlinkParent, "candidate"),
      exportReportPath: join(root, "report.json"),
      publicRepo: join(root, "missing-repo"),
      gitleaksBin: join(root, "missing-gitleaks"),
      gitleaksConfig: { path: join(root, "unused-config"), sha256: "0".repeat(64) },
      gitleaksIgnore: { path: join(root, "unused-ignore"), sha256: "0".repeat(64) },
      policy: fixturePolicy,
      policyProvenance: {
        kind: "synthetic_fixture",
        fixture_id: "symlink-parent",
        policy_sha256: createHash("sha256").update(JSON.stringify(fixturePolicy)).digest("hex")
      },
      publication: {
        candidate: { kind: "ref", ref: "refs/heads/main" },
        target: { kind: "ref", ref: "refs/heads/main" }
      }
    });

    expect(result).toMatchObject({
      status: "NOT_RUN",
      code: "SCAN_INPUT_INVALID_OR_UNAVAILABLE",
      scanner_invoked: false,
      publication_eligible: false
    });
  });
});

test("package hygiene rejects missing and non-directory roots during preflight", async () => {
  const hygiene = await import("../scripts/check-package-hygiene.mjs").catch(() => null);
  expect(typeof hygiene?.checkPackageHygiene).toBe("function");

  await withTemporaryRoot(async (root) => {
    const missingRoot = join(root, "missing-package");
    const fileParent = join(root, "not-a-directory");
    await writeFile(fileParent, "synthetic fixture");

    await expect(hygiene.checkPackageHygiene({ root: missingRoot })).rejects.toMatchObject({
      code: "ENOENT"
    });
    await expect(hygiene.checkPackageHygiene({ root: join(fileParent, "package") })).rejects.toMatchObject({
      code: "ENOTDIR"
    });
  });
});

test("package hygiene rejects symlinked parent and final root components", async () => {
  const hygiene = await import("../scripts/check-package-hygiene.mjs").catch(() => null);
  expect(typeof hygiene?.checkPackageHygiene).toBe("function");

  await withTemporaryRoot(async (root) => {
    const realParent = join(root, "real-parent");
    const packageRoot = join(realParent, "package");
    const linkedParent = join(root, "linked-parent");
    const linkedRoot = join(root, "linked-root");
    await mkdir(packageRoot, { recursive: true });
    await symlink(realParent, linkedParent);
    await symlink(packageRoot, linkedRoot);

    await expect(hygiene.checkPackageHygiene({
      root: join(linkedParent, "package")
    })).rejects.toThrow(/symlink/i);
    await expect(hygiene.checkPackageHygiene({ root: linkedRoot })).rejects.toThrow(/symlink/i);
  });
});
