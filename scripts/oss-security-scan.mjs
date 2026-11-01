import { execFile } from "node:child_process";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  mkdtemp,
  mkdir,
  open,
  readdir,
  readlink,
  realpath,
  rm,
  stat,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import process from "node:process";
import { URL, fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { isForbiddenPackagePath } from "./check-package-hygiene.mjs";
import {
  hasRestrictedPolicyPathSuffix as hasNormalizedRestrictedPolicySuffix,
  hasUnsupportedWindowsPathAlias
} from "./restricted-policy-path.mjs";
import {
  assertPublicationRefSetUnchanged,
  publicationGitEnvironment,
  publicationSelectionFromRefSet,
  readPublicationTagMetadata,
  resolveTagObjectChain
} from "./publication-ref-set.mjs";
const execFileAsync = promisify(execFile);
const sourceRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const MAX_HISTORY_BLOB_BYTES = 5 * 1024 * 1024;
const EXCLUDED_HISTORY_EMAIL_PATH = "security/oss-security-policy.json";
const buildExcludedHistoryPathspecs = () => [
  `:(top,exclude,glob,icase)**/${EXCLUDED_HISTORY_EMAIL_PATH}`,
  ":(top,exclude,glob,icase)**/security\\\\oss-security-policy.json",
  ":(top,exclude,glob,icase)**/*\\\\security/oss-security-policy.json",
  ":(top,exclude,glob,icase)**/*\\\\security\\\\oss-security-policy.json",
  ":(top,exclude,glob,icase)security\\\\oss-security-policy.json"
];
const DEFAULT_HISTORY_COMMIT_BATCH_BYTES = 16 * 1024;
const MAX_SCANNER_INPUT_BYTES = 5 * 1024 * 1024;
const MAX_SCANNER_BINARY_BYTES = 128 * 1024 * 1024;
const MAX_EXPORT_REPORT_BYTES = 16 * 1024 * 1024;
const GITLEAKS_PROCESS_TIMEOUT_MS = 130_000;
const MAX_DEPENDENCY_AUDIT_TIMEOUT_MS = 600_000;
const MAX_CANDIDATE_FILE_BYTES = 16 * 1024 * 1024;
const SHA256_HEX = /^[a-f0-9]{64}$/;
const WINDOWS_DRIVE_PATH = /^[A-Za-z]:/;
const ownerAuthorizedPolicyProvenance = new WeakSet();

const SAFE_SCAN_CAUSE_CODES = new Set([
  "GITLEAKS_SCAN_INCOMPLETE",
  "PRODUCTION_POLICY_UNAVAILABLE",
  "PUBLICATION_SELECTION_CHANGED",
  "RESTRICTED_POLICY_ALIAS_UNSUPPORTED",
  "WINDOWS_PATH_ALIAS_UNSUPPORTED",
  "VALIDATION_ERROR"
]);
// Production policy stays at its owner-controlled path. No approved digest is
// available here, so production selection remains unavailable until one is set.
const TRUSTED_PRODUCTION_POLICY_SOURCE = Object.freeze({
  path: join(sourceRoot, "security", "oss-security-policy.json"),
  source_id: "main-owner-controlled-oss-security-policy",
  sha256: null
});
// These digests bind production scans to the checked-in scanner rules.
const TRUSTED_GITLEAKS_CONFIG = Object.freeze({
  path: join(sourceRoot, ".gitleaks.toml"),
  sha256: "27630a96d6c55755cc37620f3933d5cab94b1eb78a726a32e11212972525d76e"
});
const TRUSTED_GITLEAKS_IGNORE = Object.freeze({
  path: join(sourceRoot, ".gitleaksignore"),
  sha256: "17220223c3774364a3223705769d6ca5ed6d89a933b4a652bca936e2d2faf8ca"
});
const GITLEAKS_ENV_ALLOWLIST = ["PATH", "LANG", "LC_ALL", "TZ"];
const GITLEAKS_ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const GITLEAKS_ENV_DENYLIST = new Set([
  "DYLD_FRAMEWORK_PATH",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "LD_LIBRARY_PATH",
  "LD_PRELOAD",
  "NODE_OPTIONS",
  "NODE_PATH"
]);
const NO_FOLLOW_SUPPORTED =
  typeof fsConstants.O_NOFOLLOW === "number" && fsConstants.O_NOFOLLOW !== 0;

/**
 * Builds the environment for every Gitleaks process. Only PATH, LANG, LC_ALL,
 * and TZ may cross the process boundary. A caller-supplied environment is
 * checked rather than trusted, so a provider cannot pass credentials through
 * an unexpected variable name. Every mandatory scan uses this environment.
 */
function gitleaksEnvironment(overrides) {
  if (overrides !== undefined) {
    if (overrides === null || typeof overrides !== "object" || Array.isArray(overrides)) {
      throw new Error("Gitleaks environment overrides must be an object.");
    }
    for (const [key, value] of Object.entries(overrides)) {
      if (
        !GITLEAKS_ENV_NAME_PATTERN.test(key) ||
        GITLEAKS_ENV_DENYLIST.has(key.toUpperCase()) ||
        !GITLEAKS_ENV_ALLOWLIST.includes(key)
      ) {
        throw new Error("Gitleaks environment variable is not permitted: " + key + ".");
      }
      if (typeof value !== "string" || value.includes("\0")) {
        throw new Error("Gitleaks environment values must be strings without NUL bytes.");
      }
    }
  }
  const environment = {};
  for (const key of GITLEAKS_ENV_ALLOWLIST) {
    const value = overrides?.[key] ?? process.env[key];
    if (value !== undefined) environment[key] = value;
  }
  return environment;
}

/**
 * Rejects restricted-path and unsupported Win32 alias spellings before file
 * metadata access, then opens a regular file read-only without following a
 * symlink in the final path component. Platforms without O_NOFOLLOW use an
 * lstat/open/fstat inode comparison and fail closed when the filesystem cannot
 * provide stable file identity. Parent-directory replacement by a hostile
 * same-account process is outside the trusted-local-operator threat model.
 */
async function openRegularFileNoFollow(path, label, platform = process.platform) {
  assertPathDoesNotTargetRestrictedPolicy(path, label, platform);
  let before;
  try {
    before = await lstat(path);
  } catch {
    throw new Error(`${label} is unavailable or is a symlink.`);
  }
  if (before.isSymbolicLink()) {
    throw new Error(`${label} is a symlink.`);
  }
  if (!before.isFile()) {
    throw new Error(`${label} is not a regular file.`);
  }
  if (before.nlink > 1) {
    throw new Error(`${label} has multiple hard links.`);
  }
  if (!Number.isSafeInteger(before.ino) || before.ino === 0) {
    throw new Error(`${label} lacks stable file identity.`);
  }
  let handle;
  try {
    handle = await open(
      path,
      fsConstants.O_RDONLY |
        (NO_FOLLOW_SUPPORTED ? fsConstants.O_NOFOLLOW : 0)
    );
  } catch {
    throw new Error(`${label} is unavailable or is a symlink.`);
  }
  try {
    const info = await handle.stat();
    if (
      !info.isFile() ||
      info.dev !== before.dev ||
      info.ino !== before.ino
    ) {
      throw new Error(`${label} changed while it was opened.`);
    }
    if (info.nlink > 1) {
      throw new Error(`${label} has multiple hard links.`);
    }
    return { handle, info };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

/**
 * Partitions selected commit ids into space-delimited argument batches that
 * stay within a UTF-8 byte budget. Every input commit appears in exactly one
 * batch, and a single commit that cannot fit in the budget is rejected.
 */
function partitionCommitBatches(
  commits,
  maxBytes = DEFAULT_HISTORY_COMMIT_BATCH_BYTES
) {
  if (!Array.isArray(commits) || commits.length === 0) {
    throw new Error("History batching requires at least one selected commit.");
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error("History batch byte budget must be a positive safe integer.");
  }

  const batches = [];
  let current = [];
  let currentBytes = 0;

  for (const commit of commits) {
    if (typeof commit !== "string" || commit.length === 0) {
      throw new Error("History batch commits must be non-empty strings.");
    }
    const commitBytes = Buffer.byteLength(commit, "utf8");
    if (commitBytes > maxBytes) {
      throw new Error("A selected commit exceeds the history batch byte budget.");
    }
    const separatorBytes = current.length === 0 ? 0 : 1;
    if (
      current.length > 0 &&
      currentBytes + separatorBytes + commitBytes > maxBytes
    ) {
      batches.push(current);
      current = [];
      currentBytes = 0;
    }
    currentBytes +=
      (current.length === 0 ? 0 : 1) + Buffer.byteLength(commit, "utf8");
    current.push(commit);
  }

  if (current.length > 0) batches.push(current);
  return batches;
}

async function runTaskLocalSecurityScan({
  candidateRoot,
  scanProgress = [],
  platform = process.platform,
  exportReportPath,
  publicRepo,
  gitleaksBin,
  policy,
  publication,
  gitleaksConfig,
  gitleaksIgnore
}) {
  if (!policy) {
    throw new Error(
      "A security policy must be supplied explicitly; the OSS security scan never loads security/oss-security-policy.json implicitly."
    );
  }
  validatePolicy(policy);
  const scope = publicationHistoryScope(publication);
  const recordStage = (name, status, details = {}) => {
    const prior = scanProgress.find((stage) => stage.name === name);
    const value = { name, status, ...details };
    if (prior) Object.assign(prior, value);
    else scanProgress.push(value);
  };
  recordStage("publication_ref_identity", "running");
  const candidate = await requireDirectory(candidateRoot, "candidate");
  const publicRoot = await requireGitRoot(publicRepo);
  if (!isAbsolute(exportReportPath)) {
    throw new Error("export report path must be absolute.");
  }
  const reportBytes = await readSnapshotBytes(
    exportReportPath,
    "Candidate export report",
    MAX_EXPORT_REPORT_BYTES,
    platform
  );
  const exportReport = JSON.parse(reportBytes.toString("utf8"));
  if (
    typeof exportReport.source_commit !== "string" ||
    exportReport.source_commit.length === 0
  ) {
    throw new Error(
      "Candidate export report must record its source commit so the publication selection can be bound."
    );
  }
  await verifyPublicationRefs(publicRoot, scope, {
    candidate_commit: exportReport.source_commit
  });
  recordStage("publication_ref_identity", "complete", {
    candidate_ref: scope.candidate.ref,
    target_ref: scope.target.ref,
    candidate_commit: scope.candidate_commit,
    target_commit: scope.target_commit,
    selection_fingerprint: scope.fingerprint
  });
  recordStage("candidate_source_snapshot", "running");
  const trustedConfigBytes = await readPinnedScannerInput(
    gitleaksConfig,
    "Gitleaks config",
    candidate,
    platform
  );
  const trustedIgnoreBytes = await readPinnedScannerInput(
    gitleaksIgnore,
    "Gitleaks ignore",
    candidate,
    platform
  );
  const trustedConfigDigest = createHash("sha256")
    .update(trustedConfigBytes)
    .digest("hex");
  const trustedIgnoreDigest = createHash("sha256")
    .update(trustedIgnoreBytes)
    .digest("hex");
  const scannerAsset = `${process.platform}_${process.arch}`;
  const scannerPolicy = policy.gitleaks.assets[scannerAsset];
  if (!scannerPolicy) {
    throw new Error(`Gitleaks is not pinned for platform ${scannerAsset}.`);
  }
  if (!isAbsolute(gitleaksBin)) {
    throw new Error("Gitleaks binary path must be absolute.");
  }
  const scannerBytes = await readSnapshotBytes(
    gitleaksBin,
    "Gitleaks binary",
    MAX_SCANNER_BINARY_BYTES,
    platform
  );
  const scannerDigest = createHash("sha256")
    .update(scannerBytes)
    .digest("hex");
  if (scannerDigest !== scannerPolicy.binary_sha256) {
    throw new Error(`Gitleaks binary checksum mismatch for ${scannerAsset}.`);
  }
  const temporary = await mkdtemp(join(tmpdir(), "gpt-repo-security-scan."));
  try {
    const scanner = await writeExecutableSnapshot(
      temporary,
      "gitleaks-bin",
      scannerBytes
    );
    const environment = gitleaksEnvironment();
    recordStage("gitleaks_version", "running", { executable: "gitleaks-bin" });
    const versionProcess = await runAllowFailure(
      scanner,
      ["version"],
      undefined,
      environment,
      { timeoutMs: GITLEAKS_PROCESS_TIMEOUT_MS }
    );
    if (versionProcess.timedOut || versionProcess.signal !== null || versionProcess.exitCode !== 0) {
      throw new Error(
        "Pinned Gitleaks version process did not complete successfully (exit " +
          String(versionProcess.exitCode) + ", signal " + String(versionProcess.signal) + ")."
      );
    }
    const version = versionProcess.stdout.trim();
    recordStage("gitleaks_version", "complete", {
      version,
      exit_code: versionProcess.exitCode,
      timed_out: versionProcess.timedOut,
      signal: versionProcess.signal
    });
    if (version !== policy.gitleaks.version) {
      throw new Error(
        `Gitleaks ${policy.gitleaks.version} is required; received ${version || "unknown"}.`
      );
    }
    const candidateScanRoot = join(temporary, "candidate-tree");
    const trustedConfigPath = await writeTaskLocalSnapshot(
      temporary,
      "gitleaks.toml",
      trustedConfigBytes
    );
    const trustedIgnorePath = await writeTaskLocalSnapshot(
      temporary,
      "gitleaksignore",
      trustedIgnoreBytes
    );
    const exportedFiles = await verifyExportedFiles(candidate, exportReport, {
      publicRoot,
      sourceCommit: exportReport.source_commit,
      snapshotRoot: candidateScanRoot,
      platform
    });
    recordStage("candidate_source_snapshot", "complete", {
      source_commit: exportReport.source_commit,
      file_count: exportedFiles.length,
      tree_sha256: exportReport.tree_sha256
    });
    recordStage("candidate_gitleaks", "running");
    const candidateLeaks = await scanGitleaks({
      scanner,
      mode: "dir",
      target: candidateScanRoot,
      config: trustedConfigPath,
      ignore: trustedIgnorePath,
      reportPath: join(temporary, "candidate.json"),
      environment
    });
    recordStage("candidate_gitleaks", "complete", {
      finding_count: candidateLeaks.finding_count,
      report_sha256: candidateLeaks.scan.report_sha256,
      exit_code: candidateLeaks.scan.exit_code,
      scan: candidateLeaks.scan
    });
    recordStage("publication_tag_scanners", "running");
    const tagScan = await scanPublicationTagMetadata({
      scanner,
      repoRoot: publicRoot,
      tagObjects: scope.tag_objects,
      reportDirectory: temporary,
      config: trustedConfigPath,
      ignore: trustedIgnorePath,
      environment
    });
    const tagLeaks = tagScan.findings;
    const tagEmails = classifyEmailOccurrences(
      tagScan.email_occurrences,
      policy.email
    );
    recordStage("publication_tag_scanners", "complete", {
      gitleaks_findings: tagLeaks.finding_count,
      gitleaks_scan: tagScan.scan,
      email_occurrences: tagEmails.occurrence_count
    });
    recordStage("public_history_gitleaks", "running");
    const historyLeaks = await scanGitleaksHistoryBatches({
      repo: publicRoot,
      platform,
      commits: scope.commits,
      reportDirectory: temporary,
      scanBatch: ({ logOpts, reportPath }) =>
        readGitleaksScanResult({
          scanner,
          mode: "git",
          target: publicRoot,
          logOpts,
          config: trustedConfigPath,
          ignore: trustedIgnorePath,
          reportPath,
          environment
        })
    });

    await verifyCandidateSnapshot(candidateScanRoot, exportedFiles, {
      publicRoot,
      sourceCommit: exportReport.source_commit,
      platform
    });
    await assertTaskLocalSnapshotUnchanged(
      trustedConfigPath,
      trustedConfigBytes,
      "Gitleaks config"
    );
    await assertTaskLocalSnapshotUnchanged(
      trustedIgnorePath,
      trustedIgnoreBytes,
      "Gitleaks ignore"
    );
    await assertTaskLocalSnapshotUnchanged(
      scanner,
      scannerBytes,
      "Gitleaks binary",
      MAX_SCANNER_BINARY_BYTES
    );

    const dependencyInputs = await readSourceDependencySnapshot(
      publicRoot,
      exportReport.source_commit,
      temporary,
      platform
    );
    recordStage("public_history_gitleaks", "complete", {
      finding_count: historyLeaks.finding_count,
      scan_batches: historyLeaks.scan_batches,
      report_sha256: historyLeaks.report_sha256
    });
    recordStage("candidate_email_classification", "running");
    const candidateEmailScan = await candidateEmailOccurrences(
      candidateScanRoot,
      exportedFiles,
      { platform }
    );
    const candidateEmailCoverage = candidateEmailScan.skipped;
    const candidateEmails = classifyEmailOccurrences(
      candidateEmailScan.occurrences,
      policy.email
    );
    recordStage("candidate_email_classification", "complete", {
      occurrence_count: candidateEmails.occurrence_count,
      source_count: candidateEmailScan.source_count,
      skipped: candidateEmailCoverage
    });
    recordStage("public_history_email_classification", "running");
    const historyEmailCoverage = {};
    const historyEmails = classifyEmailOccurrences(
      await scanHistoryEmailOccurrences(publicRoot, scope, {
        coverage: historyEmailCoverage,
        platform
      }),
      policy.email
    );
    recordStage("public_history_email_classification", "complete", {
      occurrence_count: historyEmails.occurrence_count,
      skipped: historyEmailCoverage
    });
    recordStage("dependency_license_classification", "running");
    const licenses = classifyLicenseRecords(
      sourceLicenseRecords(dependencyInputs.lock),
      policy.licenses.allowed
    );
    recordStage("dependency_license_classification", "complete", {
      package_count: licenses.package_count,
      unapproved_count: licenses.unapproved.length
    });
    recordStage("production_dependency_vulnerability_audit", "running");
    const auditRuntime = await prepareDependencyAuditRuntime(temporary);
    const auditExecutable = await snapshotDependencyAuditExecutable(policy, temporary, platform);
    const audit = await auditCandidate(dependencyInputs.auditRoot, policy, {
      ...auditExecutable,
      ...auditRuntime,
      environment: dependencyAuditEnvironment(auditRuntime)
    });
    recordStage("production_dependency_vulnerability_audit", "complete", {
      audit_executable_version: audit.evidence.executable_version,
      production_advisories: audit.production.total,
      unknown_development_advisories: audit.unknown_development.length,
      expired_development_advisories: audit.expired_development.length
    });
    recordStage("final_source_consistency", "running");
    const publicCheckedOutCommit = await git(publicRoot, ["rev-parse", "HEAD"]);
    await assertPublicationSnapshot(publicRoot, publication, scope);
    recordStage("final_source_consistency", "complete", {
      source_commit: exportReport.source_commit,
      public_checked_out_commit: publicCheckedOutCommit
    });

    const blockers = [
      ...(candidateLeaks.finding_count > 0 ? ["candidate_gitleaks_findings"] : []),
      ...(tagLeaks.finding_count > 0 ? ["publication_tag_gitleaks_findings"] : []),
      ...(tagEmails.unclassified.length > 0
        ? ["publication_tag_email_findings"]
        : []),
      ...(historyLeaks.finding_count > 0 ? ["public_history_gitleaks_findings"] : []),
      ...(candidateEmails.unclassified.length > 0 ? ["candidate_email_findings"] : []),
      ...(historyEmails.unclassified.length > 0 ? ["public_history_email_findings"] : []),
      ...(candidateEmailCoverage.large_files > 0 ||
      candidateEmailCoverage.binary_files > 0 ||
      historyEmailCoverage.blobs_skipped_large > 0 ||
      historyEmailCoverage.blobs_skipped_binary > 0
        ? ["email_coverage_incomplete"]
        : []),
      ...(licenses.unapproved.length > 0 ? ["unapproved_dependency_licenses"] : []),
      ...(audit.production.total > 0 ? ["production_dependency_advisories"] : []),
      ...(audit.unknown_development.length > 0 ? ["unknown_development_advisories"] : []),
      ...(audit.expired_development.length > 0 ? ["expired_development_advisory_review"] : [])
    ];

    return {
      schema_version: 1,
      policy_version: policy.policy_version,
      scanner: {
        name: "gitleaks",
        version,
        platform: scannerAsset,
        binary_sha256: scannerDigest,
        config_sha256: trustedConfigDigest,
        ignore_sha256: trustedIgnoreDigest
      },
      candidate: {
        source_commit: exportReport.source_commit,
        tree_sha256: exportReport.tree_sha256,
        gitleaks: candidateLeaks,
        email: candidateEmails
      },
      public_history: {
        checked_out_commit: publicCheckedOutCommit,
        selection: {
          fingerprint: scope.fingerprint,
          refs: scope.refs,
          ref_count: scope.refs.length,
          commit_count: scope.commit_count
        },
        tag_metadata: { ...tagLeaks, scan: tagScan.scan, email: tagEmails },
        gitleaks: historyLeaks,
        email: historyEmails
      },
      dependencies: {
        source: "source-commit-package-lock",
        package_json_sha256: dependencyInputs.packageJsonSha256,
        package_lock_sha256: dependencyInputs.packageLockSha256,
        licenses,
        audit
      },
      blockers,
      ok: blockers.length === 0
    };
  } finally {
    await rm(temporary, { recursive: true });
  }
}

/**
 * Reports a malformed scan request with the shared validation code so callers
 * can distinguish an argument error from a scan result.
 */
function scanOptionError(message) {
  const error = new Error(message);
  error.code = "VALIDATION_ERROR";
  return error;
}

/**
 * Keeps error identifiers in result evidence limited to known stable codes.
 * Error messages and arbitrary error properties can contain local paths.
 */
function safeScanCauseCode(error) {
  return typeof error?.code === "string" && SAFE_SCAN_CAUSE_CODES.has(error.code)
    ? error.code
    : null;
}

function assertScanOptionKeys(value, allowed, label) {
  const unknownKey = Object.keys(value).find((key) => !allowed.has(key));
  if (unknownKey !== undefined) {
    throw scanOptionError(label + ' option "' + unknownKey + '" is not supported.');
  }
}

function selectTrustedProductionPolicySource() {
  const source = TRUSTED_PRODUCTION_POLICY_SOURCE;
  return typeof source?.sha256 === "string" && SHA256_HEX.test(source.sha256)
    ? source
    : null;
}

function productionPolicyUnavailableError() {
  const error = new Error(
    "The trusted production policy source or its expected digest is unavailable; request-supplied policy labels cannot authorize production scans."
  );
  error.code = "PRODUCTION_POLICY_UNAVAILABLE";
  return error;
}

function assertTrustedProductionScannerInputs(request, checkedPaths) {
  for (const [label, supplied, checked, trusted] of [
    ["Gitleaks config", request.gitleaks_config, checkedPaths?.gitleaksConfig, TRUSTED_GITLEAKS_CONFIG],
    ["Gitleaks ignore", request.gitleaks_ignore, checkedPaths?.gitleaksIgnore, TRUSTED_GITLEAKS_IGNORE]
  ]) {
    if (!supplied || supplied.path !== trusted.path ||
        supplied.sha256 !== trusted.sha256 ||
        (checked && checked.path !== trusted.path)) {
      throw scanOptionError(`${label} must match its code-pinned path and digest.`);
    }
  }
}

/**
 * Runs every mandatory security check against an explicitly selected source
 * and a private task-local candidate snapshot. A passing scan grants technical
 * eligibility only; publication still requires separate owner approval.
 */
export async function runSecurityScan(options, { platform = process.platform } = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw scanOptionError("Scan options must be an object.");
  }
  if (Object.hasOwn(options, "trustedSource")) {
    return {
      schema_version: 2,
      status: "NOT_RUN",
      code: "HOST_ATTESTATION_RETIRED",
      reason: "The legacy trustedSource host-attestation input is retired; use the explicit trusted-local scan inputs instead.",
      obsolete_options: ["trustedSource"],
      scanner_invoked: false,
      mandatory_checks: [],
      production_eligible: false,
      scanner_clean: false,
      publication_eligible: false,
      owner_approval_required: true,
      ok: false
    };
  }
  if (options.diagnostic === true) {
    throw scanOptionError(
      "Diagnostic mode is no longer supported; provide explicit candidate and target refs to run the fail-closed scanner."
    );
  }
  const allowed = new Set([
    "candidateRoot", "exportReportPath", "publicRepo", "gitleaksBin",
    "gitleaksConfig", "gitleaksIgnore", "policy", "policyProvenance", "publication"
  ]);
  assertScanOptionKeys(options, allowed, "Security scan");
  const required = [
    "candidateRoot", "exportReportPath", "publicRepo", "gitleaksBin",
    "gitleaksConfig", "gitleaksIgnore", "policy", "policyProvenance", "publication"
  ];
  const missing = required.filter((key) => !Object.hasOwn(options, key));
  if (missing.length > 0) {
    return {
      schema_version: 2,
      status: "NOT_RUN",
      code: "SCAN_INPUT_REQUIRED",
      reason: "The explicit source selection and all mandatory scanner inputs are required.",
      missing_inputs: missing,
      scanner_invoked: false,
      mandatory_checks: [],
      scanner_clean: false,
      publication_eligible: false,
      owner_approval_required: true,
      ok: false
    };
  }
  const provenance = validatePolicyProvenance(options.policy, options.policyProvenance);
  if (provenance.status !== "valid") {
    return {
      schema_version: 2,
      status: "NOT_RUN",
      code: provenance.code,
      reason: provenance.reason,
      scanner_invoked: false,
      mandatory_checks: [],
      policy_provenance: provenance.receipt ?? null,
      production_eligible: false,
      scanner_clean: false,
      publication_eligible: false,
      owner_approval_required: true,
      ok: false
    };
  }
  const scanProgress = [];
  try {
    const checkedOptions = await canonicalizeDirectScanPaths(options, platform);
    const result = await runTaskLocalSecurityScan({
      ...checkedOptions,
      scanProgress,
      platform
    });
    const status = result.ok === true
      ? provenance.kind === "synthetic_fixture" ? "SYNTHETIC_PASSED" : "PASSED"
      : result.blockers.includes("email_coverage_incomplete") ? "INCOMPLETE" : "FAILED";
    return {
      ...result,
      schema_version: 2,
      mode: "task_local_candidate_snapshot",
      status,
      scanner_invoked: true,
      mandatory_checks: scanProgress,
      policy_provenance: provenance.receipt,
      production_eligible: status === "PASSED" && provenance.kind === "owner_authorized_policy_file",
      scanner_clean: result.ok === true,
      publication_eligible: false,
      owner_approval_required: true,
      ok: status === "PASSED"
    };
  } catch (error) {
    const scannerInvoked = scanProgress.some((stage) =>
      stage.name === "gitleaks_version" && stage.status !== "not_run"
    );
    const status = scannerInvoked ? "INCOMPLETE" : "NOT_RUN";
    const code = scannerInvoked
      ? "MANDATORY_SCAN_INCOMPLETE"
      : "SCAN_INPUT_INVALID_OR_UNAVAILABLE";
    const reason = scannerInvoked
      ? "A mandatory security check did not complete successfully."
      : "Required scan inputs could not be validated; no scanner was invoked.";
    const activeStage = [...scanProgress].reverse().find((stage) => stage.status === "running");
    if (activeStage) {
      activeStage.status = "failed";
      activeStage.reason = reason;
      if (Number.isSafeInteger(error?.exit_code) || error?.exit_code === null) {
        activeStage.exit_code = error.exit_code;
      }
      if (typeof error?.timed_out === "boolean") {
        activeStage.timed_out = error.timed_out;
      }
      if (error?.signal === null ||
          (typeof error?.signal === "string" && /^SIG[A-Z0-9]+$/.test(error.signal))) {
        activeStage.signal = error.signal;
      }
    }
    return {
      schema_version: 2,
      mode: "task_local_candidate_snapshot",
      status,
      code,
      cause_code: safeScanCauseCode(error),
      reason,
      scanner_invoked: scannerInvoked,
      mandatory_checks: scanProgress,
      policy_provenance: provenance.receipt,
      production_eligible: false,
      scanner_clean: false,
      publication_eligible: false,
      owner_approval_required: true,
      ok: false
    };
  }
}

function validatePolicyProvenance(policy, provenance) {
  if (provenance === undefined || provenance === null) {
    return {
      status: "invalid",
      code: "POLICY_PROVENANCE_REQUIRED",
      reason: "An explicit policy-source provenance record is required."
    };
  }
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    return {
      status: "invalid",
      code: "POLICY_PROVENANCE_INVALID",
      reason: "Policy provenance cannot be checked without a policy object."
    };
  }
  const policySha256 = createHash("sha256").update(JSON.stringify(policy)).digest("hex");
  if (provenance.kind === "synthetic_fixture") {
    if (typeof provenance.fixture_id !== "string" || provenance.fixture_id.length === 0 ||
        provenance.policy_sha256 !== policySha256) {
      return {
        status: "invalid",
        code: "POLICY_PROVENANCE_INVALID",
        reason: "Synthetic policy provenance is missing a fixture identifier or does not match the policy."
      };
    }
    return {
      status: "valid",
      kind: "synthetic_fixture",
      receipt: { kind: "synthetic_fixture", fixture_id: provenance.fixture_id, policy_sha256: policySha256 }
    };
  }
  if (provenance.kind === "owner_authorized_policy_file" &&
      ownerAuthorizedPolicyProvenance.has(provenance) && provenance.policy_sha256 === policySha256) {
    return {
      status: "valid",
      kind: "owner_authorized_policy_file",
      receipt: {
        kind: "owner_authorized_policy_file",
        policy_sha256: policySha256,
        source_id: provenance.source_id,
        source_sha256: provenance.source_sha256,
        request_sha256: provenance.request_sha256
      }
    };
  }
  return {
    status: "invalid",
    code: "POLICY_PROVENANCE_INVALID",
    reason: "Policy provenance is not a verified synthetic fixture or internally selected trusted production source."
  };
}


export function classifyEmailOccurrences(occurrences, policy) {
  const allowedDomains = new Set(policy.allowed_domains.map((value) => value.toLowerCase()));
  const allowedAddresses = new Set(policy.allowed_addresses.map((value) => value.toLowerCase()));
  const reviewedHistoryLocations = new Set(
    (policy.reviewed_public_history_locations ?? []).flatMap((entry) =>
      entry.roles.map((role) => `${entry.commit}:${role}`)
    )
  );
  const unclassified = [];
  let allowedCount = 0;
  let reviewedHistoryCount = 0;

  for (const occurrence of occurrences) {
    const address = occurrence.address.toLowerCase();
    const domain = address.slice(address.lastIndexOf("@") + 1);
    if (allowedAddresses.has(address) || allowedDomains.has(domain)) {
      allowedCount += 1;
    } else if (
      occurrence.location.source === "commit_metadata" &&
      reviewedHistoryLocations.has(
        `${occurrence.location.commit}:${occurrence.location.role}`
      )
    ) {
      allowedCount += 1;
      reviewedHistoryCount += 1;
    } else {
      unclassified.push(occurrence.location);
    }
  }
  return {
    occurrence_count: occurrences.length,
    allowed_count: allowedCount,
    reviewed_history_count: reviewedHistoryCount,
    unclassified
  };
}

export function classifyLicenseRecords(records, allowedLicenses) {
  const allowed = new Set(allowedLicenses);
  const counts = {};
  const unapproved = [];
  for (const record of records) {
    counts[record.license] = (counts[record.license] ?? 0) + 1;
    if (!allowed.has(record.license)) unapproved.push(record);
  }
  return {
    package_count: records.length,
    license_counts: Object.fromEntries(Object.entries(counts).sort()),
    unapproved: unapproved.sort((left, right) => left.name.localeCompare(right.name))
  };
}

export function classifyAudit(fullAudit, productionAudit, policy, today = new Date()) {
  const full = auditEntries(fullAudit, "Full npm audit");
  const production = auditEntries(productionAudit, "Production npm audit");
  const known = new Map(policy.known_development_advisories.map((entry) => [entry.package, entry]));
  const productionNames = new Set(production.entries.map(({ package: name }) => name));
  const development = full.entries.filter(({ package: name }) => !productionNames.has(name));
  const unknownDevelopment = development.filter((entry) => {
    const expected = known.get(entry.package);
    return !expected || expected.severity !== entry.severity;
  });
  const expiredDevelopment = development.filter((entry) => {
    const expected = known.get(entry.package);
    return expected && new Date(`${expected.review_by}T23:59:59Z`) < today;
  });

  return {
    production,
    development: {
      total: development.length,
      entries: development
    },
    unknown_development: unknownDevelopment,
    expired_development: expiredDevelopment
  };
}

function incompleteGitleaksScanError(message, details = {}) {
  const error = new Error(message);
  error.code = "GITLEAKS_SCAN_INCOMPLETE";
  Object.assign(error, details);
  return error;
}

async function readGitleaksScanResult({
  scanner,
  mode,
  target,
  config,
  ignore,
  reportPath,
  logOpts,
  environment
}) {
  const result = await runAllowFailure(scanner, [
    mode,
    target,
    ...(logOpts ? ["--log-opts", logOpts] : []),
    "--config", config,
    "--gitleaks-ignore-path", ignore,
    "--no-banner", "--no-color", "--redact=100",
    "--report-format", "json",
    "--report-path", reportPath,
    "--timeout", "120"
  ], undefined, environment, { timeoutMs: GITLEAKS_PROCESS_TIMEOUT_MS });
  if (result.timedOut || result.signal !== null) {
    throw incompleteGitleaksScanError(
      `Gitleaks ${mode} scan did not complete${result.signal === null ? "" : ` (signal ${result.signal})`}.`,
      { exit_code: result.exitCode, timed_out: result.timedOut, signal: result.signal }
    );
  }
  if (![0, 1].includes(result.exitCode)) {
    throw incompleteGitleaksScanError(
      `Gitleaks ${mode} scan failed with exit code ${result.exitCode}.`,
      { exit_code: result.exitCode, timed_out: result.timedOut, signal: result.signal }
    );
  }
  let reportBytes;
  let findings;
  try {
    reportBytes = await readSnapshotBytes(reportPath, "Gitleaks report", MAX_SCANNER_INPUT_BYTES);
    findings = JSON.parse(reportBytes.toString("utf8"));
  } catch (error) {
    throw incompleteGitleaksScanError(
      `Gitleaks ${mode} scan did not produce a valid report: ${error.message}`,
      { exit_code: result.exitCode, timed_out: result.timedOut, signal: result.signal }
    );
  }
  if (!Array.isArray(findings)) throw new Error(`Gitleaks ${mode} report must be a JSON array.`);
  if (result.exitCode === 1 && findings.length === 0) {
    throw incompleteGitleaksScanError(`Gitleaks ${mode} scan exited 1 without findings; scan completion is not proven.`, { exit_code: result.exitCode });
  }
  if (result.exitCode === 0 && findings.length > 0) {
    throw incompleteGitleaksScanError(`Gitleaks ${mode} scan exited 0 with findings; scanner exit status is inconsistent.`, { exit_code: result.exitCode });
  }
  return {
    findings,
    exit_code: result.exitCode,
    report_sha256: createHash("sha256").update(reportBytes).digest("hex"),
    stdout_sha256: createHash("sha256").update(result.stdout).digest("hex"),
    stderr_sha256: createHash("sha256").update(result.stderr).digest("hex"),
    timed_out: false
  };
}

async function readPinnedScannerInput(input, label, candidateRoot, platform = process.platform) {
  if (!input || typeof input !== "object" || Array.isArray(input) ||
      typeof input.path !== "string" || !isAbsolute(input.path) ||
      typeof input.sha256 !== "string" || !SHA256_HEX.test(input.sha256)) {
    throw new Error(`${label} requires an absolute path and lowercase SHA-256 digest.`);
  }
  assertPathDoesNotTargetRestrictedPolicy(input.path, label, platform);
  const resolvedParent = await realpath(dirname(input.path));
  const resolvedInput = join(resolvedParent, basename(input.path));
  if (resolvedInput === candidateRoot || resolvedInput.startsWith(`${candidateRoot}${sep}`)) {
    throw new Error(`${label} must resolve outside the candidate root: ${input.path}`);
  }
  const { handle, info } = await openRegularFileNoFollow(input.path, label, platform);
  try {
    if (info.size > MAX_SCANNER_INPUT_BYTES) {
      throw new Error(`${label} must be a regular file within the scanner input size limit.`);
    }
    const bytes = await readBoundedHandleBytes(handle, label, MAX_SCANNER_INPUT_BYTES);
    if (bytes.byteLength !== info.size) throw new Error(`${label} changed while it was read.`);
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (digest !== input.sha256) throw new Error(`${label} SHA-256 digest does not match the selected value.`);
    return bytes;
  } finally {
    await handle.close();
  }
}

/**
 * Reads an open regular file while never buffering more than maxBytes + 1.
 *
 * The destination buffer is allocated once at exactly maxBytes + 1 bytes, so
 * memory use stays bounded by the caller's cap even when the file grows
 * between the stat and the read. Reading stops as soon as the cap is crossed
 * and the call fails closed instead of returning the excess. A file that grew
 * only within the cap is still rejected by the caller's size comparison.
 */
async function readBoundedHandleBytes(handle, label, maxBytes) {
  const buffer = Buffer.allocUnsafe(maxBytes + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await handle.read(
      buffer,
      offset,
      buffer.length - offset,
      offset
    );
    if (bytesRead === 0) {
      break;
    }
    offset += bytesRead;
  }
  if (offset > maxBytes) {
    throw new Error(
      `${label} exceeds the ${maxBytes}-byte snapshot bound.`
    );
  }
  return buffer.subarray(0, offset);
}

/**
 * Reads a regular-file snapshot within maxBytes and verifies that the read
 * matches the size observed when the file was opened.
 */
async function readSnapshotBytes(
  path,
  label,
  maxBytes = MAX_SCANNER_INPUT_BYTES,
  platform = process.platform
) {
  const { handle, info } = await openRegularFileNoFollow(path, label, platform);
  try {
    if (info.size > maxBytes) {
      throw new Error(
        `${label} exceeds the ${maxBytes}-byte snapshot bound.`
      );
    }
    const bytes = await readBoundedHandleBytes(handle, label, maxBytes);
    if (bytes.byteLength !== info.size) {
      throw new Error(`${label} snapshot changed while it was read.`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function writeTaskLocalSnapshot(directory, name, bytes) {
  const path = join(directory, name);
  await writeFile(path, bytes, { flag: "wx", mode: 0o400 });
  await assertTaskLocalSnapshotUnchanged(path, bytes, name);
  return path;
}

async function writeExecutableSnapshot(directory, name, bytes) {
  const path = join(directory, name);
  await writeFile(path, bytes, { flag: "wx", mode: 0o500 });
  await assertTaskLocalSnapshotUnchanged(
    path,
    bytes,
    "Gitleaks binary",
    MAX_SCANNER_BINARY_BYTES
  );
  return path;
}

async function assertTaskLocalSnapshotUnchanged(
  path,
  expected,
  label,
  maxBytes = MAX_SCANNER_INPUT_BYTES
) {
  const current = await readSnapshotBytes(path, label, maxBytes);
  if (
    current.byteLength !== expected.byteLength ||
    createHash("sha256").update(current).digest("hex") !==
      createHash("sha256").update(expected).digest("hex")
  ) {
    throw new Error(`${label} snapshot changed after verification.`);
  }
}

/**
 * Scans Git tag object metadata, including every object in each selected tag
 * chain, from a private snapshot. Only selected-chain object ids supplied by
 * the validated publication scope are read. The source tag objects are read
 * again after the scanner returns and must be byte-identical.
 */
async function scanPublicationTagMetadata({
  scanner,
  repoRoot,
  tagObjects,
  reportDirectory,
  config,
  ignore,
  environment,
  executionBinding,
  executionEvidence,
  stage
}) {
  if (!Array.isArray(tagObjects) || tagObjects.length === 0) {
    return {
      findings: summarizeGitleaksFindings([]),
      scan: { status: "NOT_RUN", reason: "No selected tag metadata requires scanning." },
      email_occurrences: []
    };
  }
  const metadata = await readPublicationTagMetadata(repoRoot, tagObjects);
  const tagRoot = join(reportDirectory, "tag-metadata");
  await mkdir(tagRoot, { recursive: true, mode: 0o700 });
  const snapshotNames = metadata.map(
    (entry, index) =>
      `${String(index).padStart(4, "0")}-${entry.object_sha}.txt`
  );
  for (const [index, entry] of metadata.entries()) {
    await writeFile(
      join(tagRoot, snapshotNames[index]),
      entry.bytes,
      { flag: "wx", mode: 0o400 }
    );
  }
  const scan = await readGitleaksScanResult({
    scanner,
    mode: "dir",
    target: tagRoot,
    config,
    ignore,
    reportPath: join(reportDirectory, "tag-metadata.json"),
    environment,
    executionBinding,
    executionEvidence,
    stage
  });
  await assertSnapshotInventory(tagRoot, snapshotNames);
  for (const [index, entry] of metadata.entries()) {
    const snapshotBytes = await readSnapshotBytes(
      join(tagRoot, snapshotNames[index]),
      `Publication tag metadata ${entry.object_sha}`,
      MAX_SCANNER_INPUT_BYTES
    );
    if (!snapshotBytes.equals(entry.bytes)) {
      throw new Error(
        `Publication tag metadata snapshot changed: ${entry.object_sha}`
      );
    }
  }
  const after = await readPublicationTagMetadata(repoRoot, tagObjects);
  if (
    after.length !== metadata.length ||
    after.some(
      (entry, index) =>
        entry.ref !== metadata[index].ref ||
        entry.object_sha !== metadata[index].object_sha ||
        !entry.bytes.equals(metadata[index].bytes)
    )
  ) {
    throw new Error("Publication tag metadata changed while it was scanned.");
  }
  const emailOccurrences = [];
  for (const entry of metadata) {
    collectEmails(entry.bytes.toString("utf8"), (line) => ({
      source: "annotated_tag",
      ref: entry.ref,
      object_sha: entry.object_sha,
      line
    }), emailOccurrences);
  }
  return {
    findings: summarizeGitleaksFindings(scan.findings),
    scan: {
      status: "COMPLETE",
      exit_code: scan.exit_code,
      report_sha256: scan.report_sha256,
      stdout_sha256: scan.stdout_sha256,
      stderr_sha256: scan.stderr_sha256
    },
    email_occurrences: emailOccurrences
  };
}

function summarizeGitleaksFindings(findings) {
  const ruleCounts = {};
  for (const finding of findings) {
    const rule = typeof finding.RuleID === "string" ? finding.RuleID : "unknown";
    ruleCounts[rule] = (ruleCounts[rule] ?? 0) + 1;
  }
  return {
    finding_count: findings.length,
    rule_counts: Object.fromEntries(Object.entries(ruleCounts).sort())
  };
}

async function scanGitleaks(options) {
  const scan = await readGitleaksScanResult(options);
  return {
    ...summarizeGitleaksFindings(scan.findings),
    scan: {
      status: "COMPLETE",
      exit_code: scan.exit_code,
      report_sha256: scan.report_sha256,
      stdout_sha256: scan.stdout_sha256,
      stderr_sha256: scan.stderr_sha256
    }
  };
}

/**
 * Checks each distinct selected commit tree before any history blobs are read.
 * Tree listings retain separate paths when multiple paths share one blob.
 */
async function assertHistoryPathsSupported(repo, commits, platform = process.platform) {
  const seenTrees = new Set();
  const seenPaths = new Set();

  for (const commit of commits) {
    const tree = await git(repo, ["rev-parse", `${commit}^{tree}`]);
    if (seenTrees.has(tree)) continue;
    seenTrees.add(tree);

    const names = await gitBuffer(repo, [
      "ls-tree",
      "-r",
      "-z",
      "--full-tree",
      "--name-only",
      tree
    ]);
    for (const path of names.toString("utf8").split("\0")) {
      if (!path || seenPaths.has(path)) continue;
      seenPaths.add(path);
      assertNoUnsupportedRestrictedPathAlias(path, "Git history entry", platform);
    }
  }
}

/**
 * Copies the selected commit list before preflight, validates its tree paths,
 * and scans that same list in bounded Gitleaks batches. It combines the
 * findings from each batch. The injected runner lets tests exercise this
 * orchestration without starting Gitleaks.
 */
async function scanGitleaksHistoryBatches({
  repo,
  platform = process.platform,
  commits,
  reportDirectory,
  maxBatchBytes = DEFAULT_HISTORY_COMMIT_BATCH_BYTES,
  scanBatch
}) {
  const selectedCommits = [...commits];
  if (typeof scanBatch !== "function") {
    throw new Error("History batching requires a Gitleaks batch runner.");
  }
  await assertHistoryPathsSupported(repo, selectedCommits, platform);
  const excludedHistoryPathspecs = buildExcludedHistoryPathspecs();
  const merged = [];
  const scanBatches = [];
  const batches = partitionCommitBatches(selectedCommits, maxBatchBytes);
  for (const [index, batch] of batches.entries()) {
    const batchResult = await scanBatch({
      batch,
      logOpts: [
        "--no-walk",
        ...batch,
        "--",
        ".",
        ...excludedHistoryPathspecs
      ].join(" "),
      reportPath: join(reportDirectory, `history-${index}.json`)
    });
    const batchFindings = Array.isArray(batchResult) ? batchResult : batchResult?.findings;
    if (!Array.isArray(batchFindings)) {
      throw new Error("A Gitleaks history batch must return a findings array.");
    }
    merged.push(...batchFindings);
    scanBatches.push({
      batch_index: index,
      commit_count: batch.length,
      commits_sha256: createHash("sha256").update(batch.join("\n")).digest("hex"),
      exit_code: Array.isArray(batchResult) ? null : batchResult.exit_code,
      report_sha256: Array.isArray(batchResult) ? null : batchResult.report_sha256,
      stdout_sha256: Array.isArray(batchResult) ? null : batchResult.stdout_sha256,
      stderr_sha256: Array.isArray(batchResult) ? null : batchResult.stderr_sha256
    });
  }
  return { ...summarizeGitleaksFindings(merged), scan_batches: scanBatches };
}

export async function candidateEmailOccurrences(
  candidate,
  files,
  { platform = process.platform } = {}
) {
  const occurrences = [];
  const skipped = { large_files: 0, binary_files: 0 };
  for (const entry of files) {
    if (!entry || typeof entry.path !== "string") continue;
    assertNoUnsupportedRestrictedPathAlias(
      entry.path,
      "Candidate email file",
      platform
    );
    if (hasRestrictedPolicyPathSuffix(entry.path, platform)) continue;
    if (entry.bytes > MAX_HISTORY_BLOB_BYTES) {
      skipped.large_files += 1;
      continue;
    }
    const bytes = await readSnapshotBytes(
      join(candidate, entry.path),
      `Candidate email file ${entry.path}`,
      MAX_HISTORY_BLOB_BYTES,
      platform
    );
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (bytes.byteLength !== entry.bytes || digest !== entry.sha256) {
      throw new Error(
        `Candidate email snapshot checksum mismatch: ${entry.path}`
      );
    }
    if (bytes.includes(0)) {
      skipped.binary_files += 1;
      continue;
    }
    collectEmails(bytes.toString("utf8"), (line) => ({
      source: "candidate",
      path: entry.path,
      line
    }), occurrences);
  }
  return { occurrences, skipped };
}

function parseGitTreeEntries(buffer) {
  const entries = [];
  for (const record of buffer.toString("utf8").split("\0")) {
    if (record.length === 0) continue;
    const tab = record.indexOf("\t");
    if (tab < 0) throw new Error("Malformed Git tree entry in source commit.");
    const [mode, type, object] = record.slice(0, tab).split(" ");
    if (!mode || !type || !object) {
      throw new Error("Malformed Git tree metadata in source commit.");
    }
    entries.push({ mode, type, object, path: record.slice(tab + 1) });
  }
  return entries;
}

async function expectedSourceFiles(publicRoot, sourceCommit, platform = process.platform) {
  // git-ls-tree accepts fewer pathspec magic forms than git-log and
  // git-rev-list. Read only tree metadata here, reject unsupported aliases
  // before filtering, and exclude only canonical restricted suffixes before
  // any source blob is opened or read.
  const tree = await gitBuffer(publicRoot, [
    "ls-tree",
    "-r",
    "-z",
    "--full-tree",
    sourceCommit,
    "--",
    "."
  ]);
  const expected = new Map();
  for (const entry of parseGitTreeEntries(tree)) {
    assertNoUnsupportedRestrictedPathAlias(entry.path, "Source commit path", platform);
    if (hasRestrictedPolicyPathSuffix(entry.path, platform)) continue;
    if (
      entry.type !== "blob" ||
      (entry.mode !== "100644" && entry.mode !== "100755")
    ) {
      throw new Error(
        "Source commit " +
          sourceCommit +
          " contains non-regular entry " +
          entry.path +
          "; candidate export parity cannot be verified."
      );
    }
    if (isForbiddenPackagePath(entry.path, platform)) continue;
    if (expected.has(entry.path)) {
      throw new Error("Source commit repeats candidate path: " + entry.path);
    }
    expected.set(entry.path, entry.object);
  }
  if (expected.size === 0) {
    throw new Error(
      "Source commit " + sourceCommit + " contains no scannable candidate files."
    );
  }
  return expected;
}

/**
 * Rejects export paths whose parent components are symlinks or non-directories.
 *
 * Candidate roots themselves are already resolved and checked by
 * requireDirectory. This walk covers every component below that root using
 * lstat, which never follows a link. It runs before the file is opened so a
 * symlinked parent present at verification time is rejected before any read.
 * This static check rejects symlinks present during inspection. A malicious
 * same-UID process can replace a checked parent before the file is opened; the
 * trusted-local-operator model accepts that residual TOCTOU window and makes
 * no claim to protect against such mutation. The scanner consumes bytes
 * written from source-commit blobs and rechecks the resulting snapshot.
 */
async function assertNoSymlinkedParents(root, absolutePath) {
  const relativePath = relative(root, absolutePath);
  if (!relativePath || relativePath === ".." || relativePath.startsWith(`..${sep}`)) {
    throw new Error("Candidate report path escapes the verified candidate root.");
  }
  const components = relativePath.split(sep);
  let current = root;
  for (const component of components.slice(0, -1)) {
    if (!component || component === "." || component === "..") {
      throw new Error("Candidate report path contains an unsafe parent component.");
    }
    current = join(current, component);
    const parentStat = await lstat(current);
    if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) {
      throw new Error(
        `Candidate report path has a symlinked or non-directory parent: ${relativePath}`
      );
    }
  }
}

function isSafeCandidateReportPath(root, path) {
  if (typeof path !== "string" || path.length === 0 || isAbsolute(path) ||
      WINDOWS_DRIVE_PATH.test(path) || path.includes("\\") || path.includes("\0") ||
      path.split("/").some((component) =>
        component.length === 0 || component === "." || component === "..")) {
    return false;
  }
  const absolutePath = resolve(root, path);
  const pathFromRoot = relative(root, absolutePath);
  return pathFromRoot.length > 0 && pathFromRoot !== ".." &&
    !pathFromRoot.startsWith(`..${sep}`) && !isAbsolute(pathFromRoot);
}

async function verifyExportedFiles(
  candidate,
  report,
  { publicRoot, sourceCommit, snapshotRoot, platform = process.platform }
) {
  if (!Array.isArray(report.files) || typeof report.tree_sha256 !== "string") {
    throw new Error("Malformed candidate export report.");
  }
  if (report.files.length === 0) {
    throw new Error("Candidate export report must list at least one file.");
  }
  const seenPaths = new Set();
  for (const entry of report.files) {
    if (!entry || typeof entry.path !== "string" ||
        !Number.isSafeInteger(entry.bytes) ||
        typeof entry.sha256 !== "string") {
      throw new Error("Malformed candidate export report file entry.");
    }
    assertNoUnsupportedRestrictedPathAlias(
      entry.path,
      "Candidate export report path",
      platform
    );
    if (isForbiddenPackagePath(entry.path, platform)) {
      throw new Error(`Candidate export report contains forbidden path: ${entry.path}`);
    }
    if (!isSafeCandidateReportPath(candidate, entry.path) || seenPaths.has(entry.path)) {
      throw new Error(`Unsafe candidate report path: ${entry.path || "<empty>"}`);
    }
    seenPaths.add(entry.path);
  }

  const expected = await expectedSourceFiles(publicRoot, sourceCommit, platform);
  for (const entry of report.files) {
    if (!expected.has(entry.path)) {
      throw new Error(
        `Candidate export report contains a path not in the source commit ${sourceCommit}: ${entry.path}`
      );
    }
  }
  const missing = [...expected.keys()]
    .filter((path) => !seenPaths.has(path))
    .sort();
  if (missing.length > 0) {
    throw new Error(
      "Candidate export report is missing files from source commit " +
        sourceCommit +
        ": " +
        missing.join(", ")
    );
  }
  const verified = [];
  for (const entry of report.files) {
    const absolutePath = resolve(candidate, entry.path);
    await assertNoSymlinkedParents(candidate, absolutePath);
    const fileStat = await lstat(absolutePath);
    if (!fileStat.isFile() || fileStat.isSymbolicLink() || fileStat.nlink !== 1) {
      throw new Error(`Candidate report path is not a regular single-link file: ${entry.path}`);
    }
    const bytes = await readSnapshotBytes(
      absolutePath,
      `Candidate file ${entry.path}`,
      MAX_CANDIDATE_FILE_BYTES,
      platform
    );
    const afterRead = await lstat(absolutePath);
    if (
      !afterRead.isFile() ||
      afterRead.isSymbolicLink() ||
      afterRead.dev !== fileStat.dev ||
      afterRead.ino !== fileStat.ino ||
      afterRead.size !== fileStat.size ||
      afterRead.ctimeMs !== fileStat.ctimeMs
    ) {
      throw new Error(
        `Candidate report path changed while it was read: ${entry.path}`
      );
    }
    await assertNoSymlinkedParents(candidate, absolutePath);
    if ((await realpath(absolutePath)) !== absolutePath) {
      throw new Error(
        `Candidate report path resolves through a symlink: ${entry.path}`
      );
    }
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (bytes.byteLength !== entry.bytes || digest !== entry.sha256) {
      throw new Error(`Candidate checksum mismatch: ${entry.path}`);
    }
    verified.push(entry);
  }
  const tree = createHash("sha256");
  for (const entry of [...verified].sort((left, right) => left.path.localeCompare(right.path))) {
    tree.update(entry.path);
    tree.update("\0");
    tree.update(entry.sha256);
    tree.update("\0");
    tree.update(String(entry.bytes));
    tree.update("\n");
  }
  if (tree.digest("hex") !== report.tree_sha256) {
    throw new Error("Candidate tree checksum does not match its export report.");
  }

  for (const entry of verified) {
    const sourceBytes = await gitBuffer(publicRoot, [
      "cat-file",
      "blob",
      expected.get(entry.path)
    ]);
    const sourceDigest = createHash("sha256").update(sourceBytes).digest("hex");
    if (sourceBytes.byteLength !== entry.bytes || sourceDigest !== entry.sha256) {
      throw new Error(
        "Candidate export bytes do not match source commit " +
          sourceCommit +
          ": " +
          entry.path
      );
    }
    const snapshotPath = resolve(snapshotRoot, entry.path);
    if (!snapshotPath.startsWith(`${snapshotRoot}${sep}`)) {
      throw new Error(`Unsafe candidate snapshot path: ${entry.path}`);
    }
    await mkdir(dirname(snapshotPath), { recursive: true, mode: 0o700 });
    await writeFile(snapshotPath, sourceBytes, { flag: "wx", mode: 0o400 });
  }
  return verified;
}

/**
 * Enumerates every entry below a private verification snapshot without
 * following symlinks. The scan target must contain exactly the paths declared
 * in the verified export report, so an added file cannot become scanner input
 * that the post-scan source check never verified.
 */
async function assertSnapshotInventory(root, expectedPaths) {
  const actual = [];
  async function walk(directory, prefix) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) {
        throw new Error(`Candidate snapshot contains a symlink: ${relativePath}`);
      }
      const absolutePath = join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(absolutePath, relativePath);
        continue;
      }
      if (!entry.isFile()) {
        throw new Error(
          `Candidate snapshot contains a non-regular entry: ${relativePath}`
        );
      }
      actual.push(relativePath);
    }
  }
  await walk(root, "");
  actual.sort();
  const expected = [...expectedPaths].sort();
  if (
    actual.length !== expected.length ||
    actual.some((path, index) => path !== expected[index])
  ) {
    throw new Error(
      "Candidate snapshot inventory does not match the verified export manifest."
    );
  }
}

async function verifyCandidateSnapshot(
  destination,
  files,
  { publicRoot, sourceCommit, platform = process.platform }
) {
  const expected = await expectedSourceFiles(publicRoot, sourceCommit, platform);
  await assertSnapshotInventory(
    destination,
    files.map((entry) => entry.path)
  );
  for (const entry of files) {
    assertNoUnsupportedRestrictedPathAlias(
      entry.path,
      "Candidate snapshot file",
      platform
    );
    const destinationPath = resolve(destination, entry.path);
    if (!destinationPath.startsWith(`${destination}${sep}`)) {
      throw new Error(`Unsafe candidate snapshot path: ${entry.path}`);
    }
    const bytes = await readSnapshotBytes(
      destinationPath,
      `Candidate snapshot ${entry.path}`,
      MAX_CANDIDATE_FILE_BYTES,
      platform
    );
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (bytes.byteLength !== entry.bytes || digest !== entry.sha256) {
      throw new Error(`Candidate snapshot checksum mismatch: ${entry.path}`);
    }
    const sourceBytes = await gitBuffer(publicRoot, [
      "cat-file",
      "blob",
      expected.get(entry.path)
    ]);
    const sourceDigest = createHash("sha256").update(sourceBytes).digest("hex");
    if (sourceBytes.byteLength !== entry.bytes || sourceDigest !== entry.sha256) {
      throw new Error(
        "Candidate snapshot no longer matches source commit " +
          sourceCommit +
          ": " +
          entry.path
      );
    }
  }
}

async function scanHistoryEmailOccurrences(
  repo,
  scope,
  { includeBlobs = true, coverage, platform = process.platform } = {}
) {
  const occurrences = [];
  const commits = [...scope.commits];
  const batches = partitionCommitBatches(commits);
  if (includeBlobs) await assertHistoryPathsSupported(repo, commits, platform);
  const excludedHistoryPathspecs = includeBlobs
    ? buildExcludedHistoryPathspecs()
    : [];
  const metadataSeen = new Set();
  if (coverage) {
    coverage.blobs_skipped_large = 0;
    coverage.blobs_skipped_binary = 0;
  }
  for (const batch of batches) {
    const metadata = await git(repo, [
      "log",
      "--no-walk",
      ...batch,
      "--format=%H%x09%ae%x09%ce"
    ]);
    for (const line of metadata.split("\n").filter(Boolean)) {
      const [commit, author, committer] = line.split("\t");
      for (const [role, address] of [["author", author], ["committer", committer]]) {
        if (!address) continue;
        const key = `${commit}\0${role}\0${address}`;
        if (metadataSeen.has(key)) continue;
        metadataSeen.add(key);
        occurrences.push({
          address,
          location: { source: "commit_metadata", commit, role }
        });
      }
    }
  }

  if (!includeBlobs) return occurrences;
  const seen = new Set();
  for (const batch of batches) {
    const objects = await gitBuffer(repo, [
      "rev-list",
      "--objects",
      "--no-walk",
      ...batch,
      "--",
      ".",
      ...excludedHistoryPathspecs
    ]);
    for (const line of objects.toString("utf8").split("\n").filter(Boolean)) {
      const separator = line.indexOf(" ");
      const object = separator < 0 ? line : line.slice(0, separator);
      const path = separator < 0 ? undefined : line.slice(separator + 1);
      if (!path) continue;
      assertNoUnsupportedRestrictedPathAlias(path, "Git history email path", platform);
      if (hasRestrictedPolicyPathSuffix(path, platform)) continue;
      if (seen.has(object)) continue;
      seen.add(object);
      if (await git(repo, ["cat-file", "-t", object]) !== "blob") continue;
      const size = Number(await git(repo, ["cat-file", "-s", object]));
      if (!Number.isSafeInteger(size) || size > MAX_HISTORY_BLOB_BYTES) {
        if (coverage) coverage.blobs_skipped_large += 1;
        continue;
      }
      const bytes = await gitBuffer(repo, ["cat-file", "blob", object]);
      if (bytes.includes(0)) {
        if (coverage) coverage.blobs_skipped_binary += 1;
        continue;
      }
      collectEmails(bytes.toString("utf8"), (lineNumber) => ({
        source: "git_blob",
        blob: object,
        path,
        line: lineNumber
      }), occurrences);
    }
  }
  return occurrences;
}

export async function historyEmailOccurrences(
  repo,
  scope,
  { includeBlobs = true, coverage, platform = process.platform } = {}
) {
  return scanHistoryEmailOccurrences(repo, scope, { includeBlobs, coverage, platform });
}

function isEmailLocalPartCode(code) {
  return (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    code === 37 || code === 43 || code === 45 || code === 46 || code === 95;
}

function isEmailDomainCode(code) {
  return (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    code === 45 || code === 46;
}

function isEmailLetterCode(code) {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function collectEmails(text, location, output) {
  const lineStarts = [0];
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === "\n") lineStarts.push(index + 1);
  }
  let searchFrom = 0;
  while (searchFrom < text.length) {
    const at = text.indexOf("@", searchFrom);
    if (at < 0) break;
    let addressStart = at;
    while (
      addressStart > searchFrom &&
      isEmailLocalPartCode(text.charCodeAt(addressStart - 1))
    ) {
      addressStart -= 1;
    }
    if (addressStart === at) {
      searchFrom = at + 1;
      continue;
    }

    const domainStart = at + 1;
    let domainEnd = domainStart;
    while (
      domainEnd < text.length &&
      isEmailDomainCode(text.charCodeAt(domainEnd))
    ) {
      domainEnd += 1;
    }
    let domainMatchEnd = -1;
    let cursor = domainEnd;
    while (cursor > domainStart) {
      const letterRunEnd = cursor;
      while (cursor > domainStart && isEmailLetterCode(text.charCodeAt(cursor - 1))) {
        cursor -= 1;
      }
      if (
        letterRunEnd - cursor >= 2 &&
        cursor > domainStart + 1 &&
        text.charCodeAt(cursor - 1) === 46
      ) {
        domainMatchEnd = letterRunEnd;
        break;
      }
      if (cursor === letterRunEnd) cursor -= 1;
    }
    if (domainMatchEnd < 0) {
      searchFrom = at + 1;
      continue;
    }

    let low = 0;
    let high = lineStarts.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (lineStarts[middle] <= addressStart) low = middle + 1;
      else high = middle;
    }
    output.push({
      address: text.slice(addressStart, domainMatchEnd),
      location: location(Math.max(1, low))
    });
    searchFrom = domainMatchEnd;
  }
}

async function readSourceDependencySnapshot(
  publicRoot,
  sourceCommit,
  temporary,
  platform = process.platform
) {
  const expected = await expectedSourceFiles(publicRoot, sourceCommit, platform);
  const required = ["package.json", "package-lock.json"];
  for (const path of required) {
    if (!expected.has(path)) {
      throw new Error(
        "Source commit " +
          sourceCommit +
          " is missing dependency metadata required for audit and license checks: " +
          path
      );
    }
  }
  const [manifestBytes, lockBytes] = await Promise.all(
    required.map((path) =>
      gitBuffer(publicRoot, ["cat-file", "blob", expected.get(path)])
    )
  );
  const auditRoot = join(temporary, "dependency-audit");
  await mkdir(auditRoot, { recursive: true, mode: 0o700 });
  await writeFile(join(auditRoot, "package.json"), manifestBytes, {
    flag: "wx",
    mode: 0o400
  });
  await writeFile(join(auditRoot, "package-lock.json"), lockBytes, {
    flag: "wx",
    mode: 0o400
  });
  return {
    auditRoot,
    lock: JSON.parse(lockBytes.toString("utf8")),
    packageJsonSha256: createHash("sha256").update(manifestBytes).digest("hex"),
    packageLockSha256: createHash("sha256").update(lockBytes).digest("hex")
  };
}

function sourceLicenseRecords(lock) {
  if (!lock || typeof lock !== "object" || typeof lock.packages !== "object") {
    throw new Error(
      "Source package-lock.json must include a packages map for license classification."
    );
  }
  const records = [];
  for (const [path, value] of Object.entries(lock.packages)) {
    if (path === "" || !path.startsWith("node_modules/") || !value) continue;
    const name =
      typeof value.name === "string"
        ? value.name
        : path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
    const version = typeof value.version === "string" ? value.version : "unknown";
    const license =
      typeof value.license === "string"
        ? value.license
        : Array.isArray(value.licenses)
          ? value.licenses.map((entry) => entry?.type).filter(Boolean).join(" OR ")
          : "MISSING";
    records.push({ name, version, license });
  }
  return records.sort((left, right) =>
    `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`)
  );
}

function isPlainRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}



function validateDependencyAuditPolicy(policy) {
  const audit = policy?.dependency_audit;
  if (!isPlainRecord(audit)) {
    throw new Error(
      "Authenticated security policy must include dependency_audit configuration."
    );
  }
  if (
    typeof audit.executable_path !== "string" ||
    !isAbsolute(audit.executable_path) ||
    typeof audit.executable_sha256 !== "string" ||
    !SHA256_HEX.test(audit.executable_sha256) ||
    !Number.isSafeInteger(audit.timeout_ms) ||
    audit.timeout_ms <= 0 ||
    audit.timeout_ms > MAX_DEPENDENCY_AUDIT_TIMEOUT_MS ||
    typeof audit.registry !== "string"
  ) {
    throw new Error("Malformed dependency_audit security policy.");
  }
  let registry;
  try {
    registry = new URL(audit.registry);
  } catch {
    throw new Error("Dependency audit registry must be an absolute HTTPS URL.");
  }
  if (
    registry.protocol !== "https:" ||
    registry.username !== "" ||
    registry.password !== "" ||
    registry.search !== "" ||
    registry.hash !== ""
  ) {
    throw new Error(
      "Dependency audit registry must be an HTTPS URL without credentials, query, or fragment."
    );
  }
  return {
    executable_path: audit.executable_path,
    executable_sha256: audit.executable_sha256,
    registry: audit.registry,
    timeout_ms: audit.timeout_ms
  };
}

async function snapshotDependencyAuditExecutable(policy, directory, platform = process.platform) {
  const config = validateDependencyAuditPolicy(policy);
  const bytes = await readSnapshotBytes(
    config.executable_path,
    "Dependency audit executable",
    MAX_SCANNER_BINARY_BYTES,
    platform
  );
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== config.executable_sha256) {
    throw new Error("Dependency audit executable checksum mismatch.");
  }
  const executablePath = await writeExecutableSnapshot(
    directory,
    "dependency-audit-executable",
    bytes
  );
  return {
    ...config,
    executablePath,
    executable_bytes_sha256: digest
  };
}

async function prepareDependencyAuditRuntime(temporary) {
  const root = join(temporary, "dependency-audit-runtime");
  const home = join(root, "home");
  const tmp = join(root, "tmp");
  const cachePath = join(root, "cache");
  const emptyConfigPath = join(root, "empty-npmrc");
  await mkdir(home, { recursive: true, mode: 0o700 });
  await mkdir(tmp, { recursive: true, mode: 0o700 });
  await mkdir(cachePath, { recursive: true, mode: 0o700 });
  await writeFile(emptyConfigPath, "", { flag: "wx", mode: 0o400 });
  return { root, home, tmp, cachePath, emptyConfigPath };
}

function dependencyAuditEnvironment(runtime) {
  const environment = {};
  for (const key of ["PATH", "LANG", "LC_ALL", "TZ"]) {
    const value = process.env[key];
    if (value !== undefined) environment[key] = value;
  }
  return {
    ...environment,
    HOME: runtime.home,
    TMPDIR: runtime.tmp,
    CI: "1",
    NO_COLOR: "1",
    NPM_CONFIG_USERCONFIG: runtime.emptyConfigPath,
    NPM_CONFIG_GLOBALCONFIG: runtime.emptyConfigPath,
    NPM_CONFIG_CACHE: runtime.cachePath,
    NPM_CONFIG_UPDATE_NOTIFIER: "false",
    NPM_CONFIG_FUND: "false"
  };
}

function validateNpmAuditReport(audit, label) {
  if (!isPlainRecord(audit)) {
    throw new Error(label + " must be a JSON object.");
  }
  if (
    !Number.isSafeInteger(audit.auditReportVersion) ||
    audit.auditReportVersion <= 0 ||
    !isPlainRecord(audit.vulnerabilities) ||
    !isPlainRecord(audit.metadata) ||
    !isPlainRecord(audit.metadata.vulnerabilities) ||
    !isPlainRecord(audit.metadata.dependencies)
  ) {
    throw new Error(label + " is missing complete advisory metadata.");
  }
  const dependencyCount = audit.metadata.dependencies.total;
  if (!Number.isSafeInteger(dependencyCount) || dependencyCount <= 0) {
    throw new Error(label + " does not describe any audited dependencies.");
  }
  const counts = {
    info: 0,
    low: 0,
    moderate: 0,
    high: 0,
    critical: 0,
    total: Object.keys(audit.vulnerabilities).length
  };
  for (const [name, value] of Object.entries(audit.vulnerabilities)) {
    if (!isPlainRecord(value) || typeof value.severity !== "string") {
      throw new Error(label + " contains malformed vulnerability data for " + name + ".");
    }
    if (!(value.severity in counts) || value.severity === "total") {
      throw new Error(label + " contains an unsupported vulnerability severity.");
    }
    counts[value.severity] += 1;
  }
  for (const severity of ["info", "low", "moderate", "high", "critical", "total"]) {
    if (audit.metadata.vulnerabilities[severity] !== counts[severity]) {
      throw new Error(label + " advisory counts are internally inconsistent.");
    }
  }
  return { vulnerability_count: counts.total, dependency_count: dependencyCount };
}

async function auditCandidate(candidate, policy, context) {
  const versionResult = await runAllowFailure(
    context.executablePath,
    ["--version"],
    undefined,
    context.environment,
    { timeoutMs: context.timeout_ms }
  );
  const executableVersion = versionResult.stdout.trim();
  if (versionResult.timedOut || versionResult.signal !== null ||
      versionResult.exitCode !== 0 || executableVersion.length === 0) {
    const error = new Error(
      `Dependency audit executable version check failed with exit code ${versionResult.exitCode}.`
    );
    error.exit_code = versionResult.exitCode;
    error.timed_out = versionResult.timedOut;
    error.signal = versionResult.signal;
    throw error;
  }
  const full = await npmAudit(candidate, [], {
    ...context,
    label: "Full npm audit"
  });
  const production = await npmAudit(candidate, ["--omit=dev"], {
    ...context,
    label: "Production npm audit"
  });
  return {
    ...classifyAudit(full.report, production.report, policy),
    evidence: {
      executable_sha256: context.executable_sha256,
      executable_version: executableVersion,
      version_exit_code: versionResult.exitCode,
      registry: context.registry,
      timeout_ms: context.timeout_ms,
      full: full.evidence,
      production: production.evidence
    }
  };
}

async function npmAudit(candidate, extra, context) {
  const result = await runAllowFailure(
    context.executablePath,
    [
      "audit",
      "--json",
      "--package-lock-only",
      "--registry",
      context.registry,
      "--userconfig",
      context.emptyConfigPath,
      "--globalconfig",
      context.emptyConfigPath,
      "--cache",
      context.cachePath,
      "--ignore-scripts",
      ...extra
    ],
    candidate,
    context.environment,
    { timeoutMs: context.timeout_ms }
  );
  if (result.timedOut || result.signal !== null) {
    throw new Error(
      context.label + " did not complete" +
        (result.signal === null ? "." : " (signal " + result.signal + ").")
    );
  }
  if (![0, 1].includes(result.exitCode)) {
    throw new Error(context.label + " failed with exit code " + result.exitCode + ".");
  }
  if (result.stdout.trim().length === 0) {
    throw new Error(context.label + " produced empty advisory output.");
  }
  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(context.label + " produced truncated or invalid JSON: " + error.message);
  }
  const validated = validateNpmAuditReport(report, context.label);
  if (result.exitCode === 1 && validated.vulnerability_count === 0) {
    const error = new Error(
      context.label + " exited 1 without reported vulnerabilities."
    );
    error.exit_code = result.exitCode;
    throw error;
  }
  return {
    report,
    evidence: {
      exit_code: result.exitCode,
      stdout_sha256: createHash("sha256").update(result.stdout).digest("hex"),
      stderr_sha256: createHash("sha256").update(result.stderr).digest("hex")
    }
  };
}

function auditEntries(audit, label) {
  const validated = validateNpmAuditReport(audit, label);
  const entries = Object.entries(audit.vulnerabilities).map(([name, value]) => ({
    package: name,
    severity: value.severity,
    direct: value.isDirect === true,
    fix_available: Boolean(value.fixAvailable)
  })).sort((left, right) => left.package.localeCompare(right.package));
  return {
    total: entries.length,
    entries,
    dependency_count: validated.dependency_count
  };
}

function validatePolicy(policy) {
  if (!policy || policy.schema_version !== 1 ||
      typeof policy.policy_version !== "string" ||
      typeof policy.gitleaks?.version !== "string" ||
      typeof policy.gitleaks?.assets !== "object" ||
      !Array.isArray(policy.email?.allowed_domains) ||
      !Array.isArray(policy.email?.allowed_addresses) ||
      !Array.isArray(policy.email?.reviewed_public_history_locations) ||
      !Array.isArray(policy.licenses?.allowed) ||
      !Array.isArray(policy.known_development_advisories)) {
    throw new Error("Malformed OSS security policy.");
  }
  validateDependencyAuditPolicy(policy);
  const reviewed = policy.email.reviewed_public_history_locations;
  const locations = new Set();
  for (const entry of reviewed) {
    if (!entry ||
        !/^[a-f0-9]{40}$/.test(entry.commit) ||
        !Array.isArray(entry.roles) ||
        entry.roles.length === 0 ||
        entry.roles.some((role) => !["author", "committer"].includes(role)) ||
        typeof entry.context !== "string" ||
        entry.context.length === 0) {
      throw new Error("Malformed reviewed public-history email location.");
    }
    for (const role of entry.roles) {
      const location = `${entry.commit}:${role}`;
      if (locations.has(location)) {
        throw new Error(`Duplicate reviewed public-history email location: ${location}`);
      }
      locations.add(location);
    }
  }
}

function assertPublicationSha(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/.test(value)) {
    throw new Error("Publication " + label + " must be a full 40-hex commit id.");
  }
}

function isExactGitRefName(ref) {
  if (typeof ref !== "string" || ref.length === 0 || ref === "@") return false;
  for (const character of ref) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint <= 0x20 ||
      codePoint === 0x7f ||
      "~^:?*[\\".includes(character)
    ) {
      return false;
    }
  }
  if (
    ref.includes("..") ||
    ref.includes("@{") ||
    ref.includes("//") ||
    ref.startsWith("/") ||
    ref.endsWith("/") ||
    ref.endsWith(".")
  ) {
    return false;
  }
  return ref.split("/").every(
    (component) =>
      component.length > 0 &&
      !component.startsWith(".") &&
      !component.endsWith(".lock")
  );
}

function normalizePublicationSelection(value, label, { target = false } = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(
      "Publication " + label + " selection must be a ref or pinned commit."
    );
  }
  if (value.kind === "commit") {
    if (target) {
      throw new Error("Publication target must be an exact refs/heads/* ref.");
    }
    assertPublicationSha(value.sha, label + " commit");
    return { kind: "commit", sha: value.sha };
  }
  if (value.kind !== "ref") {
    throw new Error("Publication " + label + " selection uses an unsupported kind.");
  }
  if (typeof value.ref !== "string" || value.ref.length === 0) {
    throw new Error("Publication " + label + " must name an explicit Git ref.");
  }
  const prefixes = target
    ? ["refs/heads/"]
    : ["refs/heads/", "refs/tags/"];
  if (!prefixes.some((prefix) => value.ref.startsWith(prefix))) {
    throw new Error(
      "Publication " + label + " must be an exact refs/heads/*" +
        (target ? "" : " or refs/tags/*") +
        " ref."
    );
  }
  if (!isExactGitRefName(value.ref)) {
    throw new Error(
      "Publication " + label + " is not an exact safe Git ref name."
    );
  }
  return { kind: "ref", ref: value.ref };
}

/**
 * Validates the publication ref set produced by publication-ref-set.mjs and
 * returns the immutable history scope. History scans consume these commits
 * instead of every local ref, so unrelated branches, stashes and notes cannot
 * change the result. Selected refs must be exact refs/heads/* or refs/tags/*
 * names and describe the declared candidate and target selection; a
 * self-consistent ref set for unrelated history is rejected before any Git
 * history is read.
 */
export function publicationHistoryScope(publication) {
  if (!publication || typeof publication !== "object") {
    throw new Error("A publication ref set is required for the history scan.");
  }
  const tagObjects = publication.tag_objects;
  if (tagObjects !== undefined && !Array.isArray(tagObjects)) {
    throw new Error("Publication ref set tag_objects must be an array.");
  }
  const refEntries = publication.refs;
  if (!Array.isArray(refEntries) || refEntries.length === 0) {
    throw new Error("Publication ref set must contain at least one selected ref.");
  }
  const refPairs = [];
  for (const entry of refEntries) {
    if (!entry || typeof entry.ref !== "string" || entry.ref.length === 0) {
      throw new Error("Publication ref set contains a ref without a name.");
    }
    const selectedRef = normalizePublicationSelection(
      { kind: "ref", ref: entry.ref },
      "selected ref"
    );
    assertPublicationSha(entry.commit_sha, "ref " + entry.ref);
    refPairs.push({ ref: selectedRef.ref, commit_sha: entry.commit_sha });
  }
  const refs = refPairs.map((entry) => entry.ref);
  if (new Set(refs).size !== refs.length) {
    throw new Error("Publication ref set must not repeat ref names.");
  }
  const refsByRef = new Map(refPairs.map((entry) => [entry.ref, entry]));
  const normalizedTagObjects = [];
  const tagObjectPairs = new Set();
  for (const entry of tagObjects ?? []) {
    if (
      !entry ||
      typeof entry.ref !== "string" ||
      typeof entry.object_sha !== "string" ||
      typeof entry.commit_sha !== "string"
    ) {
      throw new Error("Publication tag_objects entry is malformed.");
    }
    if (Object.hasOwn(entry, "body") || Object.hasOwn(entry, "bytes")) {
      throw new Error(
        "Publication tag_objects must reference Git objects; embedded tag bytes are not trusted."
      );
    }
    const selectedRef = normalizePublicationSelection(
      { kind: "ref", ref: entry.ref },
      "tag metadata ref"
    );
    assertPublicationSha(entry.object_sha, "tag object " + entry.ref);
    assertPublicationSha(entry.commit_sha, "tag commit " + entry.ref);
    const selected = refsByRef.get(selectedRef.ref);
    if (!selected || selected.commit_sha !== entry.commit_sha) {
      throw new Error(
        "Publication tag object is not part of a selected ref's commit closure."
      );
    }
    const pair = entry.ref + "\0" + entry.object_sha;
    if (tagObjectPairs.has(pair)) {
      throw new Error("Publication tag_objects must not repeat a tag object for a ref.");
    }
    tagObjectPairs.add(pair);
    normalizedTagObjects.push({
      ref: selectedRef.ref,
      object_sha: entry.object_sha,
      commit_sha: entry.commit_sha
    });
  }
  const commits = publication.commits;
  if (!Array.isArray(commits) || commits.length === 0) {
    throw new Error("Publication ref set must contain at least one commit.");
  }
  for (const commit of commits) assertPublicationSha(commit, "commit");
  if (new Set(commits).size !== commits.length) {
    throw new Error("Publication ref set commit list must not repeat commits.");
  }
  if (publication.commit_count !== commits.length) {
    throw new Error(
      "Publication ref set commit count " +
        String(publication.commit_count) +
        " does not match " +
        commits.length +
        " listed commits."
    );
  }
  const pinned = publication.pinned_commits ?? [];
  if (!Array.isArray(pinned)) {
    throw new Error("Publication ref set pinned_commits must be an array.");
  }
  for (const commit of pinned) {
    assertPublicationSha(commit, "pinned commit");
    if (!commits.includes(commit)) {
      throw new Error(
        "Publication ref set pinned commit is outside the selected closure."
      );
    }
  }
  const candidate = normalizePublicationSelection(
    publication.candidate,
    "candidate"
  );
  const target = normalizePublicationSelection(
    publication.target,
    "target",
    { target: true }
  );
  if (candidate.kind === "ref" && !refsByRef.has(candidate.ref)) {
    throw new Error(
      "Publication candidate ref " +
        candidate.ref +
        " is not part of the selected refs."
    );
  }
  if (!refsByRef.has(target.ref)) {
    throw new Error(
      "Publication target ref " +
        target.ref +
        " is not part of the selected refs."
    );
  }
  const candidateCommit =
    candidate.kind === "ref"
      ? refsByRef.get(candidate.ref).commit_sha
      : candidate.sha;
  if (!commits.includes(candidateCommit)) {
    throw new Error(
      "Publication candidate selection is outside the selected closure."
    );
  }
  const targetCommit = refsByRef.get(target.ref).commit_sha;
  return {
    fingerprint:
      typeof publication.fingerprint === "string" ? publication.fingerprint : "",
    candidate,
    target,
    candidate_commit: candidateCommit,
    target_commit: targetCommit,
    refs: [...refs].sort(),
    ref_entries: [...refPairs].sort((left, right) =>
      left.ref.localeCompare(right.ref)
    ),
    commits: [...commits].sort(),
    pinned_commits: [...pinned].sort(),
    commit_count: commits.length,
    tag_objects: normalizedTagObjects.sort((left, right) =>
      left.ref.localeCompare(right.ref)
    )
  };
}

/**
 * Re-resolves the selected publication refs after scanning and fails closed
 * if any ref or the reachable closure moved. The report therefore describes
 * the selection that still resolves at completion, not a stale snapshot.
 * Fingerprint resolution re-derives each selected ref's object type and tag
 * chain, so a ref that becomes an annotated tag during the scan also changes
 * the fingerprint and fails closed here.
 */
async function assertPublicationSnapshot(repoRoot, publication, scope) {
  return assertPublicationRefSetUnchanged(
    { repoRoot, ...publicationSelectionFromRefSet(publication) },
    { fingerprint: scope.fingerprint }
  );
}

/**
 * Verifies selected refs and their annotated-tag metadata against Git.
 *
 * Publication ref-set metadata is supplied by the caller and cannot describe
 * repository object types on its own. Lightweight refs must resolve directly
 * to commits. For annotated refs, the repository's actual outer-to-inner tag
 * chain must exactly equal the listed tag objects, each with the selected
 * commit. Extra, missing, or unselected objects fail closed. Tag bytes are
 * read later from those verified Git objects rather than from this metadata.
 */
async function assertSelectedRefsAndTagObjects(repoRoot, scope) {
  const selectedRefs = new Set(scope.ref_entries.map((entry) => entry.ref));
  const tagObjects = scope.tag_objects ?? [];
  for (const tag of tagObjects) {
    if (!selectedRefs.has(tag.ref)) {
      throw new Error(
        "Publication tag object " + tag.object_sha + " belongs to an unselected ref."
      );
    }
  }
  for (const entry of scope.ref_entries) {
    const objectSha = await git(repoRoot, [
      "rev-parse",
      "--verify",
      "--end-of-options",
      entry.ref
    ]);
    const objectType = await git(repoRoot, ["cat-file", "-t", objectSha]);
    const expected = tagObjects.filter((tag) => tag.ref === entry.ref);
    if (objectType === "commit") {
      if (expected.length !== 0) {
        throw new Error(
          "Publication tag metadata is listed for lightweight ref " + entry.ref + "."
        );
      }
      continue;
    }
    if (objectType !== "tag") {
      throw new Error(
        "Selected ref " +
          entry.ref +
          " does not resolve to a commit object or annotated tag (found " +
          (objectType || "unknown") +
          ")."
      );
    }
    const chain = await resolveTagObjectChain(repoRoot, objectSha);
    if (chain.length === 0 || expected.length !== chain.length) {
      throw new Error(
        "Publication tag metadata does not match selected annotated-tag chain " +
          entry.ref +
          "."
      );
    }
    for (let index = 0; index < chain.length; index += 1) {
      if (
        expected[index].object_sha !== chain[index] ||
        expected[index].commit_sha !== entry.commit_sha
      ) {
        throw new Error(
          "Publication tag metadata does not match selected annotated-tag chain " +
            entry.ref +
            "."
        );
      }
    }
  }
}

/**
 * Confirms every selected ref still resolves to its pinned commit, that the
 * listed commits equal, by identity, the commits reachable from those refs,
 * and that the candidate selection matches the independently supplied export
 * source commit. A matching commit count or a self-consistent ref set alone is
 * not accepted.
 */
export async function verifyPublicationRefs(repoRoot, scope, expected = {}) {
  await assertSelectedRefsAndTagObjects(repoRoot, scope);
  for (const entry of scope.ref_entries) {
    const resolved = await git(repoRoot, ["rev-parse", entry.ref + "^{commit}"]);
    if (resolved !== entry.commit_sha) {
      throw new Error(
        "Publication ref " +
          entry.ref +
          " resolves to " +
          resolved +
          ", not the selected " +
          entry.commit_sha +
          "."
      );
    }
  }
  const reachable = (
    await git(repoRoot, [
      "rev-list",
      "--topo-order",
      ...scope.ref_entries.map((entry) => entry.commit_sha)
    ])
  )
    .split("\n")
    .filter(Boolean)
    .sort();
  const listed = [...scope.commits].sort();
  if (
    reachable.length !== listed.length ||
    reachable.some((commit, index) => commit !== listed[index])
  ) {
    throw new Error(
      "Publication commit list does not match the closure of the selected refs (" +
        reachable.length +
        " reachable, " +
        listed.length +
        " listed)."
    );
  }
  if (Object.hasOwn(expected, "candidate_commit")) {
    const expectedCandidate = expected.candidate_commit;
    if (typeof expectedCandidate !== "string" || expectedCandidate.length === 0) {
      throw new Error(
        "Expected candidate commit is required to bind the publication selection."
      );
    }
    if (scope.candidate_commit !== expectedCandidate) {
      throw new Error(
        "Publication candidate selection resolves to " +
          scope.candidate_commit +
          ", not the export source commit " +
          expectedCandidate +
          "."
      );
    }
  }
  return { ref_count: scope.refs.length, commit_count: scope.commit_count };
}

function pathValidationError(message, code) {
  const error = new Error(message);
  if (code) error.code = code;
  return error;
}

/**
 * Rejects symlinks and non-directory components found during a static walk of
 * an absolute directory path. A same-UID process can still replace a checked
 * component before a later operation; this is the approved static-check model.
 */
async function assertRealDirectoryPath(path, label) {
  if (!isAbsolute(path)) throw new Error(`${label} path must be absolute.`);
  const absolutePath = resolve(path);
  const filesystemRoot = parse(absolutePath).root;
  const components = relative(filesystemRoot, absolutePath)
    .split(sep)
    .filter(Boolean);
  let current = filesystemRoot;
  let info = await lstat(current);
  if (info.isSymbolicLink()) throw new Error(`${label} path has a symlinked ancestor.`);
  if (!info.isDirectory()) {
    throw pathValidationError(`${label} path ancestor is not a directory.`, "ENOTDIR");
  }
  for (const component of components) {
    current = join(current, component);
    info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error(`${label} path has a symlinked ancestor.`);
    if (!info.isDirectory()) {
      throw pathValidationError(`${label} path ancestor is not a directory.`, "ENOTDIR");
    }
  }
  return absolutePath;
}

async function assertRealParentPath(path, label) {
  await assertRealDirectoryPath(dirname(resolve(path)), `${label} parent`);
}

async function requireDirectory(path, label) {
  if (!isAbsolute(path)) throw new Error(`${label} path must be absolute.`);
  const absolutePath = await assertRealDirectoryPath(path, label);
  const info = await lstat(absolutePath);
  if (info.isSymbolicLink()) throw new Error(`${label} path must not be a symlink.`);
  if (!info.isDirectory()) throw new Error(`${label} path must be a directory.`);
  const resolved = await realpath(absolutePath);
  if (!(await stat(resolved)).isDirectory()) throw new Error(`${label} path must be a directory.`);
  return resolved;
}

async function requireGitRoot(path) {
  const resolved = await requireDirectory(path, "public repository");
  const root = await git(resolved, ["rev-parse", "--show-toplevel"]);
  if (await realpath(root) !== resolved) throw new Error("Public repository path must be its Git root.");
  return resolved;
}

async function git(cwd, args) {
  return (await run("git", ["-C", cwd, ...args])).stdout.trim();
}

async function gitBuffer(cwd, args) {
  const { stdout } = await execFileAsync("git", ["-C", cwd, ...args], {
    env: publicationGitEnvironment(),
    encoding: "buffer",
    maxBuffer: 16 * 1024 * 1024
  });
  return stdout;
}

async function run(command, args, cwd, environment = publicationGitEnvironment()) {
  return execFileAsync(command, args, {
    cwd: cwd ?? process.cwd(),
    env: environment,
    maxBuffer: 16 * 1024 * 1024
  });
}

function runAllowFailure(
  command,
  args,
  cwd,
  environment = publicationGitEnvironment(),
  execution = {}
) {
  return new Promise((resolvePromise, rejectPromise) => {
    let child;
    child = execFile(command, args, {
      cwd: cwd ?? process.cwd(),
      env: environment,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      ...(execution.uid === undefined ? {} : { uid: execution.uid }),
      ...(execution.gid === undefined ? {} : { gid: execution.gid }),
      ...(execution.timeoutMs === undefined
        ? {}
        : { timeout: execution.timeoutMs, killSignal: "SIGKILL" })
    }, (error, stdout, stderr) => {
      const timedOut = Boolean(error && error.killed === true);
      const signal = typeof error?.signal === "string" ? error.signal : null;
      if (error && typeof error.code !== "number" && !timedOut && signal === null) {
        rejectPromise(error);
        return;
      }
      resolvePromise({
        exitCode: error === null
          ? 0
          : typeof error.code === "number"
            ? error.code
            : null,
        stdout,
        stderr,
        pid: Number.isSafeInteger(child?.pid) ? child.pid : null,
        timedOut,
        signal
      });
    });
  });
}







/**
 * Resolves a synthetic policy selection without opening the protected policy
 * file. Parent-directory symlinks are resolved as paths, and final symlink
 * targets are inspected with readlink so a protected target is rejected
 * before its path is opened or read.
 */
async function targetsRestrictedPolicyPath(policyPath, publicRepo, platform = process.platform) {
  assertPathDoesNotTargetRestrictedPolicy(policyPath, "Selected policy", platform);
  assertPathDoesNotTargetRestrictedPolicy(publicRepo, "Public repository", platform);
  const publicRoot = await requireDirectory(publicRepo, "public repository");
  const restrictedPath = resolve(
    publicRoot,
    "security",
    "oss-security-policy.json"
  );
  let currentPath = resolve(policyPath);
  const visited = new Set();

  for (let linkCount = 0; linkCount < 40; linkCount += 1) {
    assertPathDoesNotTargetRestrictedPolicy(currentPath, "Selected policy", platform);
    if (currentPath === restrictedPath ||
        hasRestrictedPolicyPathSuffix(currentPath, platform)) {
      return true;
    }
    if (visited.has(currentPath)) {
      throw new Error("Synthetic policy path contains a symbolic-link cycle.");
    }
    visited.add(currentPath);

    await assertRealParentPath(currentPath, "Selected policy");
    const parentPath = await realpath(dirname(currentPath));
    const resolvedPath = resolve(parentPath, basename(currentPath));
    assertPathDoesNotTargetRestrictedPolicy(resolvedPath, "Selected policy", platform);
    if (resolvedPath === restrictedPath ||
        hasRestrictedPolicyPathSuffix(resolvedPath, platform)) {
      return true;
    }

    let target;
    try {
      target = await readlink(resolvedPath);
    } catch (error) {
      if (["EINVAL", "ENOENT", "ENOTDIR"].includes(error?.code)) return false;
      throw error;
    }
    currentPath = isAbsolute(target)
      ? resolve(target)
      : resolve(dirname(resolvedPath), target);
  }

  throw new Error("Synthetic policy path exceeds the symbolic-link resolution limit.");
}

/**
 * Identifies the restricted root-relative policy pathname without opening it.
 * A request file at this path must be rejected before its bytes can be read,
 * so the check uses only its final path components. Separator styles are
 * normalized, and Unicode normalization and case-fold aliases are handled
 * before comparison. The platform parameter supports deterministic path tests;
 * filesystem paths with unsupported Win32 alias syntax are rejected by the
 * request-path guards before metadata or content access.
 */
export function hasRestrictedPolicyPathSuffix(path, platform = process.platform) {
  if (typeof path !== "string") return false;
  return hasNormalizedRestrictedPolicySuffix(
    resolve(path.replace(/[\\/]/g, "/")),
    platform
  );
}

/**
 * Only the exact lowercase suffix with forward slashes is canonical. Other
 * spellings that normalize to the restricted path must fail before filtering.
 */
function isCanonicalRestrictedPolicyPathSuffix(path) {
  if (typeof path !== "string" || path.includes("\\")) return false;
  return path === EXCLUDED_HISTORY_EMAIL_PATH ||
    path.endsWith(`/${EXCLUDED_HISTORY_EMAIL_PATH}`);
}

/**
 * Rejects path spellings that can alias a protected or unsupported Win32 path
 * before callers filter entries or perform filesystem, Git object, or blob I/O.
 */
function assertNoUnsupportedRestrictedPathAlias(path, label, platform = process.platform) {
  if (hasUnsupportedWindowsPathAlias(path, platform)) {
    throw windowsPathAliasUnsupportedError(label);
  }
  if (
    hasRestrictedPolicyPathSuffix(path, platform) &&
    !isCanonicalRestrictedPolicyPathSuffix(path)
  ) {
    throw restrictedPolicyAliasUnsupportedError(label);
  }
}

/**
 * Rejects request-controlled paths with unsupported Win32 alias syntax or a
 * restricted-path suffix before filesystem operations use the path.
 */
function assertPathDoesNotTargetRestrictedPolicy(path, label, platform = process.platform) {
  assertNoUnsupportedRestrictedPathAlias(path, label, platform);
  if (typeof path === "string" && hasRestrictedPolicyPathSuffix(path, platform)) {
    throw new Error(`${label} cannot target the restricted security policy path.`);
  }
}

function windowsPathAliasUnsupportedError(label) {
  const error = new Error(`${label} uses unsupported Windows path alias syntax.`);
  error.code = "WINDOWS_PATH_ALIAS_UNSUPPORTED";
  return error;
}

function restrictedPolicyAliasUnsupportedError(label) {
  const error = new Error(`${label} uses an unsupported alias of a restricted security path.`);
  error.code = "RESTRICTED_POLICY_ALIAS_UNSUPPORTED";
  return error;
}

/**
 * Resolves a request-selected file path through its canonical parent and
 * returns the parent-canonical spelling with the supplied final component.
 * This detects parent aliases without opening or reading the target; callers
 * also apply lexical restricted-path and Win32 alias checks to the returned
 * spelling before opening it.
 */
async function resolveAllowedRequestPath(path, label, platform = process.platform) {
  assertPathDoesNotTargetRestrictedPolicy(path, label, platform);
  if (!isAbsolute(path)) throw new Error(`${label} path must be absolute.`);
  let resolvedParent;
  try {
    await assertRealParentPath(path, label);
    resolvedParent = await realpath(dirname(path));
  } catch {
    throw new Error(`${label} parent is unavailable.`);
  }
  const resolvedPath = join(resolvedParent, basename(path));
  assertPathDoesNotTargetRestrictedPolicy(resolvedPath, label, platform);
  return resolvedPath;
}

/**
 * Validates every filesystem path supplied to the exported scan API before any
 * caller-selected file is opened or any scanner runs. Parent directories are
 * canonicalized and the supplied final component is retained after static
 * restricted-path and Win32 alias checks. The resulting spellings are returned
 * in a new options object for the scan implementation.
 */
async function canonicalizeDirectScanPaths(options, platform = process.platform) {
  const pathEntries = [
    ["candidateRoot", options.candidateRoot],
    ["exportReportPath", options.exportReportPath],
    ["publicRepo", options.publicRepo],
    ["gitleaksBin", options.gitleaksBin],
    ["gitleaksConfig.path", options.gitleaksConfig?.path],
    ["gitleaksIgnore.path", options.gitleaksIgnore?.path]
  ];
  for (const [label, path] of pathEntries) {
    if (typeof path !== "string") {
      throw new Error(`${label} must be an absolute path.`);
    }
    assertPathDoesNotTargetRestrictedPolicy(path, label, platform);
    if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path.`);
  }
  for (const [label, input] of [
    ["Gitleaks config", options.gitleaksConfig],
    ["Gitleaks ignore", options.gitleaksIgnore]
  ]) {
    if (!input || typeof input !== "object" || Array.isArray(input) ||
        typeof input.sha256 !== "string" || !SHA256_HEX.test(input.sha256)) {
      throw new Error(`${label} requires an absolute path and lowercase SHA-256 digest.`);
    }
  }

  const [candidateRoot, publicRepo] = await Promise.all([
    requireDirectory(options.candidateRoot, "candidate root"),
    requireDirectory(options.publicRepo, "public repository")
  ]);
  const restrictedPath = resolve(publicRepo, "security", "oss-security-policy.json");
  const canonicalize = async (path, label) => {
    const canonicalPath = await resolveAllowedRequestPath(path, label, platform);
    if (canonicalPath === restrictedPath ||
        await targetsRestrictedPolicyPath(canonicalPath, publicRepo, platform)) {
      throw new Error(`${label} cannot target the restricted security policy path.`);
    }
    return canonicalPath;
  };

  const [exportReportPath, gitleaksBin,
    gitleaksConfigPath, gitleaksIgnorePath] = await Promise.all([
    canonicalize(options.exportReportPath, "export report"),
    canonicalize(options.gitleaksBin, "Gitleaks binary"),
    canonicalize(options.gitleaksConfig.path, "Gitleaks config"),
    canonicalize(options.gitleaksIgnore.path, "Gitleaks ignore")
  ]);
  return {
    ...options,
    candidateRoot,
    exportReportPath,
    publicRepo,
    gitleaksBin,
    gitleaksConfig: { ...options.gitleaksConfig, path: gitleaksConfigPath },
    gitleaksIgnore: { ...options.gitleaksIgnore, path: gitleaksIgnorePath }
  };
}

/**
 * Checks each filesystem path in a parsed scan request before any request
 * field is used to access the filesystem.
 */
function assertRequestPathsAvoidRestrictedPolicy(request, platform = process.platform) {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return;
  }
  const paths = [
    ["candidate_root", request.candidate_root],
    ["export_report_path", request.export_report_path],
    ["public_repo", request.public_repo],
    ["gitleaks_bin", request.gitleaks_bin],
    ["gitleaks_config.path", request.gitleaks_config?.path],
    ["gitleaks_ignore.path", request.gitleaks_ignore?.path]
  ];
  for (const [label, path] of paths) {
    assertPathDoesNotTargetRestrictedPolicy(path, label, platform);
  }
}

/**
 * Loads a scan request only when an owner explicitly invokes the CLI with a
 * request file. The policy path is an explicit input; no repository default is
 * opened or inferred. Win32 alias syntax in the request or its path fields is
 * rejected before the corresponding target is inspected or read.
 */
async function readExplicitScanRequest(requestPath, platform = process.platform) {
  if (typeof requestPath !== "string") {
    throw new Error("Scan request path must be absolute.");
  }
  assertPathDoesNotTargetRestrictedPolicy(requestPath, "Scan request", platform);
  if (!isAbsolute(requestPath)) throw new Error("Scan request path must be absolute.");
  const resolvedRequestPath = await resolveAllowedRequestPath(
    requestPath,
    "Scan request",
    platform
  );
  const requestBytes = await readSnapshotBytes(
    resolvedRequestPath,
    "Scan request",
    MAX_SCANNER_INPUT_BYTES,
    platform
  );
  const request = JSON.parse(requestBytes.toString("utf8"));
  assertRequestPathsAvoidRestrictedPolicy(request, platform);
  const allowed = new Set([
    "schema_version", "candidate_root", "export_report_path", "public_repo",
    "candidate_ref", "target_ref", "gitleaks_bin", "gitleaks_config",
    "gitleaks_ignore", "policy_path", "policy_source", "publication"
  ]);
  assertScanOptionKeys(request, allowed, "Scan request");
  if (request.schema_version !== 2) {
    throw new Error("Scan request must use schema version 2.");
  }
  if (!isPlainRecord(request.policy_source)) {
    throw new Error("Scan request must declare an explicit policy_source.");
  }
  if (request.policy_source.kind === "synthetic_fixture") {
    if (process.env.NODE_ENV !== "test") {
      throw new Error("Synthetic policy requests are available only to tests.");
    }
    assertScanOptionKeys(request.policy_source, new Set(["kind", "fixture_id"]), "Synthetic policy source");
    if (typeof request.policy_source.fixture_id !== "string" ||
        request.policy_source.fixture_id.length === 0) {
      throw new Error("Synthetic policy source requires a non-empty fixture_id.");
    }
    if (typeof request.policy_path !== "string" || !isAbsolute(request.policy_path)) {
      throw new Error("Synthetic policy requests require an explicit absolute policy_path.");
    }
  } else if (request.policy_source.kind === "owner_authorized_policy_file") {
    assertScanOptionKeys(request.policy_source, new Set(["kind"]), "Production policy source");
    if (request.policy_path !== undefined &&
        (typeof request.policy_path !== "string" || !isAbsolute(request.policy_path) ||
         request.policy_path !== TRUSTED_PRODUCTION_POLICY_SOURCE.path)) {
      throw productionPolicyUnavailableError();
    }
    assertTrustedProductionScannerInputs(request);
  } else {
    throw new Error("Scan request policy_source kind must be synthetic_fixture or owner_authorized_policy_file.");
  }
  const checkedPaths = await canonicalizeDirectScanPaths({
    candidateRoot: request.candidate_root,
    exportReportPath: request.export_report_path,
    publicRepo: request.public_repo,
    gitleaksBin: request.gitleaks_bin,
    gitleaksConfig: request.gitleaks_config,
    gitleaksIgnore: request.gitleaks_ignore
  }, platform);
  if (request.policy_source.kind === "owner_authorized_policy_file") {
    assertTrustedProductionScannerInputs(request, checkedPaths);
  }
  for (const key of ["candidate_ref", "target_ref"]) {
    if (typeof request[key] !== "string" || request[key].length === 0) {
      throw new Error("Scan request must include explicit candidate_ref and target_ref values.");
    }
  }
  if (request.publication?.candidate?.kind !== "ref" ||
      request.publication.candidate.ref !== request.candidate_ref ||
      request.publication?.target?.kind !== "ref" ||
      request.publication.target.ref !== request.target_ref) {
    throw new Error("Explicit candidate_ref and target_ref must match the publication selection.");
  }
  let trustedProductionSource = null;
  const exportReportPath = checkedPaths.exportReportPath;
  let policyPath = request.policy_path;
  if (request.policy_source.kind === "owner_authorized_policy_file") {
    trustedProductionSource = selectTrustedProductionPolicySource();
    if (!trustedProductionSource) throw productionPolicyUnavailableError();
    if (typeof trustedProductionSource.path !== "string" ||
        !isAbsolute(trustedProductionSource.path) ||
        typeof trustedProductionSource.source_id !== "string" ||
        trustedProductionSource.source_id.length === 0) {
      throw productionPolicyUnavailableError();
    }
    policyPath = trustedProductionSource.path;
  }
  if (request.policy_source.kind === "synthetic_fixture") {
    assertPathDoesNotTargetRestrictedPolicy(policyPath, "Selected security policy", platform);
    policyPath = await resolveAllowedRequestPath(
      policyPath,
      "Selected security policy",
      platform
    );
    if (await targetsRestrictedPolicyPath(policyPath, checkedPaths.publicRepo, platform)) {
      throw new Error("Synthetic policy requests cannot select the restricted repository policy path.");
    }
  } else {
    await assertRealParentPath(policyPath, "Selected security policy");
  }
  const policyBytes = await readSnapshotBytes(
    policyPath,
    "Selected security policy",
    MAX_SCANNER_INPUT_BYTES,
    platform
  );
  const sourceSha256 = createHash("sha256").update(policyBytes).digest("hex");
  if (trustedProductionSource && sourceSha256 !== trustedProductionSource.sha256) {
    throw productionPolicyUnavailableError();
  }
  const policy = JSON.parse(policyBytes.toString("utf8"));
  const policySha256 = createHash("sha256").update(JSON.stringify(policy)).digest("hex");
  const policyProvenance = request.policy_source.kind === "synthetic_fixture"
    ? {
        kind: "synthetic_fixture",
        fixture_id: request.policy_source.fixture_id,
        policy_sha256: policySha256
      }
    : {
        kind: "owner_authorized_policy_file",
        policy_sha256: policySha256,
        source_id: trustedProductionSource.source_id,
        source_sha256: sourceSha256,
        request_sha256: createHash("sha256").update(requestBytes).digest("hex")
      };
  if (policyProvenance.kind === "owner_authorized_policy_file") {
    ownerAuthorizedPolicyProvenance.add(policyProvenance);
  }
  return {
    candidateRoot: checkedPaths.candidateRoot,
    exportReportPath,
    publicRepo: checkedPaths.publicRepo,
    gitleaksBin: checkedPaths.gitleaksBin,
    gitleaksConfig: { ...request.gitleaks_config, path: checkedPaths.gitleaksConfig.path },
    gitleaksIgnore: { ...request.gitleaks_ignore, path: checkedPaths.gitleaksIgnore.path },
    policy,
    policyProvenance,
    publication: request.publication
  };
}

/**
 * Converts request-file failures into the CLI's path-redacted NOT_RUN result.
 * A validated request proceeds through the same trusted-local scanner entry
 * point as direct callers.
 */
export async function runSecurityScanRequest(
  requestPath,
  { platform = process.platform } = {}
) {
  try {
    const options = await readExplicitScanRequest(requestPath, platform);
    return await runSecurityScan(options, { platform });
  } catch (error) {
    const causeCode = safeScanCauseCode(error);
    return {
      schema_version: 2,
      status: "NOT_RUN",
      code: causeCode ?? "SCAN_INPUT_INVALID_OR_UNAVAILABLE",
      reason: causeCode === "PRODUCTION_POLICY_UNAVAILABLE"
        ? "The trusted production policy source or its expected digest is unavailable; the scan was not run."
        : "The scan request could not be validated or required inputs were unavailable.",
      scanner_invoked: false,
      mandatory_checks: [],
      production_eligible: false,
      scanner_clean: false,
      publication_eligible: false,
      owner_approval_required: true,
      ok: false
    };
  }
}

/**
 * The CLI requires an explicit owner-authored request and never infers a
 * candidate, target, or policy path.
 */
async function main() {
  const args = process.argv.slice(2);
  let result;
  if (args.length !== 2 || args[0] !== "--request") {
    result = {
      schema_version: 2,
      status: "NOT_RUN",
      code: "SCAN_REQUEST_REQUIRED",
      reason: "Pass --request with an explicit candidate, target, policy, and scanner configuration.",
      scanner_invoked: false,
      mandatory_checks: [],
      publication_eligible: false,
      owner_approval_required: true,
      ok: false
    };
  } else {
    result = await runSecurityScanRequest(args[1]);
  }
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  process.exitCode = result.status === "PASSED" ? 0 :
    result.status === "FAILED" ? 1 :
      result.status === "INCOMPLETE" ? 2 : 78;
}

if (process.argv[1] &&
  await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url))) {
  main().catch(() => {
    process.stderr.write("OSS security scan failed before producing a result.\n");
    process.exitCode = 1;
  });
}
