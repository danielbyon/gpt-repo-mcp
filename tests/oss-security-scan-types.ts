import {
  candidateEmailOccurrences,
  classifyAudit,
  classifyEmailOccurrences,
  classifyLicenseRecords,
  historyEmailOccurrences,
  runSecurityScan,
  runSecurityScanRequest,
  type SecurityEmailOccurrence,
  type SecurityEvidenceLocation,
  type SecurityHistoryEmailCoverage,
  type SecurityScanOptions,
  type SecurityScanResult,
  type SecurityNpmAuditInput,
  type SecurityAdvisory
} from "../scripts/oss-security-scan.mjs";

declare const completeOptions: SecurityScanOptions;
void runSecurityScan(completeOptions);

const requestResult: Promise<SecurityScanResult> = runSecurityScanRequest(
  "security-scan-request.json"
);
void requestResult;

const restrictedPolicyAliasCode: Extract<SecurityScanResult, {
  status: "NOT_RUN"
}>["code"] = "RESTRICTED_POLICY_ALIAS_UNSUPPORTED";
void restrictedPolicyAliasCode;

const callerConstructedOwnerAuthorizedProvenance = {
  kind: "owner_authorized_policy_file",
  policy_sha256: "policy-hash",
  source_id: "production-policy",
  source_sha256: "source-hash",
  request_sha256: "request-hash"
} as const;
// @ts-expect-error Owner-authorized provenance is minted by the explicit request flow, not callers.
void runSecurityScan({ ...completeOptions, policyProvenance: callerConstructedOwnerAuthorizedProvenance });

// @ts-expect-error Retired trustedSource remains runtime-only for legacy JavaScript callers.
void runSecurityScan({ ...completeOptions, trustedSource: {} });

// @ts-expect-error Policy provenance is required by the runtime contract.
void runSecurityScan({ ...completeOptions, policyProvenance: undefined });

declare const looseOptions: Record<string, unknown>;
// @ts-expect-error Arbitrary records are not a supported typed entry point.
void runSecurityScan(looseOptions);

declare const result: SecurityScanResult;
if (result.status === "NOT_RUN") {
  const scannerInvoked: false = result.scanner_invoked;
  const ok: false = result.ok;
  void scannerInvoked;
  void ok;
}
// @ts-expect-error No trusted production policy source is configured in this build.
const productionStatus: "PASSED" = result.status;
void productionStatus;
if (result.status === "SYNTHETIC_PASSED") {
  const ok: false = result.ok;
  const scannerClean: true = result.scanner_clean;
  const productionEligible: false = result.production_eligible;
  const provenance: "synthetic_fixture" = result.policy_provenance.kind;
  const binarySha256: string = result.scanner.binary_sha256;
  const configSha256: string = result.scanner.config_sha256;
  const ignoreSha256: string = result.scanner.ignore_sha256;
  void ok;
  void scannerClean;
  void productionEligible;
  void provenance;
  void binarySha256;
  void configSha256;
  void ignoreSha256;
}
if (result.status === "FAILED" || result.status === "SYNTHETIC_PASSED") {
  const sourceCommit: string = result.candidate.source_commit;
  const candidateFindingCount: number = result.candidate.gitleaks.finding_count;
  const historyFingerprint: string = result.public_history.selection.fingerprint;
  const auditVersion: string = result.dependencies.audit.evidence.executable_version;
  void sourceCommit;
  void candidateFindingCount;
  void historyFingerprint;
  void auditVersion;
}
if (result.status === "INCOMPLETE") {
  const failedStage = result.mandatory_checks.find((stage) => stage.status === "failed");
  const reason: string | undefined = failedStage?.reason;
  const exitCode: number | null | undefined = failedStage?.exit_code;
  const timedOut: boolean | undefined = failedStage?.timed_out;
  const signal: string | null | undefined = failedStage?.signal;
  void reason;
  void exitCode;
  void timedOut;
  void signal;
}

const historyCoverage: SecurityHistoryEmailCoverage = {};
const candidateFiles = [
  { path: "src/index.js", bytes: 0, sha256: "0".repeat(64) }
];
const candidateEmailResult: Promise<{
  occurrences: SecurityEmailOccurrence[];
  skipped: { large_files: number; binary_files: number };
}> = candidateEmailOccurrences(".", candidateFiles, { platform: "linux" });
const defaultPlatformCandidateEmailResult = candidateEmailOccurrences(
  ".",
  candidateFiles
);
void candidateEmailResult;
void defaultPlatformCandidateEmailResult;

const historyOccurrences = historyEmailOccurrences(
  ".",
  { commits: [] },
  { includeBlobs: true, coverage: historyCoverage }
);
void historyOccurrences.then((occurrences) => {
  const preciseOccurrences: SecurityEmailOccurrence[] = occurrences;
  const firstAddress: string | undefined = preciseOccurrences[0]?.address;
  const firstLocation: SecurityEvidenceLocation | undefined =
    preciseOccurrences[0]?.location;
  if (firstLocation?.source === "candidate") {
    const path: string = firstLocation.path;
    const line: number = firstLocation.line;
    void path;
    void line;
  }
  if (firstLocation?.source === "commit_metadata") {
    const commit: string = firstLocation.commit;
    const role: "author" | "committer" = firstLocation.role;
    void commit;
    void role;
  }
  if (firstLocation?.source === "git_blob") {
    const blob: string = firstLocation.blob;
    const path: string = firstLocation.path;
    const line: number = firstLocation.line;
    void blob;
    void path;
    void line;
  }
  if (firstLocation?.source === "annotated_tag") {
    const ref: string = firstLocation.ref;
    const objectSha: string = firstLocation.object_sha;
    const line: number = firstLocation.line;
    void ref;
    void objectSha;
    void line;
  }
  void firstAddress;
});
const skippedLargeBlobs: number | undefined = historyCoverage.blobs_skipped_large;
const skippedBinaryBlobs: number | undefined = historyCoverage.blobs_skipped_binary;
void skippedLargeBlobs;
void skippedBinaryBlobs;

const emailClassification = classifyEmailOccurrences([], {
  allowed_domains: [],
  allowed_addresses: []
});
const emailOccurrenceCount: number = emailClassification.occurrence_count;
const emailAllowedCount: number = emailClassification.allowed_count;
const emailLocationSource: string | undefined = emailClassification.unclassified[0]?.source;
void emailOccurrenceCount;
void emailAllowedCount;
void emailLocationSource;

const licenseClassification = classifyLicenseRecords([], []);
const packageCount: number = licenseClassification.package_count;
const licenseCount: number | undefined = licenseClassification.license_counts.MIT;
const unapprovedPackageName: string | undefined = licenseClassification.unapproved[0]?.name;
void packageCount;
void licenseCount;
void unapprovedPackageName;

const auditInput: SecurityNpmAuditInput = {
  vulnerabilities: {},
  metadata: { dependencies: { total: 0 } }
};
const auditClassification = classifyAudit(auditInput, auditInput, {
  known_development_advisories: []
});
const productionAdvisoryCount: number = auditClassification.production.total;
const productionDependencyCount: number = auditClassification.production.dependency_count;
const advisory: SecurityAdvisory | undefined = auditClassification.production.entries[0];
const developmentAdvisoryCount: number = auditClassification.development.total;
const unknownAdvisoryCount: number = auditClassification.unknown_development.length;
void productionAdvisoryCount;
void productionDependencyCount;
void advisory;
void developmentAdvisoryCount;
void unknownAdvisoryCount;

// @ts-expect-error Audit classification accepts the documented npm audit structure.
classifyAudit("opaque", auditInput, { known_development_advisories: [] });
