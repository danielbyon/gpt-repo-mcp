/** A publication candidate selected by a commit or an exact Git ref. */
export interface PublicationSelection {
  kind: "commit" | "ref";
  sha?: string;
  ref?: string;
}

/** Immutable ref and commit identity used to scope publication-history scans. */
export interface PublicationScope {
  fingerprint: string;
  candidate: PublicationSelection;
  target: PublicationSelection;
  candidate_commit: string;
  target_commit: string;
  refs: string[];
  ref_entries: Array<{ ref: string; commit_sha: string }>;
  commits: string[];
  pinned_commits: string[];
  commit_count: number;
  tag_objects: Array<{ ref: string; object_sha: string; commit_sha: string }>;
}

/**
 * Inputs accepted by direct callers for synthetic scans. When configured, a
 * trusted production source is selected internally by the CLI request flow.
 */
export interface SecurityScanOptions {
  candidateRoot: string;
  exportReportPath: string;
  publicRepo: string;
  gitleaksBin: string;
  gitleaksConfig: { path: string; sha256: string };
  gitleaksIgnore: { path: string; sha256: string };
  policy: unknown;
  policyProvenance: SyntheticPolicyProvenance;
  publication: unknown;
}

/** Provenance attached to an explicitly selected synthetic policy. */
export type PolicyProvenance = SyntheticPolicyProvenance;

export interface SyntheticPolicyProvenance {
  kind: "synthetic_fixture";
  fixture_id: string;
  policy_sha256: string;
}

/** A source location retained when an email occurrence needs owner review. */
export type SecurityEvidenceLocation =
  | { source: "candidate"; path: string; line: number }
  | { source: "commit_metadata"; commit: string; role: "author" | "committer" }
  | { source: "git_blob"; blob: string; path: string; line: number }
  | { source: "annotated_tag"; ref: string; object_sha: string; line: number };

/** An email address and its source location. */
export interface SecurityEmailOccurrence {
  address: string;
  location: SecurityEvidenceLocation;
}

/** Policy fields consumed by email occurrence classification. */
export interface SecurityEmailClassificationPolicy {
  allowed_domains: string[];
  allowed_addresses: string[];
  reviewed_public_history_locations?: Array<{
    commit: string;
    roles: Array<"author" | "committer">;
  }>;
}

/** Email classification totals and any locations that require owner review. */
export interface SecurityEmailEvidence {
  occurrence_count: number;
  allowed_count: number;
  reviewed_history_count: number;
  unclassified: SecurityEvidenceLocation[];
}

/** Stable result returned by the exported email classifier. */
export type SecurityEmailClassificationResult = SecurityEmailEvidence;

/** Package license data consumed by the exported license classifier. */
export interface SecurityLicenseRecord {
  name: string;
  version: string;
  license: string;
}

/** Stable result returned by the exported license classifier. */
export interface SecurityLicenseClassificationResult {
  package_count: number;
  license_counts: Record<string, number>;
  unapproved: SecurityLicenseRecord[];
}

/** Hashes and exit status for one completed Gitleaks invocation. */
export interface SecurityGitleaksScanReceipt {
  status: "COMPLETE";
  exit_code: 0 | 1;
  report_sha256: string;
  stdout_sha256: string;
  stderr_sha256: string;
}

/** Counts and rule-level totals for Gitleaks findings. */
export interface SecurityGitleaksSummary {
  finding_count: number;
  rule_counts: Record<string, number>;
}

/** Receipt for one bounded public-history batch scan. */
export interface SecurityGitleaksBatchReceipt {
  batch_index: number;
  commit_count: number;
  commits_sha256: string;
  exit_code: 0 | 1;
  report_sha256: string;
  stdout_sha256: string;
  stderr_sha256: string;
}

/** Candidate source identity and mandatory candidate-scan evidence. */
export interface SecurityCandidateEvidence {
  source_commit: string;
  tree_sha256: string;
  gitleaks: SecurityGitleaksSummary & { scan: SecurityGitleaksScanReceipt };
  email: SecurityEmailEvidence;
}

/** Gitleaks evidence accumulated across bounded selected-history batches. */
export interface SecurityHistoryGitleaksEvidence extends SecurityGitleaksSummary {
  scan_batches: SecurityGitleaksBatchReceipt[];
}

/** Candidate and selected-public-history identity and scan evidence. */
export interface SecurityPublicHistoryEvidence {
  checked_out_commit: string;
  selection: {
    fingerprint: string;
    refs: string[];
    ref_count: number;
    commit_count: number;
  };
  tag_metadata: SecurityHistoryGitleaksEvidence & {
    scan: { status: "COMPLETE" | "NOT_RUN"; reason?: string };
    email: SecurityEmailEvidence;
  };
  gitleaks: SecurityHistoryGitleaksEvidence;
  email: SecurityEmailEvidence;
}

/** License classification and dependency audit output. */
export interface SecurityDependencyEvidence {
  source: "source-commit-package-lock";
  package_json_sha256: string;
  package_lock_sha256: string;
  licenses: {
    package_count: number;
    license_counts: Record<string, number>;
    unapproved: Array<{ name: string; license: string; [field: string]: string | number | boolean | null }>;
  };
  audit: {
    production: SecurityAdvisorySet;
    development: SecurityDevelopmentAdvisorySet;
    unknown_development: SecurityAdvisory[];
    expired_development: SecurityAdvisory[];
    evidence: {
      executable_sha256: string;
      executable_version: string;
      version_exit_code: 0;
      registry: string;
      timeout_ms: number;
      full: SecurityNpmAuditReceipt;
      production: SecurityNpmAuditReceipt;
    };
  };
}

/** One dependency advisory included in the policy classification. */
export interface SecurityAdvisory {
  package: string;
  severity: string;
  direct: boolean;
  fix_available: boolean;
}

/** Advisory entries and audited dependency count for one audit scope. */
export interface SecurityAdvisorySet {
  total: number;
  entries: SecurityAdvisory[];
  dependency_count: number;
}

/** Development advisories excluded from the production dependency set. */
export interface SecurityDevelopmentAdvisorySet {
  total: number;
  entries: SecurityAdvisory[];
}

/** Policy fields consumed by dependency-audit classification. */
export interface SecurityAuditClassificationPolicy {
  known_development_advisories: Array<{
    package: string;
    severity: string;
    review_by: string;
  }>;
}

/** Minimal npm audit JSON accepted by the exported audit classifier. */
export interface SecurityNpmAuditInput {
  vulnerabilities: Record<string, {
    severity: string;
    isDirect: boolean;
    fixAvailable: boolean | Record<string, unknown>;
  }>;
  metadata?: {
    dependencies?: {
      total?: number;
    };
  };
}

/** Stable result returned by the exported dependency-audit classifier. */
export interface SecurityAuditClassificationResult {
  production: SecurityAdvisorySet;
  development: SecurityDevelopmentAdvisorySet;
  unknown_development: SecurityAdvisory[];
  expired_development: SecurityAdvisory[];
}

/** Hash and exit evidence for one npm audit command. */
export interface SecurityNpmAuditReceipt {
  exit_code: 0 | 1;
  stdout_sha256: string;
  stderr_sha256: string;
}

/** A recorded mandatory scanner stage, including available failure details. */
export interface SecurityScanStage {
  name: string;
  status: "running" | "complete" | "failed" | "not_run";
  reason?: string;
  exit_code?: number | null;
  timed_out?: boolean;
  signal?: string | null;
  candidate_commit?: string;
  target_commit?: string;
  candidate_ref?: string;
  target_ref?: string;
  selection_fingerprint?: string;
  file_count?: number;
  tree_sha256?: string;
  executable?: string;
  version?: string;
  finding_count?: number;
  report_sha256?: string;
  occurrence_count?: number;
  gitleaks_findings?: number;
  package_count?: number;
  unapproved_count?: number;
  audit_executable_version?: string;
  production_advisories?: number;
  unknown_development_advisories?: number;
  expired_development_advisories?: number;
  source_commit?: string;
  public_checked_out_commit?: string;
  skipped?: {
    binary_files?: number;
    large_files?: number;
    blobs_skipped_binary?: number;
    blobs_skipped_large?: number;
  };
}

/** Stable evidence fields returned after mandatory checks complete. */
export interface SecurityScanEvidence {
  schema_version: 2;
  mode: "task_local_candidate_snapshot";
  policy_version: string;
  /** Identities of the verified Gitleaks executable and ruleset inputs used. */
  scanner: {
    name: "gitleaks";
    version: string;
    platform: string;
    binary_sha256: string;
    config_sha256: string;
    ignore_sha256: string;
  };
  candidate: SecurityCandidateEvidence;
  public_history: SecurityPublicHistoryEvidence;
  dependencies: SecurityDependencyEvidence;
  blockers: string[];
  scanner_invoked: true;
  mandatory_checks: SecurityScanStage[];
  policy_provenance: PolicyProvenance;
  publication_eligible: false;
  owner_approval_required: true;
}

/** Scanner outcomes are discriminated by status; a clean scan never authorizes publication. */
export type SecurityScanResult =
  | {
      schema_version: 2;
      status: "NOT_RUN";
      code: "SCAN_REQUEST_REQUIRED" | "SCAN_INPUT_REQUIRED" | "SCAN_INPUT_INVALID_OR_UNAVAILABLE" | "POLICY_PROVENANCE_REQUIRED" | "POLICY_PROVENANCE_INVALID" | "PRODUCTION_POLICY_UNAVAILABLE" | "WINDOWS_PATH_ALIAS_UNSUPPORTED" | "RESTRICTED_POLICY_ALIAS_UNSUPPORTED" | "HOST_ATTESTATION_RETIRED";
      reason: string;
      missing_inputs?: string[];
      obsolete_options?: ["trustedSource"];
      scanner_invoked: false;
      mandatory_checks: [];
      policy_provenance?: PolicyProvenance | null;
      production_eligible?: false;
      scanner_clean: false;
      publication_eligible: false;
      owner_approval_required: true;
      ok: false;
    }
  | {
      schema_version: 2;
      mode: "task_local_candidate_snapshot";
      status: "INCOMPLETE";
      code: "MANDATORY_SCAN_INCOMPLETE";
      cause_code: string | null;
      reason: string;
      scanner_invoked: boolean;
      mandatory_checks: SecurityScanStage[];
      policy_provenance: PolicyProvenance;
      production_eligible: false;
      scanner_clean: false;
      publication_eligible: false;
      owner_approval_required: true;
      ok: false;
    }
  | (SecurityScanEvidence & {
      status: "FAILED";
      policy_provenance: PolicyProvenance;
      production_eligible: false;
      scanner_clean: false;
      ok: false;
    })
  | (SecurityScanEvidence & {
      status: "SYNTHETIC_PASSED";
      policy_provenance: SyntheticPolicyProvenance;
      production_eligible: false;
      scanner_clean: true;
      ok: false;
    });

/** Runs mandatory scanners against a selected candidate snapshot. */
export function runSecurityScan(
  options: SecurityScanOptions,
  pathOptions?: { platform?: string }
): Promise<SecurityScanResult>;

/** Runs a security scan using the request stored at the supplied filesystem path. */
export function runSecurityScanRequest(
  requestPath: string,
  pathOptions?: { platform?: string }
): Promise<SecurityScanResult>;

/** Checks a path suffix using the selected platform's lexical path rules. */
export function hasRestrictedPolicyPathSuffix(path: unknown, platform?: string): boolean;

/** Validates and resolves the exact commits and tags included in publication scans. */
export function publicationHistoryScope(publication: unknown): PublicationScope;

/** Rechecks the selected public refs against the resolved publication scope. */
export function verifyPublicationRefs(repoRoot: string, scope: PublicationScope, expected?: { candidate_commit?: string }): Promise<{ ref_count: number; commit_count: number }>;

/** Counters populated when public-history blobs are skipped during email scanning. */
export interface SecurityHistoryEmailCoverage {
  blobs_skipped_large?: number;
  blobs_skipped_binary?: number;
}

/**
 * Finds email occurrences in candidate file snapshots. The result reports
 * large and binary file skip counts.
 */
export function candidateEmailOccurrences(
  candidate: string,
  files: Array<{ path: string; bytes: number; sha256: string }>,
  options?: { platform?: string }
): Promise<{
  occurrences: SecurityEmailOccurrence[];
  skipped: { large_files: number; binary_files: number };
}>;

/**
 * When `includeBlobs` is true, validates every selected history path before
 * collecting commit metadata or reading text blobs. The optional coverage
 * object receives skipped-blob counts. `platform` supports deterministic
 * Win32 path checks.
 */
export function historyEmailOccurrences(
  repo: string,
  scope: Pick<PublicationScope, "commits">,
  options?: {
    includeBlobs?: boolean;
    coverage?: SecurityHistoryEmailCoverage;
    platform?: string;
  }
): Promise<SecurityEmailOccurrence[]>;

/** Classifies email occurrences against the selected policy. */
export function classifyEmailOccurrences(occurrences: SecurityEmailOccurrence[], policy: SecurityEmailClassificationPolicy): SecurityEmailClassificationResult;

/** Classifies package license records against the selected allowlist. */
export function classifyLicenseRecords(records: SecurityLicenseRecord[], allowedLicenses: string[]): SecurityLicenseClassificationResult;

/** Classifies production and development advisories against the selected policy. */
export function classifyAudit(fullAudit: SecurityNpmAuditInput, productionAudit: SecurityNpmAuditInput, policy: SecurityAuditClassificationPolicy, today?: Date): SecurityAuditClassificationResult;
