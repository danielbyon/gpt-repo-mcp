import { createHash } from "node:crypto";
import { lstat } from "node:fs/promises";
import { delimiter, join } from "node:path";
import ignore from "ignore";
import type { GitReviewInput, GitReviewResult } from "../contracts/git-review.contract.js";
import { ValidationLatestPointerV2Schema, ValidationReceiptV2Schema, ValidationSourceSnapshotSchema } from "../contracts/validation.contract.js";
import { IgnoreEngine } from "./ignore-engine.js";
import { GitService } from "./git-service.js";
import { OperationsPolicy } from "./operations-policy.js";
import { validateRepoPath } from "./path-sandbox.js";
import { DelegationGateService } from "./delegation-gate-service.js";
import { canonicalSha256, captureExecutableIdentity, readContainedRegularFile, ValidationEvidenceService } from "./validation-evidence.js";
import { RustRuntimeResolver } from "./rust-runtime-resolver.js";
import { NodeRuntimeResolver } from "./node-runtime-resolver.js";

const MAX_VALIDATION_POINTER_BYTES = 256 * 1024;
const MAX_VALIDATION_RECEIPT_BYTES = 128 * 1024 * 1024;
const VALIDATION_ROOT = ".chatgpt/validation";

type StatusFile = GitReviewResult["changed_paths"][number];

const STAGED_RECOVERY_WARNING = "STAGED_RECOVERY_REQUIRES_UNSTAGE_FIRST";
const STAGED_RECOVERY_GUIDANCE = [
  "Staged paths cannot be restored directly with repo_git_restore_paths because restore is worktree-only.",
  "For bad staged changes, use repo_write_recover with the review-provided unstage_paths and restore_paths, or use repo_write_unstage first when granular control is needed.",
  "If the staged diff is good, call repo_write_commit with the review-provided repo_write_commit_dry_run payload; it sets dry_run=true."
];

export class GitReviewService {
  private readonly ignoreEngine = new IgnoreEngine();

  constructor(
    private readonly root: string,
    private readonly operationsPolicy: OperationsPolicy = new OperationsPolicy(),
    private readonly delegationGate: DelegationGateService = new DelegationGateService(root)
  ) {}

  async review(input: GitReviewInput, requestedRunId?: string): Promise<GitReviewResult> {
    const git = new GitService(this.root);
    const detail = input.detail ?? "compact";
    const scopePaths = input.paths ? [...new Set(input.paths.map((path) => validateRepoPath(path)))].sort() : undefined;
    const scopeSet = scopePaths ? new Set(scopePaths) : undefined;
    const status = await git.status();
    const changedPathsAll = status.files.map((file) => ({
      ...file,
      status: classifyStatus(file.index, file.worktree),
      staged: file.index !== " " && file.index !== "?",
      unstaged: file.worktree !== " " || file.index === "?"
    }));
    const changedPaths = scopeSet ? changedPathsAll.filter((path) => scopeSet.has(path.path)) : changedPathsAll;
    const diffCandidatePaths = [...new Set(changedPaths
      .filter((path) => path.status !== "untracked")
      .map((path) => path.path))].sort();
    const maxFiles = input.max_files ?? diffCandidatePaths.length;
    const selectedDiffPaths = diffCandidatePaths.slice(0, maxFiles);
    const [unstagedDiff, stagedDiff, worktreeFingerprint, reviewStateFingerprint] = await Promise.all([
      git.diff({ paths: selectedDiffPaths }),
      git.diff({ staged: true, paths: selectedDiffPaths }),
      git.worktreeFingerprint(),
      git.reviewStateFingerprint()
    ]);
    const diff = mergeDiffs(stagedDiff, unstagedDiff);
    const diffSummaryTruncated = diff.truncated || selectedDiffPaths.length < diffCandidatePaths.length;
    const warnings = [...diff.warnings];
    if (scopeSet) {
      warnings.push("REVIEW_SCOPE_APPLIED");
      const omittedChangedPaths = changedPathsAll.filter((path) => !scopeSet.has(path.path));
      if (omittedChangedPaths.length > 0) {
        warnings.push("REVIEW_SCOPE_OMITTED_CHANGED_PATHS");
      }
      const missingScopePaths = (scopePaths ?? []).filter((path) => !changedPathsAll.some((changed) => changed.path === path));
      if (missingScopePaths.length > 0) {
        warnings.push("REVIEW_SCOPE_PATHS_NOT_CHANGED");
      }
    }
    if (diffSummaryTruncated) {
      warnings.push("DIFF_SUMMARY_TRUNCATED");
    }
    if (status.clean) {
      warnings.push("NO_CHANGES");
    }
    if (changedPaths.some((path) => path.status === "untracked")) {
      warnings.push("UNTRACKED_PATHS_REVIEWED_FOR_STAGING");
    }

    const excludedPaths: Array<{ path: string; reason: string }> = [];
    const recommendedStagePaths: string[] = [];
    for (const path of changedPaths) {
      const exclusion = this.exclusionReason(path);
      if (exclusion) {
        excludedPaths.push({ path: path.path, reason: exclusion });
        continue;
      }
      if (path.unstaged && !path.staged) {
        recommendedStagePaths.push(path.path);
      }
    }
    if (changedPaths.some((path) =>
      path.status === "untracked" && excludedPaths.some((excluded) => excluded.path === path.path)
    )) {
      warnings.push("UNTRACKED_PATHS_EXCLUDED");
    }
    const shipReadiness = await this.readShipReadiness(input.repo_id, status.head_sha, worktreeFingerprint);
    if (shipReadiness.validation.status === "stale") {
      warnings.push("VALIDATION_STALE");
    }
    if (shipReadiness.validation.status === "failed") {
      warnings.push("VALIDATION_FAILED");
    }
    if (shipReadiness.validation.status === "missing" && !status.clean) {
      warnings.push("VALIDATION_MISSING");
    }
    if (shipReadiness.validation.focused) {
      warnings.push("VALIDATION_FOCUSED");
    }

    const stagedPaths = changedPaths
      .filter((path) => path.staged && !this.exclusionReason(path))
      .map((path) => path.path)
      .sort();
    const hasStagedExcludedPaths = changedPaths.some((path) => path.staged && this.exclusionReason(path));
    const stagedRecoveryPaths = changedPaths
      .filter((path) => path.staged && this.isRecoverableWorktreePath(path))
      .map((path) => path.path)
      .sort();
    if (stagedRecoveryPaths.length > 0) {
      warnings.push(STAGED_RECOVERY_WARNING);
    }
    const recoverableWorktreePaths = changedPaths
      .filter((path) => path.unstaged && !path.staged && this.isRecoverableWorktreePath(path))
      .map((path) => path.path)
      .sort();
    const cleanupPaths = changedPaths
      .filter((path) => path.status === "untracked" && this.isCleanupEligible(path.path))
      .map((path) => path.path)
      .sort();
    const discardPaths = changedPaths
      .filter((path) => path.status === "untracked" && !this.exclusionReason(path) && !this.isCleanupEligible(path.path))
      .map((path) => path.path)
      .sort();
    const stagePaths = [...new Set(recommendedStagePaths)].sort();
    const expectedCommitPaths = [...new Set([...stagedPaths, ...stagePaths])].sort();
    const delegationGate = await this.delegationGate.evaluate({
      repo_id: input.repo_id,
      paths: expectedCommitPaths,
      operation: "review",
      requested_run_id: requestedRunId,
      head_sha: status.head_sha,
      review_state_fingerprint: reviewStateFingerprint
    });
    const happyPathAllowed = delegationGate.status !== "blocked";
    if (delegationGate.status === "blocked") {
      warnings.push("DELEGATION_REVIEW_GATE_BLOCKED", ...delegationGate.blocking_reasons);
    } else if (delegationGate.status === "advisory") {
      warnings.push("DELEGATION_REVIEW_GATE_ADVISORY", ...delegationGate.warnings);
    }
    const recoverRestorePaths = [...new Set([...recoverableWorktreePaths, ...stagedRecoveryPaths])].sort();
    const suggestedCommitMessage = suggestCommitMessage(expectedCommitPaths);
    const nextToolPayloads: GitReviewResult["next_tool_payloads"] = {};

    if (recoverableWorktreePaths.length > 0) {
      nextToolPayloads.repo_git_restore_paths_dry_run = {
        repo_id: input.repo_id,
        paths: recoverableWorktreePaths,
        expected_head_sha: status.head_sha,
        dry_run: true
      };
      nextToolPayloads.repo_git_restore_paths_actual = {
        repo_id: input.repo_id,
        paths: recoverableWorktreePaths,
        expected_head_sha: status.head_sha,
        dry_run: false
      };
    }

    if (cleanupPaths.length > 0) {
      nextToolPayloads.repo_cleanup_paths_dry_run = {
        repo_id: input.repo_id,
        paths: cleanupPaths,
        dry_run: true
      };
      nextToolPayloads.repo_cleanup_paths_actual = {
        repo_id: input.repo_id,
        paths: cleanupPaths,
        dry_run: false
      };
    }

    if (stagedPaths.length > 0) {
      nextToolPayloads.repo_write_unstage_dry_run = {
        repo_id: input.repo_id,
        paths: stagedPaths,
        expected_head_sha: status.head_sha,
        dry_run: true
      };
      nextToolPayloads.repo_write_unstage_actual = {
        repo_id: input.repo_id,
        paths: stagedPaths,
        expected_head_sha: status.head_sha,
        dry_run: false
      };
    }

    if (stagedRecoveryPaths.length > 0 || recoverRestorePaths.length > 0 || cleanupPaths.length > 0 || discardPaths.length > 0) {
      nextToolPayloads.repo_write_recover_dry_run = {
        repo_id: input.repo_id,
        expected_head_sha: status.head_sha,
        ...(stagedRecoveryPaths.length > 0 ? { unstage_paths: stagedRecoveryPaths } : {}),
        ...(recoverRestorePaths.length > 0 ? { restore_paths: recoverRestorePaths } : {}),
        ...(cleanupPaths.length > 0 ? { cleanup_paths: cleanupPaths } : {}),
        ...(discardPaths.length > 0 ? { discard_paths: discardPaths } : {}),
        dry_run: true
      };
      nextToolPayloads.repo_write_recover_actual = {
        repo_id: input.repo_id,
        expected_head_sha: status.head_sha,
        ...(stagedRecoveryPaths.length > 0 ? { unstage_paths: stagedRecoveryPaths } : {}),
        ...(recoverRestorePaths.length > 0 ? { restore_paths: recoverRestorePaths } : {}),
        ...(cleanupPaths.length > 0 ? { cleanup_paths: cleanupPaths } : {}),
        ...(discardPaths.length > 0 ? { discard_paths: discardPaths } : {}),
        dry_run: false
      };
    }

    if (stagePaths.length > 0 && happyPathAllowed) {
      nextToolPayloads.repo_write_stage_dry_run = {
        repo_id: input.repo_id,
        paths: stagePaths,
        expected_head_sha: status.head_sha,
        dry_run: true
      };
      nextToolPayloads.repo_write_stage_actual = {
        repo_id: input.repo_id,
        paths: stagePaths,
        expected_head_sha: status.head_sha,
        dry_run: false
      };
      if (stagedPaths.length === 0 && !hasStagedExcludedPaths) {
        nextToolPayloads.repo_write_stage_commit_dry_run = {
          repo_id: input.repo_id,
          paths: stagePaths,
          message: suggestedCommitMessage,
          expected_head_sha: status.head_sha,
          dry_run: true
        };
        nextToolPayloads.repo_write_stage_commit_actual = {
          repo_id: input.repo_id,
          paths: stagePaths,
          message: suggestedCommitMessage,
          expected_head_sha: status.head_sha,
          dry_run: false
        };
      }
    }

    if (expectedCommitPaths.length > 0 && happyPathAllowed) {
      nextToolPayloads.repo_write_commit_dry_run = {
        repo_id: input.repo_id,
        message: suggestedCommitMessage,
        expected_head_sha: status.head_sha,
        expected_staged_paths: expectedCommitPaths,
        dry_run: true
      };
    }

    const canonicalNextToolPayloads: GitReviewResult["next_tool_payloads"] = {};
    if (nextToolPayloads.repo_write_stage_commit_actual) {
      canonicalNextToolPayloads.repo_write_stage_commit = nextToolPayloads.repo_write_stage_commit_actual;
    }
    if (nextToolPayloads.repo_write_recover_actual) {
      canonicalNextToolPayloads.repo_write_recover = nextToolPayloads.repo_write_recover_actual;
    }
    if (stagePaths.length === 0 && stagedPaths.length > 0 && !hasStagedExcludedPaths && happyPathAllowed) {
      canonicalNextToolPayloads.repo_write_commit = {
        repo_id: input.repo_id,
        message: suggestedCommitMessage,
        expected_head_sha: status.head_sha,
        expected_staged_paths: expectedCommitPaths,
        dry_run: false
      };
    }
    const selectedNextToolPayloads = detail === "full"
      ? { ...nextToolPayloads, ...canonicalNextToolPayloads }
      : canonicalNextToolPayloads;

    return {
      ok: true,
      detail,
      branch: status.branch,
      head_sha: status.head_sha,
      clean: status.clean,
      changed_paths: changedPaths,
      diff_summary: {
        file_count: diffCandidatePaths.length,
        truncated: diffSummaryTruncated,
        files: diff.files.map((file) => ({
          path: file.path,
          status: file.status,
          hunk_count: file.hunks.length,
          summary: summarizeDiffFile(file.path, file.status, file.hunks.length)
        }))
      },
      recommendation: {
        ready_to_stage: stagePaths.length > 0 && happyPathAllowed,
        recommended_stage_paths: stagePaths,
        excluded_paths: excludedPaths,
        suggested_commit_message: suggestedCommitMessage,
        risk_level: riskLevel(warnings, excludedPaths),
        warnings,
        ...(stagedRecoveryPaths.length > 0 ? { recovery_guidance: STAGED_RECOVERY_GUIDANCE } : {})
      },
      delegation_gate: delegationGate,
      ship_readiness: shipReadiness,
      next_tool_payloads: status.clean ? {} : selectedNextToolPayloads
    };
  }

  private exclusionReason(path: StatusFile): string | undefined {
    if (isLocalCodexArtifactPath(path.path)) {
      return "LOCAL_CODEX_ARTIFACT_EXCLUDED";
    }
    if (this.ignoreEngine.isSensitiveCandidate(path.path)) {
      return "SECRET_CANDIDATE_REQUIRES_MANUAL_REVIEW";
    }
    if (this.ignoreEngine.isIgnored(path.path) || isGeneratedPath(path.path)) {
      return "GENERATED_PATH_EXCLUDED";
    }
    if (path.status === "deleted") {
      return "DELETED_PATH_REQUIRES_EXPLICIT_REVIEW";
    }
    if (path.status === "renamed") {
      return "RENAMED_PATH_REQUIRES_EXPLICIT_REVIEW";
    }
    return undefined;
  }

  private isCleanupEligible(path: string): boolean {
    if (!this.operationsPolicy.config.enabled || !this.operationsPolicy.config.cleanup_enabled) {
      return false;
    }
    if (this.ignoreEngine.isSensitiveCandidate(path)) {
      return false;
    }
    const matcher = ignore().add(this.operationsPolicy.config.cleanup_allowed_globs);
    return matcher.ignores(path) || matcher.ignores(`${path}/placeholder`);
  }

  private isRecoverableWorktreePath(path: StatusFile): boolean {
    if (path.status === "untracked" || path.status === "renamed") {
      return false;
    }
    return !this.ignoreEngine.isSensitiveCandidate(path.path);
  }

  private async readShipReadiness(
  repoId: string,
  headSha: string,
  worktreeFingerprint: string
): Promise<NonNullable<GitReviewResult["ship_readiness"]>> {
  const latestPath = ".chatgpt/validation/latest.json";
  let pointerBytes: Buffer;
  try {
    pointerBytes = await readContainedRegularFile(this.root, latestPath, MAX_VALIDATION_POINTER_BYTES);
  } catch {
    try {
      await lstat(join(this.root, latestPath));
      return { validation: { status: "unverified", eligibility: "unverified" } };
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "ENOENT"
        ? { validation: { status: "missing" } }
        : { validation: { status: "unverified", eligibility: "unverified" } };
    }
  }
  let raw: unknown;
  try {
    raw = JSON.parse(pointerBytes.toString("utf8")) as unknown;
  } catch {
    return { validation: { status: "unverified", eligibility: "unverified" } };
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { validation: { status: "unverified", eligibility: "unverified" } };
  }

  const parsedPointer = raw as Record<string, unknown>;
  if (parsedPointer.schema_version === 1) {
    const validationStatus = parsedPointer.status === "passed" || parsedPointer.status === "failed" || parsedPointer.status === "skipped"
      ? parsedPointer.status
      : undefined;
    const validationHead = typeof parsedPointer.head_sha === "string" ? parsedPointer.head_sha : undefined;
    const validationFingerprint = typeof parsedPointer.worktree_fingerprint === "string" ? parsedPointer.worktree_fingerprint : undefined;
    const fingerprintStale = validationFingerprint ? validationFingerprint !== worktreeFingerprint : worktreeFingerprint !== "clean";
    const stale = Boolean(validationHead && validationHead !== headSha) || fingerprintStale;
    const status = stale ? "stale" : validationStatus === "failed" ? "failed" : "unverified";
    return {
      validation: {
        status,
        eligibility: "unverified",
        evidence_contract_version: 1,
        ...(typeof parsedPointer.validation_id === "string" ? { validation_id: parsedPointer.validation_id } : {}),
        ...(validationStatus ? { validation_status: validationStatus } : {}),
        ...(typeof parsedPointer.profile === "string" ? { profile: parsedPointer.profile } : {}),
        ...(parsedPointer.focused === true ? { focused: true } : {}),
        ...(Array.isArray(parsedPointer.test_paths) && parsedPointer.test_paths.every((path) => typeof path === "string")
          ? { test_paths: parsedPointer.test_paths as string[] }
          : {}),
        ...(validationHead ? { head_sha: validationHead } : {}),
        ...(validationFingerprint ? { worktree_fingerprint: validationFingerprint } : {}),
        ...(typeof parsedPointer.artifact_path === "string" ? { artifact_path: parsedPointer.artifact_path } : {})
      }
    };
  }
  if (parsedPointer.schema_version !== 2) {
    return { validation: { status: "unverified", eligibility: "unverified" } };
  }

  const pointerResult = ValidationLatestPointerV2Schema.safeParse(raw);
  if (!pointerResult.success) return { validation: { status: "unverified", eligibility: "unverified", evidence_contract_version: 2 } };
  const pointer = pointerResult.data;
  const validationSummary = {
    validation_id: pointer.validation_id,
    validation_status: pointer.status,
    profile: pointer.profile,
    focused: pointer.focused,
    test_paths: pointer.test_paths,
    head_sha: pointer.head_sha,
    worktree_fingerprint: pointer.worktree_fingerprint,
    artifact_path: pointer.artifact_path,
    evidence_contract_version: 2,
    receipt_sha256: pointer.receipt_sha256
  };
  const unverified = () => ({
    validation: { status: "unverified" as const, eligibility: "unverified" as const, ...validationSummary }
  });
  if (pointer.repo_id !== repoId || !/^validation-[A-Za-z0-9-]{1,100}$/.test(pointer.validation_id)) return unverified();
  const expectedArtifactPath = VALIDATION_ROOT + "/" + pointer.validation_id + "/result.json";
  if (pointer.artifact_path !== expectedArtifactPath) return unverified();

  let receiptRaw: unknown;
  try {
    const receiptBytes = await readContainedRegularFile(this.root, pointer.artifact_path, MAX_VALIDATION_RECEIPT_BYTES);
    receiptRaw = JSON.parse(receiptBytes.toString("utf8")) as unknown;
  } catch {
    return unverified();
  }
  const receiptResult = ValidationReceiptV2Schema.safeParse(receiptRaw);
  if (!receiptResult.success) return unverified();
  const receipt = receiptResult.data;
  const { receipt_sha256: receiptSha, ...unsignedReceipt } = receipt;
  const receiptHashMatches = canonicalSha256(unsignedReceipt) === receiptSha;
  const pointerMatches = receiptSha === pointer.receipt_sha256
    && receipt.validation_id === pointer.validation_id
    && receipt.repo_id === pointer.repo_id
    && receipt.profile === pointer.profile
    && receipt.focused === pointer.focused
    && sameStrings(receipt.test_paths, pointer.test_paths)
    && receipt.status === pointer.status
    && receipt.eligibility.status === pointer.eligibility
    && receipt.head_sha === pointer.head_sha
    && receipt.worktree_fingerprint === pointer.worktree_fingerprint
    && receipt.artifact_path === pointer.artifact_path
    && receipt.timestamp === pointer.timestamp;
  if (!receiptHashMatches || !pointerMatches) return unverified();

  const ineligibleReasons: string[] = [];
  const unverifiedReasons: string[] = [];
  if (receipt.eligibility.status === "ineligible") {
    if (receipt.eligibility.reasons.length === 0) unverifiedReasons.push("VALIDATION_ELIGIBILITY_REASON_MISSING");
    else ineligibleReasons.push(...receipt.eligibility.reasons);
  } else if (receipt.eligibility.status === "unverified") {
    unverifiedReasons.push(...(receipt.eligibility.reasons.length > 0
      ? receipt.eligibility.reasons
      : ["VALIDATION_ELIGIBILITY_REASON_MISSING"]));
  } else if (receipt.eligibility.reasons.length > 0) {
    unverifiedReasons.push("VALIDATION_ELIGIBILITY_STATE_CONTRADICTORY");
  }
  if (receipt.status === "failed") ineligibleReasons.push("VALIDATION_COMMAND_FAILED");
  if (receipt.status === "skipped") unverifiedReasons.push("VALIDATION_COMMAND_NOT_EXECUTED");

  if (canonicalSha256(receipt.effective_policy.value) !== receipt.effective_policy.sha256
      || receipt.effective_policy.sha256 !== receipt.effective_policy.after_sha256
      || canonicalSha256(this.operationsPolicy.config) !== receipt.effective_policy.sha256) {
    ineligibleReasons.push("EFFECTIVE_POLICY_CHANGED");
  }

  const before = receipt.source_evidence.before;
  const after = receipt.source_evidence.after;
  if (!before || !after || !validSourceSnapshot(before) || !validSourceSnapshot(after)) {
    unverifiedReasons.push("SOURCE_EVIDENCE_UNAVAILABLE_OR_INVALID");
  } else if (before.sha256 !== after.sha256) {
    ineligibleReasons.push("SOURCE_STATE_CHANGED_DURING_RUN");
  } else {
    const recipeSourcePaths = new Set<string>();
    let recipeGraphAvailable = true;
    for (const command of receipt.commands) {
      if (!command.recipe) continue;
      try {
        const paths = await new RustRuntimeResolver(this.root).discoverRecipeSources([command.recipe.path]);
        for (const path of paths) recipeSourcePaths.add(path);
      } catch {
        recipeGraphAvailable = false;
        unverifiedReasons.push("RECIPE_SOURCE_GRAPH_UNAVAILABLE");
      }
    }
    const validatedPaths = new Map(after.files.map((file) => [file.path, file]));
    for (const path of recipeSourcePaths) {
      const source = validatedPaths.get(path);
      if (!source || source.worktree.kind !== "file" || !source.worktree.content_sha256) {
        recipeGraphAvailable = false;
        unverifiedReasons.push("RECIPE_SOURCE_EVIDENCE_INCOMPLETE");
      }
    }
    if (recipeGraphAvailable) {
      try {
        const current = await new ValidationEvidenceService(this.root).captureSourceSnapshot(undefined, [...recipeSourcePaths].sort());
        if (current.sha256 !== after.sha256) ineligibleReasons.push("CANDIDATE_STATE_CHANGED_AFTER_VALIDATION");
      } catch {
        unverifiedReasons.push("CURRENT_CANDIDATE_STATE_UNAVAILABLE");
      }
    }
  }
  if (receipt.head_sha && receipt.head_sha !== headSha) ineligibleReasons.push("CANDIDATE_HEAD_CHANGED_AFTER_VALIDATION");

  if (receipt.runner_post_state.length !== receipt.commands.length) {
    unverifiedReasons.push("RUNNER_RECHECK_UNAVAILABLE");
  } else {
    for (let index = 0; index < receipt.commands.length; index += 1) {
      const command = receipt.commands[index]!;
      const post = receipt.runner_post_state[index]!;
      if (post.status !== "verified") {
        unverifiedReasons.push("RUNNER_RECHECK_UNAVAILABLE");
        continue;
      }
      if (canonicalSha256(runnerStateFromCommand(command)) !== canonicalSha256(runnerStateFromPost(post))) {
        ineligibleReasons.push("RUNNER_STATE_CHANGED_DURING_RUN");
      }

      let pathPrefixes: string[] = [];
      let selectedRust: Awaited<ReturnType<RustRuntimeResolver["resolve"]>>;
      let selectedNode: Awaited<ReturnType<NodeRuntimeResolver["resolve"]>>;
      if (command.runtime?.name === "rust") {
        try {
          selectedRust = await new RustRuntimeResolver(this.root).resolve({ recipe_paths: command.recipe ? [command.recipe.path] : [] });
          if (!selectedRust) throw new Error("Rust toolchain unavailable.");
          pathPrefixes = selectedRust.path_prefixes;
          if (canonicalSha256(runtimeFromRust(selectedRust)) !== canonicalSha256(command.runtime)) {
            ineligibleReasons.push("RUST_TOOLCHAIN_CHANGED_AFTER_VALIDATION");
          }
        } catch {
          unverifiedReasons.push("RUST_TOOLCHAIN_UNAVAILABLE");
        }
      } else if (command.runtime?.name === "node") {
        try {
          selectedNode = await new NodeRuntimeResolver(this.root).resolve();
          if (!selectedNode) throw new Error("Node runtime unavailable.");
          pathPrefixes = [selectedNode.bin_directory];
          if (selectedNode.version !== command.runtime.version || selectedNode.source !== command.runtime.source) {
            ineligibleReasons.push("NODE_RUNTIME_CHANGED_AFTER_VALIDATION");
          }
        } catch {
          unverifiedReasons.push("NODE_RUNTIME_UNAVAILABLE");
        }
      }
      const currentPath = [...pathPrefixes, process.env.PATH ?? ""].filter(Boolean).join(delimiter);
      if (!command.executable_identity) {
        unverifiedReasons.push("RUNNER_IDENTITY_MISSING");
      } else {
        try {
          const currentIdentity = await captureExecutableIdentity(this.root, command.executable, currentPath);
          if (canonicalSha256(currentIdentity) !== canonicalSha256(command.executable_identity)) ineligibleReasons.push("RUNNER_CHANGED_AFTER_VALIDATION");
        } catch {
          unverifiedReasons.push("RUNNER_IDENTITY_UNAVAILABLE");
        }
      }
      if (command.runtime_executable_identity) {
        try {
          const runtimeExecutable = command.runtime?.name === "node" && selectedNode
            ? join(selectedNode.bin_directory, process.platform === "win32" ? "node.exe" : "node")
            : "node";
          const currentRuntimeIdentity = await captureExecutableIdentity(this.root, runtimeExecutable, currentPath);
          if (canonicalSha256(currentRuntimeIdentity) !== canonicalSha256(command.runtime_executable_identity)) {
            ineligibleReasons.push("RUNTIME_CHANGED_AFTER_VALIDATION");
          }
        } catch {
          unverifiedReasons.push("RUNTIME_IDENTITY_UNAVAILABLE");
        }
      } else if (command.executable === "npm") {
        unverifiedReasons.push("RUNTIME_IDENTITY_MISSING");
      }
      if (command.recipe) {
        try {
          const recipeBytes = await readContainedRegularFile(this.root, command.recipe.path, 256 * 1024);
          const currentRecipe = { path: command.recipe.path, size_bytes: recipeBytes.length, sha256: createHash("sha256").update(recipeBytes).digest("hex") };
          if (canonicalSha256(currentRecipe) !== canonicalSha256(command.recipe)) ineligibleReasons.push("RUNNER_RECIPE_CHANGED_AFTER_VALIDATION");
        } catch {
          ineligibleReasons.push("RUNNER_RECIPE_UNAVAILABLE");
        }
      }
    }
  }

  const eligibility = ineligibleReasons.length > 0 ? "ineligible" : unverifiedReasons.length > 0 ? "unverified" : "eligible";
  const status = receipt.status === "failed"
    ? "failed"
    : eligibility === "ineligible" ? "stale" : eligibility === "unverified" ? "unverified" : "passed";
  return { validation: { status, eligibility, ...validationSummary } };
}
}

function validSourceSnapshot(value: unknown): boolean {
  const parsed = ValidationSourceSnapshotSchema.safeParse(value);
  if (!parsed.success) return false;
  const { sha256, ...unsigned } = parsed.data;
  return canonicalSha256(unsigned) === sha256 && canonicalSha256(parsed.data.index.entries) === parsed.data.index.sha256;
}

function sameStrings(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function runnerStateFromCommand(command: {
  profile: string;
  script: string;
  executable: string;
  executable_identity?: unknown;
  runtime_executable_identity?: unknown;
  recipe?: unknown;
  runtime?: unknown;
}): Record<string, unknown> {
  return {
    profile: command.profile,
    script: command.script,
    executable: command.executable,
    executable_identity: command.executable_identity,
    runtime_executable_identity: command.runtime_executable_identity,
    recipe: command.recipe,
    runtime: command.runtime
  };
}

function runnerStateFromPost(post: {
  profile: string;
  script: string;
  executable: string;
  executable_identity?: unknown;
  runtime_executable_identity?: unknown;
  recipe?: unknown;
  runtime?: unknown;
}): Record<string, unknown> {
  return runnerStateFromCommand(post);
}

function runtimeFromRust(selection: Awaited<ReturnType<RustRuntimeResolver["resolve"]>>): unknown {
  if (!selection) return undefined;
  return {
    name: "rust",
    version: selection.version,
    source: selection.source,
    active_toolchain: selection.active_toolchain,
    ...(selection.rustup ? {
      rustup: {
        path_sha256: selection.rustup.path_sha256,
        real_path_sha256: selection.rustup.real_path_sha256,
        version: selection.rustup.version,
        sha256: selection.rustup.sha256
      }
    } : {}),
    cargo: {
      path_sha256: selection.cargo.path_sha256,
      real_path_sha256: selection.cargo.real_path_sha256,
      version: selection.cargo.version,
      sha256: selection.cargo.sha256
    },
    rustc: {
      path_sha256: selection.rustc.path_sha256,
      real_path_sha256: selection.rustc.real_path_sha256,
      version: selection.rustc.version,
      sha256: selection.rustc.sha256
    },
    cargo_home_path_sha256: selection.cargo_home_path_sha256,
    cargo_config_sha256: selection.cargo_config_sha256
  };
}

function classifyStatus(index: string, worktree: string): StatusFile["status"] {
  if (index === "?" && worktree === "?") {
    return "untracked";
  }
  if (index === "R" || worktree === "R") {
    return "renamed";
  }
  if (index === "D" || worktree === "D") {
    return "deleted";
  }
  if (index === "A" || worktree === "A") {
    return "added";
  }
  if (index === "M" || worktree === "M") {
    return "modified";
  }
  return "unknown";
}

function isGeneratedPath(path: string): boolean {
  return /^(dist|coverage|test-results|node_modules)\//.test(path);
}

function isLocalCodexArtifactPath(path: string): boolean {
  return path.startsWith(".chatgpt/codex-runs/");
}

type GitDiff = Awaited<ReturnType<GitService["diff"]>>;

function mergeDiffs(stagedDiff: GitDiff, unstagedDiff: GitDiff): GitDiff {
  const filesByPath = new Map<string, GitDiff["files"][number]>();
  for (const file of [...stagedDiff.files, ...unstagedDiff.files]) {
    const existing = filesByPath.get(file.path);
    if (!existing) {
      filesByPath.set(file.path, { ...file, hunks: [...file.hunks] });
      continue;
    }
    filesByPath.set(file.path, {
      ...existing,
      status: existing.status ?? file.status,
      original_path: existing.original_path ?? file.original_path,
      hunks: [...existing.hunks, ...file.hunks]
    });
  }

  const truncationReasons = [stagedDiff.truncation_reason, unstagedDiff.truncation_reason]
    .filter((value): value is NonNullable<GitDiff["truncation_reason"]> => Boolean(value));
  const hasMaxFiles = truncationReasons.some((value) => value.includes("max_files"));
  const hasMaxBytes = truncationReasons.some((value) => value.includes("max_bytes"));
  return {
    base: stagedDiff.base ?? unstagedDiff.base,
    compare: stagedDiff.compare ?? unstagedDiff.compare,
    staged: stagedDiff.staged,
    unstaged: unstagedDiff.unstaged,
    files: [...filesByPath.values()],
    total_file_count: new Set([
      ...stagedDiff.files.map((file) => file.path),
      ...unstagedDiff.files.map((file) => file.path)
    ]).size,
    truncated: stagedDiff.truncated || unstagedDiff.truncated,
    truncation_reason: hasMaxFiles && hasMaxBytes
      ? "max_files+max_bytes"
      : hasMaxFiles ? "max_files" : hasMaxBytes ? "max_bytes" : undefined,
    warnings: [...stagedDiff.warnings, ...unstagedDiff.warnings]
  };
}


function summarizeDiffFile(path: string, status: string | undefined, hunkCount: number): string {
  return `${status ?? "modified"} ${path} (${hunkCount} hunks)`;
}

function suggestCommitMessage(paths: string[]): string {
  if (paths.length === 0) {
    return "No changes to commit";
  }
  if (paths.every((path) => path.startsWith("docs/") || path.startsWith(".chatgpt/"))) {
    return "Update docs";
  }
  if (paths.some((path) => path.startsWith("src/tools/"))) {
    return "Update tool surface";
  }
  if (paths.some((path) => path.startsWith("src/services/") || path.startsWith("src/contracts/"))) {
    return "Update write tooling";
  }
  if (paths.some((path) => path.startsWith("tests/"))) {
    return "Update tests";
  }
  return "Update reviewed files";
}

function riskLevel(warnings: string[], excludedPaths: Array<{ path: string; reason: string }>): "low" | "medium" | "high" {
  if (excludedPaths.some((path) => path.reason.includes("SECRET"))) {
    return "high";
  }
  if (warnings.length === 1 && warnings[0] === "NO_CHANGES") {
    return "low";
  }
  if (warnings.length > 0 || excludedPaths.length > 0) {
    return "medium";
  }
  return "low";
}
