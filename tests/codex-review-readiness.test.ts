import { describe, expect, test } from "vitest";
import { evaluateCodexTechnicalReadiness } from "../src/services/codex-review-readiness.js";
import type { CodexRunManifest } from "../src/services/codex-run-manifest.js";

describe("Codex review validation readiness", () => {
  test("matches the structured profile and focused paths against eligible V2 evidence", () => {
    const readiness = evaluateCodexTechnicalReadiness(readinessInput(
      { profile: "test", test_paths: ["tests/auth.test.ts"] },
      { status: "passed", eligibility: "eligible", profile: "test", test_paths: ["tests/auth.test.ts"] }
    ));

    expect(readiness.checks.validation).toBe("passed");
  });

  test("does not accept a receipt for different profile, paths, or evidence version", () => {
    expect(evaluateCodexTechnicalReadiness(readinessInput(
      { profile: "test", test_paths: ["tests/auth.test.ts"] },
      { status: "passed", eligibility: "eligible", profile: "smoke", test_paths: ["tests/auth.test.ts"] }
    )).checks.validation).toBe("incomplete");

    expect(evaluateCodexTechnicalReadiness(readinessInput(
      { profile: "test", test_paths: ["tests/auth.test.ts"] },
      { status: "passed", eligibility: "eligible", profile: "test", test_paths: ["tests/other.test.ts"] }
    )).checks.validation).toBe("incomplete");

    expect(evaluateCodexTechnicalReadiness(readinessInput(
      { profile: "test", test_paths: ["tests/auth.test.ts"] },
      { status: "passed", eligibility: "unverified", profile: "test", test_paths: ["tests/auth.test.ts"] }
    )).checks.validation).toBe("incomplete");
  });

  test("keeps validation not applicable when the task has no structured request", () => {
    expect(evaluateCodexTechnicalReadiness(readinessInput(undefined, undefined)).checks.validation)
      .toBe("not_applicable");
  });
});

function readinessInput(
  request: { profile: string; test_paths: string[] } | undefined,
  validation: { status: string; eligibility: string; profile: string; test_paths: string[] } | undefined
): Parameters<typeof evaluateCodexTechnicalReadiness>[0] {
  const manifest = {
    schema_version: 3,
    task: { ...(request ? { validation: request } : {}) }
  } as unknown as CodexRunManifest;
  return {
    integrity: {
      manifest_found: true,
      manifest_bound: true,
      prompt_found: true,
      head_matches_baseline: true,
      authorization_matches: true
    },
    scope: {
      newly_observed_paths: [],
      pre_existing_paths: [],
      attributed_paths: [],
      dirty_baseline_attributed_paths: [],
      unattributed_paths: [],
      out_of_scope_paths: [],
      forbidden_paths: [],
      claimed_but_not_observed: [],
      observed_but_unreported: [],
      attribution_ambiguous_paths: []
    },
    technicalAcceptance: {
      binding_available: true,
      expected_ids: [],
      reported_ids: [],
      passed_ids: [],
      failed_ids: [],
      unknown_ids: [],
      duplicate_ids: [],
      missing_ids: [],
      unverified_ids: [],
      complete: true,
      all_passed: true
    },
    status: "completed",
    resultFound: true,
    connectedChangesComplete: true,
    manifest,
    gitReview: validation ? {
      ship_readiness: { validation }
    } as never : undefined
  };
}
