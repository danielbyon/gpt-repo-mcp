import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, test, vi } from "vitest";
import { createMcpServer } from "../src/register.js";
import { GitService } from "../src/services/git-service.js";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { RootRegistry } from "../src/services/root-registry.js";
import type { GitReviewService } from "../src/services/git-review-service.js";
import type { ShipReviewService } from "../src/services/ship-review-service.js";
import type { SemanticReviewService } from "../src/services/semantic-review-service.js";
import type { CodexResultService } from "../src/services/codex-result-service.js";

type ToolResults = {
  repo_git_status: Awaited<ReturnType<GitService["status"]>>;
  repo_git_review: Awaited<ReturnType<GitReviewService["review"]>>;
  repo_ship_review: Awaited<ReturnType<ShipReviewService["review"]>>;
  repo_semantic_review: Awaited<ReturnType<SemanticReviewService["review"]>>;
  repo_codex_review: Awaited<ReturnType<CodexResultService["review"]>>;
  repo_write_codex_task: unknown;
  repo_write_codex_review: unknown;
  repo_validate: unknown;
};
import { technicalTaskInput } from "./fixtures/delegation-v3-fixtures.js";
import { writeV3Result } from "./fixtures/delegation-v3-run-fixture.js";

const exec = promisify(execFile);
const childProcess = createRequire(import.meta.url)("node:child_process") as typeof import("node:child_process");
const RUN = "2026-07-19T150000Z-ignore-verification";
const fixtures: Array<{ parent: string; close: () => Promise<void> }> = [];
afterEach(async () => {
  vi.restoreAllMocks();
  syncBuiltinESMExports();
  for (const fixture of fixtures.splice(0)) {
    await fixture.close();
    await rm(fixture.parent, { recursive: true, force: true });
  }
  vi.unstubAllEnvs();
});

describe("Git-native ignored candidate provenance through MCP", () => {
  test.each(["repo", "home", "xdg", "info"] as const)("root and nested metadata use %s ignore rules", async (mode) => {
    const f = await fixture(mode);
    await f.metadata();
    const status = await f.call("repo_git_status");
    const review = await f.call("repo_git_review");
    const semantic = await f.call("repo_semantic_review");
    expect(status.files).toEqual([]);
    expect(review.changed_paths).toEqual([]);
    expect(review.recommendation.recommended_stage_paths).toEqual([]);
    expect(review.delegation_gate.requested_paths).toEqual([]);
    expect(semantic.reviewed_paths).toEqual([]);
    expect(semantic.warnings).not.toContain("SEMANTIC_UNTRACKED_CONTENT_NOT_REVIEWED");
  });

  test("ignored metadata byte changes do not change candidate fingerprints or review state", async () => {
    const f = await fixture("home");
    const git = new GitService(f.root);
    const before = [await git.worktreeFingerprint(), await git.reviewStateFingerprint()];
    await f.metadata();
    await writeFile(join(f.root, ".DS_Store"), "synthetic metadata B");
    await writeFile(join(f.root, "nested", ".DS_Store"), "synthetic nested metadata B");
    expect([await git.worktreeFingerprint(), await git.reviewStateFingerprint()]).toEqual(before);
  });

  test("ordinary untracked Python and tracked modifications stay visible alongside ignored metadata", async () => {
    const f = await fixture("home");
    await f.metadata();
    await writeFile(join(f.root, "src", "new.py"), "answer = 42\n");
    await writeFile(join(f.root, "src", "app.ts"), "export const value = 2;\n");
    const review = await f.call("repo_git_review");
    expect(review.changed_paths.map((p: { path: string }) => p.path).sort()).toEqual(["src/app.ts", "src/new.py"]);
    expect(review.recommendation.recommended_stage_paths).toEqual(["src/app.ts", "src/new.py"]);
    expect(review.delegation_gate.requested_paths).toEqual(["src/app.ts", "src/new.py"]);
  });

  test("force-tracked ignore-matching metadata is never suppressed", async () => {
    const f = await fixture("repo");
    await f.metadata();
    await git(f.root, ["add", "-f", "--", ".DS_Store", "nested/.DS_Store"]);
    await git(f.root, ["commit", "-m", "Track synthetic fixture metadata"]);
    const before = await new GitService(f.root).worktreeFingerprint();
    await writeFile(join(f.root, ".DS_Store"), "changed tracked synthetic metadata");
    const review = await f.call("repo_git_review");
    expect(review.changed_paths.map((p: { path: string }) => p.path)).toEqual([".DS_Store"]);
    expect(review.recommendation.recommended_stage_paths).toEqual([".DS_Store"]);
    expect(review.delegation_gate.requested_paths).toEqual([".DS_Store"]);
    expect(await new GitService(f.root).worktreeFingerprint()).not.toBe(before);
  });

  test("a tracked gitignore edit remains a real reviewable change", async () => {
    const f = await fixture("home");
    await writeFile(join(f.root, ".gitignore"), ".chatgpt/\n.DS_Store\n");
    await f.metadata();
    const review = await f.call("repo_git_review");
    expect(review.changed_paths.map((p: { path: string }) => p.path)).toEqual([".gitignore"]);
    expect(review.recommendation.recommended_stage_paths).toEqual([".gitignore"]);
    expect(review.delegation_gate.requested_paths).toEqual([".gitignore"]);
  });

  test("untracked metadata without any Git ignore rule remains visible", async () => {
    const f = await fixture("none");
    await f.metadata();
    expect((await f.call("repo_git_status")).files.map((p: { path: string }) => p.path).sort()).toEqual([".DS_Store", "nested/.DS_Store"]);
  });

  test("ambient Git overrides cannot hide real source or redirect the repository", async () => {
    const f = await fixture("none");
    const hostile = join(f.parent, "hostile-ignore");
    await writeFile(hostile, "*.py\n");
    vi.stubEnv("GIT_CONFIG_COUNT", "1");
    vi.stubEnv("GIT_CONFIG_KEY_0", "core.excludesFile");
    vi.stubEnv("GIT_CONFIG_VALUE_0", hostile);
    vi.stubEnv("GIT_DIR", join(f.parent, "not-a-repository"));
    await writeFile(join(f.root, "src", "new.py"), "answer = 42\n");
    expect((await f.call("repo_git_status")).files.map((p: { path: string }) => p.path)).toEqual(["src/new.py"]);
  });

  test("a genuinely attested source run remains applicable with ignored-only extra files", async () => {
    const f = await fixture("home");
    await f.startRun();
    await writeFile(join(f.root, "src", "app.ts"), "export const value = 2;\n");
    await f.attest(["src/app.ts"]);
    await f.metadata();
    const ship = await f.call("repo_ship_review", { run_id: RUN });
    expect(ship.git_review.delegation_gate.applicable_runs).toEqual([expect.objectContaining({ run_id: RUN, status: "passed" })]);
    expect(ship.git_review.delegation_gate.requested_paths).toEqual(["src/app.ts"]);
    expect(ship.ship_readiness.reasons).not.toContain("DELEGATION_GATE_RUN_MISMATCH");
  });

  test("a genuinely attested no-change verification run is not mismatched by ignored-only metadata", async () => {
    const f = await fixture("home");
    await f.startRun();
    await f.attest([]);
    await f.metadata();
    const ship = await f.call("repo_ship_review", { run_id: RUN });
    expect(ship.git_review.changed_paths).toEqual([]);
    expect(ship.git_review.delegation_gate.requested_paths).toEqual([]);
    expect(ship.git_review.delegation_gate.applicable_runs).toEqual([expect.objectContaining({ run_id: RUN, status: "passed" })]);
    expect(ship.ship_readiness.status).toBe("ready");
  });

  test("missing, unattested and stale explicit verification runs still fail closed", async () => {
    const f = await fixture("home");
    await f.startRun();
    await f.metadata();
    const unattested = await f.call("repo_ship_review", { run_id: RUN });
    expect(unattested.ship_readiness.reasons).toContain("DELEGATION_GATE_RUN_MISMATCH");
    await f.attest([]);
    const missing = await f.call("repo_ship_review", { run_id: "2026-07-19T150100Z-missing-run" });
    expect(missing.ship_readiness.reasons).toContain("DELEGATION_GATE_RUN_MISMATCH");
    await writeFile(join(f.root, "src", "app.ts"), "export const value = 3;\n");
    await git(f.root, ["add", "src/app.ts"]);
    await git(f.root, ["commit", "-m", "Invalidate fixture attestation head"]);
    const stale = await f.call("repo_ship_review", { run_id: RUN });
    expect(stale.ship_readiness.reasons).toContain("DELEGATION_GATE_RUN_MISMATCH");
  });

  test("a no-change attestation cannot conceal a changed tracked baseline", async () => {
    const f = await fixture("home");
    await writeFile(join(f.root, "src", "app.ts"), "export const value = 2;\n");
    await f.startRun();
    await f.attest([]);
    await git(f.root, ["restore", "src/app.ts"]);
    const ship = await f.call("repo_ship_review", { run_id: RUN });
    expect(ship.ship_readiness.reasons).toContain("DELEGATION_GATE_RUN_MISMATCH");
  });

  test("historical ignored baseline metadata may change or disappear without changing verification applicability", async () => {
    const f = await fixture("home");
    await f.metadata();
    const emptyHome = join(f.parent, "legacy-home");
    await mkdir(emptyHome);
    vi.stubEnv("HOME", emptyHome);
    await f.startRun();
    vi.stubEnv("HOME", join(f.parent, "home"));
    await f.attest([]);
    await writeFile(join(f.root, ".DS_Store"), "changed synthetic ignored baseline");
    await rm(join(f.root, "nested", ".DS_Store"));
    const ship = await f.call("repo_ship_review", { run_id: RUN });
    expect(ship.git_review.changed_paths).toEqual([]);
    expect(ship.ship_readiness.status).toBe("ready");
  });

  test("a tracked ignore-matching baseline cannot be silently discarded", async () => {
    const f = await fixture("repo");
    await f.metadata();
    await git(f.root, ["add", "-f", "--", ".DS_Store"]);
    await git(f.root, ["commit", "-m", "Track synthetic baseline metadata"]);
    await writeFile(join(f.root, ".DS_Store"), "modified tracked baseline metadata");
    await f.startRun();
    await f.attest([]);
    await git(f.root, ["restore", ".DS_Store"]);
    const ship = await f.call("repo_ship_review", { run_id: RUN });
    expect(ship.ship_readiness.reasons).toContain("DELEGATION_GATE_RUN_MISMATCH");
  });

  test.each([
    ["PROMPT.md", "DELEGATION_REVIEW_STATE_CHANGED"],
    ["run.json", "DELEGATION_GATE_RUN_MISMATCH"],
    ["review-gate.json", "DELEGATION_REVIEW_GATE_INVALID"],
    ["review.json", "DELEGATION_REVIEW_ATTESTATION_TAMPERED"],
    ["RESULT.json", "DELEGATION_GATE_RUN_MISMATCH"]
  ])("tampered or malformed %s keeps verification blocked", async (artifact, reason) => {
    const f = await fixture("home");
    await f.startRun();
    await f.attest([]);
    expect((await f.call("repo_ship_review", { run_id: RUN })).ship_readiness.status).toBe("ready");
    await writeFile(join(f.root, ".chatgpt", "codex-runs", RUN, artifact), "tampered synthetic artifact");
    const ship = await f.call("repo_ship_review", { run_id: RUN });
    expect(ship.ship_readiness.status).toBe("review_required");
    if (reason === "DELEGATION_GATE_RUN_MISMATCH") {
      expect(ship.ship_readiness.reasons).toContain(reason);
    } else {
      expect(ship.git_review.delegation_gate.status).toBe("blocked");
      expect(ship.git_review.delegation_gate.blocking_reasons).toContain(reason);
    }
  });

  test("an explicit verification retains enforce-mode gate failure diagnostics", async () => {
    const f = await fixture("home");
    await f.startRun();
    await f.attest([]);
    await rm(join(f.root, ".chatgpt", "codex-runs", RUN, "review.json"));
    const ship = await f.call("repo_ship_review", { run_id: RUN });
    expect(ship.git_review.delegation_gate.status).toBe("blocked");
    expect(ship.git_review.delegation_gate.applicable_runs).toEqual([expect.objectContaining({
      run_id: RUN, status: "open", reasons: ["DELEGATION_REVIEW_ATTESTATION_MISSING"]
    })]);
    expect(ship.ship_readiness.reasons).toContain("DELEGATION_REVIEW_GATE_BLOCKED");
    expect(ship.ship_readiness.reasons).toContain("DELEGATION_REVIEW_ATTESTATION_MISSING");
  });

  test("external generic ignores filter arbitrary files without a metadata basename rule", async () => {
    const f = await fixture("home");
    await writeFile(join(f.parent, "global-ignore"), "*.fixture-cache\n");
    await writeFile(join(f.root, "ignored.fixture-cache"), "synthetic ignored root data");
    await writeFile(join(f.root, "nested", "ignored.fixture-cache"), "synthetic ignored nested data");
    await writeFile(join(f.root, "src", "new.py"), "answer = 42\n");
    await f.metadata();
    const review = await f.call("repo_git_review");
    const expected = [".DS_Store", "nested/.DS_Store", "src/new.py"];
    expect(review.changed_paths.map((p) => p.path).sort()).toEqual(expected);
    expect(review.recommendation.recommended_stage_paths).toEqual(expected);
    expect(review.delegation_gate.requested_paths).toEqual(expected);
    const before = await new GitService(f.root).worktreeFingerprint();
    await writeFile(join(f.root, "ignored.fixture-cache"), "changed ignored bytes");
    expect(await new GitService(f.root).worktreeFingerprint()).toBe(before);
  });

  test("verification classifies a large ignored baseline with bounded Git subprocesses", async () => {
    const f = await fixture("home");
    await writeFile(join(f.parent, "global-ignore"), "*.fixture-cache\n");
    for (let i = 0; i < 32; i++) await writeFile(join(f.root, `baseline-${i}.fixture-cache`), "synthetic baseline");
    const emptyHome = join(f.parent, "legacy-home");
    await mkdir(emptyHome);
    vi.stubEnv("HOME", emptyHome);
    await f.startRun();
    vi.stubEnv("HOME", join(f.parent, "home"));
    await f.attest([]);
    // Observe the real process boundary without replacing Git or its results.
    const execution = vi.spyOn(childProcess, "spawn");
    syncBuiltinESMExports();
    const ship = await f.call("repo_ship_review", { run_id: RUN });
    expect(ship.ship_readiness.status).toBe("ready");
    const queries = execution.mock.calls.filter(([command, args]) => command === "git" && Array.isArray(args) && args[0] === "check-ignore");
    expect(queries.length).toBeGreaterThan(0);
    expect(queries.length).toBeLessThan(4);
  });

  test("real unreported scope and unauthorized result paths remain blocking", async () => {
    const f = await fixture("home");
    await f.startRun();
    await writeFile(join(f.root, "src", "app.ts"), "export const value = 2;\n");
    await f.attest(["src/app.ts"]);
    await f.metadata();
    await writeFile(join(f.root, "src", "unreported.ts"), "export const unreported = true;\n");
    const ship = await f.call("repo_ship_review", { run_id: RUN });
    expect(ship.git_review.delegation_gate.status).toBe("blocked");
    expect(ship.ship_readiness.status).toBe("review_required");
    expect(ship.ship_readiness.reasons).toContain("DELEGATION_REVIEW_GATE_BLOCKED");
    await writeV3Result(f.root, RUN, { changed_files: ["src/app.ts", "outside.py"] });
    const review = await f.call("repo_codex_review", { run_id: RUN });
    expect(review.technical_readiness.status).toBe("failed");
    expect(review.technical_readiness.blocking_reasons.length).toBeGreaterThan(0);
  });
});

async function fixture(mode: "repo" | "home" | "xdg" | "info" | "none") {
  const parent = await mkdtemp(join(tmpdir(), "git-ignore-provenance-"));
  const root = join(parent, "repo");
  const home = join(parent, "home");
  const xdg = join(parent, "xdg");
  await Promise.all([mkdir(join(root, "src"), { recursive: true }), mkdir(join(root, "nested"), { recursive: true }), mkdir(home), mkdir(join(xdg, "git"), { recursive: true })]);
  vi.stubEnv("HOME", home);
  vi.stubEnv("XDG_CONFIG_HOME", xdg);
  const rules = join(parent, "global-ignore");
  await writeFile(rules, ".DS_Store\n");
  if (mode === "home" || mode === "xdg") await writeFile(mode === "home" ? join(home, ".gitconfig") : join(xdg, "git", "config"), `[core]\n\texcludesFile = ${rules}\n`);
  await git(root, ["init"]);
  await git(root, ["config", "user.email", "fixture@example.invalid"]);
  await git(root, ["config", "user.name", "Fixture"]);
  if (mode === "info") await writeFile(join(root, ".git", "info", "exclude"), ".DS_Store\n");
  await writeFile(join(root, ".gitignore"), `.chatgpt/\n${mode === "repo" ? ".DS_Store\n" : ""}`);
  await writeFile(join(root, "src", "app.ts"), "export const value = 1;\n");
  await writeFile(join(root, "package.json"), JSON.stringify({ scripts: { test: "node --version" } }));
  await mkdir(join(root, "docs"));
  await writeFile(join(root, "docs", "guide.md"), "# Synthetic fixture\n");
  await writeFile(join(root, "docs", "product-contract.json"), JSON.stringify({ schema_version: 1, product: { name: "Fixture", purpose: "Guard explicit review provenance." }, primary_users: [{ id: "operator", role: "Operator", technical_level: "Technical", work_context: "Reviews synthetic local fixtures." }], jobs_to_be_done: [{ id: "review", statement: "Review changes inside their authorization boundary." }], must_reduce: ["Unreviewed changes"], must_not_become: ["A provenance bypass"], experience_principles: ["Preserve real scope checks"], canonical_docs: ["docs/guide.md"], governance: { mode: "enforce", product_review_required_for: ["product_slice", "product_correction"], checkpoint_every_root_runs: 5 } }));
  await git(root, ["add", "."]);
  await git(root, ["commit", "-m", "Synthetic fixture baseline"]);
  const registry = await RootRegistry.fromConfig({ repos: [{ repo_id: "fixture", display_name: "Isolated fixture", root, writes: { enabled: true, allowed_globs: [".chatgpt/codex-runs/**"] }, operations: { enabled: true, git_stage_enabled: true, git_commit_enabled: true, validation_enabled: true } }] });
  const server = createMcpServer({ registry });
  const client = new Client({ name: "ignore-provenance-test", version: "1" });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await Promise.all([client.connect(ct), server.connect(st)]);
  fixtures.push({ parent, close: async () => { await client.close(); await server.close(); } });
  async function call<K extends keyof ToolResults>(name: K, args: Record<string, unknown> = {}): Promise<ToolResults[K]> {
    const result = await client.callTool({ name, arguments: { repo_id: "fixture", ...args } });
    if (result.isError) throw new Error(JSON.stringify(result));
    return result.structuredContent as ToolResults[K];
  }
  async function startRun() {
    const input = technicalTaskInput();
    delete input.validation;
    await call("repo_write_codex_task", { ...input, run_id: RUN, starting_points: ["src/app.ts"], authorization_scope: ["src/**"] });
  }
  async function attest(changed: string[]) {
    await call("repo_validate", { profile: "test" });
    await writeV3Result(root, RUN, { changed_files: changed });
    const review = await call("repo_codex_review", { run_id: RUN });
    expect(review.technical_readiness.status).toBe("passed");
    if (review.review_state.status !== "available") throw new Error("Fixture review state must be available.");
    await call("repo_write_codex_review", { run_id: RUN, expected_review_state_sha256: review.review_state.state_sha256, product_verdict: "not_applicable", rationale: "Synthetic technical-only fixture verified inside its scope.", evidence: [] });
  }
  return { parent, root, call, startRun, attest, metadata: async () => { await writeFile(join(root, ".DS_Store"), "synthetic root metadata A"); await writeFile(join(root, "nested", ".DS_Store"), "synthetic nested metadata A"); } };
}

async function git(root: string, args: string[]) {
  return exec("git", args, { cwd: root, env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME, XDG_CONFIG_HOME: process.env.XDG_CONFIG_HOME } });
}
