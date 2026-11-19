import { createHash } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterAll, afterEach, beforeAll, describe, expect, test, vi } from "vitest";
import { SERVER_INSTRUCTIONS, createMcpServer } from "../src/register.js";
import { RootRegistry } from "../src/services/root-registry.js";
import { nonDestructiveMutationAnnotations, readOnlyAnnotations, safeMutationAnnotations, writeAnnotations } from "../src/tools/annotations.js";
import { toolCatalog } from "../src/tools/catalog.js";
import { MUTATING_TOOL_NAMES, isMutatingToolName } from "../src/tools/mutating-tools.js";

const execFileAsync = promisify(execFile);

describe("MCP contract", () => {
  test("initialize exposes compact safety-complete server instructions", async () => {
    const { client, close } = await connectFixtureServer();
    try {
      expect(client.getServerVersion()).toMatchObject({ name: "gpt-repo-mcp", version: "0.1.0" });
      expect(client.getServerCapabilities()).toMatchObject({ tools: {} });
      expect(client.getInstructions()).toBe(SERVER_INSTRUCTIONS);
      expect(Buffer.byteLength(SERVER_INSTRUCTIONS, "utf8")).toBeLessThan(6_000);
      expect(SERVER_INSTRUCTIONS).toContain("Tools with local side effects require the relevant repository write or operations policy");
      for (const toolName of MUTATING_TOOL_NAMES) expect(SERVER_INSTRUCTIONS).toContain(toolName);
      for (const clause of [
        "repo_code_index is a non-destructive idempotent provider/index mutation",
        "repo_prepare_patchset is a non-destructive non-idempotent local metadata mutation",
        "The canonical direct-development path is",
        "The user and ChatGPT choose what to build",
        "continuity_state distinguishes active work, blocked ongoing work, and completed_history",
        "New task creation is Delegation v3 only",
        "Runner completion never constitutes a final product verdict",
        "Agent PAC claims are evidence only",
        "detail=full only for granular dry-run payloads or expert diagnostics",
        "Dry-run is optional preview",
        "Omit optional reason by default",
        "do not push",
        "do not run shell commands"
      ]) expect(SERVER_INSTRUCTIONS).toContain(clause);
      for (const removed of ["repo_next_action", "repo_plan_review", "repo_git_stage", "repo_git_unstage", "repo_git_commit"]) {
        expect(SERVER_INSTRUCTIONS).not.toContain(removed);
      }
    } finally {
      await close();
    }
  });

  test("tools/list exposes schemas and appropriate annotations for every tool", async () => {
    const { client, close } = await connectFixtureServer();
    try {
      const listed = await client.listTools();
      expect(new Set(listed.tools.map((tool) => tool.name))).toEqual(new Set(toolCatalog.map((tool) => tool.name)));

      for (const tool of listed.tools) {
        expect(tool.title).toEqual(expect.any(String));
        expect(tool.description).toEqual(expect.stringMatching(/^Use this when/));
        expect(tool.inputSchema).toBeDefined();
        expect(tool.outputSchema).toBeDefined();
        if (isMutatingToolName(tool.name)) {
          expect(tool.annotations).toMatchObject(
            tool.name === "repo_code_index"
              ? safeMutationAnnotations
              : tool.name === "repo_prepare_patchset"
                ? nonDestructiveMutationAnnotations
                : writeAnnotations
          );
        } else {
          expect(tool.annotations).toMatchObject(readOnlyAnnotations);
        }
      }
    } finally {
      await close();
    }
  });

  test("tools/list exposed surface stays stable", async () => {
    const { client, close } = await connectFixtureServer();
    try {
      const listed = await client.listTools();

      expect(listed.tools.map((tool) => ({
        name: tool.name,
        title: tool.title,
        description: tool.description,
        annotations: tool.annotations,
        inputKeys: Object.keys(tool.inputSchema.properties ?? {}).sort(),
        outputKeys: Object.keys(tool.outputSchema?.properties ?? {}).sort()
      }))).toMatchInlineSnapshot(`
        [
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when listing approved repositories. It does not read repository contents.",
            "inputKeys": [],
            "name": "repo_list_roots",
            "outputKeys": [
              "repos",
            ],
            "title": "List approved repositories",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when repository access is blocked or policy capabilities are unclear. It explains effective read, write, cleanup, validation, and Git-operation policy without mutation.",
            "inputKeys": [
              "operation",
              "path",
              "repo_id",
            ],
            "name": "repo_policy_explain",
            "outputKeys": [
              "cleanup",
              "effective_policy",
              "guidance",
              "ok",
              "operations",
              "path",
              "read",
              "repo_id",
              "requested_operation",
              "summary",
              "validation",
              "write",
            ],
            "title": "Explain repository policy",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when resuming after a write or checking what the latest write changed. It returns safe receipt metadata only.",
            "inputKeys": [
              "repo_id",
            ],
            "name": "repo_last_write",
            "outputKeys": [
              "found",
              "next_tool_payloads",
              "ok",
              "receipt",
              "warnings",
            ],
            "title": "Read last write receipt",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when inspecting bounded historical write and operation receipts. Prefer repo_last_write for only the latest operation.",
            "inputKeys": [
              "after_operation_id",
              "cursor",
              "limit",
              "repo_id",
            ],
            "name": "repo_operation_ledger",
            "outputKeys": [
              "events",
              "next_cursor",
              "ok",
              "repo_id",
              "warnings",
            ],
            "title": "Read operation ledger",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when locating directories and likely files by repository structure. Use repo_fetch_file to read contents.",
            "inputKeys": [
              "cursor",
              "include_dependencies",
              "include_files",
              "include_generated",
              "max_depth",
              "page_size",
              "path",
              "repo_id",
              "respect_default_excludes",
            ],
            "name": "repo_tree",
            "outputKeys": [
              "entries",
              "excluded_summary",
              "next_cursor",
              "truncated",
            ],
            "title": "Inspect repository tree",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when locating code, text, usages, or likely files. Prefer it before reading multiple files.",
            "inputKeys": [
              "context_lines",
              "cursor",
              "exclude_globs",
              "include_globs",
              "max_results",
              "mode",
              "query",
              "repo_id",
            ],
            "name": "repo_search",
            "outputKeys": [
              "matched_count",
              "next_cursor",
              "results",
              "returned_count",
              "truncated",
              "warnings",
            ],
            "title": "Search repository text",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when reading one known file or line range. Do not use it for broad repository review.",
            "inputKeys": [
              "end_line",
              "max_bytes",
              "override_default_excludes",
              "path",
              "repo_id",
              "start_line",
            ],
            "name": "repo_fetch_file",
            "outputKeys": [
              "end_line",
              "language",
              "path",
              "sha256",
              "size_bytes",
              "start_line",
              "text",
              "total_lines",
              "truncated",
              "warnings",
            ],
            "title": "Fetch one file",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when reading a bounded known set of files or globs. Do not use it to read an entire repository.",
            "inputKeys": [
              "cursor",
              "exclude_globs",
              "include_globs",
              "max_bytes_per_file",
              "max_files",
              "max_total_bytes",
              "paths",
              "repo_id",
            ],
            "name": "repo_read_many",
            "outputKeys": [
              "files",
              "matched_count",
              "next_cursor",
              "returned_count",
              "skipped",
              "truncated",
            ],
            "title": "Read bounded files",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when mapping file-level impact, imports, dependents, entrypoints, routes, components, or affected tests. Use repo_symbol_context for symbol-level evidence.",
            "inputKeys": [
              "focus_paths",
              "goal",
              "max_files",
              "repo_id",
            ],
            "name": "repo_context_map",
            "outputKeys": [
              "affected_tests",
              "component_signals",
              "dependency_paths",
              "entrypoints",
              "framework_signals",
              "generated_paths",
              "import_edges",
              "reverse_dependents",
              "route_signals",
              "scanned_file_count",
              "truncated",
              "warnings",
            ],
            "title": "Map repository context",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when gathering symbol-level evidence for definitions, references, calls, implementations, reverse dependents, or affected tests. Ask before starting an optional index.",
            "inputKeys": [
              "depth",
              "direction",
              "max_files",
              "max_relations",
              "max_symbols",
              "paths",
              "repo_id",
              "symbols",
            ],
            "name": "repo_symbol_context",
            "outputKeys": [
              "affected_tests",
              "cache",
              "calls",
              "confidence",
              "definitions",
              "exports",
              "implementations",
              "imports",
              "ok",
              "provider",
              "references",
              "repo_id",
              "reverse_dependents",
              "scanned_file_count",
              "truncated",
              "warnings",
            ],
            "title": "Inspect symbol context",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when checking or managing the optional Codebase Memory index. Before action=start, explicitly ask the user; status is safe to inspect without approval.",
            "inputKeys": [
              "action",
              "repo_id",
            ],
            "name": "repo_code_index",
            "outputKeys": [
              "action",
              "events",
              "finished_at",
              "ok",
              "provider",
              "repo_id",
              "started_at",
              "status",
              "warnings",
            ],
            "title": "Manage optional code graph index",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when saved validation evidence needs normalized diagnostics and deterministic correlation. It does not run commands or claim an LLM root cause.",
            "inputKeys": [
              "max_candidates",
              "max_diagnostics",
              "repo_id",
              "scope_paths",
              "validation_id",
            ],
            "name": "repo_failure_diagnose",
            "outputKeys": [
              "candidates",
              "correlations",
              "diagnostics",
              "next_tool_payloads",
              "ok",
              "repo_id",
              "truncated",
              "validation",
              "warnings",
            ],
            "title": "Diagnose repository failure evidence",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when current changes need standalone evidence-based semantic risk review. Use repo_ship_review for combined final readiness.",
            "inputKeys": [
              "categories",
              "max_files",
              "max_findings",
              "paths",
              "repo_id",
            ],
            "name": "repo_semantic_review",
            "outputKeys": [
              "findings",
              "next_tool_payloads",
              "ok",
              "repo_id",
              "reviewed_paths",
              "ship_readiness",
              "summary",
              "truncated",
              "warnings",
            ],
            "title": "Review semantic change risks",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when combined final readiness across Git, validation, semantic, and delegation gates is needed before ship. Compact is default; detail=full adds granular expert evidence and payloads.",
            "inputKeys": [
              "categories",
              "detail",
              "max_files",
              "max_findings",
              "paths",
              "repo_id",
              "run_id",
            ],
            "name": "repo_ship_review",
            "outputKeys": [
              "delegation_gate",
              "detail",
              "failure_diagnosis",
              "git_review",
              "next_tool_payloads",
              "ok",
              "repo_id",
              "review_loop",
              "run_id",
              "semantic_review",
              "ship_readiness",
              "truncated",
              "warnings",
            ],
            "title": "Review ship readiness",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when checking branch, HEAD, cleanliness, or changed-file status. It does not read file contents.",
            "inputKeys": [
              "repo_id",
            ],
            "name": "repo_git_status",
            "outputKeys": [
              "branch",
              "clean",
              "counts",
              "files",
              "head_sha",
            ],
            "title": "Read git status",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when raw Git diff content is requested. Default first call should pass only repo_id; add filters only for a second pass.",
            "inputKeys": [
              "base",
              "compare",
              "context_lines",
              "max_bytes",
              "max_files",
              "paths",
              "repo_id",
              "staged",
              "unstaged",
            ],
            "name": "repo_git_diff",
            "outputKeys": [
              "base",
              "compare",
              "files",
              "staged",
              "total_file_count",
              "truncated",
              "truncation_reason",
              "unstaged",
              "warnings",
            ],
            "title": "Read git diff",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when reviewing current Git state or planning commit and recovery without mutation. Compact is default; detail=full adds granular and dry-run payloads.",
            "inputKeys": [
              "detail",
              "max_files",
              "mode",
              "paths",
              "repo_id",
            ],
            "name": "repo_git_review",
            "outputKeys": [
              "branch",
              "changed_paths",
              "clean",
              "delegation_gate",
              "detail",
              "diff_summary",
              "head_sha",
              "next_tool_payloads",
              "ok",
              "recommendation",
              "ship_readiness",
            ],
            "title": "Plan git review",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when explicitly restoring reviewed unstaged tracked paths. Prefer repo_write_recover for normal composite recovery.",
            "inputKeys": [
              "dry_run",
              "expected_head_sha",
              "paths",
              "reason",
              "repo_id",
            ],
            "name": "repo_git_restore_paths",
            "outputKeys": [
              "dry_run",
              "head_sha",
              "ok",
              "restored_paths",
              "skipped",
              "warnings",
            ],
            "title": "Restore explicit worktree paths",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when reviewed paths must be staged separately. Prefer the composite stage-and-commit payload when available.",
            "inputKeys": [
              "dry_run",
              "expected_head_sha",
              "paths",
              "reason",
              "repo_id",
            ],
            "name": "repo_write_stage",
            "outputKeys": [
              "dry_run",
              "head_sha",
              "ok",
              "skipped",
              "staged_paths",
              "warnings",
            ],
            "title": "Stage reviewed paths",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when reviewed paths must be unstaged separately. Prefer repo_write_recover for normal composite recovery.",
            "inputKeys": [
              "dry_run",
              "expected_head_sha",
              "paths",
              "reason",
              "repo_id",
            ],
            "name": "repo_write_unstage",
            "outputKeys": [
              "dry_run",
              "head_sha",
              "ok",
              "skipped",
              "unstaged_paths",
              "warnings",
            ],
            "title": "Unstage reviewed paths",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when committing an exact already-staged path set locally. It verifies HEAD and staged paths and never pushes.",
            "inputKeys": [
              "dry_run",
              "expected_head_sha",
              "expected_staged_paths",
              "message",
              "reason",
              "repo_id",
            ],
            "name": "repo_write_commit",
            "outputKeys": [
              "commit_sha",
              "committed_paths",
              "dry_run",
              "head_after",
              "head_before",
              "ok",
              "warnings",
            ],
            "title": "Create reviewed local commit",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when review returns the canonical stage-and-commit payload. Normal review supplies explicit paths; multi-run integration supplies only its opaque review_pathset_id. The server rechecks exact HEAD, bytes, paths, gates, and staged set, creates one local commit, and never pushes.",
            "inputKeys": [
              "dry_run",
              "expected_head_sha",
              "message",
              "paths",
              "reason",
              "repo_id",
              "review_pathset_id",
            ],
            "name": "repo_write_stage_commit",
            "outputKeys": [
              "clean_after",
              "commit_sha",
              "committed_paths",
              "dry_run",
              "head_after",
              "head_before",
              "ok",
              "remaining_changes",
              "review_pathset_id",
              "staged_paths",
              "warnings",
            ],
            "title": "Stage and commit reviewed paths",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when review returns canonical composite recovery for explicit unstage, restore, cleanup, or discard paths. It never resets, stashes, pushes, or runs a shell.",
            "inputKeys": [
              "cleanup_paths",
              "discard_paths",
              "dry_run",
              "expected_head_sha",
              "reason",
              "repo_id",
              "restore_paths",
              "unstage_paths",
            ],
            "name": "repo_write_recover",
            "outputKeys": [
              "clean_after",
              "deleted",
              "discarded",
              "dry_run",
              "head_sha",
              "ok",
              "remaining_changes",
              "restored_paths",
              "skipped",
              "unstaged_paths",
              "warnings",
            ],
            "title": "Recover reviewed paths",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when separately deleting reviewed untracked generated or local artifacts allowed by cleanup policy. Prefer composite recovery when available.",
            "inputKeys": [
              "dry_run",
              "paths",
              "reason",
              "repo_id",
            ],
            "name": "repo_cleanup_paths",
            "outputKeys": [
              "deleted",
              "dry_run",
              "ok",
              "skipped",
              "warnings",
            ],
            "title": "Clean up generated paths",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when onboarding into or summarizing a repository. It returns repository-owned product context before technical metadata and never chooses the next goal.",
            "inputKeys": [
              "include",
              "repo_id",
            ],
            "name": "repo_project_brief",
            "outputKeys": [
              "entrypoint_signals",
              "framework_signals",
              "key_docs",
              "languages",
              "likely_entrypoints",
              "package_managers",
              "product_brief",
              "project_type",
              "repo",
              "scripts",
              "test_commands",
              "truncated",
              "warnings",
            ],
            "title": "Create project brief",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when the user explicitly requests TODO, FIXME, checkbox, roadmap, or backlog evidence. It returns candidates, not priority.",
            "inputKeys": [
              "cursor",
              "exclude_globs",
              "include_globs",
              "labels",
              "max_results",
              "repo_id",
            ],
            "name": "repo_task_inventory",
            "outputKeys": [
              "matched_count",
              "next_cursor",
              "returned_count",
              "scan_complete",
              "scanned_file_count",
              "tasks",
              "truncated",
              "warnings",
            ],
            "title": "Inventory repository tasks",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when architecture rationale, conventions, or historical decisions are requested. It is supporting evidence, not product or active-work authority.",
            "inputKeys": [
              "include_sources",
              "repo_id",
            ],
            "name": "repo_decision_memory",
            "outputKeys": [
              "conventions",
              "decisions",
              "gaps",
              "warnings",
            ],
            "title": "Extract decision memory",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when the user and ChatGPT have already chosen an implementation goal. It plans how to execute that goal but never selects alternative work.",
            "inputKeys": [
              "goal",
              "include_globs",
              "max_files_to_inspect",
              "planning_depth",
              "repo_id",
            ],
            "name": "repo_change_plan",
            "outputKeys": [
              "estimated_cost",
              "goal",
              "open_questions",
              "proposed_steps",
              "relevant_files",
              "scan_complete",
              "test_strategy",
              "warnings",
            ],
            "title": "Plan repository change",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when previewing a product-grounded Delegation v3 task before writing it. Use complete review-provided payloads for lineage children.",
            "inputKeys": [
              "assignment",
              "authorization_scope",
              "explicit_exclusions",
              "forbidden_paths",
              "hard_constraints",
              "lineage",
              "must_preserve",
              "outcome",
              "product_alignment",
              "relevant_context",
              "repo_id",
              "run_id",
              "runner",
              "security_context",
              "starting_points",
              "task_kind",
              "technical_acceptance_criteria",
              "technical_context",
              "title",
              "validation",
            ],
            "name": "repo_prepare_codex_task",
            "outputKeys": [
              "delegation_audit",
              "lineage",
              "manifest_path",
              "ok",
              "product_contract_sha256",
              "prompt_path",
              "repo_id",
              "result_json_path",
              "review_gate_path",
              "review_requirement",
              "run_id",
              "schema_version",
              "task_kind",
              "warnings",
            ],
            "title": "Prepare Delegation v3 task",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when the user explicitly requests durable Codex or implementation-agent delegation. It writes bound Delegation v3 artifacts but never starts a runner, commits, or pushes.",
            "inputKeys": [
              "assignment",
              "authorization_scope",
              "dry_run",
              "explicit_exclusions",
              "forbidden_paths",
              "hard_constraints",
              "lineage",
              "must_preserve",
              "outcome",
              "product_alignment",
              "reason",
              "relevant_context",
              "repo_id",
              "run_id",
              "runner",
              "security_context",
              "starting_points",
              "task_kind",
              "technical_acceptance_criteria",
              "technical_context",
              "title",
              "validation",
            ],
            "name": "repo_write_codex_task",
            "outputKeys": [
              "delegation_audit",
              "dry_run",
              "lineage",
              "manifest_path",
              "next_tool_payloads",
              "ok",
              "product_contract_sha256",
              "prompt_path",
              "repo_id",
              "result_json_path",
              "review_gate_path",
              "review_requirement",
              "run_id",
              "schema_version",
              "task_kind",
              "warnings",
              "written_paths",
            ],
            "title": "Write Delegation v3 task",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when inspecting agent lifecycle, runtime, questions, events, drift, or checkpoint state. It is read-only and never selects work.",
            "inputKeys": [
              "cursor",
              "events_after",
              "max_events",
              "page_size",
              "repo_id",
              "run_id",
              "statuses",
              "wait_after_revision",
              "wait_timeout_ms",
            ],
            "name": "repo_agent_runs",
            "outputKeys": [
              "drift_summary",
              "matched_count",
              "mode",
              "next_cursor",
              "next_tool_payloads",
              "ok",
              "repo_id",
              "returned_count",
              "revision",
              "run",
              "runs",
              "supervisor",
              "truncated",
              "warnings",
            ],
            "title": "Inspect agent runs",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when answering the exact current structured questions for an awaiting-input run. It rejects stale or incomplete replies and only writes the reply artifact.",
            "inputKeys": [
              "answers",
              "expected_question_sha256",
              "repo_id",
              "run_id",
              "turn_index",
            ],
            "name": "repo_write_agent_reply",
            "outputKeys": [
              "agent_run",
              "next_tool_payloads",
              "ok",
              "repo_id",
              "run_id",
              "turn_index",
              "warnings",
              "written_path",
            ],
            "title": "Reply to an agent run",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when an implementation agent has finished. It validates bound result, scope, Git state, TAC/PAC evidence, technical readiness, and product-review requirements without self-approving product claims.",
            "inputKeys": [
              "max_files",
              "repo_id",
              "run_id",
            ],
            "name": "repo_codex_review",
            "outputKeys": [
              "acceptance_evidence",
              "codex_result",
              "git_review",
              "integrity",
              "legacy_result_path",
              "next_steps",
              "next_tool_payloads",
              "ok",
              "product_acceptance_evidence",
              "product_evidence",
              "product_review",
              "repo_id",
              "result_found",
              "result_json_path",
              "result_source",
              "review_attestation",
              "review_loop",
              "review_state",
              "run_id",
              "scope_evidence",
              "technical_acceptance_evidence",
              "technical_readiness",
              "warnings",
            ],
            "title": "Review Codex result",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when recording the state-bound qualitative review returned by repo_codex_review. It validates the exact state and writes review evidence without staging or committing.",
            "inputKeys": [
              "dry_run",
              "evidence",
              "expected_review_state_sha256",
              "product_verdict",
              "rationale",
              "reason",
              "repo_id",
              "run_id",
            ],
            "name": "repo_write_codex_review",
            "outputKeys": [
              "dry_run",
              "next_steps",
              "ok",
              "product_verdict",
              "repo_id",
              "review_gate_path",
              "review_gate_sha256",
              "review_path",
              "review_requirement",
              "review_sha256",
              "review_state_sha256",
              "reviewed_at",
              "run_id",
              "technical_readiness_status",
              "warnings",
              "written_paths",
            ],
            "title": "Write state-bound Codex review",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when the owner explicitly approves integrating multiple currently attested Delegation v3 runs in one worktree, and only for that integration case. It requires exact run, HEAD, pathset, validation, product-verdict, semantic, scope, and content state, then writes an opaque pathset for one atomic local commit; it is not a force or skip-review path.",
            "inputKeys": [
              "commit_message",
              "dry_run",
              "expected_head_sha",
              "reason",
              "repo_id",
              "run_ids",
              "validation_id",
            ],
            "name": "repo_write_integration_review",
            "outputKeys": [
              "dry_run",
              "head_sha",
              "integration_id",
              "integration_path",
              "next_tool_payloads",
              "ok",
              "path_count",
              "pathset_fingerprint",
              "repo_id",
              "review_pathset_id",
              "reviewed_paths",
              "run_ids",
              "validation_id",
              "warnings",
              "written_paths",
            ],
            "title": "Write multi-run integration review",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when preparing an atomic create, modify, edit, delete, or rename patchset. It writes only local manifest metadata, not target files.",
            "inputKeys": [
              "base_head_sha",
              "files",
              "intent",
              "repo_id",
              "work_session_id",
            ],
            "name": "repo_prepare_patchset",
            "outputKeys": [
              "affected_paths",
              "manifest",
              "manifest_path",
              "next_tool_payloads",
              "ok",
              "patchset_id",
              "warnings",
            ],
            "title": "Prepare patchset",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when applying a prepared patchset atomically with stale-state guards. A HEAD-bound apply returns first-class rollback guidance.",
            "inputKeys": [
              "dry_run",
              "expected_head_sha",
              "patchset_id",
              "repo_id",
            ],
            "name": "repo_apply_patchset",
            "outputKeys": [
              "changed_paths",
              "counts",
              "created_paths",
              "deleted_paths",
              "dry_run",
              "hunk_diagnostics",
              "modified_paths",
              "next_tool_payloads",
              "ok",
              "operation_id",
              "operation_receipt",
              "patchset_id",
              "renamed_paths",
              "rollback_hint",
              "warnings",
            ],
            "title": "Apply patchset",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when reviewing a prepared or applied patchset and its ledger/Git state. It does not mutate files or Git.",
            "inputKeys": [
              "max_files",
              "patchset_id",
              "repo_id",
            ],
            "name": "repo_review_patchset",
            "outputKeys": [
              "applied",
              "git_review",
              "manifest",
              "manifest_path",
              "ok",
              "patchset_id",
              "rolled_back",
              "warnings",
            ],
            "title": "Review patchset",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when the user explicitly approves rollback of an uncommitted, unchanged applied patchset. It requires the expected HEAD.",
            "inputKeys": [
              "dry_run",
              "expected_head_sha",
              "patchset_id",
              "repo_id",
            ],
            "name": "repo_rollback_patchset",
            "outputKeys": [
              "counts",
              "deleted_paths",
              "dry_run",
              "next_tool_payloads",
              "ok",
              "operation_id",
              "operation_receipt",
              "patchset_id",
              "restored_paths",
              "skipped",
              "warnings",
            ],
            "title": "Rollback patchset",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when validating. Fixed Make/Just, npm, pytest profiles. Callers cannot choose commands, executables, or args. Windows uses absolute native paths and argv; npm uses selected node.exe plus bundled npm-cli.js. Shell executables and shims fail closed. test_paths are policy-checked. Repository scripts can start shells; the server neither inspects nor sandboxes them. Output is bounded.",
            "inputKeys": [
              "dry_run",
              "profile",
              "repo_id",
              "test_paths",
              "timeout_ms",
            ],
            "name": "repo_validate",
            "outputKeys": [
              "commands",
              "counts",
              "dry_run",
              "focused",
              "ok",
              "profile",
              "repo_id",
              "status",
              "test_paths",
              "validation_artifact",
              "validation_id",
              "warnings",
            ],
            "title": "Validate repository",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when starting a focused multi-step slice that benefits from content-free local progress state.",
            "inputKeys": [
              "constraints",
              "dry_run",
              "files_inspected",
              "next_action",
              "objective",
              "repo_id",
              "title",
              "touched_files",
              "work_session_id",
            ],
            "name": "repo_start_work_session",
            "outputKeys": [
              "current_path",
              "dry_run",
              "next_tool_payloads",
              "ok",
              "session",
              "session_path",
              "warnings",
              "work_session_id",
            ],
            "title": "Start work session",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when appending decisions, inspected or touched paths, validation refs, risks, status, or next action to a work session.",
            "inputKeys": [
              "append_assumptions",
              "append_decisions",
              "append_files_inspected",
              "append_pending_patchsets",
              "append_touched_files",
              "append_unresolved_risks",
              "append_validation_results",
              "dry_run",
              "next_action",
              "repo_id",
              "status",
              "work_session_id",
            ],
            "name": "repo_update_work_session",
            "outputKeys": [
              "current_path",
              "dry_run",
              "next_tool_payloads",
              "ok",
              "session",
              "session_path",
              "warnings",
              "work_session_id",
            ],
            "title": "Update work session",
          },
          {
            "annotations": {
              "destructiveHint": false,
              "idempotentHint": true,
              "openWorldHint": false,
              "readOnlyHint": true,
            },
            "description": "Use this when resuming repository continuity. Current active or blocked work is full; completed history is compact unless work_session_id is supplied.",
            "inputKeys": [
              "repo_id",
              "work_session_id",
            ],
            "name": "repo_current_work_session",
            "outputKeys": [
              "continuity_state",
              "current_path",
              "found",
              "lookup_source",
              "ok",
              "repo_id",
              "session",
              "session_path",
              "warnings",
              "work_session_id",
            ],
            "title": "Read current work session",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when directly creating or precisely editing one allowed repository file. It supports stale-state guards and never runs Git, Codex, or a shell.",
            "inputKeys": [
              "action",
              "content",
              "create_dirs",
              "dry_run",
              "expected_head_sha",
              "expected_missing",
              "expected_old_sha256",
              "find",
              "path",
              "reason",
              "replace",
              "repo_id",
            ],
            "name": "repo_write_file",
            "outputKeys": [
              "action",
              "bytes_written",
              "changed",
              "created",
              "dry_run",
              "new_sha256",
              "ok",
              "old_sha256",
              "operation_receipt",
              "path",
              "summary",
              "warnings",
            ],
            "title": "Write one repository file",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when directly applying one cohesive multi-file write/edit pack. It supports stale-state guards and never stages, commits, restores, or runs a shell.",
            "inputKeys": [
              "changes",
              "dry_run",
              "expected_head_sha",
              "reason",
              "repo_id",
            ],
            "name": "repo_write_changes",
            "outputKeys": [
              "changed_paths",
              "counts",
              "dry_run",
              "files",
              "next_steps",
              "ok",
              "operation_receipt",
              "summary",
              "warnings",
            ],
            "title": "Apply repository edit pack",
          },
          {
            "annotations": {
              "destructiveHint": true,
              "idempotentHint": false,
              "openWorldHint": false,
              "readOnlyHint": false,
            },
            "description": "Use this when the user asks for a local-only ChatGPT handoff: skapa handoff, create handoff, skriv handoff, session handoff, or resume note. It writes .chatgpt/handoffs/*.local.md and updates current.local.md without Git mutation.",
            "inputKeys": [
              "completed_work",
              "constraints",
              "current_state",
              "current_track",
              "decisions",
              "dry_run",
              "important_files",
              "next_steps",
              "open_questions",
              "repo_id",
              "risks",
              "title",
              "update_current",
              "why",
              "workflow",
            ],
            "name": "repo_write_handoff",
            "outputKeys": [
              "branch",
              "clean",
              "current_next_step",
              "current_path",
              "dry_run",
              "handoff_path",
              "head_sha",
              "ok",
              "startup_prompt",
              "updated_current",
              "warnings",
            ],
            "title": "Create ChatGPT handoff",
          },
        ]
      `);
    } finally {
      await close();
    }
  });

  test("tools/call returns structuredContent matching the advertised output", async () => {
    const { client, close } = await connectFixtureServer();
    try {
      const result = await client.callTool({
        name: "repo_list_roots",
        arguments: {}
      });

      expect(result.isError).toBeUndefined();
      expect(result.structuredContent).toEqual({
        repos: [
          expect.objectContaining({
            repo_id: "fixture",
            display_name: "Fixture Repo",
            root: expect.any(String)
          })
        ]
      });
      expect(result.content).toEqual([{ type: "text", text: "1 approved repositories available." }]);
    } finally {
      await close();
    }
  });

  describe.sequential("public review detail", () => {
    let fixture: Awaited<ReturnType<typeof connectFixtureServer>> | undefined;
    let fixtureOwner: ReturnType<typeof createFixtureResourceOwner> | undefined;
    let setupController: AbortController | undefined;
    let setupPromise: Promise<Awaited<ReturnType<typeof connectFixtureServer>>> | undefined;
    let setupFinished = false;
    let teardownStarted = false;
    let sequenceFailed = false;

    beforeAll(async () => {
      setupController = new AbortController();
      const owner = createFixtureResourceOwner();
      fixtureOwner = owner;
      setupPromise = connectFixtureServer(setupController.signal, owner).then((candidate) => {
        if (!teardownStarted) fixture = candidate;
        return candidate;
      });
      void setupPromise.then(
        () => { setupFinished = true; },
        () => { setupFinished = true; }
      );
      await setupPromise;
    }, 5_000);

    afterAll(async () => {
      teardownStarted = true;
      await finalizeFixtureTeardown({
        setupPromise,
        setupWasPending: !setupFinished,
        abort: () => setupController?.abort(),
        cleanup: async () => {
          const errors = await fixtureOwner?.cleanup();
          if (errors && errors.length > 0) throw new AggregateError(errors, "MCP contract fixture cleanup failed.");
        },
        cleanupLateFixture: async (lateFixture) => lateFixture.close(),
        reportLateCleanupFailure: (error) => console.error("MCP contract fixture cleanup failed after its deadline.", error)
      });
    }, 5_000);

    afterEach(({ task }) => {
      if (task.result?.state === "fail") sequenceFailed = true;
    });

    const fixtureForTest = () => {
      return requireFixtureForRequest(fixture, sequenceFailed, teardownStarted);
    };

    test("repo_git_review defaults to compact", async ({ signal }) => {
      const result = await fixtureForTest().client.callTool({
        name: "repo_git_review",
        arguments: { repo_id: "fixture" }
      }, undefined, { signal });
      expect(result.structuredContent).toMatchObject({ ok: true, detail: "compact" });
    }, 5_000);

    test("repo_git_review honors full detail", async ({ signal }) => {
      const result = await fixtureForTest().client.callTool({
        name: "repo_git_review",
        arguments: { repo_id: "fixture", detail: "full" }
      }, undefined, { signal });
      expect(result.structuredContent).toMatchObject({ ok: true, detail: "full" });
    }, 5_000);

    test("repo_ship_review defaults to compact fields", async ({ signal }) => {
      const result = await fixtureForTest().client.callTool({
        name: "repo_ship_review",
        arguments: { repo_id: "fixture" }
      }, undefined, { signal });
      expect(result.structuredContent).toMatchObject({ ok: true, detail: "compact" });
      expect(result.structuredContent).not.toHaveProperty("delegation_gate");
      expect(result.structuredContent).not.toHaveProperty("review_loop");
    }, 5_000);

    test("repo_ship_review includes full detail fields when requested", async ({ signal }) => {
      const result = await fixtureForTest().client.callTool({
        name: "repo_ship_review",
        arguments: { repo_id: "fixture", detail: "full" }
      }, undefined, { signal });
      expect(result.structuredContent).toMatchObject({ ok: true, detail: "full" });
      expect(result.structuredContent).toHaveProperty("delegation_gate");
      expect(result.structuredContent).toHaveProperty("review_loop");
    }, 5_000);
  });

  test("repo_write_changes prevalidation prevents partial writes", async () => {
    const { client, close } = await connectFixtureServer();
    try {
      const result = await client.callTool({
        name: "repo_write_changes",
        arguments: {
          repo_id: "fixture",
          changes: [
            { type: "write", path: "docs/applied-a.md", content: "A\n" },
            { type: "append", path: "docs/ARCHITECTURE.md", content: "Applied\n" },
            { type: "replace", path: "src/app.ts", find: "missingNeedle", replace: "safeFetch" }
          ]
        }
      });

      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({
        ok: false,
        error: {
          code: "WRITE_FIND_NOT_FOUND",
          retryable: false
        }
      });
      const serialized = JSON.stringify(result.structuredContent);
      expect(serialized).not.toContain("/Users/");
      expect(serialized).not.toContain("A\\n");
      expect(serialized).not.toContain("Applied\\n");
    } finally {
      await close();
    }
  });

  test("repo_last_write returns missing receipt when no write receipt exists", async () => {
    const { client, close } = await connectFixtureServer();
    try {
      const result = await client.callTool({
        name: "repo_last_write",
        arguments: { repo_id: "fixture" }
      });

      expect(result.isError).toBeUndefined();
      expect(result.structuredContent).toEqual({
        ok: true,
        found: false,
        next_tool_payloads: {},
        warnings: ["NO_LAST_WRITE_RECEIPT"]
      });
    } finally {
      await close();
    }
  });

  test("actual repo_write_file creates last write receipt", async () => {
    const { client, close } = await connectFixtureServer();
    try {
      const write = await client.callTool({
        name: "repo_write_file",
        arguments: {
          repo_id: "fixture",
          path: "docs/write-file-actual.md",
          content: "actual\n"
        }
      });
      expect(write.isError).toBeUndefined();
      expect(write.structuredContent).toMatchObject({
        operation_receipt: {
          operation_id: expect.stringMatching(/^write-/),
          path: ".chatgpt/operations/last-write.json"
        }
      });

      const result = await client.callTool({
        name: "repo_last_write",
        arguments: { repo_id: "fixture" }
      });

      expect(result.structuredContent).toMatchObject({
        ok: true,
        found: true,
        receipt: {
          tool: "repo_write_file",
          repo_id: "fixture",
          touched_paths: ["docs/write-file-actual.md"],
          changed_paths: ["docs/write-file-actual.md"],
          created_paths: ["docs/write-file-actual.md"],
          modified_paths: [],
          counts: { requested: 1, changed: 1, created: 1, unchanged: 0 },
          summary: "Created docs/write-file-actual.md."
        },
        next_tool_payloads: {
          repo_git_review: { repo_id: "fixture" }
        },
        warnings: []
      });
      const serialized = JSON.stringify(result.structuredContent);
      expect(serialized).not.toContain("actual\\n");
      expect(serialized).not.toContain("/tmp/");
    } finally {
      await close();
    }
  });

  test("repo_write_changes creates receipt and dry-run failed and no-op writes do not overwrite it", async () => {
    const { client, close } = await connectFixtureServer();
    try {
      const writeChanges = await client.callTool({
        name: "repo_write_changes",
        arguments: {
          repo_id: "fixture",
          changes: [
            { type: "write", path: "docs/new-receipt.md", content: "new\n" },
            { type: "append", path: "docs/ARCHITECTURE.md", content: "changed\n" }
          ]
        }
      });
      expect(writeChanges.isError).toBeUndefined();

      const firstReceipt = await client.callTool({
        name: "repo_last_write",
        arguments: { repo_id: "fixture" }
      });
      expect(firstReceipt.structuredContent).toMatchObject({
        found: true,
        receipt: {
          tool: "repo_write_changes",
          touched_paths: ["docs/new-receipt.md", "docs/ARCHITECTURE.md"],
          changed_paths: ["docs/new-receipt.md", "docs/ARCHITECTURE.md"],
          created_paths: ["docs/new-receipt.md"],
          modified_paths: ["docs/ARCHITECTURE.md"],
          counts: { requested: 2, changed: 2, created: 1, unchanged: 0 },
          summary: "Applied 2 changes across 2 files."
        }
      });
      const firstOperationId = (firstReceipt.structuredContent as {
        receipt?: { operation_id?: string };
      }).receipt?.operation_id;

      await client.callTool({
        name: "repo_write_file",
        arguments: {
          repo_id: "fixture",
          path: "docs/dry-run-no-receipt.md",
          content: "dry\n",
          dry_run: true
        }
      });
      await client.callTool({
        name: "repo_write_file",
        arguments: {
          repo_id: "fixture",
          path: "secrets/blocked.md",
          content: "blocked\n"
        }
      });
      await client.callTool({
        name: "repo_write_file",
        arguments: {
          repo_id: "fixture",
          path: "docs/ARCHITECTURE.md",
          content: "# Architecture\nDecision: keep tools read-only.\nConvention: use contracts first.\nchanged\n"
        }
      });

      const finalReceipt = await client.callTool({
        name: "repo_last_write",
        arguments: { repo_id: "fixture" }
      });

      expect((finalReceipt.structuredContent as {
        receipt?: { operation_id?: string };
      }).receipt?.operation_id).toBe(firstOperationId);
    } finally {
      await close();
    }
  });

  test("repo_write_handoff returns success envelope from HandoffService", async () => {
    const { client, close } = await connectFixtureServer();
    try {
      const result = await client.callTool({
        name: "repo_write_handoff",
        arguments: {
          repo_id: "fixture",
          title: "MCP Handoff",
          current_state: "Tool wiring is under test.",
          why: "The next ChatGPT session needs local resume context.",
          next_steps: [{ title: "Continue Slice v2.2" }],
          dry_run: true
        }
      });

      expect(result.isError).toBeUndefined();
      expect(result.structuredContent).toMatchObject({
        ok: true,
        dry_run: true,
        handoff_path: expect.stringMatching(/^\.chatgpt\/handoffs\/\d{4}-\d{2}-\d{2}-\d{4}-mcp-handoff\.local\.md$/),
        current_path: ".chatgpt/handoffs/current.local.md",
        updated_current: true,
        branch: expect.any(String),
        head_sha: expect.any(String),
        clean: false,
        startup_prompt: expect.stringContaining("repo_id `fixture`"),
        current_next_step: "Continue Slice v2.2",
        warnings: []
      });
      expect(result.content).toEqual([
        { type: "text", text: expect.stringContaining("Dry run checked handoff") }
      ]);
    } finally {
      await close();
    }
  });

  test("repo_validate tools/call runs an allowlisted validation profile", async () => {
    const { client, close } = await connectFixtureServer();
    try {
      const result = await client.callTool({
        name: "repo_validate",
        arguments: {
          repo_id: "fixture",
          profile: "smoke"
        }
      });

      expect(result.isError).toBeUndefined();
      expect(result.structuredContent).toMatchObject({
        ok: true,
        repo_id: "fixture",
        profile: "smoke",
        dry_run: false,
        status: "passed",
        commands: [{
          profile: "smoke",
          script: "smoke",
          command: "npm run smoke",
          status: "passed",
          exit_code: 0,
          stdout_tail: expect.stringContaining("smoke ok")
        }],
        counts: { total: 1, passed: 1, failed: 0, skipped: 0 },
        warnings: []
      });
      const definition = toolCatalog.find((tool) => tool.name === "repo_validate");
      expect(definition?.outputSchema.safeParse(result.structuredContent).success).toBe(true);
    } finally {
      await close();
    }
  });

  test("work session tools create, update, and read structured local state", async () => {
    const { client, close } = await connectFixtureServer();
    try {
      const started = await client.callTool({
        name: "repo_start_work_session",
        arguments: {
          repo_id: "fixture",
          title: "MCP Work Session",
          objective: "Track MCP contract progress.",
          files_inspected: ["docs/ARCHITECTURE.md"],
          next_action: "Update session"
        }
      });
      expect(started.isError).toBeUndefined();
      const workSessionId = String((started.structuredContent as { work_session_id: string }).work_session_id);

      const updated = await client.callTool({
        name: "repo_update_work_session",
        arguments: {
          repo_id: "fixture",
          work_session_id: workSessionId,
          append_decisions: ["Keep session content-free"],
          append_touched_files: ["src/services/work-session-service.ts"],
          next_action: "Read session"
        }
      });
      expect(updated.isError).toBeUndefined();

      const current = await client.callTool({
        name: "repo_current_work_session",
        arguments: { repo_id: "fixture" }
      });

      expect(current.isError).toBeUndefined();
      expect(current.structuredContent).toMatchObject({
        ok: true,
        repo_id: "fixture",
        found: true,
        work_session_id: workSessionId,
        session: {
          objective: "Track MCP contract progress.",
          files_inspected: ["docs/ARCHITECTURE.md"],
          decisions: ["Keep session content-free"],
          touched_files: ["src/services/work-session-service.ts"],
          next_action: "Read session"
        },
        warnings: []
      });
      for (const name of ["repo_start_work_session", "repo_update_work_session", "repo_current_work_session"]) {
        const definition = toolCatalog.find((tool) => tool.name === name);
        const result = name === "repo_start_work_session" ? started : name === "repo_update_work_session" ? updated : current;
        expect(definition?.outputSchema.safeParse(result.structuredContent).success, name).toBe(true);
      }
    } finally {
      await close();
    }
  });

  test("legacy v2 creation fields are rejected at the public schema boundary", async () => {
    const { client, close } = await connectFixtureServer();
    try {
      const result = await client.callTool({
        name: "repo_prepare_codex_task",
        arguments: {
          repo_id: "fixture",
          title: "Legacy task",
          objective: "Change exactly one file.",
          inspect_first: ["src/app.ts"],
          allowed_paths: ["src/app.ts"]
        }
      });

      expect(result.isError).toBe(true);
      expect(result.structuredContent).toBeUndefined();
      expect(result.content).toEqual(expect.arrayContaining([
        expect.objectContaining({
          type: "text",
          text: expect.stringMatching(/invalid|argument|schema/i)
        })
      ]));
      const definition = toolCatalog.find((tool) => tool.name === "repo_prepare_codex_task");
      expect(definition?.description).toContain("Delegation v3");
      expect(definition?.inputSchema.safeParse({
        repo_id: "fixture",
        title: "Legacy task",
        objective: "legacy"
      }).success).toBe(false);
    } finally {
      await close();
    }
  });

  test("fixture close removes its temporary repository root", async () => {
    const fixture = await connectFixtureServer();
    try {
      await fixture.close();
      await expect(access(fixture.root)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(fixture.root, { recursive: true, force: true, maxRetries: 10, retryDelay: 25 });
    }
  });

  describe.sequential("representative tool output schemas", () => {
    const callGroups = [
      {
        name: "repository discovery and indexing",
        tools: [
          "repo_list_roots",
          "repo_last_write",
          "repo_tree",
          "repo_search",
          "repo_fetch_file",
          "repo_read_many",
          "repo_symbol_context",
          "repo_code_index"
        ]
      },
      {
        name: "diagnostic and review",
        tools: ["repo_failure_diagnose", "repo_semantic_review", "repo_ship_review"]
      },
      {
        name: "Git state and dry-run write operations",
        tools: [
          "repo_git_status",
          "repo_git_diff",
          "repo_git_review",
          "repo_git_restore_paths",
          "repo_write_stage",
          "repo_write_unstage",
          "repo_write_commit",
          "repo_write_stage_commit"
        ]
      },
      {
        name: "recovery, cleanup, and validation",
        tools: ["repo_write_recover", "repo_cleanup_paths", "repo_validate"]
      },
      {
        name: "work-session lifecycle",
        tools: ["repo_start_work_session", "repo_update_work_session", "repo_current_work_session"]
      },
      {
        name: "project context and planning",
        tools: ["repo_project_brief", "repo_task_inventory", "repo_decision_memory", "repo_change_plan"]
      },
      {
        name: "task, review, file, change, and handoff",
        tools: [
          "repo_prepare_codex_task",
          "repo_write_codex_task",
          "repo_codex_review",
          "repo_write_file",
          "repo_write_changes",
          "repo_write_handoff",
          "repo_write_codex_review"
        ]
      }
    ] as const;

    let fixture: Awaited<ReturnType<typeof connectFixtureServer>> | undefined;
    let calls: Record<string, Record<string, unknown>> = {};
    let sequenceFailed = false;
    let setupController: AbortController | undefined;
    let fixtureOwner: ReturnType<typeof createFixtureResourceOwner> | undefined;
    let setupPromise: Promise<Awaited<ReturnType<typeof connectFixtureServer>>> | undefined;
    let setupFinished = false;
    let teardownStarted = false;

    beforeAll(async () => {
      setupController = new AbortController();
      const owner = createFixtureResourceOwner();
      fixtureOwner = owner;
      setupPromise = (async () => {
        const connectedFixture = await connectFixtureServer(setupController!.signal, owner);
        if (teardownStarted) return connectedFixture;
        fixture = connectedFixture;
        try {
          const reviewWriteArgs = await representativeReviewWriteArgs(connectedFixture.client, setupController!.signal);
          if (!teardownStarted) {
            calls = {
              ...representativeCalls(connectedFixture.head),
              repo_write_codex_review: reviewWriteArgs
            };
          }
        } catch (error) {
          try {
            await connectedFixture.close();
          } catch (cleanupError) {
            throw new AggregateError([error, cleanupError], "Representative fixture setup failed and cleanup was incomplete.");
          }
          throw error;
        }
        return connectedFixture;
      })();
      void setupPromise.then(
        () => { setupFinished = true; },
        () => { setupFinished = true; }
      );
      await setupPromise;
    }, 5_000);

    afterAll(async () => {
      teardownStarted = true;
      await finalizeFixtureTeardown({
        setupPromise,
        setupWasPending: !setupFinished,
        abort: () => setupController?.abort(),
        cleanup: async () => {
          const errors = await fixtureOwner?.cleanup();
          if (errors && errors.length > 0) throw new AggregateError(errors, "MCP contract fixture cleanup failed.");
        },
        cleanupLateFixture: async (lateFixture) => lateFixture.close(),
        reportLateCleanupFailure: (error) => console.error("MCP contract fixture cleanup failed after its deadline.", error)
      });
    }, 5_000);

    afterEach(({ task }) => {
      if (task.result?.state === "fail") sequenceFailed = true;
    });

    test("groups cover every representative tool exactly once in original order", () => {
      const groupedToolNames = callGroups.flatMap((group) => group.tools);
      const expectedToolNames = Object.keys(calls);

      expect(groupedToolNames).toHaveLength(expectedToolNames.length);
      expect(new Set(groupedToolNames).size).toBe(expectedToolNames.length);
      expect(groupedToolNames).toEqual(expectedToolNames);
    });

    for (const group of callGroups) {
      test(`${group.name} outputs match their advertised schemas`, async ({ signal }) => {
        if (sequenceFailed) {
          throw new Error("Representative sequence stopped after an earlier group failed.");
        }
        if (!fixture) throw new Error("Representative MCP fixture was not initialized.");

        for (const name of group.tools) {
          if (signal.aborted) throw signal.reason;
          const args = calls[name];
          if (!args) throw new Error(`Missing representative arguments for ${name}.`);

          const result = await fixture.client.callTool({ name, arguments: args }, undefined, { signal });
          expect(result.isError, name).toBeUndefined();
          expect(result.structuredContent, name).toBeDefined();

          const definition = toolCatalog.find((tool) => tool.name === name);
          expect(definition, name).toBeDefined();
          const parsed = definition!.outputSchema.safeParse(result.structuredContent);
          expect(parsed.error?.issues, name).toBeUndefined();
          expect(result.content, name).toEqual([
            expect.objectContaining({ type: "text", text: expect.any(String) })
          ]);
        }
      }, 5_000);
    }
  });

  test("repo_rollback_patchset tools/call returns structuredContent matching the advertised output", async () => {
    const { client, close, head } = await connectFixtureServer();
    try {
      const prepared = await client.callTool({
        name: "repo_prepare_patchset",
        arguments: {
          repo_id: "fixture",
          intent: "Rollback MCP contract",
          base_head_sha: head,
          files: [
            {
              path: "docs/ARCHITECTURE.md",
              operation: "modify",
              content: "# Architecture\nDecision: allow rollback.\nConvention: use contracts first.\n",
              expected_old_sha256: sha256("# Architecture\nDecision: keep tools read-only.\nConvention: use contracts first.\n")
            },
            {
              path: "docs/rollback-mcp.md",
              operation: "create",
              content: "Rollback\n",
              expected_missing: true
            }
          ]
        }
      });
      const patchsetId = String((prepared.structuredContent as { patchset_id: string }).patchset_id);
      const applied = await client.callTool({
        name: "repo_apply_patchset",
        arguments: { repo_id: "fixture", patchset_id: patchsetId, expected_head_sha: head }
      });
      expect(applied.isError).toBeUndefined();

      const result = await client.callTool({
        name: "repo_rollback_patchset",
        arguments: {
          repo_id: "fixture",
          patchset_id: patchsetId,
          expected_head_sha: head,
          dry_run: true
        }
      });

      expect(result.isError).toBeUndefined();
      expect(result.structuredContent).toMatchObject({
        ok: true,
        dry_run: true,
        patchset_id: patchsetId,
        restored_paths: ["docs/ARCHITECTURE.md"],
        deleted_paths: ["docs/rollback-mcp.md"],
        counts: { restored: 1, deleted: 1, skipped: 0 }
      });
      const definition = toolCatalog.find((tool) => tool.name === "repo_rollback_patchset");
      expect(definition?.outputSchema.safeParse(result.structuredContent).success).toBe(true);
    } finally {
      await close();
    }
  });
});

function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

async function representativeReviewWriteArgs(client: Client, signal?: AbortSignal): Promise<Record<string, unknown>> {
  const runId = "2026-07-19T132500Z-representative-review";
  const task = await client.callTool({
    name: "repo_write_codex_task",
    arguments: {
      repo_id: "fixture",
      run_id: runId,
      title: "Representative review attestation",
      task_kind: "technical_infrastructure",
      assignment: "Create a technically complete no-change review fixture.",
      outcome: {
        beneficiary: "Repository operator",
        current_problem: "The review-write MCP output needs a live contract fixture.",
        desired_outcome: "A state-bound technical-only review can be dry-run through MCP.",
        why_now: "The RNV-03B public tool is being verified."
      },
      technical_context: {
        enabling_value: "Verify the state-bound review-write tool without mutating project files."
      },
      starting_points: ["docs/ARCHITECTURE.md"],
      authorization_scope: ["docs/**"],
      forbidden_paths: [],
      hard_constraints: ["Do not change project content."],
      must_preserve: ["Git happy paths remain closed."],
      explicit_exclusions: ["Do not push."],
      technical_acceptance_criteria: ["The no-change technical result is strictly bound."],
      runner: { mode: "manual" }
    }
  }, undefined, { signal });
  expect(task.isError).toBeUndefined();
  const taskOutput = task.structuredContent as { result_json_path: string };
  const resultJson = {
    schema_version: 3,
    repo_id: "fixture",
    run_id: runId,
    status: "completed",
    summary: "Completed the no-change technical review fixture.",
    changed_files: [],
    connected_changes: [],
    commands_run: [],
    tests: [],
    product_acceptance_criteria: [],
    technical_acceptance_criteria: [{
      id: "TAC-1",
      status: "passed",
      evidence: "The strict no-change result matches the manifest."
    }],
    scope_extension_required: [],
    blockers: [],
    followups: []
  };
  const resultWrite = await client.callTool({
    name: "repo_write_file",
    arguments: {
      repo_id: "fixture",
      path: taskOutput.result_json_path,
      content: `${JSON.stringify(resultJson, null, 2)}\n`,
      expected_missing: true
    }
  }, undefined, { signal });
  expect(resultWrite.isError).toBeUndefined();
  const review = await client.callTool({
    name: "repo_codex_review",
    arguments: { repo_id: "fixture", run_id: runId }
  }, undefined, { signal });
  expect(review.isError).toBeUndefined();
  const state = (review.structuredContent as { review_state: { status: string; state_sha256?: string } }).review_state;
  expect(state.status).toBe("available");
  expect(state.state_sha256).toMatch(/^[a-f0-9]{64}$/);
  return {
    repo_id: "fixture",
    run_id: runId,
    expected_review_state_sha256: state.state_sha256,
    product_verdict: "not_applicable",
    rationale: "The manifest is technical-only and the deterministic technical review passed.",
    evidence: [],
    dry_run: true
  };
}

function representativeCalls(head: string): Record<string, Record<string, unknown>> {
  return {
  repo_list_roots: {},
  repo_last_write: { repo_id: "fixture" },
  repo_tree: { repo_id: "fixture", path: ".", max_depth: 2, page_size: 10 },
  repo_search: { repo_id: "fixture", query: "Fixture", max_results: 5 },
  repo_fetch_file: { repo_id: "fixture", path: "README.md", start_line: 1, end_line: 5 },
  repo_read_many: { repo_id: "fixture", paths: ["README.md", "src/app.ts"], max_files: 2 },
  repo_symbol_context: { repo_id: "fixture", paths: ["src/app.ts"], max_files: 20 },
  repo_code_index: { repo_id: "fixture", action: "status" },
  repo_failure_diagnose: { repo_id: "fixture", max_diagnostics: 10, max_candidates: 5 },
  repo_semantic_review: { repo_id: "fixture", max_findings: 10, max_files: 20 },
  repo_ship_review: { repo_id: "fixture", max_findings: 10, max_files: 20 },
  repo_git_status: { repo_id: "fixture" },
  repo_git_diff: { repo_id: "fixture" },
  repo_git_review: { repo_id: "fixture" },
  repo_git_restore_paths: { repo_id: "fixture", paths: ["docs/write-dry-run.md"], expected_head_sha: head, dry_run: true },
  repo_write_stage: { repo_id: "fixture", paths: ["docs/write-dry-run.md"], expected_head_sha: head, dry_run: true },
  repo_write_unstage: { repo_id: "fixture", paths: ["docs/staged.md"], expected_head_sha: head, dry_run: true },
  repo_write_commit: { repo_id: "fixture", message: "Update staged docs", expected_head_sha: head, expected_staged_paths: ["docs/staged.md"], dry_run: true },
  repo_write_stage_commit: { repo_id: "fixture", paths: ["docs/staged.md"], message: "Update staged docs", expected_head_sha: head, dry_run: true },
  repo_write_recover: { repo_id: "fixture", restore_paths: ["docs/write-dry-run.md"], cleanup_paths: [".chatgpt/tool-tests/cleanup.txt"], expected_head_sha: head, dry_run: true },
  repo_cleanup_paths: { repo_id: "fixture", paths: [".chatgpt/tool-tests/cleanup.txt"], dry_run: true },
  repo_validate: { repo_id: "fixture", profile: "smoke", dry_run: true },
  repo_start_work_session: {
    repo_id: "fixture",
    work_session_id: "representative-work-session",
    title: "Representative Work Session",
    objective: "Track representative MCP calls.",
    next_action: "Update representative work session"
  },
  repo_update_work_session: {
    repo_id: "fixture",
    work_session_id: "representative-work-session",
    append_decisions: ["Representative decision"],
    next_action: "Read representative work session"
  },
  repo_current_work_session: {
    repo_id: "fixture"
  },
  repo_project_brief: { repo_id: "fixture" },
  repo_task_inventory: { repo_id: "fixture", max_results: 5 },
  repo_decision_memory: { repo_id: "fixture" },
  repo_change_plan: { repo_id: "fixture", goal: "Add fixture validation", planning_depth: "quick" },
  repo_prepare_codex_task: {
    repo_id: "fixture",
    title: "Strengthen fixture delegation",
    task_kind: "technical_infrastructure",
    assignment: "Create a coherent technical outcome without prescribing every internal implementation step.",
    outcome: {
      beneficiary: "Repository operator",
      current_problem: "The fixture lacks a product-aware delegation contract.",
      desired_outcome: "The repository can prepare a bounded v3 task with explicit operational value.",
      why_now: "The public task surface is being verified after the v3 cutover."
    },
    technical_context: {
      enabling_value: "Provide one safe and reviewable delegation contract for repository work."
    },
    starting_points: ["docs/ARCHITECTURE.md"],
    authorization_scope: ["docs/**"],
    forbidden_paths: [],
    hard_constraints: ["Preserve existing repository safety boundaries."],
    must_preserve: ["Historical v1 and v2 runs remain reviewable."],
    explicit_exclusions: ["Do not add arbitrary shell execution."],
    technical_acceptance_criteria: ["The task validates against the public v3 contract."],
    runner: { mode: "manual" }
  },
  repo_write_codex_task: {
    repo_id: "fixture",
    title: "Strengthen fixture delegation",
    task_kind: "technical_infrastructure",
    assignment: "Create a coherent technical outcome without prescribing every internal implementation step.",
    outcome: {
      beneficiary: "Repository operator",
      current_problem: "The fixture lacks a product-aware delegation contract.",
      desired_outcome: "The repository can write a bounded v3 task with explicit operational value.",
      why_now: "The public task surface is being verified after the v3 cutover."
    },
    technical_context: {
      enabling_value: "Provide one safe and reviewable delegation contract for repository work."
    },
    starting_points: ["docs/ARCHITECTURE.md"],
    authorization_scope: ["docs/**"],
    forbidden_paths: [],
    hard_constraints: ["Preserve existing repository safety boundaries."],
    must_preserve: ["Historical v1 and v2 runs remain reviewable."],
    explicit_exclusions: ["Do not add arbitrary shell execution."],
    technical_acceptance_criteria: ["The task validates against the public v3 contract."],
    runner: { mode: "manual" },
    dry_run: true
  },
  repo_codex_review: {
    repo_id: "fixture",
    run_id: "2026-06-04T081500Z-fix-fixture-docs"
  },
  repo_write_file: { repo_id: "fixture", path: "docs/write-file-dry-run.md", content: "planned\n", dry_run: true },
  repo_write_changes: {
    repo_id: "fixture",
    changes: [
      { type: "write", path: "docs/write-changes-dry-run.md", content: "planned\n" },
      {
        type: "edit",
        path: "docs/ARCHITECTURE.md",
        edits: [
          { type: "replace", find: "Decision: keep tools read-only.", replace: "Decision: keep tools safe by default." },
          { type: "insert_after", find: "Convention: use contracts first.", content: "\nConvention: review grouped edits through git." }
        ]
      }
    ],
    dry_run: true
  },
  repo_write_handoff: {
    repo_id: "fixture",
    title: "Representative Handoff",
    current_state: "Representative MCP contract call is running.",
    why: "Output schema should validate for the handoff tool.",
    next_steps: [{ title: "Review handoff output" }],
    dry_run: true
  }
  };
}

describe("fixture teardown", () => {
  function makeInput<T>(options: {
    setupPromise?: Promise<T>;
    setupWasPending: boolean;
    abort?: () => void;
    cleanup?: () => Promise<void>;
    cleanupLateFixture?: (fixture: T) => Promise<void>;
    reportLateCleanupFailure?: (error: unknown) => void;
    deadline?: { promise: Promise<void>; cancel: () => void };
  }) {
    return {
      setupPromise: options.setupPromise,
      setupWasPending: options.setupWasPending,
      abort: options.abort ?? (() => {}),
      cleanup: options.cleanup ?? (async () => {}),
      cleanupLateFixture: options.cleanupLateFixture ?? (async () => {}),
      reportLateCleanupFailure: options.reportLateCleanupFailure ?? (() => {}),
      deadline: options.deadline ?? controlledDeadline().deadline
    };
  }

  test("normal setup closes the fixture once", async () => {
    const fixture = { id: "fixture" };
    const close = vi.fn(async () => {});
    const abort = vi.fn();

    await finalizeFixtureTeardown(makeInput({
      setupPromise: Promise.resolve(fixture),
      setupWasPending: false,
      abort,
      cleanup: close,
      cleanupLateFixture: async () => {
        throw new Error("completed setup must not be treated as late");
      }
    }));

    expect(abort).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
  });

  test("partial fixture roots stay owned until setup activity settles", async () => {
    const owner = createFixtureResourceOwner();
    const root = await mkdtemp(join(tmpdir(), "mcp-contract-owner-"));
    const setupOperation = createDeferred<void>();
    owner.setRoot(root);
    const trackedSetup = owner.track(() => setupOperation.promise);
    const cleanup = owner.cleanup();

    await expect(access(root)).resolves.toBeUndefined();
    setupOperation.resolve();
    await trackedSetup;
    await expect(cleanup).resolves.toEqual([]);
    await expect(access(root)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("fixture transports stay open until tracked setup settles", async () => {
    const owner = createFixtureResourceOwner();
    const root = await mkdtemp(join(tmpdir(), "mcp-contract-owner-"));
    const setupOperation = createDeferred<void>();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const closeTransport = vi.spyOn(clientTransport, "close");
    owner.setRoot(root);
    owner.setTransports(clientTransport, serverTransport);
    const trackedSetup = owner.track(() => setupOperation.promise);
    const cleanup = owner.cleanup();

    try {
      await expect(owner.track(async () => {})).rejects.toThrow(/cleanup has begun/i);
      expect(closeTransport).not.toHaveBeenCalled();
      await expect(access(root)).resolves.toBeUndefined();
    } finally {
      setupOperation.resolve();
      await trackedSetup;
      await cleanup;
      expect(closeTransport).toHaveBeenCalled();
      closeTransport.mockRestore();
    }

    await expect(access(root)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("connected setup still pending after hook cancellation is cleaned and reported", async () => {
    const controller = new AbortController();
    const owner = createFixtureResourceOwner();
    const connected = createDeferred<{
      fixture: Awaited<ReturnType<typeof connectFixtureServer>>;
      transports: readonly InMemoryTransport[];
    }>();
    const setupGate = createDeferred<void>();
    const setupPromise = connectFixtureServer(controller.signal, owner, async (fixture, transports) => {
      connected.resolve({ fixture, transports });
      await setupGate.promise;
    });
    let setupSettled = false;
    void setupPromise.then(
      () => { setupSettled = true; },
      () => { setupSettled = true; }
    );

    const { fixture, transports } = await connected.promise;
    const transportClose = transports.map((transport) => vi.spyOn(transport, "close"));
    const deadline = controlledDeadline();
    const cleanupFinished = createDeferred<void>();
    let unownedRoot: string | undefined;
    let failure: unknown;
    let testFailed = false;
    const cleanupFailures: unknown[] = [];
    try {
      unownedRoot = await mkdtemp(join(tmpdir(), "mcp-contract-unowned-"));
      const finalization = finalizeFixtureTeardown({
        setupPromise,
        setupWasPending: true,
        abort: () => controller.abort(),
        cleanup: async () => {
          const errors = await owner.cleanup();
          cleanupFinished.resolve();
          if (errors.length > 0) throw new AggregateError(errors, "MCP contract fixture cleanup failed.");
        },
        cleanupLateFixture: async (lateFixture) => lateFixture.close(),
        reportLateCleanupFailure: (error) => cleanupFailures.push(error),
        deadline: deadline.deadline
      });

      // The unresolved setup gate represents initialization past the beforeAll deadline.
      await cleanupFinished.promise;
      expect(setupSettled).toBe(false);
      for (const close of transportClose) expect(close).toHaveBeenCalled();
      await expect(access(fixture.root)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(access(unownedRoot)).resolves.toBeUndefined();

      deadline.expire();
      let finalizationError: unknown;
      try {
        await finalization;
      } catch (error) {
        finalizationError = error;
      }
      const finalizationErrors = finalizationError instanceof AggregateError
        ? finalizationError.errors
        : [finalizationError];
      expect(finalizationErrors.map((error) => error instanceof Error ? error.message : String(error)))
        .toEqual(["Fixture setup settlement was not confirmed before the teardown deadline."]);
      expect(setupSettled).toBe(false);

      setupGate.resolve();
      await expect(setupPromise).rejects.toMatchObject({ name: "AbortError" });
    } catch (error) {
      failure = error;
      testFailed = true;
    } finally {
      controller.abort();
      setupGate.resolve();
      await setupPromise.catch(() => {});
      try {
        for (const cleanupError of await owner.cleanup()) {
          cleanupFailures.push(cleanupError);
        }
      } catch (error) {
        cleanupFailures.push(error);
      }
      if (unownedRoot) {
        try {
          await rm(unownedRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 25 });
        } catch (error) {
          cleanupFailures.push(error);
        }
      }
      for (const close of transportClose) close.mockRestore();
    }
    if (testFailed || cleanupFailures.length > 0) {
      const failures = [];
      if (testFailed) failures.push(failure);
      if (cleanupFailures.length > 0) {
        failures.push(new AggregateError(cleanupFailures, "MCP fixture cleanup failed."));
      }
      if (failures.length === 1) throw failures[0];
      throw new AggregateError(failures, "Fixture test and cleanup both failed.");
    }
  });

  test("setup rejection is preserved after cleanup is attempted", async () => {
    const setupError = new Error("setup rejected");
    const cleanup = vi.fn(async () => {});

    await expect(finalizeFixtureTeardown(makeInput({
      setupPromise: Promise.reject(setupError),
      setupWasPending: false,
      cleanup
    }))).rejects.toBe(setupError);

    expect(cleanup).toHaveBeenCalledOnce();
  });

  test("unsettled setup reports cleanup as unconfirmed at the deadline", async () => {
    const setup = createDeferred<{ id: string }>();
    const deadline = controlledDeadline();
    const cleanupStarted = createDeferred<void>();
    const cleanup = vi.fn(async () => {
      cleanupStarted.resolve();
    });
    const finalization = finalizeFixtureTeardown(makeInput({
      setupPromise: setup.promise,
      setupWasPending: true,
      cleanup,
      deadline: deadline.deadline
    }));

    await cleanupStarted.promise;
    deadline.expire();
    await expect(finalization).rejects.toThrow(/setup settlement was not confirmed/i);
    setup.reject(makeAbortError());
  });

  test("late fixture cleanup rejection is reported after finalization times out", async () => {
    const setup = createDeferred<{ id: string }>();
    const deadline = controlledDeadline();
    const cleanupError = new Error("late cleanup rejected");
    const reported = createDeferred<unknown>();
    const finalization = finalizeFixtureTeardown(makeInput({
      setupPromise: setup.promise,
      setupWasPending: true,
      deadline: deadline.deadline,
      cleanupLateFixture: async () => { throw cleanupError; },
      reportLateCleanupFailure: (error) => reported.resolve(error)
    }));

    deadline.expire();
    let finalizationError: unknown;
    try {
      await finalization;
    } catch (error) {
      finalizationError = error;
    }
    setup.resolve({ id: "late fixture" });
    await expect(reported.promise).resolves.toBe(cleanupError);
    expect(finalizationError).toBeInstanceOf(AggregateError);
    expect((finalizationError as AggregateError).errors).toContain(cleanupError);
  });

  test("cancellation during partial setup still runs cleanup", async () => {
    const controller = new AbortController();
    let partialSetup = false;
    let cleanupObservedPartialSetup = false;
    const setupPromise = new Promise<{ id: string }>((_resolve, reject) => {
      partialSetup = true;
      controller.signal.addEventListener("abort", () => reject(makeAbortError()), { once: true });
    });

    await finalizeFixtureTeardown(makeInput({
      setupPromise,
      setupWasPending: true,
      abort: () => controller.abort(),
      cleanup: async () => {
        cleanupObservedPartialSetup = partialSetup && controller.signal.aborted;
      }
    }));

    expect(cleanupObservedPartialSetup).toBe(true);
  });

  test("late setup settlement closes the fixture and fails visibly", async () => {
    const setup = createDeferred<{ id: string }>();
    const deadline = controlledDeadline();
    const fixture = { id: "late fixture" };
    const closeLate = vi.fn(async () => {});
    const finalization = finalizeFixtureTeardown(makeInput({
      setupPromise: setup.promise,
      setupWasPending: true,
      cleanupLateFixture: closeLate,
      deadline: deadline.deadline
    }));

    setup.resolve(fixture);
    await expect(finalization).rejects.toThrow(/setup completed after teardown began/i);
    expect(closeLate).toHaveBeenCalledOnce();
    expect(closeLate).toHaveBeenCalledWith(fixture);
  });

  test("cleanup rejection remains visible", async () => {
    const cleanupError = new Error("cleanup rejected");

    await expect(finalizeFixtureTeardown(makeInput({
      setupPromise: Promise.resolve({ id: "fixture" }),
      setupWasPending: false,
      cleanup: async () => {
        throw cleanupError;
      }
    }))).rejects.toBe(cleanupError);
  });

  test("cleanup non-settlement is reported as unconfirmed", async () => {
    const cleanup = createDeferred<void>();
    const deadline = controlledDeadline();
    const cleanupStarted = createDeferred<void>();
    const finalization = finalizeFixtureTeardown(makeInput({
      setupPromise: Promise.resolve({ id: "fixture" }),
      setupWasPending: false,
      cleanup: () => {
        cleanupStarted.resolve();
        return cleanup.promise;
      },
      deadline: deadline.deadline
    }));

    await cleanupStarted.promise;
    deadline.expire();
    await expect(finalization).rejects.toThrow(/cleanup completion was not confirmed/i);
    cleanup.resolve();
  });

  test("setup and cleanup failures are both preserved", async () => {
    const setupError = new Error("setup rejected");
    const cleanupError = new Error("cleanup rejected");

    let thrown: unknown;
    try {
      await finalizeFixtureTeardown(makeInput({
        setupPromise: Promise.reject(setupError),
        setupWasPending: false,
        cleanup: async () => {
          throw cleanupError;
        }
      }));
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(AggregateError);
    expect((thrown as AggregateError).errors).toEqual([setupError, cleanupError]);
  });

  test("a failed sequence cannot start another request", () => {
    let requestCount = 0;
    const startRequest = () => {
      requireFixtureForRequest({ id: "fixture" }, true, false);
      requestCount += 1;
    };

    expect(startRequest).toThrow(/stopped after an earlier request failed/i);
    expect(requestCount).toBe(0);
    expect(() => requireFixtureForRequest({ id: "fixture" }, false, true)).toThrow(/teardown has started/i);
  });
});

function createDeferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function controlledDeadline() {
  const signal = createDeferred<void>();
  return {
    deadline: { promise: signal.promise, cancel: () => {} },
    expire: () => signal.resolve()
  };
}

function makeAbortError(): Error {
  const error = new Error("setup canceled");
  error.name = "AbortError";
  return error;
}

type FixtureOperationOutcome<T> =
  | { status: "pending" }
  | { status: "fulfilled"; value: T }
  | { status: "rejected"; reason: unknown };

type FixtureDeadline = { promise: Promise<void>; cancel: () => void };

/** Bounds setup and cleanup settlement and keeps late cleanup failures in the timeout result. */
async function finalizeFixtureTeardown<T>(input: {
  setupPromise?: Promise<T>;
  setupWasPending: boolean;
  abort: () => void;
  cleanup: () => Promise<void>;
  cleanupLateFixture: (fixture: T) => Promise<void>;
  reportLateCleanupFailure: (error: unknown) => void;
  deadline?: FixtureDeadline;
}): Promise<void> {
  const deadline = input.deadline ?? createFixtureDeadline(4_000);
  const errors: unknown[] = [];

  try {
    input.abort();
  } catch (error) {
    errors.push(error);
  }

  const setup = observeFixtureOperation(input.setupPromise ?? Promise.resolve(undefined as T));
  let lateCleanup: ReturnType<typeof observeFixtureOperation<void>> | undefined;
  let timedOut = false;
  let timeoutFailure: AggregateError | undefined;
  const recordLateCleanupFailure = (error: unknown): void => {
    if (!timedOut) return;
    const recordedErrors = timeoutFailure?.errors ?? errors;
    if (!recordedErrors.includes(error)) recordedErrors.push(error);
    try {
      input.reportLateCleanupFailure(error);
    } catch (reportError) {
      console.error("Could not report late MCP fixture cleanup failure.", reportError);
    }
  };
  const finalizedSetup = setup.settled.then(async (outcome) => {
    if (input.setupWasPending && outcome.status === "fulfilled") {
      const cleanupPromise = invokeFixtureOperation(() => input.cleanupLateFixture(outcome.value));
      lateCleanup = observeFixtureOperation(cleanupPromise);
      lateCleanup.settled.then((cleanupOutcome) => {
        if (timedOut && cleanupOutcome.status === "rejected") {
          recordLateCleanupFailure(cleanupOutcome.reason);
        }
      });
      return {
        kind: "late" as const,
        setup: outcome,
        cleanup: await lateCleanup.settled
      };
    }
    return { kind: "settled" as const, setup: outcome };
  });

  const cleanup = observeFixtureOperation(invokeFixtureOperation(input.cleanup));
  const completion = Promise.all([finalizedSetup, cleanup.settled]);
  const waited = await waitForFixtureCompletion(completion, deadline.promise);
  deadline.cancel();

  if (waited.status === "error") {
    errors.push(waited.reason);
  } else if (waited.status === "deadline") {
    timedOut = true;
    const setupOutcome = setup.outcome();
    if (setupOutcome.status === "pending") {
      errors.push(new Error("Fixture setup settlement was not confirmed before the teardown deadline."));
    } else if (setupOutcome.status === "rejected" && !(input.setupWasPending && isAbortError(setupOutcome.reason))) {
      errors.push(setupOutcome.reason);
    } else if (setupOutcome.status === "fulfilled" && input.setupWasPending) {
      errors.push(new Error("Fixture setup completed after teardown began."));
    }

    const cleanupOutcome = cleanup.outcome();
    if (cleanupOutcome.status === "pending") {
      errors.push(new Error("Fixture cleanup completion was not confirmed before the teardown deadline."));
    } else if (cleanupOutcome.status === "rejected") {
      errors.push(cleanupOutcome.reason);
    }

    const lateCleanupOutcome = lateCleanup?.outcome();
    if (lateCleanupOutcome?.status === "pending") {
      errors.push(new Error("Late fixture cleanup completion was not confirmed before the teardown deadline."));
    } else if (lateCleanupOutcome?.status === "rejected") {
      errors.push(lateCleanupOutcome.reason);
    }
  } else {
    const [setupResult, cleanupResult] = waited.value;
    if (setupResult.kind === "late") {
      errors.push(new Error("Fixture setup completed after teardown began."));
      if (setupResult.cleanup.status === "rejected") errors.push(setupResult.cleanup.reason);
    } else if (setupResult.setup.status === "rejected") {
      if (!(input.setupWasPending && isAbortError(setupResult.setup.reason))) errors.push(setupResult.setup.reason);
    }
    if (cleanupResult.status === "rejected") errors.push(cleanupResult.reason);
  }

  if (timedOut && errors.length > 0) {
    const message = errors.find((error): error is Error => error instanceof Error)?.message ??
      "Fixture teardown did not complete before its deadline.";
    timeoutFailure = new AggregateError(errors, message);
    throw timeoutFailure;
  }
  if (errors.length === 1) throw errors[0];
  if (errors.length > 1) throw new AggregateError(errors, "Fixture teardown did not complete cleanly.");
}

function observeFixtureOperation<T>(operation: Promise<T>) {
  let outcome: FixtureOperationOutcome<T> = { status: "pending" };
  const settled = Promise.resolve(operation).then(
    (value): FixtureOperationOutcome<T> => {
      outcome = { status: "fulfilled", value };
      return outcome;
    },
    (reason): FixtureOperationOutcome<T> => {
      outcome = { status: "rejected", reason };
      return outcome;
    }
  );
  return { settled, outcome: () => outcome };
}

function invokeFixtureOperation<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return Promise.resolve(operation());
  } catch (error) {
    return Promise.reject(error);
  }
}

function waitForFixtureCompletion<T>(
  completion: Promise<T>,
  deadline: Promise<void>
): Promise<{ status: "completed"; value: T } | { status: "deadline" } | { status: "error"; reason: unknown }> {
  return new Promise((resolve) => {
    let decided = false;
    completion.then(
      (value) => {
        if (decided) return;
        decided = true;
        resolve({ status: "completed", value });
      },
      (reason: unknown) => {
        if (decided) return;
        decided = true;
        resolve({ status: "error", reason });
      }
    );
    deadline.then(
      () => {
        if (decided) return;
        decided = true;
        resolve({ status: "deadline" });
      },
      () => {
        if (decided) return;
        decided = true;
        resolve({ status: "error", reason: new Error("Fixture teardown deadline failed.") });
      }
    );
  });
}

function createFixtureDeadline(timeoutMs: number): FixtureDeadline {
  let timer: ReturnType<typeof setTimeout>;
  const promise = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, timeoutMs);
  });
  return { promise, cancel: () => clearTimeout(timer) };
}

function requireFixtureForRequest<T>(fixture: T | undefined, sequenceFailed: boolean, teardownStarted: boolean): T {
  if (teardownStarted) throw new Error("Public review fixture teardown has started.");
  if (sequenceFailed) throw new Error("Public review sequence stopped after an earlier request failed.");
  if (!fixture) throw new Error("Public review fixture was not initialized.");
  return fixture;
}

/** Tracks fixture resources. Cleanup waits for active setup, closes resources, then removes the temporary root. */
function createFixtureResourceOwner() {
  let root: string | undefined;
  let client: Client | undefined;
  let server: ReturnType<typeof createMcpServer> | undefined;
  let clientTransport: InMemoryTransport | undefined;
  let serverTransport: InMemoryTransport | undefined;
  let connected = false;
  let cleanupPromise: Promise<unknown[]> | undefined;
  const observedCleanupErrors: unknown[] = [];
  let activeSetupOperations = 0;
  let cleanupStarted = false;
  const setupIdleWaiters = new Set<() => void>();

  const track = <T>(operation: () => Promise<T>): Promise<T> => {
    if (cleanupStarted) return Promise.reject(new Error("Fixture setup cannot start after cleanup has begun."));
    activeSetupOperations += 1;
    return invokeFixtureOperation(operation).finally(() => {
      activeSetupOperations -= 1;
      if (activeSetupOperations === 0) {
        for (const resolve of setupIdleWaiters) resolve();
        setupIdleWaiters.clear();
      }
    });
  };

  const waitForSetupIdle = (): Promise<void> => {
    if (activeSetupOperations === 0) return Promise.resolve();
    return new Promise((resolve) => setupIdleWaiters.add(resolve));
  };

  const cleanup = (): Promise<unknown[]> => {
    if (cleanupPromise) return cleanupPromise;
    cleanupStarted = true;
    const errors: unknown[] = [];
    const attempt = (operation: () => Promise<void>, onSuccess?: () => void, onFailure?: () => void): Promise<boolean> => {
      return invokeFixtureOperation(operation).then(
        () => {
          onSuccess?.();
          return true;
        },
        (error) => {
          errors.push(error);
          observedCleanupErrors.push(error);
          onFailure?.();
          return false;
        }
      );
    };

    const closeOwnedResources = async (): Promise<void> => {
      const transport = clientTransport ?? serverTransport;
      let fallbackPromise: Promise<boolean> | undefined;
      const startFallback = (): void => {
        if (connected && transport && !fallbackPromise) {
          fallbackPromise = attempt(() => transport.close(), () => {
            if (clientTransport === transport) clientTransport = undefined;
            if (serverTransport === transport) serverTransport = undefined;
          });
        }
      };
      const closeAttempts: Promise<boolean>[] = [];
      if (!connected && transport) {
        closeAttempts.push(attempt(() => transport.close(), () => {
          if (clientTransport === transport) clientTransport = undefined;
          if (serverTransport === transport) serverTransport = undefined;
        }));
      }
      if (client) closeAttempts.push(attempt(() => client!.close(), () => { client = undefined; }, startFallback));
      if (server) closeAttempts.push(attempt(() => server!.close(), () => { server = undefined; }, startFallback));

      const closeResults = await Promise.all(closeAttempts);
      if (connected && closeResults.some((succeeded) => !succeeded)) startFallback();
      if (fallbackPromise) await fallbackPromise;
    };
    const removeRoot = waitForSetupIdle().then(closeOwnedResources).then(() => {
      if (!root) return true;
      const ownedRoot = root;
      return attempt(
        () => rm(ownedRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 25 }),
        () => { if (root === ownedRoot) root = undefined; }
      );
    });

    const work = removeRoot.then(() => [...observedCleanupErrors]);
    cleanupPromise = work.finally(() => { cleanupPromise = undefined; });
    return cleanupPromise;
  };

  return {
    track,
    setRoot: (value: string) => { root = value; },
    setClient: (value: Client) => { client = value; },
    setServer: (value: ReturnType<typeof createMcpServer>) => { server = value; },
    setTransports: (clientValue: InMemoryTransport, serverValue: InMemoryTransport) => {
      clientTransport = clientValue;
      serverTransport = serverValue;
    },
    markConnected: () => { connected = true; },
    cleanup
  };
}

async function connectFixtureServer(
  signal?: AbortSignal,
  owner: ReturnType<typeof createFixtureResourceOwner> = createFixtureResourceOwner(),
  afterConnected?: (
    fixture: { client: Client; head: string; root: string; close: () => Promise<void> },
    transports: readonly InMemoryTransport[]
  ) => Promise<void>
) {
  try {
    throwIfAborted(signal);
    const root = await createRepoRoot(signal, owner);
    const head = (await awaitWithAbort(
      owner.track(() => execFileAsync("git", ["rev-parse", "HEAD"], { cwd: root, env: { PATH: process.env.PATH ?? "" }, signal })),
      signal
    )).stdout.trim();
    const registry = await awaitWithAbort(owner.track(() => RootRegistry.fromConfig({
      repos: [{
        repo_id: "fixture",
        display_name: "Fixture Repo",
        root,
        writes: { enabled: true, allowed_globs: ["docs/**", "src/**", ".chatgpt/**"] },
        operations: {
          enabled: true,
          git_stage_enabled: true,
          git_commit_enabled: true,
          cleanup_enabled: true,
          validation_enabled: true
        }
      }],
      limits: {}
    })), signal);
    throwIfAborted(signal);
    const server = createMcpServer({ registry });
    const client = new Client({ name: "contract-test-client", version: "0.1.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    owner.setServer(server);
    owner.setClient(client);
    owner.setTransports(clientTransport, serverTransport);

    const serverConnection = owner.track(() => server.connect(serverTransport));
    const clientConnection = owner.track(() => client.connect(clientTransport));
    await awaitWithAbort(Promise.all([serverConnection, clientConnection]), signal);
    throwIfAborted(signal);
    owner.markConnected();

    let closed = false;
    const fixture = {
      client,
      head,
      root,
      close: async () => {
        if (closed) return;
        const errors = await owner.cleanup();
        if (errors.length > 0) throw new AggregateError(errors, "MCP contract fixture cleanup failed.");
        closed = true;
      }
    };
    await afterConnected?.(fixture, [clientTransport, serverTransport]);
    throwIfAborted(signal);
    return fixture;
  } catch (error) {
    const cleanupErrors = await owner.cleanup();
    if (cleanupErrors.length > 0) {
      throw new AggregateError([error, ...cleanupErrors], "MCP contract fixture setup failed and cleanup was incomplete.");
    }
    throw error;
  }
}

async function createRepoRoot(signal: AbortSignal | undefined, owner: ReturnType<typeof createFixtureResourceOwner>) {
  throwIfAborted(signal);
  const root = await owner.track(async () => {
    const createdRoot = await mkdtemp(join(tmpdir(), "gpt-repo-mcp-contract-"));
    owner.setRoot(createdRoot);
    return createdRoot;
  });
  const run = <T>(operation: () => Promise<T>) => owner.track(operation);

  throwIfAborted(signal);
  await run(() => mkdir(join(root, "src"), { recursive: true }));
  throwIfAborted(signal);
  await run(() => mkdir(join(root, "docs"), { recursive: true }));
  throwIfAborted(signal);
  await run(() => mkdir(join(root, ".chatgpt", "tool-tests"), { recursive: true }));
  throwIfAborted(signal);
  await run(() => writeFile(join(root, "README.md"), "# Fixture\n"));
  throwIfAborted(signal);
  await run(() => writeFile(join(root, "docs", "ARCHITECTURE.md"), "# Architecture\nDecision: keep tools read-only.\nConvention: use contracts first.\n"));
  throwIfAborted(signal);
  await run(() => writeFile(join(root, "TODO.md"), "- [ ] Wire repo_task_inventory\n"));
  throwIfAborted(signal);
  await run(() => writeFile(join(root, "package.json"), JSON.stringify({
    type: "module",
    scripts: {
      build: "tsc",
      test: "vitest",
      smoke: "node -e \"console.log('smoke ok')\""
    },
    dependencies: {
      "@modelcontextprotocol/sdk": "^1.0.0"
    }
  }, null, 2)));
  throwIfAborted(signal);
  await run(() => writeFile(join(root, "src", "app.ts"), "export const fixture = true;\n"));
  throwIfAborted(signal);
  await awaitWithAbort(run(() => execFileAsync("git", ["init"], { cwd: root, env: { PATH: process.env.PATH ?? "" }, signal })), signal);
  throwIfAborted(signal);
  await awaitWithAbort(run(() => execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: root, env: { PATH: process.env.PATH ?? "" }, signal })), signal);
  throwIfAborted(signal);
  await awaitWithAbort(run(() => execFileAsync("git", ["config", "user.name", "Test User"], { cwd: root, env: { PATH: process.env.PATH ?? "" }, signal })), signal);
  throwIfAborted(signal);
  await awaitWithAbort(run(() => execFileAsync("git", ["add", "--", "README.md", "docs/ARCHITECTURE.md", "TODO.md", "package.json", "src/app.ts"], { cwd: root, env: { PATH: process.env.PATH ?? "" }, signal })), signal);
  throwIfAborted(signal);
  await awaitWithAbort(run(() => execFileAsync("git", ["commit", "-m", "initial"], { cwd: root, env: { PATH: process.env.PATH ?? "" }, signal })), signal);
  throwIfAborted(signal);
  await run(() => writeFile(join(root, "src-placeholder.txt"), "changed\n"));
  throwIfAborted(signal);
  await run(() => writeFile(join(root, "docs", "staged.md"), "staged\n"));
  throwIfAborted(signal);
  await run(() => writeFile(join(root, "docs", "write-dry-run.md"), "planned\n"));
  throwIfAborted(signal);
  await run(() => writeFile(join(root, ".chatgpt", "tool-tests", "cleanup.txt"), "temporary\n"));
  throwIfAborted(signal);
  await awaitWithAbort(run(() => execFileAsync("git", ["add", "--", "docs/staged.md"], { cwd: root, env: { PATH: process.env.PATH ?? "" }, signal })), signal);
  throwIfAborted(signal);
  return root;
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw abortReason(signal);
}

function abortReason(signal: AbortSignal): Error {
  if (signal.reason instanceof Error) return signal.reason;
  const error = new Error("Fixture setup was aborted.");
  error.name = "AbortError";
  return error;
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

function awaitWithAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(abortReason(signal));

  return new Promise((resolve, reject) => {
    const cleanup = (): void => signal.removeEventListener("abort", onAbort);
    const onAbort = (): void => {
      cleanup();
      reject(abortReason(signal));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        cleanup();
        resolve(value);
      },
      (error) => {
        cleanup();
        reject(error);
      }
    );
  });
}
