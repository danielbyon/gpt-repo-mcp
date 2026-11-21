import { execFile } from "node:child_process";
import { access, mkdir, readFile, realpath, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { expect, onTestFinished, test, vi } from "vitest";
import { createMcpServer } from "../src/register.js";
import type { CodebaseMemoryClientFactory } from "../src/services/codebase-memory-client.js";
import { CodeIntelligenceService } from "../src/services/code-intelligence-service.js";
import { RootRegistry } from "../src/services/root-registry.js";
import { createTempDir } from "./fixtures/temp-dir.js";

const exec = promisify(execFile);
const markerPath = "docs/marker.md";
const notesPath = "docs/notes.md";
const primaryMarker = "routing marker in primary";
const linkedMarker = "routing marker in linked";
const archiveMarker = "routing marker in archive";

test("configured roots expose canonical paths and route reads and searches by repository ID", async () => {
  const { primary, linked, archive, call, callResult } = await createFixture();

  expect(await callResult("repo_list_roots")).toEqual({
    repos: [
      { repo_id: "primary", display_name: "Primary", root: primary },
      { repo_id: "linked", display_name: "Linked", root: linked },
      { repo_id: "archive", display_name: "Archive", root: archive }
    ]
  });

  for (const [repoId, marker] of [["primary", primaryMarker], ["linked", linkedMarker], ["archive", archiveMarker]]) {
    expect(await callResult("repo_fetch_file", { repo_id: repoId, path: markerPath })).toMatchObject({
      path: markerPath,
      text: marker + "\n"
    });
    expect(await callResult("repo_search", { repo_id: repoId, query: "routing marker" })).toMatchObject({
      results: [{ path: markerPath, line: 1, text: marker }]
    });
  }

  expect(await call("repo_git_status", { repo_id: "archive" })).toMatchObject({
    isError: true,
    structuredContent: { ok: false, error: { code: "GIT_ERROR", message: expect.stringContaining("not a git repository") } }
  });
});

test("writes, validation, and Git operations stay on the configured checkout", async () => {
  const { primary, linked, call, callResult } = await createFixture();
  const before = await primaryState(primary);
  const linkedHead = await git(linked, "rev-parse", "HEAD");
  expect(linkedHead).not.toBe(before.head);
  const commonDir = await git(linked, "rev-parse", "--path-format=absolute", "--git-common-dir");
  expect(await realpath(commonDir)).toBe(await realpath(join(primary, ".git")));

  const content = "routing marker updated in linked\n";
  const linkedRepo = { repo_id: "linked", expected_head_sha: linkedHead };
  expect(await callResult("repo_write_file", { ...linkedRepo, path: markerPath, content }))
    .toMatchObject({ path: markerPath, changed: true });
  expect(await readFile(join(linked, markerPath), "utf8")).toBe(content);
  expect(await callResult("repo_validate", { repo_id: "linked", profile: "smoke" })).toMatchObject({
    status: "passed",
    commands: [{ status: "passed", stdout_tail: expect.stringContaining(content.trim()) }]
  });
  expect(await callResult("repo_git_review", { repo_id: "linked", paths: [markerPath] })).toMatchObject({
    head_sha: linkedHead,
    changed_paths: [{ path: markerPath }],
    recommendation: { warnings: expect.arrayContaining(["REVIEW_SCOPE_APPLIED"]) }
  });

  expect(await callResult("repo_write_stage", { ...linkedRepo, paths: [markerPath] }))
    .toMatchObject({ head_sha: linkedHead, staged_paths: [markerPath] });
  expect(await callResult("repo_git_status", { repo_id: "linked" })).toMatchObject({
    branch: "linked",
    head_sha: linkedHead,
    files: [{ path: markerPath, index: "M", worktree: " " }]
  });

  const commit = { ...linkedRepo, message: "Update linked guide", expected_staged_paths: [markerPath] };
  expect(await call("repo_write_commit", { ...commit, expected_head_sha: before.head })).toMatchObject({
    isError: true,
    structuredContent: { error: { code: "GIT_HEAD_MISMATCH" } }
  });
  expect(await call("repo_write_commit", { ...commit, expected_staged_paths: [notesPath] })).toMatchObject({
    isError: true,
    structuredContent: { error: { code: "GIT_STAGED_PATHS_MISMATCH" } }
  });
  expect(await git(linked, "rev-parse", "HEAD")).toBe(linkedHead);
  expect(await git(linked, "diff", "--cached", "--name-only")).toBe(markerPath);
  expect(await git(linked, "show", ":" + markerPath)).toBe(content.trim());

  const committed = await callResult("repo_write_commit", commit);
  const newHead = await git(linked, "rev-parse", "HEAD");
  expect(committed).toMatchObject({ head_before: linkedHead, commit_sha: newHead, committed_paths: [markerPath] });
  expect(await git(primary, "rev-parse", "refs/heads/linked")).toBe(newHead);
  expect(await git(primary, "show", "refs/heads/linked:" + markerPath)).toBe(content.trim());
  expect(await git(linked, "diff", "--cached", "--name-only")).toBe("");
  expect(await primaryState(primary)).toEqual(before);
  await expect(access(join(primary, ".chatgpt"))).rejects.toMatchObject({ code: "ENOENT" });
}, 15_000);

test("runs native symbol analysis and provider enrichment against the configured linked root", async () => {
  const sourcePath = "linked.ts";
  const symbol = "linkedOnly";
  const factory = vi.fn<CodebaseMemoryClientFactory>(async (root) => ({
    async call(tool) {
      if (tool === "list_projects") return { projects: [{ name: "linked-graph", root_path: root }] };
      if (tool === "search_graph") return {
        results: [{ name: symbol, label: "Function", file_path: join(root, sourcePath), start_line: 1, end_line: 1 }]
      };
      if (tool === "trace_path") return { callers: [], callees: [] };
      throw new Error("Unexpected provider call " + tool);
    },
    async close() {}
  }));
  const { linked, callResult } = await createFixture(new CodeIntelligenceService(factory, 1_000, 1_000));
  await writeFile(join(linked, sourcePath), `export function ${symbol}() {}
`);

  expect(await callResult("repo_symbol_context", {
    repo_id: "linked", paths: [sourcePath], symbols: [symbol], depth: 0
  })).toMatchObject({
    definitions: [{ name: symbol, path: sourcePath }],
    provider: { status: "ready", graph: { definitions: [{ name: symbol, path: sourcePath }] } }
  });
  expect(factory).toHaveBeenCalledExactlyOnceWith(linked);
});

async function createFixture(codeIntelligence?: CodeIntelligenceService) {
  const parent = await realpath(await createTempDir("configured-root-routing-"));
  const primary = join(parent, "primary");
  const linked = join(parent, "linked");
  const linkedAlias = join(parent, "linked-alias");
  const archive = join(parent, "archive");
  await mkdir(join(primary, "docs"), { recursive: true });
  await mkdir(join(archive, "docs"), { recursive: true });
  await writeFile(join(primary, markerPath), primaryMarker + "\n");
  await writeFile(join(primary, notesPath), "Initial notes\n");
  await writeFile(join(primary, ".gitignore"), ".chatgpt/\n");
  await writeFile(join(primary, "package.json"), JSON.stringify({ scripts: { smoke: "node smoke.cjs" } }));
  await writeFile(join(primary, "smoke.cjs"),
    `process.stdout.write(require("node:fs").readFileSync("${markerPath}", "utf8"));\n`);
  await writeFile(join(archive, markerPath), archiveMarker + "\n");
  await git(primary, "init", "--initial-branch=primary", "--template=");
  await git(primary, "config", "user.name", "Routing Fixture");
  await git(primary, "config", "user.email", "routing@example.invalid");
  await git(primary, "config", "commit.gpgsign", "false");
  await git(primary, "config", "core.autocrlf", "false");
  await git(primary, "config", "core.hooksPath", join(parent, "no-hooks"));
  await git(primary, "add", "--", ".gitignore", "package.json", "smoke.cjs", markerPath, notesPath);
  await git(primary, "commit", "-m", "Seed guide");
  await git(primary, "worktree", "add", "-b", "linked", linked);
  await writeFile(join(linked, markerPath), linkedMarker + "\n");
  await git(linked, "commit", "-am", "Set linked guide marker");
  // Stage a different path in the primary so the path check can distinguish the two indexes.
  await writeFile(join(primary, notesPath), "Staged primary notes\n");
  await git(primary, "add", "--", notesPath);
  await symlink(linked, linkedAlias, "junction");

  const configPath = join(parent, "config.json");
  await writeFile(configPath, JSON.stringify({
    repos: [
      { repo_id: "primary", display_name: "Primary", root: primary },
      {
        repo_id: "linked",
        display_name: "Linked",
        root: linkedAlias,
        writes: { enabled: true, allowed_globs: ["docs/**"] },
        operations: { enabled: true, git_stage_enabled: true, git_commit_enabled: true, validation_enabled: true }
      },
      { repo_id: "archive", display_name: "Archive", root: archive, allow_non_git: true }
    ]
  }));

  const server = createMcpServer({ registry: await RootRegistry.fromFile(configPath), codeIntelligence });
  const client = new Client({ name: "configured-root-routing-test", version: "1" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  onTestFinished(async () => {
    await client.close();
    await server.close();
  });
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  function call(name: string, args: Record<string, unknown> = {}) {
    return client.callTool({ name, arguments: args });
  }

  async function callResult(name: string, args?: Record<string, unknown>) {
    const result = await call(name, args);
    expect(result.isError, JSON.stringify(result.structuredContent)).toBeUndefined();
    return result.structuredContent;
  }

  return { primary, linked, archive, call, callResult };
}

async function primaryState(root: string) {
  return {
    head: await git(root, "rev-parse", "HEAD"),
    index: await readFile(join(root, ".git", "index")),
    files: await Promise.all([markerPath, notesPath, ".gitignore", "package.json", "smoke.cjs"]
      .map((path) => readFile(join(root, path), "utf8")))
  };
}

async function git(root: string, ...args: string[]): Promise<string> {
  const result = await exec("git", args, { cwd: root, env: { PATH: process.env.PATH ?? "" } });
  return result.stdout.trim();
}
