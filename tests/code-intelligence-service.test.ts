import { chmod, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test, vi } from "vitest";
import { CodeIntelligenceService } from "../src/services/code-intelligence-service.js";
import { createCodebaseMemoryClientFactory, validateCodebaseMemoryExecutable, type CodebaseMemoryClientFactory } from "../src/services/codebase-memory-client.js";
import { RootRegistry, type RepoConfig } from "../src/services/root-registry.js";
import { taskExecutionError } from "../src/services/task-execution-errors.js";

describe("CodeIntelligenceService", () => {
  test("returns native fallback metadata and asks for approval when the exact repo root is not indexed", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-code-intelligence-"));
    const { factory, calls } = fakeFactory(() => ({ projects: [] }));
    const service = new CodeIntelligenceService(factory, 100, 1_000);

    const result = await service.enrich(repo(root), { repo_id: "fixture", symbols: ["run"] });

    expect(result).toMatchObject({
      name: "codebase_memory",
      status: "index_required",
      fallback_used: "native",
      index_available: true
    });
    expect(result.suggested_action).toContain("Ask the user");
    expect(calls.map((call) => call.tool)).toEqual(["list_projects"]);
  });

  test("matches projects by canonical root and returns bounded graph enrichment without absolute paths", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-code-intelligence-"));
    const { factory } = fakeFactory((tool) => {
      if (tool === "list_projects") return { projects: [{ name: "fixture-graph", root_path: root }] };
      if (tool === "search_graph") return {
        results: [
          { name: "run", label: "Function", file_path: join(root, "src", "run.ts"), start_line: 2, end_line: 5 },
          { name: "outside", label: "Function", file_path: "/private/outside.ts", start_line: 1, end_line: 1 }
        ]
      };
      return { callers: [{ qualified_name: "fixture.src.caller", hop: 1 }], callees: [{ name: "helper", hop: 1 }] };
    });
    const service = new CodeIntelligenceService(factory, 100, 1_000);

    const result = await service.enrich(repo(root), { repo_id: "fixture", symbols: ["run"], depth: 1 });

    expect(result.status).toBe("ready");
    expect(result.graph?.definitions).toEqual([
      { name: "run", kind: "Function", path: "src/run.ts", line_start: 2, line_end: 5 }
    ]);
    expect(result.graph?.callers).toEqual([{ name: "caller", hop: 1 }]);
    expect(JSON.stringify(result)).not.toContain(root);
    expect(JSON.stringify(result)).not.toContain("/private/outside.ts");
  });

  test("does not trust a matching project name when its root differs", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-code-intelligence-"));
    const other = await mkdtemp(join(tmpdir(), "gpt-code-intelligence-other-"));
    const { factory } = fakeFactory(() => ({ projects: [{ name: "fixture", root_path: other }] }));
    const service = new CodeIntelligenceService(factory, 100, 1_000);

    expect((await service.enrich(repo(root), { repo_id: "fixture", symbols: ["run"] })).status).toBe("index_required");
  });

  test("starts one approved-root index job and deduplicates concurrent starts", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-code-intelligence-"));
    let indexed = false;
    const { factory, calls } = fakeFactory((tool) => {
      if (tool === "list_projects") return { projects: indexed ? [{ name: "fixture", root_path: root }] : [] };
      if (tool === "index_repository") {
        indexed = true;
        return { status: "indexed" };
      }
      return {};
    });
    const service = new CodeIntelligenceService(factory, 100, 1_000);

    const [first, second] = await Promise.all([
      service.index(repo(root), "start"),
      service.index(repo(root), "start")
    ]);
    expect(["queued", "running"]).toContain(first.status);
    expect(["queued", "running"]).toContain(second.status);

    await vi.waitFor(async () => {
      expect((await service.index(repo(root), "status")).status).toBe("ready");
    });
    const indexCalls = calls.filter((call) => call.tool === "index_repository");
    expect(indexCalls).toHaveLength(1);
    expect(indexCalls[0]?.args).toEqual({ repo_path: root, mode: "full", persistence: false });
  });

  test("preserves unenrolled initial status cleanup compatibility", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-code-intelligence-cleanup-compat-"));
    try {
      const cleanupError = new Error("provider cleanup failed");
      let scheduled: (() => Promise<void>) | undefined;
      const { CodebaseMemoryIndexService } = await import("../src/services/codebase-memory-index-service.js");
      const service = new CodebaseMemoryIndexService(
        async () => ({
          call: async () => ({ projects: [] }),
          close: async () => { throw cleanupError; }
        }),
        100,
        1_000,
        {
          loadBoundary: async () => undefined,
          scheduleJob: (job) => { scheduled = job; }
        }
      );

      const result = await service.index(repo(root), "start");

      expect(result.status).toBe("queued");
      expect(scheduled).toBeTypeOf("function");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("fails closed when indexing returns an unknown result status", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-code-intelligence-"));
    const { factory } = fakeFactory((tool) => tool === "list_projects" ? { projects: [] } : {});
    const service = new CodeIntelligenceService(factory, 100, 1_000);

    await service.index(repo(root), "start");

    await vi.waitFor(async () => {
      const result = await service.index(repo(root), "status");
      expect(result.status).toBe("failed");
      expect(result.warnings).toContain("CODEBASE_MEMORY_INDEX_FAILED");
    });
  });

  test("uses one deadline across sequential graph traces", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-code-intelligence-"));
    const { factory, calls } = fakeFactory(async (tool, _args, timeoutMs) => {
      if (tool === "list_projects") return { projects: [{ name: "fixture", root_path: root }] };
      if (tool === "search_graph") return { results: [] };
      const delay = Math.min(30, timeoutMs);
      await new Promise((resolve) => setTimeout(resolve, delay));
      if (timeoutMs < 30) throw new Error("provider timeout");
      return { callers: [], callees: [] };
    });
    const service = new CodeIntelligenceService(factory, 80, 1_000);

    const result = await service.enrich(repo(root), {
      repo_id: "fixture",
      symbols: ["a", "b", "c", "d", "e", "f", "g", "h"]
    });

    expect(result.status).toBe("provider_unavailable");
    expect(calls.filter((call) => call.tool === "trace_path").length).toBeLessThan(8);
  });

  test("reports provider failure without throwing from symbol enrichment", async () => {
    const factory: CodebaseMemoryClientFactory = async () => { throw new Error("missing provider"); };
    const result = await new CodeIntelligenceService(factory, 100, 1_000)
      .enrich(repo("/approved/repo"), { repo_id: "fixture", symbols: ["run"] });
    expect(result).toMatchObject({ status: "provider_unavailable", fallback_used: "native" });
    expect(result.warnings).toContain("CODEBASE_MEMORY_UNAVAILABLE");
  });

  test("propagates task boundary rejection before provider setup or native fallback", async () => {
    const boundaryError = taskExecutionError("repository_registration_changed");
    const revalidateBeforeProvider = vi.fn(async () => { throw boundaryError; });
    const factory: CodebaseMemoryClientFactory = vi.fn(async () => { throw new Error("provider must not start"); });
    const service = new CodeIntelligenceService(factory, 100, 1_000);

    await expect(service.enrich(repo("/approved/repo"), { repo_id: "fixture", symbols: ["run"] }, {
      revalidateBeforeProvider,
      bindTaskPrompt: async (prompt) => prompt
    })).rejects.toBe(boundaryError);

    expect(revalidateBeforeProvider).toHaveBeenCalledOnce();
    expect(factory).not.toHaveBeenCalled();
  });

  test("retains native fallback for provider failure after successful task boundary validation", async () => {
    const revalidateBeforeProvider = vi.fn(async () => undefined);
    const factory: CodebaseMemoryClientFactory = vi.fn(async () => { throw new Error("provider unavailable"); });
    const service = new CodeIntelligenceService(factory, 100, 1_000);

    const result = await service.enrich(repo("/approved/repo"), { repo_id: "fixture", symbols: ["run"] }, {
      revalidateBeforeProvider,
      bindTaskPrompt: async (prompt) => prompt
    });

    expect(revalidateBeforeProvider).toHaveBeenCalledOnce();
    expect(factory).toHaveBeenCalledOnce();
    expect(result).toMatchObject({ status: "provider_unavailable", fallback_used: "native" });
    expect(result.warnings).toContain("CODEBASE_MEMORY_UNAVAILABLE");
  });

  test("keeps native fallback available when a configured executable disappears", async () => {
    const service = new CodeIntelligenceService(
      createCodebaseMemoryClientFactory("/definitely/missing/codebase-memory-mcp"),
      100,
      1_000
    );
    const result = await service.enrich(repo("/approved/repo"), { repo_id: "fixture", symbols: ["run"] });
    expect(result.status).toBe("provider_unavailable");
  });

  test("accepts only a real executable file", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-code-intelligence-exec-"));
    const executable = join(root, "codebase-memory-mcp");
    await writeFile(executable, "#!/bin/sh\nexit 0\n");
    await chmod(executable, 0o755);
    await expect(validateCodebaseMemoryExecutable(executable)).resolves.toBe(await realpath(executable));
    await expect(validateCodebaseMemoryExecutable(join(root, "missing"))).rejects.toThrow();
  });

  test("loads optional provider configuration through the runtime root registry", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-code-intelligence-config-"));
    const registry = await RootRegistry.fromConfig({
      repos: [{ repo_id: "fixture", display_name: "Fixture", root }],
      limits: {},
      code_intelligence: {
        provider: "codebase_memory",
        executable: "/usr/local/bin/codebase-memory-mcp"
      }
    });
    expect(registry.codeIntelligence).toMatchObject({
      provider: "codebase_memory",
      executable: "/usr/local/bin/codebase-memory-mcp",
      query_timeout_ms: 3_000,
      index_timeout_ms: 1_800_000
    });
  });
});

function repo(root: string): RepoConfig {
  return { repo_id: "fixture", display_name: "Fixture", root } as RepoConfig;
}

function fakeFactory(
  response: (tool: string, args: Record<string, unknown>, timeoutMs: number) => Record<string, unknown> | Promise<Record<string, unknown>>
): { factory: CodebaseMemoryClientFactory; calls: Array<{ root: string; tool: string; args: Record<string, unknown>; timeoutMs: number }> } {
  const calls: Array<{ root: string; tool: string; args: Record<string, unknown>; timeoutMs: number }> = [];
  return {
    calls,
    factory: async (root) => ({
      async call(tool, args, timeoutMs) {
        calls.push({ root, tool, args, timeoutMs });
        return response(tool, args, timeoutMs);
      },
      async close() {}
    })
  };
}
