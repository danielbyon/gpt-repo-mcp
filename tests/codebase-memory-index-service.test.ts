import { realpath } from "node:fs/promises";
import { describe, expect, test, vi } from "vitest";
import type { CodebaseMemoryClient, CodebaseMemoryClientFactory } from "../src/services/codebase-memory-client.js";
import { CodebaseMemoryIndexService } from "../src/services/codebase-memory-index-service.js";
import type { RepoConfig } from "../src/services/root-registry.js";
import { createTempDir } from "./fixtures/temp-dir.js";

function repo(root: string, repoId = "fixture"): RepoConfig {
  return { root, repo_id: repoId, display_name: "Fixture" };
}

function deferred() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { promise, release };
}

function captureJobs() {
  const jobs: Array<() => Promise<void>> = [];
  return {
    jobs,
    scheduleJob: (job: () => Promise<void>) => { jobs.push(job); }
  };
}

describe("Codebase Memory indexing", () => {
  test("deduplicates a pending root and gives each scheduled job its admitted root", async () => {
    const root = await realpath(await createTempDir("index-primary-"));
    const otherRoot = await realpath(await createTempDir("index-other-"));
    const original = repo(root);
    const alias = repo(root, "alias");
    const later = repo(otherRoot);
    const scheduler = captureJobs();
    const probeStarted = deferred();
    const releaseProbe = deferred();
    const indexing = vi.fn<(args: Record<string, unknown>) => Promise<{ status: string }>>()
      .mockResolvedValue({ status: "indexed" });
    const factory = vi.fn(async (repoRoot: string): Promise<CodebaseMemoryClient> => ({
      call: async (tool, args) => {
        if (tool === "index_repository") return indexing(args);
        if (repoRoot === root) {
          probeStarted.release();
          await releaseProbe.promise;
        }
        return { projects: [] };
      },
      close: async () => {}
    }));
    const service = new CodebaseMemoryIndexService(factory, 100, 1_000, scheduler);
    const first = service.index(original, "start");
    try {
      await probeStarted.promise;
      await expect(service.index(alias, "start")).resolves.toMatchObject({ repo_id: "alias", status: "queued" });
      await expect(service.index(alias, "status")).resolves.toMatchObject({ repo_id: "alias", status: "queued" });
      expect(factory).toHaveBeenCalledExactlyOnceWith(root);
      expect(scheduler.jobs).toHaveLength(0);

      releaseProbe.release();
      await expect(first).resolves.toMatchObject({ status: "queued" });
      await expect(service.index(later, "start")).resolves.toMatchObject({ status: "queued" });
      expect(scheduler.jobs).toHaveLength(2);
      await scheduler.jobs[0]!();
      await expect(service.index(original, "status")).resolves.toMatchObject({ status: "ready" });
      await expect(service.index(later, "status")).resolves.toMatchObject({ status: "queued" });
      await scheduler.jobs[1]!();
      await expect(service.index(later, "status")).resolves.toMatchObject({ status: "ready" });
      expect(indexing.mock.calls).toEqual([
        [{ repo_path: root, mode: "full", persistence: false }],
        [{ repo_path: otherRoot, mode: "full", persistence: false }]
      ]);
      expect(factory.mock.calls.map(([repoRoot]) => repoRoot)).toEqual([root, otherRoot, root, otherRoot]);
    } finally {
      releaseProbe.release();
      await first.catch(() => undefined);
    }
  });

  test.each([false, true])("keeps a successful initial lookup when the client closes with an error (project exists: %s)", async (exists) => {
    const root = await realpath(await createTempDir("index-probe-"));
    const scheduler = captureJobs();
    const call = vi.fn(async () => ({ projects: exists ? [{ name: "fixture", root_path: root }] : [] }));
    const close = vi.fn(async () => { throw new Error("probe close failed"); });
    const service = new CodebaseMemoryIndexService(async () => ({ call, close }), 100, 1_000, scheduler);

    await expect(service.index(repo(root), "status")).resolves.toMatchObject({ status: exists ? "ready" : "index_required" });
    expect(scheduler.jobs).toHaveLength(0);
    const result = await service.index(repo(root), "start");
    expect(result.status).toBe(exists ? "ready" : "queued");
    expect(result.started_at).toBeUndefined();
    expect(Boolean(result.finished_at)).toBe(exists);
    expect(scheduler.jobs).toHaveLength(exists ? 0 : 1);
    expect(call.mock.calls).toEqual([["list_projects", {}, 100], ["list_projects", {}, 100]]);
    expect(close).toHaveBeenCalledTimes(2);
  });

  test("status reports an unavailable probe while an explicit start still queues indexing", async () => {
    const scheduler = captureJobs();
    const close = vi.fn(async () => {});
    const call = vi.fn(async () => { throw new Error("lookup failed"); });
    const service = new CodebaseMemoryIndexService(async () => ({ call, close }), 100, 1_000, scheduler);
    const target = repo("/approved/root");

    await expect(service.index(target, "status")).resolves.toMatchObject({
      status: "provider_unavailable",
      warnings: ["CODEBASE_MEMORY_UNAVAILABLE"]
    });
    expect(scheduler.jobs).toHaveLength(0);
    await expect(service.index(target, "start")).resolves.toMatchObject({ status: "queued" });
    expect(scheduler.jobs).toHaveLength(1);
    expect(close).toHaveBeenCalledTimes(2);
  });

  test.each([
    { outcome: "indexed", closeFails: false, terminal: "ready" },
    { outcome: "degraded", closeFails: false, terminal: "degraded" },
    { outcome: "unknown", closeFails: false, terminal: "failed" },
    { outcome: "throw", closeFails: false, terminal: "failed" },
    { outcome: "indexed", closeFails: true, terminal: "failed" }
  ])("publishes $terminal after close (provider: $outcome, close fails: $closeFails)", async ({ outcome, closeFails, terminal }) => {
    const scheduler = captureJobs();
    const closeStarted = deferred();
    const releaseClose = deferred();
    const closeIndex = vi.fn(async () => {
      closeStarted.release();
      await releaseClose.promise;
      if (closeFails) throw new Error("index close failed");
    });
    const indexCall = vi.fn(async () => {
      if (outcome === "throw") throw new Error("index request failed");
      return { status: outcome };
    });
    const factory = vi.fn<CodebaseMemoryClientFactory>()
      .mockResolvedValueOnce({ call: async () => ({ projects: [] }), close: async () => {} })
      .mockResolvedValueOnce({ call: indexCall, close: closeIndex });
    const service = new CodebaseMemoryIndexService(factory, 100, 1_000, scheduler);
    const target = repo("/approved/root");
    let run: Promise<void> | undefined;
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const queuedAt = "2026-01-01T00:00:00.000Z";
      const startedAt = "2026-01-01T00:00:01.000Z";
      const finishedAt = "2026-01-01T00:00:02.000Z";
      vi.setSystemTime(new Date(queuedAt));
      const queued = await service.index(target, "start");
      expect(queued.status).toBe("queued");
      expect(queued.started_at).toBeUndefined();
      expect(queued.finished_at).toBeUndefined();

      vi.setSystemTime(new Date(startedAt));
      run = scheduler.jobs[0]!();
      await closeStarted.promise;
      const running = await service.index(target, "status");
      expect(running).toMatchObject({ status: "running", started_at: startedAt, warnings: [] });
      expect(running.finished_at).toBeUndefined();
      await expect(service.index(target, "start")).resolves.toMatchObject({ status: "running" });
      expect(scheduler.jobs).toHaveLength(1);

      vi.setSystemTime(new Date(finishedAt));
      releaseClose.release();
      await run;
      const completed = await service.index(target, "status");
      expect(completed).toMatchObject({
        status: terminal,
        started_at: startedAt,
        finished_at: finishedAt,
        events: [
          { status: "queued", at: queuedAt },
          { status: "running", at: startedAt },
          { status: terminal, at: finishedAt }
        ],
        warnings: terminal === "failed" ? ["CODEBASE_MEMORY_INDEX_FAILED"] : []
      });
      expect(indexCall).toHaveBeenCalledExactlyOnceWith(
        "index_repository", { repo_path: target.root, mode: "full", persistence: false }, 1_000
      );
      expect(closeIndex).toHaveBeenCalledTimes(1);
    } finally {
      releaseClose.release();
      await run;
      vi.useRealTimers();
    }
  });
});
