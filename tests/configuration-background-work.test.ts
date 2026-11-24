import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import type { CodebaseMemoryClientFactory } from "../src/services/codebase-memory-client.js";
import { CodebaseMemoryIndexService } from "../src/services/codebase-memory-index-service.js";
import { ConfigurationRevisionStore, prepareConfigurationCandidate } from "../src/services/configuration-revision-store.js";

test("keeps queued and running indexing on each root captured at start", async () => {
  const directory = await mkdtemp(join(tmpdir(), "configuration-background-"));
  const previousRoot = join(directory, "previous-root");
  const activeRoot = join(directory, "active-root");
  const configPath = join(directory, "config.json");
  const jobs: Array<() => Promise<void>> = [];
  const indexedRoots: string[] = [];
  const runningJobs: Promise<void>[] = [];
  let previousRootPath = "";
  let activeRootPath = "";
  let pauseNextPreviousIndex = false;
  let pauseNextActiveIndex = false;
  let signalPreviousIndexStarted!: () => void;
  const previousIndexStarted = new Promise<void>((resolve) => { signalPreviousIndexStarted = resolve; });
  let releasePreviousIndex!: () => void;
  const previousIndexRelease = new Promise<void>((resolve) => { releasePreviousIndex = resolve; });
  let signalActiveIndexStarted!: () => void;
  const activeIndexStarted = new Promise<void>((resolve) => { signalActiveIndexStarted = resolve; });
  const clientFactory: CodebaseMemoryClientFactory = async () => ({
    async call(tool, args) {
      if (tool === "list_projects") return { projects: [] };
      if (tool === "index_repository") {
        const repoPath = String(args.repo_path);
        indexedRoots.push(repoPath);
        if (pauseNextPreviousIndex && repoPath === previousRootPath) {
          pauseNextPreviousIndex = false;
          signalPreviousIndexStarted();
          await previousIndexRelease;
        }
        if (pauseNextActiveIndex && repoPath === activeRootPath) {
          pauseNextActiveIndex = false;
          signalActiveIndexStarted();
        }
        return { status: "indexed" };
      }
      throw new Error(`Unexpected provider call: ${tool}`);
    },
    async close() {}
  });

  try {
    await Promise.all([mkdir(previousRoot), mkdir(activeRoot)]);
    previousRootPath = await realpath(previousRoot);
    activeRootPath = await realpath(activeRoot);
    await writeFile(configPath, JSON.stringify(config(previousRoot)));
    const initial = await prepareConfigurationCandidate(await readFile(configPath), configPath);
    const store = new ConfigurationRevisionStore({ configPath, initial });
    const indexer = new CodebaseMemoryIndexService(clientFactory, 100, 1_000, {
      scheduleJob: (job) => { jobs.push(job); }
    });
    const admittedRevision = store.capture();

    const previousRepo = admittedRevision.runtimeContext.registry.get("fixture");
    await expect(indexer.index(previousRepo, "start"))
      .resolves.toMatchObject({ status: "queued" });
    expect(jobs).toHaveLength(1);

    await writeFile(configPath, JSON.stringify(config(activeRoot)));
    const activated = await store.reloadFromFile();
    const activeRepo = activated.effectiveHotRevision.runtimeContext.registry.get("fixture");
    await expect(indexer.index(activeRepo, "start"))
      .resolves.toMatchObject({ status: "queued" });
    expect(jobs).toHaveLength(2);

    await jobs[0]!();
    await jobs[1]!();

    expect(indexedRoots).toEqual([await realpath(previousRoot), await realpath(activeRoot)]);
    await expect(indexer.index(previousRepo, "status")).resolves.toMatchObject({ status: "ready" });
    await expect(indexer.index(activeRepo, "status")).resolves.toMatchObject({ status: "ready" });

    await writeFile(configPath, JSON.stringify(config(previousRoot)));
    const previousRootReactivated = await store.reloadFromFile();
    const runningPreviousRepo = previousRootReactivated.effectiveHotRevision.runtimeContext.registry.get("fixture");
    await expect(indexer.index(runningPreviousRepo, "start")).resolves.toMatchObject({ status: "queued" });
    expect(jobs).toHaveLength(3);

    pauseNextPreviousIndex = true;
    const runningPreviousJob = jobs[2]!();
    runningJobs.push(runningPreviousJob);
    await previousIndexStarted;
    expect(indexedRoots[indexedRoots.length - 1]).toBe(runningPreviousRepo.root);

    await writeFile(configPath, JSON.stringify(config(activeRoot)));
    const activeRootReactivated = await store.reloadFromFile();
    const runningActiveRepo = activeRootReactivated.effectiveHotRevision.runtimeContext.registry.get("fixture");
    await expect(indexer.index(runningActiveRepo, "start")).resolves.toMatchObject({ status: "queued" });
    expect(jobs).toHaveLength(4);

    pauseNextActiveIndex = true;
    const runningActiveJob = jobs[3]!();
    runningJobs.push(runningActiveJob);
    await activeIndexStarted;
    expect(indexedRoots.slice(-2)).toEqual([runningPreviousRepo.root, runningActiveRepo.root]);

    releasePreviousIndex();
    await Promise.all([runningPreviousJob, runningActiveJob]);
    await expect(indexer.index(runningPreviousRepo, "status")).resolves.toMatchObject({ status: "ready" });
    await expect(indexer.index(runningActiveRepo, "status")).resolves.toMatchObject({ status: "ready" });
  } finally {
    releasePreviousIndex();
    await Promise.allSettled(runningJobs);
    await rm(directory, { recursive: true, force: true });
  }
});

function config(root: string) {
  return {
    repos: [{ repo_id: "fixture", display_name: "Fixture", root, allow_non_git: true }],
    limits: {}
  };
}
