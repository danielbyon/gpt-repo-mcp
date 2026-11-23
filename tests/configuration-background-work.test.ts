import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import type { CodebaseMemoryClientFactory } from "../src/services/codebase-memory-client.js";
import { CodebaseMemoryIndexService } from "../src/services/codebase-memory-index-service.js";
import { ConfigurationRevisionStore, prepareConfigurationCandidate } from "../src/services/configuration-revision-store.js";

test("finishes accepted indexing on its captured root while later starts use the active root", async () => {
  const directory = await mkdtemp(join(tmpdir(), "configuration-background-"));
  const previousRoot = join(directory, "previous-root");
  const activeRoot = join(directory, "active-root");
  const configPath = join(directory, "config.json");
  const jobs: Array<() => Promise<void>> = [];
  const indexedRoots: string[] = [];
  const clientFactory: CodebaseMemoryClientFactory = async () => ({
    async call(tool, args) {
      if (tool === "list_projects") return { projects: [] };
      if (tool === "index_repository") {
        indexedRoots.push(String(args.repo_path));
        return { status: "indexed" };
      }
      throw new Error(`Unexpected provider call: ${tool}`);
    },
    async close() {}
  });

  try {
    await Promise.all([mkdir(previousRoot), mkdir(activeRoot)]);
    await writeFile(configPath, JSON.stringify(config(previousRoot)));
    const initial = await prepareConfigurationCandidate(await readFile(configPath), configPath);
    const store = new ConfigurationRevisionStore({ configPath, initial });
    const indexer = new CodebaseMemoryIndexService(clientFactory, 100, 1_000, {
      scheduleJob: (job) => { jobs.push(job); }
    });
    const admittedRevision = store.capture();

    await expect(indexer.index(admittedRevision.runtimeContext.registry.get("fixture"), "start"))
      .resolves.toMatchObject({ status: "queued" });
    expect(jobs).toHaveLength(1);

    await writeFile(configPath, JSON.stringify(config(activeRoot)));
    const activated = await store.reloadFromFile();
    await expect(indexer.index(activated.effectiveHotRevision.runtimeContext.registry.get("fixture"), "start"))
      .resolves.toMatchObject({ status: "queued" });
    expect(jobs).toHaveLength(2);

    await jobs[0]!();
    await jobs[1]!();

    expect(indexedRoots).toEqual([await realpath(previousRoot), await realpath(activeRoot)]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function config(root: string) {
  return {
    repos: [{ repo_id: "fixture", display_name: "Fixture", root, allow_non_git: true }],
    limits: {}
  };
}
