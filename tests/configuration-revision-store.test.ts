import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { expect, test } from "vitest";
import {
  ConfigurationRevisionStore,
  prepareConfigurationCandidate
} from "../src/services/configuration-revision-store.js";
import type { CodeIntelligenceService } from "../src/services/code-intelligence-service.js";

test("tracks exact accepted bytes without advancing an unchanged hot revision", async () => {
  const directory = await mkdtemp(join(tmpdir(), "configuration-revision-source-"));
  const root = join(directory, "repo");
  const configPath = join(directory, "config.json");
  try {
    await mkdir(root);
    const document = repositoryConfig(root);
    const firstBytes = Buffer.from(JSON.stringify(document));
    await writeFile(configPath, firstBytes);
    const initial = await prepareConfigurationCandidate(firstBytes, configPath);
    const store = new ConfigurationRevisionStore({ configPath, initial });
    const originalRevision = store.capture();
  expect(Object.hasOwn(originalRevision, "registry")).toBe(false);

    const formattedBytes = Buffer.from(`${JSON.stringify(document, null, 2)}\n`);
    await writeFile(configPath, formattedBytes);
    const accepted = await store.reloadFromFile();

    expect(accepted.acceptedCandidate?.sourceSha256).toBe(createHash("sha256").update(formattedBytes).digest("hex"));
    expect(accepted.acceptedCandidate?.sourceSha256).not.toBe(initial.sourceSha256);
    expect(accepted.effectiveHotRevision).toBe(originalRevision);
    expect(accepted.effectiveHotRevision.generation).toBe(originalRevision.generation);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejects invalid candidates without changing accepted or effective state", async () => {
  const directory = await mkdtemp(join(tmpdir(), "configuration-revision-rollback-"));
  const root = join(directory, "repo");
  const configPath = join(directory, "config.json");
  try {
    await mkdir(root);
    await writeFile(configPath, JSON.stringify(repositoryConfig(root)));
    const initial = await prepareConfigurationCandidate(await readFile(configPath), configPath);
    const store = new ConfigurationRevisionStore({ configPath, initial });
    const before = store.getState();

    await writeFile(configPath, "{broken json");
    await expect(store.reloadFromFile()).rejects.toThrow();
    expect(store.getState()).toBe(before);

    await writeFile(configPath, JSON.stringify({ repos: [], limits: {}, extra: true }));
    await expect(store.reloadFromFile()).rejects.toThrow("SCHEMA_INVALID");
    expect(store.getState()).toBe(before);

    await writeFile(configPath, JSON.stringify(repositoryConfig(join(directory, "missing-root"))));
    await expect(store.reloadFromFile()).rejects.toThrow("ROOT_MISSING");
    expect(store.getState()).toBe(before);

    await rm(configPath);
    await expect(store.reloadFromFile()).rejects.toThrow();
    expect(store.getState()).toBe(before);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("accepts an empty repository list and later accepts a re-added root", async () => {
  const directory = await mkdtemp(join(tmpdir(), "configuration-revision-empty-"));
  const root = join(directory, "repo");
  const configPath = join(directory, "config.json");
  try {
    await mkdir(root);
    await writeFile(configPath, JSON.stringify(repositoryConfig(root)));
    const initial = await prepareConfigurationCandidate(await readFile(configPath), configPath);
    const store = new ConfigurationRevisionStore({ configPath, initial });

    await writeFile(configPath, JSON.stringify({ repos: [], limits: {} }));
    const emptyState = await store.reloadFromFile();
  expect(emptyState.effectiveHotRevision.runtimeContext.registry.list()).toEqual([]);

    await writeFile(configPath, JSON.stringify(repositoryConfig(root)));
    const restoredState = await store.reloadFromFile();
  expect(restoredState.effectiveHotRevision.runtimeContext.registry.list()).toHaveLength(1);
  expect(restoredState.effectiveHotRevision.runtimeContext.registry.get("fixture").root).toBe(await realpath(root));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("keeps restart-only additions, removals, modifications, and reversions separate from hot state", async () => {
  const directory = await mkdtemp(join(tmpdir(), "configuration-revision-restart-"));
  const root = join(directory, "repo");
  const configPath = join(directory, "config.json");
  const startupSettings = codeIntelligenceSettings(3_000);
  const service = {} as CodeIntelligenceService;
  try {
    await mkdir(root);
    const startupDocument = repositoryConfig(root, startupSettings);
    await writeFile(configPath, JSON.stringify(startupDocument));
    const initial = await prepareConfigurationCandidate(await readFile(configPath), configPath);
    const store = new ConfigurationRevisionStore({ configPath, initial, codeIntelligence: service });
    const startupRevision = store.capture();

    await writeFile(configPath, JSON.stringify(repositoryConfig(root, codeIntelligenceSettings(5_000))));
    const modified = await store.reloadFromFile();
    expect(modified.acceptedCandidate?.restartSettings?.query_timeout_ms).toBe(5_000);
    expect(modified.pendingRestart?.initialized?.query_timeout_ms).toBe(3_000);
    expect(modified.pendingRestart?.accepted?.query_timeout_ms).toBe(5_000);
    expect(modified.effectiveHotRevision).toBe(startupRevision);
    expect(modified.effectiveHotRevision.runtimeContext.codeIntelligence).toBe(service);

    await writeFile(configPath, JSON.stringify(repositoryConfig(root, startupSettings)));
    expect((await store.reloadFromFile()).pendingRestart).toBeUndefined();

    await writeFile(configPath, JSON.stringify(repositoryConfig(root)));
    const removed = await store.reloadFromFile();
    expect(removed.pendingRestart?.initialized?.query_timeout_ms).toBe(3_000);
    expect(removed.pendingRestart?.accepted).toBeUndefined();
    expect(removed.effectiveHotRevision).toBe(startupRevision);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }

  const additionDirectory = await mkdtemp(join(tmpdir(), "configuration-revision-addition-"));
  const additionRoot = join(additionDirectory, "repo");
  const additionPath = join(additionDirectory, "config.json");
  try {
    await mkdir(additionRoot);
    await writeFile(additionPath, JSON.stringify(repositoryConfig(additionRoot)));
    const initial = await prepareConfigurationCandidate(await readFile(additionPath), additionPath);
    const store = new ConfigurationRevisionStore({ configPath: additionPath, initial });
    const originalRevision = store.capture();

    await writeFile(additionPath, JSON.stringify(repositoryConfig(additionRoot, codeIntelligenceSettings(3_000))));
    const added = await store.reloadFromFile();
    expect(added.pendingRestart?.initialized).toBeUndefined();
    expect(added.pendingRestart?.accepted?.query_timeout_ms).toBe(3_000);
    expect(added.effectiveHotRevision).toBe(originalRevision);
  } finally {
    await rm(additionDirectory, { recursive: true, force: true });
  }
});

test("commits mixed hot and restart-only changes together while retaining the startup service", async () => {
  const directory = await mkdtemp(join(tmpdir(), "configuration-revision-mixed-"));
  const oldRoot = join(directory, "old-repo");
  const newRoot = join(directory, "new-repo");
  const configPath = join(directory, "config.json");
  const service = {} as CodeIntelligenceService;
  try {
    await mkdir(oldRoot);
    await mkdir(newRoot);
    await writeFile(configPath, JSON.stringify(repositoryConfig(oldRoot, codeIntelligenceSettings(3_000))));
    const initial = await prepareConfigurationCandidate(await readFile(configPath), configPath);
    const store = new ConfigurationRevisionStore({ configPath, initial, codeIntelligence: service });
    const before = store.capture();

    await writeFile(configPath, JSON.stringify(repositoryConfig(newRoot, codeIntelligenceSettings(5_000))));
    const accepted = await store.reloadFromFile();

    expect(accepted.effectiveHotRevision).not.toBe(before);
    expect(accepted.effectiveHotRevision.generation).toBe(before.generation + 1);
  expect(accepted.effectiveHotRevision.runtimeContext.registry.get("fixture").root).toBe(await realpath(newRoot));
    expect(accepted.effectiveHotRevision.runtimeContext.codeIntelligence).toBe(service);
    expect(accepted.pendingRestart?.accepted?.query_timeout_ms).toBe(5_000);
    expect(before.runtimeContext.registry.get("fixture").root).toBe(await realpath(oldRoot));
    expect(Reflect.set(before.runtimeContext.registry.get("fixture").writes!, "enabled", false)).toBe(false);
    expect(Reflect.set(before.runtimeContext.registry.get("fixture").writes!.allowed_globs!, 0, "**")).toBe(false);
    expect(before.runtimeContext.registry.get("fixture").writes?.enabled).toBe(true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("serializes overlapping reloads before either later read or publication can overtake", async () => {
  const directory = await mkdtemp(join(tmpdir(), "configuration-revision-fifo-"));
  const rootA = join(directory, "repo-a");
  const rootB = join(directory, "repo-b");
  const configPath = join(directory, "config.json");
  try {
    await mkdir(rootA);
    await mkdir(rootB);
    const initialBytes = Buffer.from(JSON.stringify(repositoryConfig(rootA)));
    const bytesA = Buffer.from(JSON.stringify(repositoryConfig(rootA, undefined, "accepted-a")));
    const bytesB = Buffer.from(JSON.stringify(repositoryConfig(rootB, undefined, "accepted-b")));
    await writeFile(configPath, initialBytes);
    const initial = await prepareConfigurationCandidate(initialBytes, configPath);
    const firstPreparationStarted = deferred<void>();
    const releaseFirstPreparation = deferred<void>();
    let reads = 0;
    let preparations = 0;
    const store = new ConfigurationRevisionStore({
      configPath,
      initial,
      readCandidateBytes: async () => {
        reads += 1;
        return reads === 1 ? bytesA : bytesB;
      },
      prepareCandidate: async (bytes, path) => {
        if (preparations++ === 0) {
          firstPreparationStarted.resolve();
          await releaseFirstPreparation.promise;
        }
        return prepareConfigurationCandidate(bytes, path);
      }
    });
    const initialState = store.getState();

    const firstReload = store.reloadFromFile();
    await firstPreparationStarted.promise;
    const secondReload = store.reloadFromFile();
    await Promise.resolve();
    expect(reads).toBe(1);
    expect(store.getState()).toBe(initialState);

    releaseFirstPreparation.resolve();
    const firstState = await firstReload;
    expect(firstState.acceptedCandidate?.sourceSha256).toBe(createHash("sha256").update(bytesA).digest("hex"));
    const secondState = await secondReload;
    expect(secondState.acceptedCandidate?.sourceSha256).toBe(createHash("sha256").update(bytesB).digest("hex"));
    expect(secondState.effectiveHotRevision.generation).toBe(firstState.effectiveHotRevision.generation + 1);
    expect(reads).toBe(2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function repositoryConfig(root: string, codeIntelligence?: ReturnType<typeof codeIntelligenceSettings>, repoId = "fixture") {
  return {
    repos: [{ repo_id: repoId, display_name: "Fixture", root, allow_non_git: true, writes: { enabled: true, allowed_globs: ["docs/**"] } }],
    limits: { max_files: 12 },
    ...(codeIntelligence ? { code_intelligence: codeIntelligence } : {})
  };
}

function codeIntelligenceSettings(queryTimeoutMs: number) {
  return {
    provider: "codebase_memory" as const,
    executable: process.execPath,
    query_timeout_ms: queryTimeoutMs,
    index_timeout_ms: 1_800_000
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => { resolve = complete; });
  return { promise, resolve };
}
