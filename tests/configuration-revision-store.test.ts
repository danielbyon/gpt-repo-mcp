import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { expect, test } from "vitest";
import { createConfigurationSourceIdentity } from "../src/config/config-source-identity.js";
import { createConfigurationAdminController } from "../src/runtime/configuration-admin-controller.js";
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
    expect(store.getState().lastReloadOutcome).toBe("not-run");
  expect(Object.hasOwn(originalRevision, "registry")).toBe(false);

    const formattedBytes = Buffer.from(`${JSON.stringify(document, null, 2)}\n`);
    await writeFile(configPath, formattedBytes);
    const accepted = await store.reloadFromFile();

    expect(accepted.lastReloadOutcome).toBe("accepted");
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
    expect(store.getState()).toMatchObject({ lastReloadOutcome: "rejected" });
    expect(store.getState().acceptedCandidate).toBe(before.acceptedCandidate);
    expect(store.getState().effectiveHotRevision).toBe(before.effectiveHotRevision);

    await writeFile(configPath, JSON.stringify({ repos: [], limits: {}, extra: true }));
    await expect(store.reloadFromFile()).rejects.toThrow("SCHEMA_INVALID");
    expect(store.getState()).toMatchObject({ lastReloadOutcome: "rejected" });
    expect(store.getState().acceptedCandidate).toBe(before.acceptedCandidate);
    expect(store.getState().effectiveHotRevision).toBe(before.effectiveHotRevision);

    await writeFile(configPath, JSON.stringify(repositoryConfig(join(directory, "missing-root"))));
    await expect(store.reloadFromFile()).rejects.toThrow("ROOT_MISSING");
    expect(store.getState()).toMatchObject({ lastReloadOutcome: "rejected" });
    expect(store.getState().acceptedCandidate).toBe(before.acceptedCandidate);
    expect(store.getState().effectiveHotRevision).toBe(before.effectiveHotRevision);

    await rm(configPath);
    await expect(store.reloadFromFile()).rejects.toThrow();
    expect(store.getState()).toMatchObject({ lastReloadOutcome: "rejected" });
    expect(store.getState().acceptedCandidate).toBe(before.acceptedCandidate);
    expect(store.getState().effectiveHotRevision).toBe(before.effectiveHotRevision);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("observes saved source failures with safe categories and raw-byte fingerprints", async () => {
  const directory = await mkdtemp(join(tmpdir(), "configuration-status-observation-"));
  const root = join(directory, "repo");
  const configPath = join(directory, "config.json");
  try {
    await mkdir(root);
    const initialBytes = Buffer.from(JSON.stringify(repositoryConfig(root)));
    await writeFile(configPath, initialBytes);
    const initial = await prepareConfigurationCandidate(initialBytes, configPath);
    const store = new ConfigurationRevisionStore({ configPath, initial });

    const matching = await store.captureStatus();
    expect(matching.savedSource).toMatchObject({
      status: "valid",
      sourceSha256: createHash("sha256").update(initialBytes).digest("hex"),
      matchesAccepted: true,
      repositoryCount: 1
    });
    expect(matching.state.lastReloadOutcome).toBe("not-run");

    const malformedBytes = Buffer.from("{broken json");
    await writeFile(configPath, malformedBytes);
    const malformed = await store.captureStatus();
    expect(malformed.savedSource).toEqual({
      status: "invalid-json",
      sourceSha256: createHash("sha256").update(malformedBytes).digest("hex")
    });

    const invalidConfigurationBytes = Buffer.from(JSON.stringify({ repos: [], extra: true }));
    await writeFile(configPath, invalidConfigurationBytes);
    const invalidConfiguration = await store.captureStatus();
    expect(invalidConfiguration.savedSource).toMatchObject({
      status: "validation-failed",
      category: "configuration",
      sourceSha256: createHash("sha256").update(invalidConfigurationBytes).digest("hex"),
      issueCodes: ["SCHEMA_INVALID"]
    });

    const missingRepositoryBytes = Buffer.from(JSON.stringify(repositoryConfig(join(directory, "missing-repo"))));
    await writeFile(configPath, missingRepositoryBytes);
    const invalidRepository = await store.captureStatus();
    expect(invalidRepository.savedSource).toMatchObject({
      status: "validation-failed",
      category: "repository-filesystem",
      sourceSha256: createHash("sha256").update(missingRepositoryBytes).digest("hex"),
      issueCodes: ["ROOT_MISSING"]
    });

    await rm(configPath);
    const missingFile = await store.captureStatus();
    expect(missingFile.savedSource).toEqual({ status: "read-failed", code: "FILE_NOT_FOUND" });
    expect(missingFile.state.acceptedCandidate.sourceSha256).toBe(initial.sourceSha256);
    expect(missingFile.state.effectiveHotRevision.generation).toBe(1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("captures runtime state before a concurrent reload without joining its queue", async () => {
  const directory = await mkdtemp(join(tmpdir(), "configuration-status-concurrency-"));
  const rootA = join(directory, "repo-a");
  const rootB = join(directory, "repo-b");
  const configPath = join(directory, "config.json");
  try {
    await mkdir(rootA);
    await mkdir(rootB);
    const initialBytes = Buffer.from(JSON.stringify(repositoryConfig(rootA)));
    const nextBytes = Buffer.from(JSON.stringify(repositoryConfig(rootB)));
    await writeFile(configPath, initialBytes);
    const initial = await prepareConfigurationCandidate(initialBytes, configPath);
    const statusReadStarted = deferred<void>();
    const releaseStatusRead = deferred<void>();
    let reads = 0;
    const store = new ConfigurationRevisionStore({
      configPath,
      initial,
      readCandidateBytes: async () => {
        reads += 1;
        if (reads === 1) {
          statusReadStarted.resolve();
          await releaseStatusRead.promise;
          return nextBytes;
        }
        return nextBytes;
      }
    });

    const statusPromise = store.captureStatus();
    await statusReadStarted.promise;
    const reloadPromise = store.reloadFromFile();
    const reloaded = await reloadPromise;
    expect(reloaded.lastReloadOutcome).toBe("accepted");
    expect(reloaded.effectiveHotRevision.generation).toBe(2);

    releaseStatusRead.resolve();
    const observed = await statusPromise;
    expect(observed.state.effectiveHotRevision.generation).toBe(1);
    expect(observed.state.acceptedCandidate.sourceSha256).toBe(initial.sourceSha256);
    expect(observed.savedSource).toMatchObject({
      status: "valid",
      sourceSha256: createHash("sha256").update(nextBytes).digest("hex"),
      matchesAccepted: false
    });
    expect(reads).toBe(2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("reports intentional no-source mode without reading a file", async () => {
  const directory = await mkdtemp(join(tmpdir(), "configuration-status-no-source-"));
  const root = join(directory, "repo");
  try {
    await mkdir(root);
    const initialBytes = Buffer.from(JSON.stringify(repositoryConfig(root)));
    const initial = await prepareConfigurationCandidate(initialBytes, join(directory, "unused.json"));
    const readCandidateBytes = async () => {
      throw new Error("no-source status must not read a configuration file");
    };
    const store = new ConfigurationRevisionStore({ initial, readCandidateBytes });

    const observed = await store.captureStatus();

    expect(observed.savedSource).toEqual({ status: "no-source" });
    expect(observed.state.lastReloadOutcome).toBe("not-run");
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
    const instanceId = "88888888-8888-4888-8888-888888888888";
    const sourceIdentity = createConfigurationSourceIdentity(configPath, process.cwd());
    const controller = createConfigurationAdminController({
      serverPid: process.pid,
      instanceId,
      sourceIdentity,
      revisionStore: store
    });
    let statusRequestId = "";
    const status = () => {
      statusRequestId = randomUUID();
      return controller.handle({
        protocol_version: 1,
        request_id: statusRequestId,
        operation: "status",
        expected_server_pid: process.pid,
        expected_instance_id: instanceId,
        expected_source_identity: sourceIdentity
      });
    };
    const restartFields = ["executable", "index_timeout_ms", "provider", "query_timeout_ms"];
    const expectedStatus = (options: {
      fingerprint: string;
      acceptedFields?: string[];
      initializedFields: string[];
      pendingFields: string[];
    }) => ({
      protocol_version: 1,
      request_id: statusRequestId,
      server_pid: process.pid,
      instance_id: instanceId,
      source_identity: sourceIdentity,
      operation: "status_result",
      accepted_candidate: {
        source_status: "available",
        source_sha256: options.fingerprint,
        repository_count: 1,
        restart_fields: options.acceptedFields ?? restartFields
      },
      saved_source: {
        status: "valid",
        source_sha256: options.fingerprint,
        matches_accepted: true,
        repository_count: 1,
        restart_fields: options.acceptedFields ?? restartFields
      },
      active_hot_revision: { generation: startupRevision.generation, repository_count: 1 },
      initialized_restart_fields: options.initializedFields,
      pending_restart_fields: options.pendingFields,
      last_reload_outcome: "accepted"
    });

    const modifiedBytes = Buffer.from(JSON.stringify(repositoryConfig(root, codeIntelligenceSettings(5_000))));
    await writeFile(configPath, modifiedBytes);
    const modified = await store.reloadFromFile();
    expect(modified.acceptedCandidate?.restartSettings?.query_timeout_ms).toBe(5_000);
    expect(modified.pendingRestart?.initialized?.query_timeout_ms).toBe(3_000);
    expect(modified.pendingRestart?.accepted?.query_timeout_ms).toBe(5_000);
    expect(modified.effectiveHotRevision).toBe(startupRevision);
    expect(modified.effectiveHotRevision.runtimeContext.codeIntelligence).toBe(service);
    const modifiedStatus = await status();
    expect(modifiedStatus).toStrictEqual(expectedStatus({
      fingerprint: createHash("sha256").update(modifiedBytes).digest("hex"),
      initializedFields: restartFields,
      pendingFields: ["query_timeout_ms"]
    }));

    const restoredBytes = Buffer.from(JSON.stringify(repositoryConfig(root, startupSettings)));
    await writeFile(configPath, restoredBytes);
    expect((await store.reloadFromFile()).pendingRestart).toBeUndefined();
    const restoredStatus = await status();
    expect(restoredStatus).toStrictEqual(expectedStatus({
      fingerprint: createHash("sha256").update(restoredBytes).digest("hex"),
      initializedFields: restartFields,
      pendingFields: []
    }));

    const removedBytes = Buffer.from(JSON.stringify(repositoryConfig(root)));
    await writeFile(configPath, removedBytes);
    const removed = await store.reloadFromFile();
    expect(removed.pendingRestart?.initialized?.query_timeout_ms).toBe(3_000);
    expect(removed.pendingRestart?.accepted).toBeUndefined();
    expect(removed.effectiveHotRevision).toBe(startupRevision);
    const removedStatus = await status();
    expect(removedStatus).toStrictEqual(expectedStatus({
      fingerprint: createHash("sha256").update(removedBytes).digest("hex"),
      acceptedFields: [],
      initializedFields: restartFields,
      pendingFields: restartFields
    }));
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
    const originalFingerprint = store.getState().acceptedCandidate.sourceSha256;
    const instanceId = "99999999-9999-4999-8999-999999999999";
    const sourceIdentity = createConfigurationSourceIdentity(additionPath, process.cwd());
    const controller = createConfigurationAdminController({
      serverPid: process.pid,
      instanceId,
      sourceIdentity,
      revisionStore: store
    });

    const addedCandidate = configurationWithFingerprintFragment((attempt) => repositoryConfig(
      additionRoot,
      {
        ...codeIntelligenceSettings(3_000),
        executable: join(additionDirectory, `private-code-indexer-${attempt}`)
      }
    ), "3000");
    expect(addedCandidate.fingerprint).toContain("3000");
    await writeFile(additionPath, addedCandidate.bytes);
    const added = await store.reloadFromFile();
    expect(added.pendingRestart?.initialized).toBeUndefined();
    expect(added.pendingRestart?.accepted?.query_timeout_ms).toBe(3_000);
    expect(added.effectiveHotRevision).toBe(originalRevision);
    const addedBytes = await readFile(additionPath);
    const addedFingerprint = createHash("sha256").update(addedBytes).digest("hex");
    expect(addedFingerprint).toBe(addedCandidate.fingerprint);
    expect(addedFingerprint).not.toBe(originalFingerprint);
    const addedRequestId = randomUUID();
    const addedStatus = await controller.handle({
      protocol_version: 1,
      request_id: addedRequestId,
      operation: "status",
      expected_server_pid: process.pid,
      expected_instance_id: instanceId,
      expected_source_identity: sourceIdentity
    });
    expect(addedStatus).toStrictEqual({
      protocol_version: 1,
      request_id: addedRequestId,
      server_pid: process.pid,
      instance_id: instanceId,
      source_identity: sourceIdentity,
      operation: "status_result",
      accepted_candidate: {
        source_status: "available",
        source_sha256: addedFingerprint,
        repository_count: 1,
        restart_fields: ["executable", "index_timeout_ms", "provider", "query_timeout_ms"]
      },
      saved_source: {
        status: "valid",
        source_sha256: addedFingerprint,
        matches_accepted: true,
        repository_count: 1,
        restart_fields: ["executable", "index_timeout_ms", "provider", "query_timeout_ms"]
      },
      active_hot_revision: { generation: originalRevision.generation, repository_count: 1 },
      initialized_restart_fields: [],
      pending_restart_fields: ["executable", "index_timeout_ms", "provider", "query_timeout_ms"],
      last_reload_outcome: "accepted"
    });
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
    expect(store.capture()).toBe(initialState.effectiveHotRevision);
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

test("records a failed reload before publishing the next queued reload outcome", async () => {
  const directory = await mkdtemp(join(tmpdir(), "configuration-revision-rejected-fifo-"));
  const root = join(directory, "repo");
  const configPath = join(directory, "config.json");
  const initialBytes = Buffer.from(JSON.stringify(repositoryConfig(root)));
  const rejectedBytes = Buffer.from("invalid candidate");
  const acceptedBytes = Buffer.from(JSON.stringify(repositoryConfig(root, undefined, "accepted-after-rejection")));
  const firstPreparationStarted = deferred<void>();
  const releaseFirstPreparation = deferred<void>();
  let reads = 0;

  try {
    await mkdir(root);
    await writeFile(configPath, initialBytes);
    const initial = await prepareConfigurationCandidate(initialBytes, configPath);
    const store = new ConfigurationRevisionStore({
      configPath,
      initial,
      readCandidateBytes: async () => reads++ === 0 ? rejectedBytes : acceptedBytes,
      prepareCandidate: async (bytes, path) => {
        if (Buffer.from(bytes).equals(rejectedBytes)) {
          firstPreparationStarted.resolve();
          await releaseFirstPreparation.promise;
          throw new Error("The first queued candidate is rejected.");
        }
        return prepareConfigurationCandidate(bytes, path);
      }
    });

    const rejectedReload = store.reloadFromFile();
    await firstPreparationStarted.promise;
    const acceptedReload = store.reloadFromFile();
    releaseFirstPreparation.resolve();

    await expect(rejectedReload).rejects.toThrow("The first queued candidate is rejected.");
    const acceptedState = await acceptedReload;
    expect(acceptedState.lastReloadOutcome).toBe("accepted");
    expect(acceptedState.acceptedCandidate.sourceSha256).toBe(createHash("sha256").update(acceptedBytes).digest("hex"));
    expect(store.getState()).toBe(acceptedState);
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

function configurationWithFingerprintFragment(
  createDocument: (attempt: number) => unknown,
  fragment: string
): { bytes: Buffer; fingerprint: string } {
  for (let attempt = 0; attempt < 100_000; attempt += 1) {
    const bytes = Buffer.from(JSON.stringify(createDocument(attempt)));
    const fingerprint = createHash("sha256").update(bytes).digest("hex");
    if (fingerprint.includes(fragment)) return { bytes, fingerprint };
  }
  throw new Error(`No configuration fingerprint contained ${fragment} after 100000 candidates.`);
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => { resolve = complete; });
  return { promise, resolve };
}
