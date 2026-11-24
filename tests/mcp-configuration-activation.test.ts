import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { access, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { expect, test, vi } from "vitest";
import { createMcpHttpApp } from "../src/runtime/mcp-http-app.js";
import { ConfigurationRevisionStore, prepareConfigurationCandidate } from "../src/services/configuration-revision-store.js";
import type { EffectiveHotRevision } from "../src/services/configuration-revision-store.js";

const { requireAdmittedRuntimeContextSpy } = vi.hoisted(() => ({
  requireAdmittedRuntimeContextSpy: vi.fn()
}));

vi.mock("../src/runtime/admitted-runtime-context.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/runtime/admitted-runtime-context.js")>();
  requireAdmittedRuntimeContextSpy.mockImplementation(actual.requireAdmittedRuntimeContext);
  return { ...actual, requireAdmittedRuntimeContext: requireAdmittedRuntimeContextSpy };
});

test("keeps one HTTP session while connection setup skips context lookup and requests use admitted revisions", async () => {
  const fixture = await createFixture();
  const heldAdmission = deferred<EffectiveHotRevision>();
  const releaseHeldAdmission = deferred<void>();
  const heldWriteAdmission = deferred<EffectiveHotRevision>();
  const releaseHeldWrite = deferred<void>();
  let holdNextOldRootRead = true;
  let holdNextAddedRootWrite = false;

  const initialRevision = fixture.store.capture();
  const httpApp = createMcpHttpApp({
    revisionStore: fixture.store,
    maxSessions: 8,
    sessionIdleTtlMs: 60_000,
    afterAdmission: async (revision, request) => {
      const body = request.body as {
        method?: string;
        params?: { name?: string; arguments?: { path?: string } };
      };
      if (holdNextOldRootRead && body.method === "tools/call" &&
          body.params?.name === "repo_fetch_file" && body.params.arguments?.path === "marker.txt") {
        holdNextOldRootRead = false;
        heldAdmission.resolve(revision);
        await releaseHeldAdmission.promise;
      }
      if (holdNextAddedRootWrite && body.method === "tools/call" &&
          body.params?.name === "repo_write_file" && body.params.arguments?.path === "written.txt") {
        holdNextAddedRootWrite = false;
        heldWriteAdmission.resolve(revision);
        await releaseHeldWrite.promise;
      }
    }
  });
  const server = createServer(httpApp.app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${address.port}/mcp`));
  const client = new Client({ name: "configuration-revision-test", version: "1" });

  try {
    await client.connect(transport);
    expect(requireAdmittedRuntimeContextSpy).not.toHaveBeenCalled();
    const toolsBefore = (await client.listTools()).tools;
    expect(requireAdmittedRuntimeContextSpy).not.toHaveBeenCalled();
    const activateCandidate = async (repos: ReturnType<typeof repository>[]) => {
      await fixture.writeCandidate(repos);
      await httpApp.reloadConfiguration();
    };

    const oldRootRead = callRawTool(client, "repo_fetch_file", { repo_id: "fixture", path: "marker.txt" });
    const admittedA = await heldAdmission.promise;
    expect(admittedA).toBe(initialRevision);

    await activateCandidate([repository("fixture", fixture.newRoot, false)]);
    const admittedBResult = await callRawTool(client, "repo_fetch_file", { repo_id: "fixture", path: "marker.txt" });
    expect(JSON.stringify(admittedBResult)).toContain("marker from new root");
    expect(fixture.store.capture().generation).toBe(initialRevision.generation + 1);

    releaseHeldAdmission.resolve();
    const admittedAResult = await oldRootRead;
    expect(JSON.stringify(admittedAResult)).toContain("marker from old root");
    expect(requireAdmittedRuntimeContextSpy).toHaveBeenCalled();

    const rootsAfterRebind = await callRawTool(client, "repo_list_roots", {});
    const listedRoots = rootsAfterRebind.structuredContent as { repos: Array<{ root: string }> };
    const rootPaths = listedRoots.repos.map(({ root }) => root);
    expect(rootPaths).toContain(await realpath(fixture.newRoot));
    expect(rootPaths).not.toContain(await realpath(fixture.oldRoot));

    const historicalArtifact = join(fixture.newRoot, ".chatgpt", "runs", "past", "prompt.md");
    await expect(access(historicalArtifact)).rejects.toMatchObject({ code: "ENOENT" });
    const historicalRead = await callRawTool(client, "repo_fetch_file", {
      repo_id: "fixture", path: ".chatgpt/runs/past/prompt.md"
    });
    expect(historicalRead.isError).toBe(true);

    await activateCandidate([]);
    const removedRootRead = await callRawTool(client, "repo_fetch_file", {
      repo_id: "fixture", path: "marker.txt"
    });
    expect(removedRootRead.isError).toBe(true);

    await activateCandidate([repository("added", fixture.addedRoot, false)]);
    const addedRoots = await callRawTool(client, "repo_list_roots", {});
    expect(JSON.stringify(addedRoots)).toContain("added");
    const deniedWrite = await callRawTool(client, "repo_write_file", {
      repo_id: "added", path: "written.txt", content: "denied"
    });
    expect(deniedWrite.isError).toBe(true);
    await expect(readFile(join(fixture.addedRoot, "written.txt"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });

    await activateCandidate([repository("added", fixture.addedRoot, true)]);
    holdNextAddedRootWrite = true;
    const admittedWrite = callRawTool(client, "repo_write_file", {
      repo_id: "added", path: "written.txt", content: "allowed"
    });
    const admittedWriteRevision = await heldWriteAdmission.promise;
    expect(admittedWriteRevision).toBe(fixture.store.capture());

    await activateCandidate([repository("added", fixture.addedRoot, false)]);
    const deniedAfterWriteDowngrade = await callRawTool(client, "repo_write_file", {
      repo_id: "added", path: "written.txt", content: "denied after downgrade"
    });
    expect(deniedAfterWriteDowngrade.structuredContent).toMatchObject({
      ok: false,
      error: { code: "WRITE_DISABLED" }
    });

    releaseHeldWrite.resolve();
    const admittedWriteResult = await admittedWrite;
    expect(admittedWriteResult.isError).not.toBe(true);
    expect(await readFile(join(fixture.addedRoot, "written.txt"), "utf8")).toBe("allowed");

    const cleanupRelativePath = ".chatgpt/tool-tests/preserved.txt";
    const cleanupFilePath = join(fixture.addedRoot, cleanupRelativePath);
    await mkdir(join(fixture.addedRoot, ".chatgpt", "tool-tests"), { recursive: true });
    await writeFile(cleanupFilePath, "keep this fixture intact");
    const cleanupBaselineRepo = fixture.store.capture().runtimeContext.registry.get("added");
    const cleanupScope = {
      root: cleanupBaselineRepo.root,
      writes: cleanupBaselineRepo.writes,
      operationsEnabled: cleanupBaselineRepo.operations?.enabled,
      cleanupAllowedGlobs: cleanupBaselineRepo.operations?.cleanup_allowed_globs
    };
    const cleanupDryRun = () => callRawTool(client, "repo_cleanup_paths", {
      repo_id: "added", paths: [cleanupRelativePath], dry_run: true
    });

    const initialCleanupDryRun = await cleanupDryRun();
    expect(initialCleanupDryRun.structuredContent).toMatchObject({
      ok: true,
      dry_run: true,
      deleted: [{ path: cleanupRelativePath }]
    });
    expect(await readFile(cleanupFilePath, "utf8")).toBe("keep this fixture intact");

    await activateCandidate([repository("added", fixture.addedRoot, false, false)]);
    const cleanupDisabledRepo = fixture.store.capture().runtimeContext.registry.get("added");
    expect(cleanupDisabledRepo.root).toBe(cleanupScope.root);
    expect(cleanupDisabledRepo.writes).toEqual(cleanupScope.writes);
    expect(cleanupDisabledRepo.operations?.enabled).toBe(cleanupScope.operationsEnabled);
    expect(cleanupDisabledRepo.operations?.cleanup_enabled).toBe(false);
    expect(cleanupDisabledRepo.operations?.cleanup_allowed_globs).toEqual(cleanupScope.cleanupAllowedGlobs);
    const disabledCleanup = await cleanupDryRun();
    expect(disabledCleanup.structuredContent).toMatchObject({
      ok: false,
      error: { code: "CLEANUP_DISABLED" }
    });
    expect(await readFile(cleanupFilePath, "utf8")).toBe("keep this fixture intact");

    await activateCandidate([repository("added", fixture.addedRoot, false, true)]);
    const cleanupUpgradedRepo = fixture.store.capture().runtimeContext.registry.get("added");
    expect(cleanupUpgradedRepo.root).toBe(cleanupScope.root);
    expect(cleanupUpgradedRepo.writes).toEqual(cleanupScope.writes);
    expect(cleanupUpgradedRepo.operations?.enabled).toBe(cleanupScope.operationsEnabled);
    expect(cleanupUpgradedRepo.operations?.cleanup_enabled).toBe(true);
    expect(cleanupUpgradedRepo.operations?.cleanup_allowed_globs).toEqual(cleanupScope.cleanupAllowedGlobs);
    const upgradedCleanupDryRun = await cleanupDryRun();
    expect(upgradedCleanupDryRun.structuredContent).toMatchObject({
      ok: true,
      dry_run: true,
      deleted: [{ path: cleanupRelativePath }]
    });
    expect(await readFile(cleanupFilePath, "utf8")).toBe("keep this fixture intact");

    expect((await client.listTools()).tools).toEqual(toolsBefore);
  } finally {
    releaseHeldAdmission.resolve();
    releaseHeldWrite.resolve();
    await client.close().catch(() => undefined);
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await httpApp.dispose();
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

async function createFixture() {
  const directory = await mkdtemp(join(tmpdir(), "mcp-config-activation-"));
  const oldRoot = join(directory, "old-root");
  const newRoot = join(directory, "new-root");
  const addedRoot = join(directory, "added-root");
  const configPath = join(directory, "config.json");
  await Promise.all([mkdir(oldRoot), mkdir(newRoot), mkdir(addedRoot)]);
  await writeFile(join(oldRoot, "marker.txt"), "marker from old root");
  await writeFile(join(newRoot, "marker.txt"), "marker from new root");
  await mkdir(join(oldRoot, ".chatgpt", "runs", "past"), { recursive: true });
  await writeFile(join(oldRoot, ".chatgpt", "runs", "past", "prompt.md"), "historical delegation artifact");
  await writeFile(configPath, JSON.stringify({ repos: [repository("fixture", oldRoot, true)], limits: {} }));
  const initial = await prepareConfigurationCandidate(await readFile(configPath), configPath);
  const store = new ConfigurationRevisionStore({ configPath, initial });
  return {
    directory,
    oldRoot,
    newRoot,
    addedRoot,
    store,
    async writeCandidate(repos: ReturnType<typeof repository>[]) {
      await writeFile(configPath, JSON.stringify({ repos, limits: {} }));
    }
  };
}

function repository(repoId: string, root: string, writesEnabled: boolean, cleanupEnabled = true) {
  return {
    repo_id: repoId,
    display_name: repoId,
    root,
    allow_non_git: true,
    writes: { enabled: writesEnabled, allowed_globs: ["written.txt"] },
    operations: {
      enabled: true,
      cleanup_enabled: cleanupEnabled,
      cleanup_allowed_globs: [".chatgpt/tool-tests/**"]
    }
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => { resolve = complete; });
  return { promise, resolve };
}

async function callRawTool(client: Client, name: string, args: Record<string, unknown>) {
  return client.request({ method: "tools/call", params: { name, arguments: args } }, CallToolResultSchema);
}
