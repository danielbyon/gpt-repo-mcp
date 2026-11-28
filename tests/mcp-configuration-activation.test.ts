import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { access, chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { expect, test, vi } from "vitest";
import { createHash } from "node:crypto";
import { createConfigurationSourceIdentity } from "../src/config/config-source-identity.js";
import { createConfigurationAdminController } from "../src/runtime/configuration-admin-controller.js";
import { startConfigurationAdminHost } from "../src/runtime/configuration-admin-host.js";
import { parseAdminRequest, type ConfigurationAdminResponse } from "../src/runtime/configuration-admin-protocol.js";
import { createMcpHttpApp } from "../src/runtime/mcp-http-app.js";
import { ConfigurationRevisionStore, prepareConfigurationCandidate } from "../src/services/configuration-revision-store.js";
import type { EffectiveHotRevision } from "../src/services/configuration-revision-store.js";
import type { CodeIntelligenceService } from "../src/services/code-intelligence-service.js";

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

test("serves the published snapshot after an administrative reload acknowledgement", async () => {
  const fixture = await createFixture();
  const sourceIdentity = createConfigurationSourceIdentity(fixture.configPath, process.cwd());
  const instanceId = "88888888-8888-4888-8888-888888888888";
  const httpApp = createMcpHttpApp({ revisionStore: fixture.store, maxSessions: 4, sessionIdleTtlMs: 60_000 });
  const controller = createConfigurationAdminController({
    serverPid: process.pid,
    instanceId,
    sourceIdentity,
    revisionStore: fixture.store
  });
  const server = createServer(httpApp.app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${address.port}/mcp`));
  const client = new Client({ name: "configuration-admin-revision-test", version: "1" });

  try {
    await client.connect(transport);
    await fixture.writeCandidate([repository("fixture", fixture.newRoot, false)]);
    const acceptedBytes = await readFile(fixture.configPath);
    const response = await controller.handle({
      protocol_version: 1,
      request_id: "99999999-9999-4999-8999-999999999999",
      operation: "reload",
      expected_server_pid: process.pid,
      expected_instance_id: instanceId,
      expected_source_identity: sourceIdentity
    });

    expect(response).toMatchObject({
      outcome: "published",
      effective_generation: 2,
      accepted_source_sha256: createHash("sha256").update(acceptedBytes).digest("hex")
    });

    const rootsResult = await callRawTool(client, "repo_list_roots", {});
    const roots = rootsResult.structuredContent as { repos: Array<{ root: string }> };
    const rootPaths = roots.repos.map(({ root }) => root);
    expect(rootPaths).toContain(await realpath(fixture.newRoot));
    expect(rootPaths).not.toContain(await realpath(fixture.oldRoot));
  } finally {
    await client.close().catch(() => undefined);
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await httpApp.dispose();
    await rm(fixture.directory, { recursive: true, force: true });
  }
}, 15_000);

test("production CLI recovers a lost reload response and reports restart-only state over real IPC", async () => {
  const startupSettings = codeIntelligenceSettings();
  const codeIntelligenceService = {} as CodeIntelligenceService;
  const fixture = await createFixture({
    codeIntelligence: startupSettings,
    codeIntelligenceService
  });
  const publication = deferred<ConfigurationAdminResponse>();
  let ipcDirectory: string | undefined;
  let localAppData: string | undefined;
  let httpApp: ReturnType<typeof createMcpHttpApp> | undefined;
  let server: ReturnType<typeof createServer> | undefined;
  let client: Client | undefined;
  let adminHost: Awaited<ReturnType<typeof startConfigurationAdminHost>> | undefined;
  let dropNextPublishedResponse = true;

  try {
    if (process.platform === "win32") {
      const profile = process.env.USERPROFILE;
      if (!profile) throw new Error("Windows acceptance tests require USERPROFILE.");
      localAppData = await mkdtemp(join(profile, "gpt-repo-admin-e2e-"));
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
    } else {
      ipcDirectory = await mkdtemp(join("/tmp", "gpt-admin-"));
      await chmod(ipcDirectory, 0o700);
      vi.stubEnv("GPT_REPO_TEST_BUILT_SERVER", "1");
      vi.stubEnv("GPT_REPO_ADMIN_TEST_DIRECTORY", ipcDirectory);
    }
    const cliPath = join(process.cwd(), "dist", "cli", "connect-gpt.js");
    await access(cliPath);
    const sourceIdentity = createConfigurationSourceIdentity(fixture.configPath, process.cwd());
    const instanceId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    httpApp = createMcpHttpApp({ revisionStore: fixture.store, maxSessions: 4, sessionIdleTtlMs: 60_000 });
    let helperPid: number | undefined;
    const controller = createConfigurationAdminController({
      serverPid: process.pid,
      helperPid: () => helperPid,
      instanceId,
      sourceIdentity,
      revisionStore: fixture.store
    });
    adminHost = await startConfigurationAdminHost({
      serverPid: process.pid,
      instanceId,
      onHelperPid: (pid) => { helperPid = pid; },
      handle: async (value) => {
        const request = parseAdminRequest(value);
        const response = await controller.handle(request);
        if (dropNextPublishedResponse && request.operation === "reload"
          && response.operation === "reload_result" && response.outcome === "published") {
          dropNextPublishedResponse = false;
          publication.resolve(response);
          throw new Error("The test host drops the published reload response.");
        }
        return response;
      }
    });
    const httpServer = createServer(httpApp.app);
    server = httpServer;
    const mcpClient = new Client({ name: "configuration-admin-recovery-test", version: "1" });
    client = mcpClient;

    await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
    const address = httpServer.address() as AddressInfo;
    await mcpClient.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${address.port}/mcp`)));
    const rootsBefore = await callRawTool(mcpClient, "repo_list_roots", {});
    expect(JSON.stringify(rootsBefore)).toContain("old-root");

    await fixture.writeCandidate([repository("fixture", fixture.newRoot, false)], startupSettings);
    const acceptedBytes = await readFile(fixture.configPath);
    const reloadPromise = runBuiltCli(["--config", fixture.configPath, "config", "reload"], createCliEnvironment(ipcDirectory, localAppData));
    const response = await publication.promise;
    const reloadResult = await reloadPromise;
    expect(response).toMatchObject({
      outcome: "published",
      effective_generation: 2,
      accepted_source_sha256: createHash("sha256").update(acceptedBytes).digest("hex")
    });
    expect(reloadResult.code).toBe(1);
    expect(reloadResult.stderr).toContain("Configuration reload outcome is indeterminate");
    expect(await readFile(fixture.configPath)).toEqual(acceptedBytes);
    expect(fixture.store.getState()).toMatchObject({
      acceptedCandidate: { sourceSha256: createHash("sha256").update(acceptedBytes).digest("hex") },
      effectiveHotRevision: { generation: 2 },
      lastReloadOutcome: "accepted"
    });

    const cliEnv = createCliEnvironment(ipcDirectory, localAppData);
    const statusResult = await runBuiltCli([
      "--config", fixture.configPath, "config", "status", "--instance", String(process.pid)
    ], cliEnv);
    expect(statusResult.code).toBe(0);
    expect(statusResult.stdout).toContain(`Server PID: ${process.pid}`);
    expect(statusResult.stdout).toContain(`Accepted candidate: sha256=${createHash("sha256").update(acceptedBytes).digest("hex")}`);
    expect(statusResult.stdout).toContain("Effective hot revision: generation=2");
    expect(statusResult.stdout).toContain("Saved file: valid");
    expect(statusResult.stdout).toContain("matches_accepted=true");
    expect(statusResult.stdout).toContain("Last reload outcome: accepted");

    const initializedFields = "executable,index_timeout_ms,provider,query_timeout_ms";
    let previousFingerprint = createHash("sha256").update(acceptedBytes).digest("hex");
    const initializedEffectiveRevision = fixture.store.getState().effectiveHotRevision;
    const restartMutations = [
      {
        field: "executable",
        settings: { ...startupSettings, executable: join(fixture.directory, "private-code-indexer") },
        value: join(fixture.directory, "private-code-indexer")
      },
      {
        field: "index_timeout_ms",
        settings: { ...startupSettings, index_timeout_ms: 1_799_999 },
        value: "1799999"
      },
      {
        field: "query_timeout_ms",
        settings: { ...startupSettings, query_timeout_ms: 4_123 },
        value: "4123"
      }
    ] as const;

    for (const mutation of restartMutations) {
      await fixture.writeCandidate([repository("fixture", fixture.newRoot, false)], mutation.settings);
      const candidateBytes = await readFile(fixture.configPath);
      const candidateFingerprint = createHash("sha256").update(candidateBytes).digest("hex");
      expect(candidateFingerprint).not.toBe(previousFingerprint);

      const reloadStatus = await runBuiltCli([
        "--config", fixture.configPath, "config", "reload"
      ], cliEnv);
      expect(reloadStatus.code).toBe(0);
      expect(fixture.store.getState()).toMatchObject({
        acceptedCandidate: { sourceSha256: candidateFingerprint },
        effectiveHotRevision: { generation: 2, runtimeContext: { codeIntelligence: codeIntelligenceService } }
      });
      expect(fixture.store.getState().effectiveHotRevision).toBe(initializedEffectiveRevision);
      expect(fixture.store.getState().effectiveHotRevision.runtimeContext.codeIntelligence).toBe(codeIntelligenceService);

      const observedStatus = await runBuiltCli([
        "--config", fixture.configPath, "config", "status", "--instance", String(process.pid)
      ], cliEnv);
      expect(observedStatus.code).toBe(0);
      expect(observedStatus.stdout).toContain(`Server PID: ${process.pid}`);
      expect(observedStatus.stdout).toContain(`Accepted candidate: sha256=${candidateFingerprint}`);
      expect(observedStatus.stdout).toContain("Effective hot revision: generation=2");
      expect(observedStatus.stdout).toContain(`Initialized restart fields: ${initializedFields}`);
      expect(observedStatus.stdout.split("\n").find((line) => line.startsWith("Pending restart fields:")))
        .toBe(`Pending restart fields: ${mutation.field}`);
      for (const value of [
        mutation.value,
        startupSettings.executable,
        String(startupSettings.index_timeout_ms),
        String(startupSettings.query_timeout_ms)
      ]) {
        expect(observedStatus.stdout).not.toContain(value);
      }
      expect(observedStatus.stdout).toContain("Last reload outcome: accepted");
      previousFingerprint = candidateFingerprint;
    }

    await fixture.writeCandidate([repository("fixture", fixture.newRoot, false)]);
    const removedSectionBytes = await readFile(fixture.configPath);
    const removedSectionFingerprint = createHash("sha256").update(removedSectionBytes).digest("hex");
    const removalReload = await runBuiltCli(["--config", fixture.configPath, "config", "reload"], cliEnv);
    expect(removalReload.code).toBe(0);
    expect(removedSectionFingerprint).not.toBe(previousFingerprint);
    expect(fixture.store.getState()).toMatchObject({
      acceptedCandidate: { sourceSha256: removedSectionFingerprint },
      effectiveHotRevision: { generation: 2, runtimeContext: { codeIntelligence: codeIntelligenceService } }
    });
    expect(fixture.store.getState().effectiveHotRevision).toBe(initializedEffectiveRevision);
    const removedSectionStatus = await runBuiltCli([
      "--config", fixture.configPath, "config", "status", "--instance", String(process.pid)
    ], cliEnv);
    expect(removedSectionStatus.code).toBe(0);
    expect(removedSectionStatus.stdout).toContain(`Accepted candidate: sha256=${removedSectionFingerprint}`);
    expect(removedSectionStatus.stdout).toContain(`Initialized restart fields: ${initializedFields}`);
    expect(removedSectionStatus.stdout).toContain(`Pending restart fields: ${initializedFields}`);
    expect(removedSectionStatus.stdout).not.toContain(startupSettings.executable);
    expect(removedSectionStatus.stdout).not.toContain(String(startupSettings.index_timeout_ms));
    expect(removedSectionStatus.stdout).not.toContain(String(startupSettings.query_timeout_ms));

    await fixture.writeCandidate([repository("fixture", fixture.newRoot, false)], startupSettings);
    const restoredBytes = await readFile(fixture.configPath);
    const restoredFingerprint = createHash("sha256").update(restoredBytes).digest("hex");
    const restorationReload = await runBuiltCli(["--config", fixture.configPath, "config", "reload"], cliEnv);
    expect(restorationReload.code).toBe(0);
    expect(restoredFingerprint).not.toBe(removedSectionFingerprint);
    const restoredStatus = await runBuiltCli([
      "--config", fixture.configPath, "config", "status", "--instance", String(process.pid)
    ], cliEnv);
    expect(restoredStatus.code).toBe(0);
    expect(restoredStatus.stdout).toContain(`Accepted candidate: sha256=${restoredFingerprint}`);
    expect(restoredStatus.stdout).toContain(`Initialized restart fields: ${initializedFields}`);
    expect(restoredStatus.stdout).toContain("Pending restart fields: none");
    expect(restoredStatus.stdout).toContain("Last reload outcome: accepted");
    expect(restoredStatus.stdout).not.toContain(startupSettings.executable);
    expect(fixture.store.getState()).toMatchObject({
      acceptedCandidate: { sourceSha256: restoredFingerprint },
      effectiveHotRevision: { generation: 2, runtimeContext: { codeIntelligence: codeIntelligenceService } }
    });
    expect(fixture.store.getState().effectiveHotRevision).toBe(initializedEffectiveRevision);

    const rootsResult = await callRawTool(mcpClient, "repo_list_roots", {});
    const roots = rootsResult.structuredContent as { repos: Array<{ root: string }> };
    const rootPaths = roots.repos.map(({ root }) => root);
    expect(rootPaths).toContain(await realpath(fixture.newRoot));
    expect(rootPaths).not.toContain(await realpath(fixture.oldRoot));
  } finally {
    await client?.close().catch(() => undefined);
    server?.closeAllConnections();
    try {
      const httpServer = server;
      if (httpServer) await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    } finally {
      try {
        if (adminHost) await adminHost.close();
      } finally {
        try {
            if (httpApp) await httpApp.dispose();
        } finally {
          try {
            if (ipcDirectory) await rm(ipcDirectory, { recursive: true, force: true });
          } finally {
            try {
              if (localAppData) await rm(localAppData, { recursive: true, force: true });
            } finally {
              vi.unstubAllEnvs();
              await rm(fixture.directory, { recursive: true, force: true });
            }
          }
        }
      }
    }
  }
}, 30_000);

function createCliEnvironment(ipcDirectory: string | undefined, localAppData: string | undefined): NodeJS.ProcessEnv {
  return {
    ...process.env,
    GPT_REPO_CONFIG: undefined,
    REPO_READER_CONFIG: undefined,
    ...(ipcDirectory ? {
      GPT_REPO_TEST_BUILT_SERVER: "1",
      GPT_REPO_ADMIN_TEST_DIRECTORY: ipcDirectory
    } : {}),
    ...(localAppData ? {
      LOCALAPPDATA: localAppData,
      GPT_REPO_ADMIN_TEST_HELPER: "1"
    } : {})
  };
}

function runBuiltCli(args: string[], env: NodeJS.ProcessEnv): Promise<{
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}> {
  const child = spawn(process.execPath, [join(process.cwd(), "dist", "cli", "connect-gpt.js"), ...args], {
    cwd: process.cwd(),
    env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({
      code,
      signal,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8")
    }));
  });
}

async function createFixture(options: {
  codeIntelligence?: ReturnType<typeof codeIntelligenceSettings>;
  codeIntelligenceService?: CodeIntelligenceService;
} = {}) {
  const directory = await mkdtemp(join(tmpdir(), "mcp-config-activation-"));
  const oldRoot = join(directory, "old-root");
  const newRoot = join(directory, "new-root");
  const addedRoot = join(directory, "added-root");
  const configPath = join(directory, "config.json");
  try {
    await Promise.all([mkdir(oldRoot), mkdir(newRoot), mkdir(addedRoot)]);
    await writeFile(join(oldRoot, "marker.txt"), "marker from old root");
    await writeFile(join(newRoot, "marker.txt"), "marker from new root");
    await mkdir(join(oldRoot, ".chatgpt", "runs", "past"), { recursive: true });
    await writeFile(join(oldRoot, ".chatgpt", "runs", "past", "prompt.md"), "historical delegation artifact");
    await writeFile(configPath, JSON.stringify({
      repos: [repository("fixture", oldRoot, true)],
      limits: {},
      ...(options.codeIntelligence ? { code_intelligence: options.codeIntelligence } : {})
    }));
    const initial = await prepareConfigurationCandidate(await readFile(configPath), configPath);
    const store = new ConfigurationRevisionStore({
      configPath,
      initial,
      ...(options.codeIntelligenceService ? { codeIntelligence: options.codeIntelligenceService } : {})
    });
    return {
      directory,
      oldRoot,
      newRoot,
      addedRoot,
      configPath,
      store,
      async writeCandidate(
        repos: ReturnType<typeof repository>[],
        codeIntelligence?: ReturnType<typeof codeIntelligenceSettings>
      ) {
        await writeFile(configPath, JSON.stringify({
          repos,
          limits: {},
          ...(codeIntelligence ? { code_intelligence: codeIntelligence } : {})
        }));
      }
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
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

function codeIntelligenceSettings(overrides: Partial<ReturnType<typeof baseCodeIntelligenceSettings>> = {}) {
  return { ...baseCodeIntelligenceSettings(), ...overrides };
}

function baseCodeIntelligenceSettings() {
  return {
    provider: "codebase_memory" as const,
    executable: process.execPath,
    query_timeout_ms: 3_000,
    index_timeout_ms: 1_800_000
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
