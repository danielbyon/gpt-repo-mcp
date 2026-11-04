import { chmod, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { delimiter, join } from "node:path";
import { describe, expect, test, vi } from "vitest";
import { ValidationService } from "../src/services/validation-service.js";
import { OperationsPolicy } from "../src/services/operations-policy.js";
import * as fsHelpers from "../src/runtime/fs-helpers.js";
import { GitService } from "../src/services/git-service.js";
import { ValidateInputSchema } from "../src/contracts/validation.contract.js";
import { descriptions } from "../src/tools/descriptions.js";
import type { NodeRuntimeResolverOptions } from "../src/services/node-runtime-resolver.js";
import { createTempDir } from "./fixtures/temp-dir.js";
import * as processExec from "../src/services/process-exec.js";

describe("ValidationService", () => {
  test("accepts npm banners before validation JSON and rejects malformed final output", () => {
    expect(lastJsonLine("> smoke\n> fixture\n{\"ok\":true}")).toEqual({ ok: true });
    expect(() => lastJsonLine("{\"ok\":true}\nmalformed")).toThrow(SyntaxError);
  });

  test("tool and contract describe repo-owned priority plus safe fallbacks without shell execution", async () => {
    expect(descriptions.repo_validate).toContain("repo-owned make or just target takes priority");
    expect(descriptions.repo_validate).toContain("safe pytest");
    expect(descriptions.repo_validate).toContain("bounded tail without a shell");
    expect(descriptions.repo_validate).not.toContain("allowlisted package.json script profile");
    expect(ValidateInputSchema.shape.profile.description).toContain("safe pytest");
    const source = await readFile(join(process.cwd(), "src", "services", "validation-service.ts"), "utf8");
    expect(source).toContain("runProcessWithTail({");
    expect(source).not.toContain("shell: true");
  });
  test("selects pytest for a Python repository without package.json", async () => {
    const root = await fixtureRepo({ pythonMarker: true, localPython: true });
    const result = await service(root).validate({ repo_id: "fixture", profile: "test", dry_run: true });
    expect(result.commands).toEqual([{ profile: "test", script: "pytest", command: ".venv/bin/python -m pytest", status: "skipped" }]);
  });

  test("prefers executable .venv Python and passes focused paths as separate arguments", async () => {
    const root = await fixtureRepo({ pythonMarker: true, localPython: true });
    const result = await service(root, { validation_test_path_globs: ["tests/**"] }).validate({
      repo_id: "fixture", profile: "test", test_paths: ["tests/test_a.py", "tests/test_b.py"]
    });
    expect(result.commands[0]).toMatchObject({
      script: "pytest",
      command: ".venv/bin/python -m pytest tests/test_a.py tests/test_b.py",
      stdout_tail: "-m|pytest|tests/test_a.py|tests/test_b.py"
    });
  });

  test("uses fixed python3 fallback when local Python is absent", async () => {
    const root = await fixtureRepo({ pythonMarker: true });
    const result = await service(root).validate({ repo_id: "fixture", profile: "test", dry_run: true });
    expect(result.commands[0]?.command).toBe("python3 -m pytest");
  });

  test("prefers an npm test script over pytest", async () => {
    const root = await fixtureRepo({ scripts: { test: "echo npm" }, pythonMarker: true, localPython: true });
    const result = await service(root).validate({ repo_id: "fixture", profile: "test", dry_run: true });
    expect(result.commands[0]?.command).toBe("npm run test");
  });

  test("does not use pytest fallback for build", async () => {
    const root = await fixtureRepo({ pythonMarker: true, localPython: true });
    await expect(service(root).validate({ repo_id: "fixture", profile: "build", dry_run: true }))
      .rejects.toMatchObject({ code: "VALIDATION_PROFILE_UNAVAILABLE" });
  });

  test("rejects Python repositories without test-suite signals", async () => {
    const root = await fixtureRepo({ localPython: true });
    await expect(service(root).validate({ repo_id: "fixture", profile: "test", dry_run: true }))
      .rejects.toMatchObject({ code: "VALIDATION_PROFILE_UNAVAILABLE" });
  });

  test("does not select a non-executable or root-escaping local Python", async () => {
    const root = await fixtureRepo({ pythonMarker: true, localPython: "non-executable" });
    expect((await service(root).validate({ repo_id: "fixture", profile: "test", dry_run: true })).commands[0]?.command).toBe("python3 -m pytest");

    const outside = await createTempDir("gpt-python-outside-");
    const outsidePython = join(outside, "python");
    await writeFile(outsidePython, "#!/usr/bin/env node\nprocess.exit(0)\n");
    await chmod(outsidePython, 0o755);
    const escapingRoot = await fixtureRepo({ pythonMarker: true });
    await mkdir(join(escapingRoot, ".venv", "bin"), { recursive: true });
    await symlink(outsidePython, join(escapingRoot, ".venv", "bin", "python"));
    expect((await service(escapingRoot).validate({ repo_id: "fixture", profile: "test", dry_run: true })).commands[0]?.command).toBe("python3 -m pytest");
  });

  test("all includes pytest in profile order alongside available npm profiles", async () => {
    const root = await fixtureRepo({ scripts: { lint: "echo lint", build: "echo build" }, pythonMarker: true, localPython: true });
    const result = await service(root).validate({ repo_id: "fixture", profile: "all", dry_run: true });
    expect(result.commands.map(({ profile, script }) => ({ profile, script }))).toEqual([
      { profile: "lint", script: "lint" }, { profile: "test", script: "pytest" }, { profile: "build", script: "build" }
    ]);
  });

  test("declared all profile uses canonical make verify instead of npm or pytest fallback", async () => {
    const root = await fixtureRepo({ scripts: { test: "echo npm-should-not-run" }, pythonMarker: true, localPython: true });
    await writeFile(join(root, "Makefile"), "verify:\n\t@echo canonical-make-verify\n");
    const result = await service(root, {
      validation_profiles: { all: { runner: "make", target: "verify" } }
    }).validate({ repo_id: "fixture", profile: "all" });
    console.log("MAKE_RUNNER_DIAGNOSTIC_RESULT", JSON.stringify(result));

    expect(result).toMatchObject({
      status: "passed",
      commands: [{
        profile: "all",
        script: "make:verify",
        command: "make verify",
        status: "passed",
        stdout_tail: expect.stringContaining("canonical-make-verify")
      }]
    });
    expect(result.commands).toHaveLength(1);
  });

  test("declared just profile takes priority over npm and pytest fallback", async () => {
    const root = await fixtureRepo({
      scripts: { test: "echo npm-should-not-run" },
      pythonMarker: true,
      localPython: true
    });

    const result = await service(root, {
      validation_profiles: { test: { runner: "just", target: "test" } }
    }).validate({ repo_id: "fixture", profile: "test", dry_run: true });

    expect(result.commands).toEqual([{
      profile: "test",
      script: "just:test",
      command: "just test",
      status: "skipped"
    }]);
  });

  test("executes a declared just profile directly with a single target argument", async () => {
    const bin = await createTempDir("gpt-just-bin-");
    const just = join(bin, "just");
    await writeFile(
      just,
      `#!${process.execPath}\nconsole.log("x".repeat(5000));\nconsole.log("args:" + process.argv.slice(2).join("|"));\n`
    );
    await chmod(just, 0o755);

    const previousPath = process.env.PATH;
    process.env.PATH = `${bin}${delimiter}${previousPath ?? ""}`;
    try {
      const root = await fixtureRepo({});
      const result = await service(root, {
        validation_profiles: { smoke: { runner: "just", target: "smoke" } }
      }).validate({ repo_id: "fixture", profile: "smoke" });

      expect(result.commands[0]).toMatchObject({
        script: "just:smoke",
        command: "just smoke",
        status: "passed",
        exit_code: 0
      });
      expect(result.commands[0]?.stdout_tail).toContain("smoke");
      expect(result.commands[0]?.stdout_tail?.length).toBeLessThanOrEqual(4000);
    } finally {
      process.env.PATH = previousPath;
    }
  });

  test("forwards HOME and XDG_CONFIG_HOME to validation children while keeping the environment allowlisted", async () => {
    const original = captureEnv(["HOME", "XDG_CONFIG_HOME", "VALIDATION_ENV_LEAK", "CI", "NO_COLOR", "npm_config_color", "PATH"]);
    const home = "gpt-validation-home-marker";
    const xdg = "gpt-validation-xdg-marker";
    process.env.HOME = home;
    process.env.XDG_CONFIG_HOME = xdg;
    process.env.VALIDATION_ENV_LEAK = "must-not-leak";
    process.env.CI = "0";
    process.env.NO_COLOR = "0";
    process.env.npm_config_color = "true";
    await envProbeJust();
    const root = await fixtureRepo({});
    try {
      const result = await service(root, {
        validation_profiles: { smoke: { runner: "just", target: "smoke" } }
      }).validate({ repo_id: "fixture", profile: "smoke" });

      expect(JSON.parse(result.commands[0]?.stdout_tail ?? "{}")).toEqual({
        HOME: home,
        XDG_CONFIG_HOME: xdg,
        CI: "1",
        NO_COLOR: "1",
        npm_config_color: "false",
        VALIDATION_ENV_LEAK: null
      });
      expect(result.commands[0]?.stdout_tail).not.toContain("must-not-leak");
    } finally {
      restoreEnv(original);
    }
  });

  test("does not synthesize HOME or XDG_CONFIG_HOME when the host environment lacks or empties them", async () => {
    const original = captureEnv(["HOME", "XDG_CONFIG_HOME", "VALIDATION_ENV_LEAK", "PATH"]);
    const root = await fixtureRepo({});
    process.env.VALIDATION_ENV_LEAK = "must-not-leak";
    await envProbeJust();
    try {
      delete process.env.HOME;
      delete process.env.XDG_CONFIG_HOME;
      let result = await service(root, {
        validation_profiles: { smoke: { runner: "just", target: "smoke" } }
      }).validate({ repo_id: "fixture", profile: "smoke" });

      expect(JSON.parse(result.commands[0]?.stdout_tail ?? "{}")).toMatchObject({
        HOME: null,
        XDG_CONFIG_HOME: null,
        CI: "1",
        NO_COLOR: "1",
        npm_config_color: "false",
        VALIDATION_ENV_LEAK: null
      });

      process.env.HOME = "";
      process.env.XDG_CONFIG_HOME = "";
      result = await service(root, {
        validation_profiles: { smoke: { runner: "just", target: "smoke" } }
      }).validate({ repo_id: "fixture", profile: "smoke" });

      expect(JSON.parse(result.commands[0]?.stdout_tail ?? "{}")).toMatchObject({
        HOME: null,
        XDG_CONFIG_HOME: null
      });
    } finally {
      restoreEnv(original);
    }
  });

  test("npm validation chain passes HOME and XDG_CONFIG_HOME to the script child", async () => {
    const original = captureEnv(["HOME", "XDG_CONFIG_HOME"]);
    const home = "gpt-validation-home-marker";
    const xdg = "gpt-validation-xdg-marker";
    process.env.HOME = home;
    process.env.XDG_CONFIG_HOME = xdg;
    const root = await fixtureRepo({
      scripts: { smoke: `node -e "console.log(JSON.stringify({ home: process.env.HOME ?? null, xdg: process.env.XDG_CONFIG_HOME ?? null }))"` }
    });
    try {
      const result = await service(root).validate({ repo_id: "fixture", profile: "smoke" });

      expect(result.status).toBe("passed");
      expect(lastJsonLine(result.commands[0]?.stdout_tail)).toEqual({ home, xdg });
    } finally {
      restoreEnv(original);
    }
  });

  test("validation artifact records the pytest runner and display command", async () => {
    const root = await fixtureRepo({ pythonMarker: true, localPython: true });
    const result = await service(root).validate({ repo_id: "fixture", profile: "test" });
    const artifact = JSON.parse(await readFile(join(root, result.validation_artifact!.path), "utf8"));
    expect(artifact.commands[0]).toMatchObject({ script: "pytest", command: ".venv/bin/python -m pytest" });
  });

  test("selects an installed exact Node version from .node-version for npm validation", async () => {
    const root = await fixtureRepo({ scripts: { test: "node -e \"console.log(process.env.FAKE_NODE_RUNTIME)\"" }, nodeVersion: "24.18.0" });
    const runtime = await fakeNvmRuntime("24.18.0");
    const result = await service(root, {}, runtime.options).validate({ repo_id: "fixture", profile: "test" });

    expect(result.commands[0]).toMatchObject({
      command: "npm run test",
      runtime: { name: "node", version: "24.18.0", source: ".node-version" },
      stdout_tail: expect.stringContaining("24.18.0")
    });
  });

  test("uses deterministic version-source priority", async () => {
    const root = await fixtureRepo({
      scripts: { test: "echo ok" },
      nodeVersion: "22.22.2",
      nvmrc: "23.0.0",
      voltaNode: "24.18.0"
    });
    const runtime = await fakeNvmRuntime("24.18.0");
    const result = await service(root, {}, runtime.options).validate({ repo_id: "fixture", profile: "test", dry_run: true });
    expect(result.commands[0]?.runtime).toEqual({ name: "node", version: "24.18.0", source: "package.json#volta.node" });
  });

  test("ignores non-exact engines ranges and keeps the host PATH", async () => {
    const root = await fixtureRepo({ scripts: { test: "echo ok" }, enginesNode: ">=24" });
    const result = await service(root, {}, { home: await createTempDir("gpt-empty-runtime-"), env: {} })
      .validate({ repo_id: "fixture", profile: "test", dry_run: true });
    expect(result.commands[0]?.runtime).toBeUndefined();
  });

  test("fails safely when an exact requested Node runtime is not installed", async () => {
    const root = await fixtureRepo({ scripts: { test: "echo ok" }, nvmrc: "24.18.0" });
    await expect(service(root, {}, { home: await createTempDir("gpt-empty-runtime-"), env: {} })
      .validate({ repo_id: "fixture", profile: "test", dry_run: true }))
      .rejects.toMatchObject({ code: "VALIDATION_NODE_RUNTIME_UNAVAILABLE" });
  });

  test("rejects a runtime symlink that escapes its approved manager root", async () => {
    const root = await fixtureRepo({ scripts: { test: "echo ok" }, nodeVersion: "24.18.0" });
    const home = await createTempDir("gpt-runtime-home-");
    const outside = await fakeNodeExecutable(join(await createTempDir("gpt-runtime-outside-"), "node"), "24.18.0");
    const candidate = join(home, ".nvm", "versions", "node", "v24.18.0", "bin", "node");
    await mkdir(join(home, ".nvm", "versions", "node", "v24.18.0", "bin"), { recursive: true });
    await symlink(outside, candidate);
    await expect(service(root, {}, { home, env: {} }).validate({ repo_id: "fixture", profile: "test", dry_run: true }))
      .rejects.toMatchObject({ code: "VALIDATION_NODE_RUNTIME_UNAVAILABLE" });
  });

  test("validation artifact records selected Node runtime without an absolute runtime path", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo ok" }, nodeVersion: "24.18.0" });
    const runtime = await fakeNvmRuntime("24.18.0");
    const result = await service(root, {}, runtime.options).validate({ repo_id: "fixture", profile: "smoke" });
    const artifactText = await readFile(join(root, result.validation_artifact!.path), "utf8");
    expect(JSON.parse(artifactText).commands[0].runtime).toEqual({ name: "node", version: "24.18.0", source: ".node-version" });
    expect(artifactText).not.toContain(runtime.home);
  });
  test("dry run resolves the allowlisted npm script without executing it", async () => {
    const root = await fixtureRepo({
      scripts: { test: "node -e \"throw new Error('should not run')\"" }
    });

    const result = await service(root).validate({
      repo_id: "fixture",
      profile: "test",
      dry_run: true
    });

    expect(result).toMatchObject({
      ok: true,
      repo_id: "fixture",
      profile: "test",
      dry_run: true,
      status: "skipped",
      commands: [{ profile: "test", script: "test", command: "npm run test", status: "skipped" }],
      counts: { total: 1, passed: 0, failed: 0, skipped: 1 },
      warnings: ["VALIDATION_DRY_RUN"]
    });
  });

  test("runs an allowlisted npm script and returns bounded output", async () => {
    const root = await fixtureRepo({
      scripts: { smoke: "node -e \"console.log('smoke ok')\"" }
    });

    const result = await service(root).validate({
      repo_id: "fixture",
      profile: "smoke"
    });

    expect(result).toMatchObject({
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
    expect(result.commands[0]?.stdout_tail?.length).toBeLessThanOrEqual(4000);
  });

  test("cancellation during command planning prevents a dry-run result", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo should-not-run" } });
    const planningStarted = deferred<void>();
    const releasePlanning = deferred<void>();
    const internals = ValidationService.prototype as unknown as {
      readScripts(this: ValidationService): Promise<Record<string, string>>;
    };
    const originalReadScripts = internals.readScripts;
    const readSpy = vi.spyOn(internals, "readScripts").mockImplementation(async function (this: ValidationService) {
      planningStarted.resolve();
      await releasePlanning.promise;
      return originalReadScripts.call(this);
    });
    const controller = new AbortController();
    try {
      const validation = service(root).validate({ repo_id: "fixture", profile: "smoke", dry_run: true }, { signal: controller.signal });
      await planningStarted.promise;
      controller.abort();
      releasePlanning.resolve();

      await expect(validation).rejects.toMatchObject({ name: "AbortError" });
    } finally {
      controller.abort();
      releasePlanning.resolve();
      readSpy.mockRestore();
    }
  });

  test("cancels an npm validation tree without writing a receipt", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "node fixture.cjs" } });
    const parentPidPath = join(root, "parent.pid");
    const childReadyPath = join(root, "child.ready");
    const cleanupPath = join(root, "cleanup");
    await writeFile(cleanupPath, "wait");
    const childScript = [
      "const { readFileSync, watch, writeFileSync } = require('node:fs');",
      `const cleanupWatcher = watch(${JSON.stringify(cleanupPath)}, () => { cleanupWatcher.close(); process.exit(0); });`,
      `if (readFileSync(${JSON.stringify(cleanupPath)}, 'utf8') === 'stop') process.exit(0);`,
      "process.on('SIGTERM', () => {});",
      `writeFileSync(${JSON.stringify(childReadyPath)}, String(process.pid));`,
      "setInterval(() => {}, 1_000);"
    ].join("\n");
    const fixtureScript = [
      "const { spawn } = require('node:child_process');",
      "const { readFileSync, watch, writeFileSync } = require('node:fs');",
      `const cleanupWatcher = watch(${JSON.stringify(cleanupPath)}, () => { cleanupWatcher.close(); process.exit(0); });`,
      `if (readFileSync(${JSON.stringify(cleanupPath)}, 'utf8') === 'stop') process.exit(0);`,
      "process.on('SIGTERM', () => {});",
      `spawn(process.execPath, ['-e', ${JSON.stringify(childScript)}], { stdio: 'ignore' });`,
      `writeFileSync(${JSON.stringify(parentPidPath)}, String(process.pid));`,
      "setInterval(() => {}, 1_000);"
    ].join("\n");
    await writeFile(join(root, "fixture.cjs"), fixtureScript);

    const controller = new AbortController();
    const validationPromise = service(root).validate({
      repo_id: "fixture",
      profile: "smoke",
      timeout_ms: 1_500
    }, { signal: controller.signal });

    let childPid: number | undefined;
    let parentPid: number | undefined;
    try {
      childPid = Number(await waitForFile(childReadyPath));
      parentPid = Number(await readFile(parentPidPath, "utf8"));
      controller.abort();

      await expect(validationPromise).rejects.toMatchObject({ name: "AbortError" });
      await Promise.all([expectProcessGone(parentPid), expectProcessGone(childPid)]);
      await expect(readFile(join(root, ".chatgpt", "validation", "latest.json"), "utf8"))
        .rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      controller.abort();
      await writeFile(cleanupPath, "stop");
      await validationPromise.catch(() => undefined);
      const pids = [parentPid, childPid].filter((pid): pid is number => pid !== undefined);
      await Promise.all(pids.map(expectProcessGone));
    }
  }, 5_000);

  test("preserves the latest receipt when Windows cleanup is unconfirmed", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo validation-complete" } });
    const validationDirectory = join(root, ".chatgpt", "validation");
    const latestPath = join(validationDirectory, "latest.json");
    const previousReceipt = "previous committed receipt";
    await mkdir(validationDirectory, { recursive: true });
    await writeFile(latestPath, previousReceipt);
    const processSpy = vi.spyOn(processExec, "runProcessWithTail").mockResolvedValue({
      timed_out: false,
      cancelled: true,
      cleanup_confirmed: false,
      duration_ms: 1,
      stdout_tail: "",
      stderr_tail: ""
    });

    try {
      await expect(service(root).validate({ repo_id: "fixture", profile: "smoke" }))
        .rejects.toThrow("Validation process cleanup could not be confirmed");
      expect(await readFile(latestPath, "utf8")).toBe(previousReceipt);
    } finally {
      processSpy.mockRestore();
    }
  });

  test("cancellation during identity capture preserves the existing latest receipt", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo validation-complete" } });
    const latestPath = join(root, ".chatgpt", "validation", "latest.json");
    const previousLatest = "previous-latest-receipt";
    await mkdir(join(root, ".chatgpt", "validation"), { recursive: true });
    await writeFile(latestPath, previousLatest);

    const identityStarted = deferred<void>();
    const releaseIdentity = deferred<void>();
    const originalFingerprint = GitService.prototype.worktreeFingerprint;
    const fingerprintSpy = vi.spyOn(GitService.prototype, "worktreeFingerprint").mockImplementation(async function (this: GitService) {
      identityStarted.resolve();
      await releaseIdentity.promise;
      return originalFingerprint.call(this);
    });
    const controller = new AbortController();
    try {
      const validation = service(root).validate({ repo_id: "fixture", profile: "smoke" }, { signal: controller.signal });
      await identityStarted.promise;
      controller.abort();
      releaseIdentity.resolve();

      await expect(validation).rejects.toMatchObject({ name: "AbortError" });
      expect(await readFile(latestPath, "utf8")).toBe(previousLatest);
    } finally {
      controller.abort();
      releaseIdentity.resolve();
      fingerprintSpy.mockRestore();
    }
  });

  test("cancellation during result staging does not admit receipt publication", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo validation-complete" } });
    const latestPath = join(root, ".chatgpt", "validation", "latest.json");
    const previousLatest = "previous-latest-receipt";
    await mkdir(join(root, ".chatgpt", "validation"), { recursive: true });
    await writeFile(latestPath, previousLatest);

    const stagingStarted = deferred<void>();
    const releaseStaging = deferred<void>();
    const originalWrite = fsHelpers.atomicWriteJson;
    const writeSpy = vi.spyOn(fsHelpers, "atomicWriteJson").mockImplementation(async (path, value) => {
      if (path.endsWith("result.json")) {
        stagingStarted.resolve();
        await releaseStaging.promise;
      }
      return originalWrite(path, value);
    });
    const controller = new AbortController();
    try {
      const validation = service(root).validate({ repo_id: "fixture", profile: "smoke" }, { signal: controller.signal });
      await stagingStarted.promise;
      controller.abort();
      releaseStaging.resolve();

      await expect(validation).rejects.toMatchObject({ name: "AbortError" });
      expect(await readFile(latestPath, "utf8")).toBe(previousLatest);
    } finally {
      controller.abort();
      releaseStaging.resolve();
      writeSpy.mockRestore();
    }
  });

  test("cancellation immediately before commit admission preserves latest", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo validation-complete" } });
    const latestPath = join(root, ".chatgpt", "validation", "latest.json");
    const previousLatest = "previous-latest-receipt";
    await mkdir(join(root, ".chatgpt", "validation"), { recursive: true });
    await writeFile(latestPath, previousLatest);

    const controller = new AbortController();
    const originalWrite = fsHelpers.atomicWriteJson;
    const writeSpy = vi.spyOn(fsHelpers, "atomicWriteJson").mockImplementation(async (path, value) => {
      const result = await originalWrite(path, value);
      if (path.endsWith("result.json")) controller.abort();
      return result;
    });
    try {
      await expect(service(root).validate({ repo_id: "fixture", profile: "smoke" }, { signal: controller.signal }))
        .rejects.toMatchObject({ name: "AbortError" });
      expect(await readFile(latestPath, "utf8")).toBe(previousLatest);
    } finally {
      writeSpy.mockRestore();
    }
  });

  test("commit admission makes receipt publication non-cancellable", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo validation-complete" } });
    const latestPath = join(root, ".chatgpt", "validation", "latest.json");
    const previousLatest = "previous-latest-receipt";
    await mkdir(join(root, ".chatgpt", "validation"), { recursive: true });
    await writeFile(latestPath, previousLatest);

    const commitStarted = deferred<void>();
    const releaseCommit = deferred<void>();
    const controller = new AbortController();
    const originalWrite = fsHelpers.atomicWriteJson;
    const writeSpy = vi.spyOn(fsHelpers, "atomicWriteJson").mockImplementation(async (path, value) => {
      if (path.endsWith("latest.json")) {
        commitStarted.resolve();
        await releaseCommit.promise;
      }
      return originalWrite(path, value);
    });
    try {
      const validation = service(root).validate({ repo_id: "fixture", profile: "smoke" }, { signal: controller.signal });
      await commitStarted.promise;
      controller.abort();
      releaseCommit.resolve();

      const result = await validation;
      const latest = JSON.parse(await readFile(latestPath, "utf8")) as { validation_id?: string };
      expect(result.status).toBe("passed");
      expect(latest.validation_id).toBe(result.validation_id);
    } finally {
      controller.abort();
      releaseCommit.resolve();
      writeSpy.mockRestore();
    }
  });

  test("latest replacement failure rejects and preserves the previous receipt", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo validation-complete" } });
    const latestPath = join(root, ".chatgpt", "validation", "latest.json");
    const previousLatest = "previous-latest-receipt";
    await mkdir(join(root, ".chatgpt", "validation"), { recursive: true });
    await writeFile(latestPath, previousLatest);

    const originalWrite = fsHelpers.atomicWriteJson;
    const writeSpy = vi.spyOn(fsHelpers, "atomicWriteJson").mockImplementation(async (path, value) => {
      if (path.endsWith("latest.json")) throw new Error("injected latest replacement failure");
      return originalWrite(path, value);
    });
    try {
      await expect(service(root).validate({ repo_id: "fixture", profile: "smoke" }))
        .rejects.toThrow("injected latest replacement failure");
      expect(await readFile(latestPath, "utf8")).toBe(previousLatest);
    } finally {
      writeSpy.mockRestore();
    }
  });

  test("does not report validation success when receipt persistence fails", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo validation-complete" } });
    const receiptPath = join(root, ".chatgpt");
    await writeFile(receiptPath, "preserve-existing-file");

    await expect(service(root).validate({ repo_id: "fixture", profile: "smoke" }))
      .rejects.toMatchObject({ code: "ENOTDIR" });
    expect(await readFile(receiptPath, "utf8")).toBe("preserve-existing-file");
  });

  test("reports validation failure as a structured result instead of a tool error", async () => {
    const root = await fixtureRepo({
      scripts: { test: "node -e \"console.error('failed safely'); process.exit(3)\"" }
    });

    const result = await service(root).validate({
      repo_id: "fixture",
      profile: "test"
    });

    expect(result).toMatchObject({
      ok: true,
      status: "failed",
      commands: [{
        profile: "test",
        script: "test",
        command: "npm run test",
        status: "failed",
        exit_code: 3,
        stderr_tail: expect.stringContaining("failed safely")
      }],
      counts: { total: 1, passed: 0, failed: 1, skipped: 0 },
      warnings: []
    });
  });

  test("requires explicit validation opt-in in operations policy", async () => {
    const root = await fixtureRepo({ scripts: { test: "node -e \"console.log('ok')\"" } });

    await expect(new ValidationService(root, new OperationsPolicy({ enabled: true })).validate({
      repo_id: "fixture",
      profile: "test",
      dry_run: true
    })).rejects.toMatchObject({ code: "VALIDATION_DISABLED" });
  });

  test("rejects unavailable profiles before running npm", async () => {
    const root = await fixtureRepo({ scripts: { test: "node -e \"console.log('ok')\"" } });

    await expect(service(root).validate({
      repo_id: "fixture",
      profile: "build",
      dry_run: true
    })).rejects.toMatchObject({ code: "VALIDATION_PROFILE_UNAVAILABLE" });
  });

  test("runs focused test paths only when allowed by operations policy", async () => {
    const root = await fixtureRepo({
      scripts: { test: "node -e \"console.log(process.argv.slice(1).join('|'))\"" }
    });

    const result = await service(root, { validation_test_path_globs: ["tests/**"] }).validate({
      repo_id: "fixture",
      profile: "test",
      test_paths: ["tests/auth.test.ts"]
    });

    expect(result).toMatchObject({
      ok: true,
      profile: "test",
      status: "passed",
      commands: [{
        profile: "test",
        script: "test",
        command: "npm run test -- tests/auth.test.ts",
        status: "passed",
        stdout_tail: expect.stringContaining("tests/auth.test.ts")
      }],
      focused: true,
      test_paths: ["tests/auth.test.ts"],
      validation_artifact: {
        path: expect.stringMatching(/^\.chatgpt\/validation\/validation-[^/]+\/result\.json$/)
      }
    });
    expect(result.validation_id).toMatch(/^validation-/);

    const artifact = JSON.parse(await readFile(join(root, result.validation_artifact!.path), "utf8")) as {
      validation_id?: string;
      focused?: boolean;
      test_paths?: string[];
      commands?: Array<{ stdout_tail?: string }>;
    };
    expect(artifact.validation_id).toBe(result.validation_id);
    expect(artifact.focused).toBe(true);
    expect(artifact.test_paths).toEqual(["tests/auth.test.ts"]);
    expect(artifact.commands?.[0]?.stdout_tail).toContain("tests/auth.test.ts");

    const latest = JSON.parse(await readFile(join(root, ".chatgpt", "validation", "latest.json"), "utf8")) as {
      validation_id?: string;
      focused?: boolean;
      test_paths?: string[];
      worktree_fingerprint?: string;
    };
    expect(latest.validation_id).toBe(result.validation_id);
    expect(latest.focused).toBe(true);
    expect(latest.test_paths).toEqual(["tests/auth.test.ts"]);
    expect(latest.worktree_fingerprint).toBeTypeOf("string");
  });

  test("rejects focused test paths outside configured validation globs", async () => {
    const root = await fixtureRepo({
      scripts: { test: "node -e \"console.log('ok')\"" }
    });

    await expect(service(root, { validation_test_path_globs: ["tests/**"] }).validate({
      repo_id: "fixture",
      profile: "test",
      test_paths: ["src/app.ts"],
      dry_run: true
    })).rejects.toMatchObject({ code: "VALIDATION_TEST_PATH_NOT_ALLOWED" });
  });

  test("rejects focused test paths for a declared just profile", async () => {
    const root = await fixtureRepo({ scripts: { test: "echo fallback" } });

    await expect(service(root, {
      validation_test_path_globs: ["tests/**"],
      validation_profiles: { test: { runner: "just", target: "test" } }
    }).validate({
      repo_id: "fixture",
      profile: "test",
      test_paths: ["tests/auth.test.ts"],
      dry_run: true
    })).rejects.toMatchObject({
      code: "VALIDATION_TEST_PATHS_DISABLED",
      message: "Focused test paths are not supported by the declared repository validation profile."
    });
  });

  test("allows overlapping validations and preserves each receipt", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "node concurrent-validation.cjs" } });
    const startedPath = join(root, "started.txt");
    const releasePath = join(root, "release.txt");
    const runner = [
      'const { appendFileSync, existsSync } = require("node:fs");',
      `appendFileSync(${JSON.stringify(startedPath)}, String(process.pid) + "\\n");`,
      `const releasePath = ${JSON.stringify(releasePath)};`,
      "const gate = new Int32Array(new SharedArrayBuffer(4));",
      "const deadline = Date.now() + 8_000;",
      "while (!existsSync(releasePath) && Date.now() < deadline) Atomics.wait(gate, 0, 0, 20);",
      "if (!existsSync(releasePath)) process.exit(2);",
      "console.log(JSON.stringify({ pid: process.pid }));"
    ].join("\n");
    await writeFile(join(root, "concurrent-validation.cjs"), runner);

    const validator = service(root);
    const runs = [
      validator.validate({ repo_id: "fixture", profile: "smoke" }),
      validator.validate({ repo_id: "fixture", profile: "smoke" })
    ];
    let started: string[] | undefined;
    let startError: unknown;
    try {
      started = await waitForFileLineCount(startedPath, 2);
    } catch (error) {
      startError = error;
    } finally {
      await writeFile(releasePath, "release\n");
    }

    const settled = await Promise.allSettled(runs);
    if (startError) throw startError;
    expect(started).toHaveLength(2);
    expect(new Set(started).size).toBe(2);
    expect(settled.every((result) => result.status === "fulfilled")).toBe(true);
    const results = settled.map((result) => {
      if (result.status === "rejected") throw result.reason;
      return result.value;
    });
    expect(results.map((result) => result.status)).toEqual(["passed", "passed"]);
    const validationIds = results.map((result) => result.validation_id);
    expect(new Set(validationIds).size).toBe(2);

    const latest = JSON.parse(await readFile(join(root, ".chatgpt", "validation", "latest.json"), "utf8")) as {
      validation_id?: string;
      artifact_path?: string;
    };
    const latestResult = results.find((result) => result.validation_id === latest.validation_id);
    expect(latestResult).toBeDefined();
    expect(latest.artifact_path).toBe(latestResult?.validation_artifact?.path);
    for (const result of results) {
      const artifact = JSON.parse(await readFile(join(root, result.validation_artifact!.path), "utf8")) as {
        validation_id?: string;
      };
      expect(artifact.validation_id).toBe(result.validation_id);
    }
  });
});

async function waitForFile(path: string): Promise<string> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    try {
      return await readFile(path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await delay(20);
    }
  }
  throw new Error(`Timed out waiting for ${path}.`);
}

async function waitForFileLineCount(path: string, count: number): Promise<string[]> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    try {
      const lines = (await readFile(path, "utf8")).split(/\r?\n/).filter(Boolean);
      if (lines.length >= count) return lines;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await delay(20);
  }
  throw new Error(`Timed out waiting for ${count} lines in ${path}.`);
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ESRCH") return false;
    throw error;
  }
}

async function expectProcessGone(pid: number): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (isProcessAlive(pid) && Date.now() < deadline) await delay(20);
  expect(isProcessAlive(pid)).toBe(false);
}

function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => { resolve = complete; });
  return { promise, resolve };
}

function service(
  root: string,
  operations: Partial<ConstructorParameters<typeof OperationsPolicy>[0]> = {},
  runtimeOptions: NodeRuntimeResolverOptions = {}
): ValidationService {
  return new ValidationService(root, new OperationsPolicy({
    enabled: true,
    validation_enabled: true,
    ...operations
  }), runtimeOptions);
}

async function envProbeJust(): Promise<void> {
  const bin = await createTempDir("gpt-just-env-probe-");
  const just = join(bin, "just");
  await writeFile(
    just,
    `#!${process.execPath}\n` +
      `const keys = ["HOME", "XDG_CONFIG_HOME", "CI", "NO_COLOR", "npm_config_color", "VALIDATION_ENV_LEAK"];\n` +
      `console.log(JSON.stringify(Object.fromEntries(keys.map((key) => [key, process.env[key] ?? null]))));\n`
  );
  await chmod(just, 0o755);
  process.env.PATH = `${bin}${delimiter}${process.env.PATH ?? ""}`;
}

function lastJsonLine(stdoutTail: string | undefined): unknown {
  const finalLine = stdoutTail?.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).at(-1);
  if (!finalLine) {
    throw new SyntaxError("Validation command produced no JSON output.");
  }
  return JSON.parse(finalLine);
}

function captureEnv(keys: string[]): Record<string, string | undefined> {
  return Object.fromEntries(keys.map((key) => [key, process.env[key]]));
}

function restoreEnv(original: Record<string, string | undefined>): void {
  for (const [key, value] of Object.entries(original)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
}

async function fixtureRepo(options: {
  scripts?: Record<string, string>;
  pythonMarker?: boolean;
  localPython?: boolean | "non-executable";
  nodeVersion?: string;
  nvmrc?: string;
  voltaNode?: string;
  enginesNode?: string;
}): Promise<string> {
  const root = await createTempDir("gpt-repo-validation-");
  await mkdir(root, { recursive: true });
  if (options.scripts) {
    await writeFile(join(root, "package.json"), JSON.stringify({
      type: "module",
      scripts: options.scripts,
      ...(options.voltaNode ? { volta: { node: options.voltaNode } } : {}),
      ...(options.enginesNode ? { engines: { node: options.enginesNode } } : {})
    }, null, 2));
  }
  if (options.nodeVersion) await writeFile(join(root, ".node-version"), `${options.nodeVersion}\n`);
  if (options.nvmrc) await writeFile(join(root, ".nvmrc"), `${options.nvmrc}\n`);
  if (options.pythonMarker) await writeFile(join(root, "pyproject.toml"), "[tool.pytest.ini_options]\n");
  if (options.localPython) {
    const python = join(root, ".venv", "bin", "python");
    await mkdir(join(root, ".venv", "bin"), { recursive: true });
    await writeFile(python, "#!/usr/bin/env node\nconsole.log(process.argv.slice(2).join('|'))\n");
    await chmod(python, options.localPython === "non-executable" ? 0o644 : 0o755);
  }
  await mkdir(join(root, "venv", "bin"), { recursive: true });
  return root;
}

async function fakeNvmRuntime(version: string): Promise<{ home: string; options: NodeRuntimeResolverOptions }> {
  const home = await createTempDir("gpt-runtime-home-");
  await fakeNodeExecutable(join(home, ".nvm", "versions", "node", `v${version}`, "bin", "node"), version);
  return { home, options: { home, env: {} } };
}

async function fakeNodeExecutable(path: string, version: string): Promise<string> {
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, `#!${process.execPath}\n` +
    `const { spawnSync } = require("node:child_process");\n` +
    `if (process.argv[2] === "--version") { console.log("v${version}"); process.exit(0); }\n` +
    `const result = spawnSync(${JSON.stringify(process.execPath)}, process.argv.slice(2), { stdio: "inherit", env: { ...process.env, FAKE_NODE_RUNTIME: "${version}" } });\n` +
    `process.exit(result.status ?? 1);\n`);
  await chmod(path, 0o755);
  return path;
}
