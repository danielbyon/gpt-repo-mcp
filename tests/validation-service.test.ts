import { chmod, mkdir, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { delimiter, dirname, join } from "node:path";
import { describe, expect, test, vi } from "vitest";
import { ValidationService } from "../src/services/validation-service.js";
import { GitReviewService } from "../src/services/git-review-service.js";
import { RustRuntimeResolver } from "../src/services/rust-runtime-resolver.js";
import { OperationsPolicy } from "../src/services/operations-policy.js";
import * as fsHelpers from "../src/runtime/fs-helpers.js";
import { GitService } from "../src/services/git-service.js";
import { ValidateInputSchema, ValidationLatestPointerV2Schema, ValidationReceiptV2Schema } from "../src/contracts/validation.contract.js";
import { descriptions } from "../src/tools/descriptions.js";
import type { NodeRuntimeResolverOptions } from "../src/services/node-runtime-resolver.js";
import { waitForFile, waitForFileLineCount } from "./fixtures/file-event-wait.js";
import { copyNscbMakefileFixture } from "./fixtures/nscb-makefile.js";
import { createTempDir } from "./fixtures/temp-dir.js";
import { createExternalValidationCoordination, createTrustedTestRunner, withTrustedRunnerPath } from "./fixtures/validation-test-tools.js";
import * as processExec from "../src/services/process-exec.js";
import { canonicalSha256, type ValidationSourceSnapshot } from "../src/services/validation-evidence.js";

describe("ValidationService", () => {
  test("accepts npm banners before validation JSON and rejects malformed final output", () => {
    expect(lastJsonLine("> smoke\n> fixture\n{\"ok\":true}")).toEqual({ ok: true });
    expect(() => lastJsonLine("{\"ok\":true}\nmalformed")).toThrow(SyntaxError);
  });

  test("tool and contract describe fixed profiles, constrained paths, and shell-free Windows supervision", async () => {
    expect(descriptions.repo_validate).toContain("Fixed Make/Just, npm, pytest profiles");
    expect(descriptions.repo_validate).toContain("test_paths");
    expect(descriptions.repo_validate).toContain("absolute native paths and argv");
    expect(descriptions.repo_validate).toContain("can start shells");
    expect(descriptions.repo_validate).toContain("neither inspects nor sandboxes");
    expect(descriptions.repo_validate).toContain("Callers cannot choose commands, executables, or args");
    expect(descriptions.repo_validate).not.toContain("cmd.exe may launch");
    expect(ValidateInputSchema.shape.profile.description).toContain("detected pytest test fallback");
    expect(ValidateInputSchema.shape.test_paths.description).toContain("validation_test_path_globs");
    const source = await readFile(join(process.cwd(), "src", "services", "validation-service.ts"), "utf8");
    expect(source).toContain("runProcessWithTail({");
    expect(source).not.toContain("shell: true");
  });
  test("selects pytest for a Python repository without package.json", async () => {
    const root = await fixtureRepo({ pythonMarker: true, localPython: true });
    const result = await service(root).validate({ repo_id: "fixture", profile: "test", dry_run: true });
    expect(result.commands[0]).toMatchObject({ profile: "test", script: "pytest", command: ".venv/bin/python -m pytest", status: "skipped" });
    expect(result.commands[0]?.executable_identity).toMatchObject({ sha256: expect.any(String), path_sha256: expect.any(String) });
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

  test.skipIf(process.platform === "win32")("runs Windows npm validation through the pinned node.exe and its adjacent npm-cli.js", async () => {
    const version = "24.18.0";
    const root = await fixtureRepo({ scripts: { test: "node -e process.exit(0)" }, nodeVersion: version });
    const runtime = await fakeWindowsNvmRuntime(version);
    const npmCli = join(dirname(runtime.node), "node_modules", "npm", "bin", "npm-cli.js");
    await mkdir(join(npmCli, ".."), { recursive: true });
    await writeFile(npmCli, "process.exit(0);\n");
    const originalSystemEnvironment = { SystemRoot: process.env.SystemRoot, ComSpec: process.env.ComSpec };
    process.env.SystemRoot = "C:\\Windows";
    process.env.ComSpec = "C:\\Tools\\powershell.exe";
    const processSpy = vi.spyOn(processExec, "runProcessWithTail").mockResolvedValue({
      exit_code: 0,
      duration_ms: 1,
      timed_out: false,
      cancelled: false,
      cleanup_confirmed: true,
      stdout_tail: "",
      stderr_tail: ""
    });

    try {
      const result = await service(root, {}, runtime.options).validate({ repo_id: "fixture", profile: "test" });
      expect(result.status).toBe("passed");
      expect(processSpy).toHaveBeenCalledWith(expect.objectContaining({
        executable: await realpath(runtime.node),
        args: [await realpath(npmCli), "run", "test"],
        env: expect.objectContaining({
          PATH: `${dirname(await realpath(runtime.node))};${process.env.PATH ?? ""}`,
          ComSpec: "C:\\Windows\\System32\\cmd.exe"
        })
      }));
      expect(processSpy.mock.calls[0]?.[0].executable).not.toMatch(/npm(?:\.cmd)?$/i);
    } finally {
      processSpy.mockRestore();
      restoreEnv(originalSystemEnvironment);
    }
  });

  test.skipIf(process.platform === "win32").each([
    ["missing", undefined],
    ["relative", "Windows"]
  ] as const)("does not start Windows npm validation with %s SystemRoot", async (_case, systemRoot) => {
    const root = await fixtureRepo({ scripts: { test: "node -e process.exit(0)" }, nodeVersion: "24.18.0" });
    const runtime = await fakeWindowsNvmRuntime("24.18.0");
    const npmCli = join(dirname(runtime.node), "node_modules", "npm", "bin", "npm-cli.js");
    await mkdir(join(npmCli, ".."), { recursive: true });
    await writeFile(npmCli, "process.exit(0);\n");
    const originalSystemEnvironment = { SystemRoot: process.env.SystemRoot, ComSpec: process.env.ComSpec };
    if (systemRoot) process.env.SystemRoot = systemRoot;
    else delete process.env.SystemRoot;
    process.env.ComSpec = "C:\\Tools\\cmd.exe";
    const processSpy = vi.spyOn(processExec, "runProcessWithTail");

    try {
      await expect(service(root, {}, runtime.options).validate({ repo_id: "fixture", profile: "test" }))
        .rejects.toMatchObject({
          code: "VALIDATION_PROFILE_UNAVAILABLE",
          diagnostics: { recovery_hint: expect.stringContaining("SystemRoot") }
        });
      expect(processSpy).not.toHaveBeenCalled();
    } finally {
      processSpy.mockRestore();
      restoreEnv(originalSystemEnvironment);
    }
  });

  test.skipIf(process.platform !== "win32")("does not start Windows npm validation when System32/cmd.exe is unavailable", async () => {
    const version = process.version.slice(1);
    const root = await fixtureRepo({ scripts: { test: "node -e process.exit(0)" }, nodeVersion: version });
    const home = await createTempDir("gpt-windows-missing-shell-");
    const runtimeOptions: NodeRuntimeResolverOptions = {
      platform: "win32",
      home,
      env: {
        NVM_HOME: join(home, "nvm"),
        APPDATA: join(home, "roaming"),
        LOCALAPPDATA: join(home, "local"),
        FNM_DIR: join(home, "fnm"),
        VOLTA_HOME: join(home, "volta"),
        MISE_INSTALLS_DIR: join(home, "mise-installs"),
        ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {})
      }
    };
    const invalidSystemRoot = await createTempDir("gpt-missing-system-shell-");
    const originalSystemEnvironment = { SystemRoot: process.env.SystemRoot, ComSpec: process.env.ComSpec };
    process.env.SystemRoot = invalidSystemRoot;
    const processSpy = vi.spyOn(processExec, "runProcessWithTail");

    try {
      await expect(service(root, {}, runtimeOptions).validate({ repo_id: "fixture", profile: "test" }))
        .rejects.toMatchObject({
          code: "VALIDATION_PROFILE_UNAVAILABLE",
          diagnostics: { recovery_hint: expect.stringContaining("cmd.exe") }
        });
      expect(processSpy).not.toHaveBeenCalled();
    } finally {
      processSpy.mockRestore();
      restoreEnv(originalSystemEnvironment);
    }
  });

  test.skipIf(process.platform === "win32")("does not fall back to npm.cmd when the selected Node runtime lacks npm-cli.js", async () => {
    const version = "24.18.0";
    const root = await fixtureRepo({ scripts: { test: "node -e process.exit(0)" }, nodeVersion: version });
    const runtime = await fakeWindowsNvmRuntime(version);
    await writeFile(join(runtime.bin, "npm.cmd"), "@echo off\r\n");
    const processSpy = vi.spyOn(processExec, "runProcessWithTail");

    try {
      await expect(service(root, {}, runtime.options).validate({ repo_id: "fixture", profile: "test" }))
        .rejects.toMatchObject({
          code: "VALIDATION_PROFILE_UNAVAILABLE",
          diagnostics: { recovery_hint: expect.stringContaining("npm.cmd") }
        });
      expect(processSpy).not.toHaveBeenCalled();
    } finally {
      processSpy.mockRestore();
    }
  });

  test.skipIf(process.platform === "win32")("rejects a bundled npm CLI that resolves outside the selected Node installation", async () => {
    const version = "24.18.0";
    const root = await fixtureRepo({ scripts: { test: "node -e process.exit(0)" }, nodeVersion: version });
    const runtime = await fakeWindowsNvmRuntime(version);
    const npmDirectory = join(dirname(runtime.node), "node_modules", "npm", "bin");
    const npmCli = join(npmDirectory, "npm-cli.js");
    const outside = join(await createTempDir("gpt-untrusted-npm-cli-"), "npm-cli.js");
    await mkdir(npmDirectory, { recursive: true });
    await writeFile(outside, "process.exit(0);\n");
    await symlink(outside, npmCli);
    const processSpy = vi.spyOn(processExec, "runProcessWithTail");

    try {
      await expect(service(root, {}, runtime.options).validate({ repo_id: "fixture", profile: "test" }))
        .rejects.toMatchObject({ code: "VALIDATION_PROFILE_UNAVAILABLE" });
      expect(processSpy).not.toHaveBeenCalled();
    } finally {
      processSpy.mockRestore();
    }
  });

  test.skipIf(process.platform !== "win32")("runs Windows npm through the exact running Node and bundled npm CLI", async () => {
    const version = process.version.slice(1);
    const root = await fixtureRepo({ scripts: { test: "node -e process.exit(0)" }, nodeVersion: version });
    const home = await createTempDir("gpt-windows-current-node-");
    const runtimeOptions: NodeRuntimeResolverOptions = {
      platform: "win32",
      home,
      env: {
        NVM_HOME: join(home, "nvm"),
        APPDATA: join(home, "roaming"),
        LOCALAPPDATA: join(home, "local"),
        FNM_DIR: join(home, "fnm"),
        VOLTA_HOME: join(home, "volta"),
        MISE_INSTALLS_DIR: join(home, "mise-installs"),
        ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {})
      }
    };
    const executable = await realpath(process.execPath);
    const npmCli = await realpath(join(dirname(executable), "node_modules", "npm", "bin", "npm-cli.js"));
    const processSpy = vi.spyOn(processExec, "runProcessWithTail").mockResolvedValue({
      exit_code: 0,
      duration_ms: 1,
      timed_out: false,
      cancelled: false,
      cleanup_confirmed: true,
      stdout_tail: "",
      stderr_tail: ""
    });

    try {
      const result = await service(root, {}, runtimeOptions).validate({ repo_id: "fixture", profile: "test" });
      expect(result.status).toBe("passed");
      expect(processSpy).toHaveBeenCalledWith(expect.objectContaining({
        executable,
        args: [npmCli, "run", "test"],
        env: expect.objectContaining({ PATH: `${dirname(executable)};${process.env.PATH ?? ""}` })
      }));
    } finally {
      processSpy.mockRestore();
    }
  });

  test.each([
    ["make", "make.exe"],
    ["just", "just.exe"]
  ] as const)("resolves the configured Windows %s profile to its native executable", async (runner, fileName) => {
    const root = await fixtureRepo({});
    await writeFile(join(root, runner === "make" ? "Makefile" : "justfile"), runner === "make" ? "unit:\n\t@true\n" : "unit:\n  echo ok\n");
    const bin = await createTempDir("gpt native runner bin ");
    const executable = join(bin, fileName);
    await writeFile(executable, "MZ-native-test-fixture\n");
    const processSpy = vi.spyOn(processExec, "runProcessWithTail").mockResolvedValue({
      exit_code: 0,
      duration_ms: 1,
      timed_out: false,
      cancelled: false,
      cleanup_confirmed: true,
      stdout_tail: "",
      stderr_tail: ""
    });

    try {
      const result = await service(root, {
        validation_profiles: { test: { runner, target: "unit" } }
      }, { platform: "win32", env: { PATH: bin } }).validate({ repo_id: "fixture", profile: "test" });
      expect(result.status).toBe("passed");
      expect(processSpy).toHaveBeenCalledWith(expect.objectContaining({
        executable: await realpath(executable),
        args: ["unit"]
      }));
      expect(processSpy.mock.calls[0]?.[0].env).not.toHaveProperty("ComSpec");
    } finally {
      processSpy.mockRestore();
    }
  });

  test.each(["make.cmd", "make.bat", "make.ps1"])("does not resolve Windows command shim %s", async (shim) => {
    const root = await fixtureRepo({});
    const bin = await createTempDir("gpt runner shim ");
    await writeFile(join(bin, shim), "shim\n");
    const processSpy = vi.spyOn(processExec, "runProcessWithTail");

    try {
      await expect(service(root, {
        validation_profiles: { test: { runner: "make", target: "unit" } }
      }, { platform: "win32", env: { PATH: bin } }).validate({ repo_id: "fixture", profile: "test" }))
        .rejects.toMatchObject({
          code: "VALIDATION_PROFILE_UNAVAILABLE",
          diagnostics: { recovery_hint: expect.stringContaining("native .exe") }
        });
      expect(processSpy).not.toHaveBeenCalled();
    } finally {
      processSpy.mockRestore();
    }
  });

  test("does not select a repository-controlled make.exe from the worktree", async () => {
    const root = await fixtureRepo({});
    const executable = join(root, "make.exe");
    await writeFile(executable, "MZ-repository-fixture\n");
    const processSpy = vi.spyOn(processExec, "runProcessWithTail");

    try {
      await expect(service(root, {
        validation_profiles: { test: { runner: "make", target: "unit" } }
      }, { platform: "win32", env: { PATH: root } }).validate({ repo_id: "fixture", profile: "test" }))
        .rejects.toMatchObject({ code: "VALIDATION_PROFILE_UNAVAILABLE" });
      expect(processSpy).not.toHaveBeenCalled();
    } finally {
      processSpy.mockRestore();
    }
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

  test.skipIf(process.platform === "win32")("executes the configured all profile as make all", async () => {
    const root = await fixtureRepo({});
    await writeFile(join(root, "Makefile"), "all:\n\t@echo make-all-ok\n");
    const result = await service(root, {
      validation_profiles: { all: { runner: "make", target: "all" } }
    }).validate({ repo_id: "fixture", profile: "all" });

    expect(result.commands[0]).toMatchObject({
      command: "make all",
      status: "passed",
      stdout_tail: expect.stringContaining("make-all-ok")
    });
  });

  test("declared just profile takes priority over npm and pytest fallback", async () => {
    const root = await fixtureRepo({
      scripts: { test: "echo npm-should-not-run" },
      pythonMarker: true,
      localPython: true
    });
    await writeFile(join(root, "justfile"), "test:\n    @echo just-test\n");
    const fake = await createTrustedTestRunner("just", 'throw new Error("dry run must not execute the selected runner");', { dryRunOnly: true });
    const processSpy = vi.spyOn(processExec, "runProcessWithTail");

    try {
      await withTrustedRunnerPath(fake.bin, async () => {
        const result = await service(root, {
          validation_profiles: { test: { runner: "just", target: "test" } }
        }).validate({ repo_id: "fixture", profile: "test", dry_run: true });
        expect(result.commands).toMatchObject([{
          profile: "test",
          script: "just:test",
          command: "just test",
          executable: process.platform === "win32" ? fake.executable : "just",
          status: "skipped"
        }]);
        expect(processSpy).not.toHaveBeenCalled();
      });
    } finally {
      processSpy.mockRestore();
    }
  });

  test.skipIf(process.platform === "win32")("executes a declared just profile directly with a single target argument", async () => {
    const fake = await createTrustedTestRunner("just",
      'console.log("x".repeat(5000));\nconsole.log("args:" + process.argv.slice(2).join("|"));');

    await withTrustedRunnerPath(fake.bin, async () => {
      const root = await fixtureRepo({});
      await writeFile(join(root, "justfile"), "smoke:\n    @echo smoke\n");
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
    });
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
    await writeFile(join(root, "justfile"), "smoke:\n    @echo smoke\n");
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
    await writeFile(join(root, "justfile"), "smoke:\n    @echo smoke\n");
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

    try {
      const childPid = Number(await waitForFile(childReadyPath));
      const parentPid = Number(await waitForFile(parentPidPath));
      expect(isProcessAlive(parentPid)).toBe(true);
      expect(isProcessAlive(childPid)).toBe(true);
      controller.abort();

      await expect(validationPromise).rejects.toMatchObject({ name: "AbortError" });
      expect(isProcessAlive(parentPid)).toBe(false);
      expect(isProcessAlive(childPid)).toBe(false);
      await expect(readFile(join(root, ".chatgpt", "validation", "latest.json"), "utf8"))
        .rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      controller.abort();
      await writeFile(cleanupPath, "stop");
      await validationPromise.catch(() => undefined);
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
        .rejects.toMatchObject({ code: "VALIDATION_PROCESS_CLEANUP_UNCONFIRMED" });
      expect(await readFile(latestPath, "utf8")).toBe(previousReceipt);
    } finally {
      processSpy.mockRestore();
    }
  });

  test("does not publish a validation receipt after process supervision fails", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo validation-complete" } });
    const validationDirectory = join(root, ".chatgpt", "validation");
    const latestPath = join(validationDirectory, "latest.json");
    const previousReceipt = "previous committed receipt";
    await mkdir(validationDirectory, { recursive: true });
    await writeFile(latestPath, previousReceipt);
    const artifactsBefore = await readdir(validationDirectory);
    vi.spyOn(processExec, "runProcessWithTail").mockResolvedValue({
      timed_out: false,
      cancelled: false,
      cleanup_confirmed: true,
      host_failure: "The process anchor could not be started.",
      duration_ms: 1,
      stdout_tail: "",
      stderr_tail: ""
    } as never);

    try {
      await expect(service(root).validate({ repo_id: "fixture", profile: "smoke" }))
        .rejects.toMatchObject({ code: "VALIDATION_PROCESS_SUPERVISION_FAILED" });
      expect(await readFile(latestPath, "utf8")).toBe(previousReceipt);
      expect(await readdir(validationDirectory)).toEqual(artifactsBefore);
    } finally {
      vi.restoreAllMocks();
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
    const validationDirectory = join(root, ".chatgpt", "validation");
    const latestPath = join(validationDirectory, "latest.json");
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
      expect((await readdir(validationDirectory)).sort()).toEqual(["latest.json"]);
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

  test("preserves the result when an admitted receipt commit errors after publication", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo validation-complete" } });
    const latestPath = join(root, ".chatgpt", "validation", "latest.json");
    const controller = new AbortController();
    const originalWrite = fsHelpers.atomicWriteJson;
    const writeSpy = vi.spyOn(fsHelpers, "atomicWriteJson").mockImplementation(async (path, value) => {
      if (path.endsWith("latest.json")) {
        await originalWrite(path, value);
        controller.abort();
        throw new Error("injected post-publication write error");
      }
      return originalWrite(path, value);
    });

    try {
      await expect(service(root).validate({ repo_id: "fixture", profile: "smoke" }, { signal: controller.signal }))
        .rejects.toThrow("injected post-publication write error");
      const latest = JSON.parse(await readFile(latestPath, "utf8")) as {
        validation_id?: string;
        artifact_path?: string;
      };
      expect(latest.artifact_path).toBe(`.chatgpt/validation/${latest.validation_id}/result.json`);
      const artifact = JSON.parse(await readFile(join(root, latest.artifact_path!), "utf8")) as {
        validation_id?: string;
      };
      expect(artifact.validation_id).toBe(latest.validation_id);
    } finally {
      controller.abort();
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
      .rejects.toMatchObject({ code: "VALIDATION_ARTIFACT_WRITE_FAILED" });
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

  test("writes an eligible V2 receipt that review independently verifies", async () => {
    const root = await fixtureRepo({ scripts: { test: "node -e \"console.log('validation-ok')\"" } });
    await initializeGitFixture(root);
    const policy = new OperationsPolicy({ enabled: true, validation_enabled: true });

    const result = await new ValidationService(root, policy).validate({ repo_id: "fixture", profile: "test" });
    const receipt = JSON.parse(await readFile(join(root, result.validation_artifact!.path), "utf8")) as {
      schema_version: number;
      evidence_contract_version: number;
      status: string;
      eligibility: { status: string; reasons: string[] };
      source_evidence: {
        before: { sha256: string };
        after: { sha256: string };
        observation: string;
        continuous_detection: boolean;
        limitation: string;
      };
    };
    expect(result.status).toBe("passed");
    expect(receipt).toMatchObject({
      schema_version: 2,
      evidence_contract_version: 2,
      status: "passed",
      eligibility: { status: "eligible", reasons: [] },
      source_evidence: {
        observation: "endpoint_snapshots_only",
        continuous_detection: false,
        limitation: "Endpoint snapshots do not establish detection of transient change-and-revert activity."
      }
    });
    expect(receipt.source_evidence.before.sha256).toBe(receipt.source_evidence.after.sha256);

    const review = await new GitReviewService(root, policy).review({ repo_id: "fixture" });
    expect(review.ship_readiness.validation).toMatchObject({
      status: "passed",
      eligibility: "eligible",
      evidence_contract_version: 2,
      validation_id: result.validation_id,
      profile: "test"
    });
    const otherRepo = await new GitReviewService(root, policy).review({ repo_id: "other-repository" });
    expect(otherRepo.ship_readiness.validation).toMatchObject({ status: "unverified", eligibility: "unverified" });

    const packagePath = join(root, "package.json");
    const packageBytes = await readFile(packagePath, "utf8");
    await writeFile(packagePath, packageBytes.replace("validation-ok", "changed-after-validation"));
    const changedCandidate = await new GitReviewService(root, policy).review({ repo_id: "fixture" });
    expect(changedCandidate.ship_readiness.validation).toMatchObject({ status: "stale", eligibility: "ineligible" });
    await writeFile(packagePath, packageBytes);

    const changedPolicy = new OperationsPolicy({
      enabled: true,
      validation_enabled: true,
      validation_test_path_globs: ["tests/**"]
    });
    const policyMismatch = await new GitReviewService(root, changedPolicy).review({ repo_id: "fixture" });
    expect(policyMismatch.ship_readiness.validation).toMatchObject({ status: "stale", eligibility: "ineligible" });

    const latestPath = join(root, ".chatgpt", "validation", "latest.json");
    const latestBytes = await readFile(latestPath, "utf8");
    const pointer = JSON.parse(latestBytes) as { artifact_path: string };
    pointer.artifact_path = "../outside.json";
    await writeFile(latestPath, JSON.stringify(pointer));
    const escapedArtifact = await new GitReviewService(root, policy).review({ repo_id: "fixture" });
    expect(escapedArtifact.ship_readiness.validation).toMatchObject({ status: "unverified", eligibility: "unverified" });

    await writeFile(latestPath, latestBytes);
    const receiptPath = join(root, result.validation_artifact!.path);
    const tamperedReceipt = JSON.parse(await readFile(receiptPath, "utf8")) as { repo_id: string };
    tamperedReceipt.repo_id = "different-repository";
    await writeFile(receiptPath, JSON.stringify(tamperedReceipt));
    const mismatchedReceipt = await new GitReviewService(root, policy).review({ repo_id: "fixture" });
    expect(mismatchedReceipt.ship_readiness.validation).toMatchObject({ status: "unverified", eligibility: "unverified" });
  });

  test("keeps an eligible validation receipt current when an untracked Delegation RESULT.json changes", async () => {
    const root = await fixtureRepo({ scripts: { test: "node -e \"console.log('validation-ok')\"" } });
    await initializeGitFixture(root);
    const resultPath = join(root, ".chatgpt", "codex-runs", "2026-11-06T092748Z-issue-44", "RESULT.json");
    await mkdir(join(root, ".chatgpt", "codex-runs", "2026-11-06T092748Z-issue-44"), { recursive: true });
    await writeFile(resultPath, "{\"state\":\"before\"}\n");
    const policy = new OperationsPolicy({ enabled: true, validation_enabled: true });

    const result = await new ValidationService(root, policy).validate({ repo_id: "fixture", profile: "test" });
    const reviewService = new GitReviewService(root, policy);
    expect((await reviewService.review({ repo_id: "fixture" })).ship_readiness.validation)
      .toMatchObject({ status: "passed", eligibility: "eligible", validation_id: result.validation_id });

    await writeFile(resultPath, "{\"state\":\"after\"}\n");
    const reviewAfterControlArtifactChange = await reviewService.review({ repo_id: "fixture" });
    expect(reviewAfterControlArtifactChange.ship_readiness.validation)
      .toMatchObject({ status: "passed", eligibility: "eligible", validation_id: result.validation_id });
  });

  test("keeps command outcome passed while staged index drift makes V2 ineligible", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo validation-ok" } });
    await writeFile(join(root, "state.txt"), "committed state\n");
    await initializeGitFixture(root);
    const original = await readFile(join(root, "state.txt"), "utf8");
    const processSpy = vi.spyOn(processExec, "runProcessWithTail").mockImplementation(async () => {
      await writeFile(join(root, "state.txt"), "staged state\n");
      execFileSync("git", ["add", "state.txt"], { cwd: root, stdio: "ignore" });
      await writeFile(join(root, "state.txt"), original);
      return {
        timed_out: false,
        cancelled: false,
        cleanup_confirmed: true,
        exit_code: 0,
        duration_ms: 1,
        stdout_tail: "validation-ok",
        stderr_tail: ""
      };
    });

    try {
      const result = await service(root).validate({ repo_id: "fixture", profile: "smoke" });
      const receipt = JSON.parse(await readFile(join(root, result.validation_artifact!.path), "utf8")) as {
        status: string;
        eligibility: { status: string; reasons: string[] };
        source_evidence: {
          before: { sha256: string; index: { sha256: string } };
          after: { sha256: string; index: { sha256: string } };
        };
      };
      expect(result.status).toBe("passed");
      expect(receipt.status).toBe("passed");
      expect(receipt.eligibility).toMatchObject({ status: "ineligible", reasons: ["SOURCE_STATE_CHANGED_DURING_RUN"] });
      expect(receipt.source_evidence.before.index.sha256).not.toBe(receipt.source_evidence.after.index.sha256);
      expect(receipt.source_evidence.before.sha256).not.toBe(receipt.source_evidence.after.sha256);
    } finally {
      processSpy.mockRestore();
    }
  });

  test("preserves the latest receipt when a validation id collides with an existing artifact", async () => {
    const root = await fixtureRepo({ scripts: { smoke: "echo ok" } });
    await initializeGitFixture(root);
    const result = await service(root).validate({ repo_id: "fixture", profile: "smoke" });
    const artifactPath = join(root, result.validation_artifact!.path);
    const latestPath = join(root, ".chatgpt", "validation", "latest.json");
    const previousReceipt = await readFile(artifactPath, "utf8");
    const previousPointer = await readFile(latestPath, "utf8");
    const priorEvidence = JSON.parse(previousReceipt) as {
      source_evidence: Record<string, unknown>;
      effective_policy: { value: unknown };
      runner_post_state: unknown[];
    };
    const writer = service(root) as unknown as {
      writeValidationArtifact(result: unknown, evidence: unknown): Promise<string>;
    };

    await expect(writer.writeValidationArtifact(result, {
      sourceEvidence: priorEvidence.source_evidence,
      policyBefore: priorEvidence.effective_policy.value,
      policyAfter: priorEvidence.effective_policy.value,
      runnerPostState: priorEvidence.runner_post_state
    })).rejects.toMatchObject({ code: "VALIDATION_ARTIFACT_WRITE_FAILED" });

    await expect(readFile(artifactPath, "utf8")).resolves.toBe(previousReceipt);
    await expect(readFile(latestPath, "utf8")).resolves.toBe(previousPointer);
  });

  test.skipIf(process.platform === "win32")("keeps an unchanged Rust receipt eligible after review and preserves the recipe's test thread setting", async () => {
    const root = await fixtureRepo({});
    await writeFile(join(root, "rust-toolchain.toml"), '[toolchain]\nchannel = "1.98.1"\n');
    await writeFile(join(root, "Cargo.toml"), "[workspace]\nresolver = \"2\"\n");
    await mkdir(join(root, "scripts"), { recursive: true });
    await writeFile(join(root, "Makefile"), "test:\n\tRUST_TEST_THREADS=1 ./scripts/run-tests.sh\n");
    await writeFile(join(root, "scripts", "run-tests.sh"), "#!/bin/sh\ncargo test\n");
    await chmod(join(root, "scripts", "run-tests.sh"), 0o755);
    const cargoHome = await createTempDir("validation-cargo-home-");
    const rustTools = await createFakeRustToolchain("1.98.1", cargoHome);
    const previousPath = process.env.PATH;
    const previousCargoHome = process.env.CARGO_HOME;
    process.env.PATH = `${rustTools.bin}${delimiter}${previousPath ?? ""}`;
    process.env.CARGO_HOME = cargoHome;
    await initializeGitFixture(root);
    try {
      const operations = {
        validation_profiles: { test: { runner: "make", target: "test" } }
      } as const;
      const result = await service(root, operations).validate({ repo_id: "fixture", profile: "test" });

      expect(result.commands[0]).toMatchObject({
        status: "passed",
        stdout_tail: expect.stringContaining("toolchain=1.98.1; threads=1; rustc=[REDACTED_PATH]"),
        runtime: {
          name: "rust",
          version: "1.98.1",
          cargo_home_path_sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
          cargo_config_sha256: expect.stringMatching(/^[a-f0-9]{64}$/)
        }
      });
      expect(result.commands[0]?.stdout_tail).toContain("cargo-home-matches=true");
      const receipt = JSON.parse(await readFile(join(root, result.validation_artifact!.path), "utf8")) as Record<string, unknown>;
      expect(ValidationReceiptV2Schema.safeParse(receipt).success).toBe(true);
      const missingCargoConfigIdentity = structuredClone(receipt) as {
        commands: Array<{ runtime?: { cargo_config_sha256?: string } }>;
      };
      delete missingCargoConfigIdentity.commands[0]!.runtime!.cargo_config_sha256;
      expect(ValidationReceiptV2Schema.safeParse(missingCargoConfigIdentity).success).toBe(false);

      const review = await new GitReviewService(root, new OperationsPolicy({
        enabled: true,
        validation_enabled: true,
        ...operations
      })).review({ repo_id: "fixture" });
      expect(review.ship_readiness.validation).toMatchObject({
        status: "passed",
        eligibility: "eligible",
        evidence_contract_version: 2,
        validation_status: "passed"
      });
    } finally {
      process.env.PATH = previousPath;
      if (previousCargoHome === undefined) delete process.env.CARGO_HOME;
      else process.env.CARGO_HOME = previousCargoHome;
    }
  });

  test.skipIf(process.platform === "win32")("resolves pinned Rust tools in dry-run without executing Make", async () => {
    const root = await fixtureRepo({});
    await writeFile(join(root, "rust-toolchain.toml"), '[toolchain]\nchannel = "1.98.1"\n');
    await writeFile(join(root, "Makefile"), "test:\n\tcargo test\n");
    const rustTools = await createFakeRustToolchain("1.98.1");
    const previousPath = process.env.PATH;
    process.env.PATH = `${rustTools.bin}${delimiter}${previousPath ?? ""}`;
    const processSpy = vi.spyOn(processExec, "runProcessWithTail");
    try {
      const result = await service(root, {
        validation_profiles: { test: { runner: "make", target: "test" } }
      }).validate({ repo_id: "fixture", profile: "test", dry_run: true });

      expect(result.commands[0]).toMatchObject({
        command: "make test",
        status: "skipped",
        runtime: { name: "rust", version: "1.98.1" }
      });
      expect(processSpy).not.toHaveBeenCalled();
    } finally {
      processSpy.mockRestore();
      process.env.PATH = previousPath;
    }
  });

  test.skipIf(process.platform === "win32")("binds ignored Make helpers in validation and review source evidence", async () => {
    const root = await fixtureRepo({});
    const helperPath = "scripts/ignored-helper.sh";
    await mkdir(join(root, "scripts"), { recursive: true });
    await writeFile(join(root, ".gitignore"), `${helperPath}\n`);
    await writeFile(join(root, "Makefile"), "smoke:\n\t@./scripts/ignored-helper.sh\n");
    await writeFile(join(root, helperPath), "#!/bin/sh\necho first-helper-version\n");
    await chmod(join(root, helperPath), 0o755);
    await initializeGitFixture(root);

    const policy = new OperationsPolicy({
      enabled: true,
      validation_enabled: true,
      validation_profiles: { smoke: { runner: "make", target: "smoke" } }
    });
    const result = await new ValidationService(root, policy).validate({ repo_id: "fixture", profile: "smoke" });
    const receipt = JSON.parse(await readFile(join(root, result.validation_artifact!.path), "utf8")) as {
      receipt_sha256: string;
      source_evidence: {
        before: ValidationSourceSnapshot;
        after: ValidationSourceSnapshot;
      };
      eligibility: { status: string };
    };
    const helperEvidence = receipt.source_evidence.after.files.find((file) => file.path === helperPath);

    expect(result.status).toBe("passed");
    expect(receipt.eligibility.status).toBe("eligible");
    expect(helperEvidence).toMatchObject({ path: helperPath, worktree: { kind: "file", content_sha256: expect.any(String) } });
    expect(execFileSync("git", ["check-ignore", helperPath], { cwd: root, encoding: "utf8" }).trim()).toBe(helperPath);

    const omitRecipeHelper = (snapshot: ValidationSourceSnapshot): ValidationSourceSnapshot => {
      const unsignedSnapshot = Object.fromEntries(Object.entries(snapshot).filter(([key]) => key !== "sha256")) as Omit<ValidationSourceSnapshot, "sha256">;
      const helper = snapshot.files.find((file) => file.path === helperPath)!;
      const unsigned = {
        ...unsignedSnapshot,
        files: snapshot.files.filter((file) => file.path !== helperPath),
        content_bytes: snapshot.content_bytes - helper.worktree.size_bytes
      };
      return { ...unsigned, sha256: canonicalSha256(unsigned) };
    };
    const receiptPath = join(root, result.validation_artifact!.path);
    const omitted = {
      ...receipt,
      source_evidence: {
        ...receipt.source_evidence,
        before: omitRecipeHelper(receipt.source_evidence.before),
        after: omitRecipeHelper(receipt.source_evidence.after)
      }
    };
    const unsignedOmitted = Object.fromEntries(Object.entries(omitted).filter(([key]) => key !== "receipt_sha256"));
    const omittedReceipt = { ...unsignedOmitted, receipt_sha256: canonicalSha256(unsignedOmitted) };
    const latestPath = join(root, ".chatgpt", "validation", "latest.json");
    const latest = JSON.parse(await readFile(latestPath, "utf8")) as Record<string, unknown>;
    const omittedPointer = { ...latest, receipt_sha256: omittedReceipt.receipt_sha256 };
    const omittedReceiptParse = ValidationReceiptV2Schema.safeParse(omittedReceipt);
    expect(omittedReceiptParse.success, JSON.stringify(omittedReceiptParse.success ? [] : omittedReceiptParse.error.issues)).toBe(true);
    expect(ValidationLatestPointerV2Schema.safeParse(omittedPointer).success).toBe(true);
    await writeFile(receiptPath, JSON.stringify(omittedReceipt));
    await writeFile(latestPath, JSON.stringify(omittedPointer));
    const omittedReview = await new GitReviewService(root, policy).review({ repo_id: "fixture" });
    expect(omittedReview.ship_readiness.validation).toMatchObject({ status: "unverified", eligibility: "unverified" });

    await writeFile(receiptPath, JSON.stringify(receipt));
    await writeFile(latestPath, JSON.stringify(latest));
    await writeFile(join(root, helperPath), "#!/bin/sh\necho changed-helper-version\n");
    const review = await new GitReviewService(root, policy).review({ repo_id: "fixture" });
    expect(review.ship_readiness.validation).toMatchObject({ status: "stale", eligibility: "ineligible" });

  await rm(join(root, helperPath));
  const reviewWithoutRecordedHelper = await new GitReviewService(root, policy).review({ repo_id: "fixture" });
  expect(reviewWithoutRecordedHelper.ship_readiness.validation).toMatchObject({ status: "unverified", eligibility: "unverified" });
  });

  test.skipIf(process.platform === "win32")("runs NSCB's exact Makefile all profile with pinned Rust tools and one test thread", async () => {
    const root = await fixtureRepo({});
    await copyNscbMakefileFixture(root);
    await writeFile(join(root, ".gitignore"), "target/\n");
    await initializeGitFixture(root);
    const cargoHome = await createTempDir("nscb-validation-cargo-home-");
    const pythonBin = await createTempDir("nscb-validation-python-");
    const python3 = join(pythonBin, "python3");
    await writeFile(python3, `#!${process.execPath}\nconsole.log("python fixture: " + process.argv.slice(2).join(" "));\n`);
    await chmod(python3, 0o755);
    const rustupLogDirectory = await createTempDir("nscb-rustup-log-");
    const rustupLog = join(rustupLogDirectory, "calls.log");
    const rustTools = await createFakeRustToolchain("1.98.1", cargoHome, rustupLog);
    const previous = captureEnv(["PATH", "CARGO_HOME", "CARGO_TARGET_DIR", "RUSTUP", "RUST_TEST_THREADS"]);

    try {
      process.env.PATH = `${rustTools.bin}${delimiter}${pythonBin}${delimiter}${previous.PATH ?? ""}`;
      process.env.CARGO_HOME = cargoHome;
      process.env.RUSTUP = join(root, "untrusted-rustup");
      delete process.env.RUST_TEST_THREADS;

      const operations = { validation_profiles: { all: { runner: "make", target: "all" } } } as const;
      const result = await service(root, operations).validate({ repo_id: "fixture", profile: "all" });

      expect(result).toMatchObject({
        status: "passed",
        commands: [{
          command: "make all",
          status: "passed",
          runtime: {
            name: "rust",
            version: "1.98.1",
            rustup: {
              version: "1.28.2",
              sha256: expect.stringMatching(/^[a-f0-9]{64}$/)
            },
            cargo: {
              version: "1.98.1",
              path_sha256: createHash("sha256").update(rustTools.cargo).digest("hex")
            },
            rustc: {
              version: "1.98.1",
              path_sha256: createHash("sha256").update(rustTools.rustc).digest("hex")
            }
          }
        }]
      });
      expect(result.commands[0]?.stdout_tail).toContain("threads=1");
      const rustupCalls = await readFile(rustupLog, "utf8");
      expect(rustupCalls).toContain("which --toolchain 1.98.1 cargo");
      expect(rustupCalls).toContain("which --toolchain 1.98.1 rustc");
      const receipt = JSON.parse(await readFile(join(root, result.validation_artifact!.path), "utf8")) as Record<string, unknown>;
      expect(ValidationReceiptV2Schema.safeParse(receipt).success).toBe(true);
    } finally {
      restoreEnv(previous);
    }
  }, 15_000);

  test.skipIf(process.platform === "win32").each(["Cargo configuration", "Make recipe"] as const)(
    "rechecks Rust execution inputs before the selected Make profile runs when %s changes",
    async (changedInput) => {
    const root = await fixtureRepo({});
    await writeFile(join(root, "rust-toolchain.toml"), '[toolchain]\nchannel = "1.98.1"\n');
    await writeFile(join(root, "Cargo.toml"), "[workspace]\nresolver = \"2\"\n");
    await writeFile(join(root, "Makefile"), "test:\n\tRUST_TEST_THREADS=1 cargo test\n");
    const cargoHome = await createTempDir("validation-rust-config-preflight-cargo-home-");
    const rustTools = await createFakeRustToolchain("1.98.1", cargoHome);
    const executionMarker = join(root, "cargo-executed.txt");
    await writeFile(rustTools.cargo, `#!${process.execPath}\nconst fs = require("node:fs");\nconst args = process.argv.slice(2);\nif (args[0] === "--version") console.log("cargo 1.98.1 (fixture)");\nelse fs.writeFileSync(${JSON.stringify(executionMarker)}, "executed");\n`);
    await initializeGitFixture(root);
    const previous = captureEnv(["PATH", "CARGO_HOME"]);
    const originalResolve = RustRuntimeResolver.prototype.resolve;
    let changedConfiguration = false;
    const resolveSpy = vi.spyOn(RustRuntimeResolver.prototype, "resolve").mockImplementation(async function (
      this: RustRuntimeResolver,
      options: Parameters<RustRuntimeResolver["resolve"]>[0]
    ) {
      const selection = await originalResolve.call(this, options);
      if (selection && !changedConfiguration) {
        changedConfiguration = true;
        if (changedInput === "Cargo configuration") {
          await writeFile(join(cargoHome, "config.toml"), '[build]\nrustc-wrapper = "sccache"\n');
        } else {
          await writeFile(join(root, "Makefile"), "test:\n\tRUST_TEST_THREADS=1 cargo +1.99.0 test\n");
        }
      }
      return selection;
    });

    try {
      process.env.PATH = `${rustTools.bin}${delimiter}${previous.PATH ?? ""}`;
      process.env.CARGO_HOME = cargoHome;
      const operations = { validation_profiles: { test: { runner: "make", target: "test" } } } as const;

      await expect(service(root, operations).validate({ repo_id: "fixture", profile: "test" }))
        .rejects.toMatchObject({ code: "VALIDATION_RUNNER_UNAVAILABLE" });
      expect(changedConfiguration).toBe(true);
      await expect(readFile(executionMarker, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      resolveSpy.mockRestore();
      restoreEnv(previous);
    }
    }
  );

  test.skipIf(process.platform === "win32")("rejects a prior receipt when the selected Rustup executable changes", async () => {
    const root = await fixtureRepo({});
    await writeFile(join(root, "rust-toolchain.toml"), '[toolchain]\nchannel = "1.98.1"\n');
    await writeFile(join(root, "Cargo.toml"), "[workspace]\nresolver = \"2\"\n");
    await writeFile(join(root, "Makefile"), "test:\n\tRUST_TEST_THREADS=1 cargo test\n");
    const cargoHome = await createTempDir("validation-rustup-identity-cargo-home-");
    const rustTools = await createFakeRustToolchain("1.98.1", cargoHome);
    const previous = captureEnv(["PATH", "CARGO_HOME", "RUSTUP"]);

    try {
      process.env.PATH = `${rustTools.bin}${delimiter}${previous.PATH ?? ""}`;
      process.env.CARGO_HOME = cargoHome;
      delete process.env.RUSTUP;
      await initializeGitFixture(root);
      const operations = { validation_profiles: { test: { runner: "make", target: "test" } } } as const;
      const policy = new OperationsPolicy({ enabled: true, validation_enabled: true, ...operations });
      const result = await new ValidationService(root, policy).validate({ repo_id: "fixture", profile: "test" });
      expect(result.status).toBe("passed");
      expect(result.commands[0]?.runtime).toMatchObject({
        name: "rust",
        rustup: {
          version: "1.28.2",
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/)
        }
      });

      const reviewService = new GitReviewService(root, policy);
      const initialRustupReview = await reviewService.review({ repo_id: "fixture" });
      expect(initialRustupReview.ship_readiness.validation)
        .toMatchObject({ status: "passed", eligibility: "eligible", validation_id: result.validation_id });
      const rustupSource = await readFile(rustTools.rustup, "utf8");
      await writeFile(rustTools.rustup, `${rustupSource}\n// executable identity changed; outputs remain unchanged\n`);
      const reviewAfterRustupChange = await reviewService.review({ repo_id: "fixture" });
      expect(reviewAfterRustupChange.ship_readiness.validation)
        .toMatchObject({ status: "stale", eligibility: "ineligible" });
    } finally {
      restoreEnv(previous);
    }
  }, 15_000);

  test.skipIf(process.platform === "win32")("reports a prior Rust receipt as unverified when the current toolchain cannot be resolved", async () => {
    const root = await fixtureRepo({});
    await writeFile(join(root, "rust-toolchain.toml"), '[toolchain]\nchannel = "1.98.1"\n');
    await writeFile(join(root, "Cargo.toml"), "[workspace]\nresolver = \"2\"\n");
    await writeFile(join(root, "Makefile"), "test:\n\tRUST_TEST_THREADS=1 cargo test\n");
    const cargoHome = await createTempDir("validation-rust-toolchain-unavailable-cargo-home-");
    const rustTools = await createFakeRustToolchain("1.98.1", cargoHome);
    const toolBin = await createTempDir("validation-review-tool-bin-");
    for (const executable of ["git", "make"]) {
      const executablePath = execFileSync("which", [executable], { encoding: "utf8" }).trim();
      await symlink(executablePath, join(toolBin, executable));
    }
    await symlink(process.execPath, join(toolBin, "node"));
    const previous = captureEnv(["PATH", "CARGO_HOME", "RUSTUP"]);

    try {
      process.env.PATH = [rustTools.bin, dirname(rustTools.cargo), toolBin].join(delimiter);
      process.env.CARGO_HOME = cargoHome;
      delete process.env.RUSTUP;
      await initializeGitFixture(root);
      const operations = { validation_profiles: { test: { runner: "make", target: "test" } } } as const;
      const policy = new OperationsPolicy({ enabled: true, validation_enabled: true, ...operations });
      const result = await new ValidationService(root, policy).validate({ repo_id: "fixture", profile: "test" });
      expect(result.status).toBe("passed");
      expect(result.commands[0]?.runtime).toMatchObject({ name: "rust" });
      const receipt = JSON.parse(await readFile(join(root, result.validation_artifact!.path), "utf8")) as {
        runner_post_state: Array<{ status: string }>;
      };
      expect(receipt.runner_post_state).toMatchObject([{ status: "verified" }]);

      process.env.PATH = toolBin;
      await expect(new RustRuntimeResolver(root).resolve({ required: true, recipe_paths: ["Makefile"] })).rejects.toThrow();

      const review = await new GitReviewService(root, policy).review({ repo_id: "fixture" });
      expect(review.ship_readiness.validation).toMatchObject({ status: "unverified", eligibility: "unverified" });
    } finally {
      restoreEnv(previous);
    }
  }, 15_000);

  test.skipIf(process.platform === "win32")("does not promote contradictory V2 eligibility or command outcome state", async () => {
    const root = await fixtureRepo({});
    await writeFile(join(root, "rust-toolchain.toml"), '[toolchain]\nchannel = "1.98.1"\n');
    await writeFile(join(root, "Cargo.toml"), "[workspace]\nresolver = \"2\"\n");
    await mkdir(join(root, "scripts"), { recursive: true });
    await writeFile(join(root, "Makefile"), "test:\n\tRUST_TEST_THREADS=1 ./scripts/run-tests.sh\n");
    await writeFile(join(root, "scripts", "run-tests.sh"), "#!/bin/sh\ncargo test\n");
    await chmod(join(root, "scripts", "run-tests.sh"), 0o755);
    const cargoHome = await createTempDir("validation-cargo-home-");
    const rustTools = await createFakeRustToolchain("1.98.1", cargoHome);
    const previousPath = process.env.PATH;
    const previousCargoHome = process.env.CARGO_HOME;
    process.env.PATH = `${rustTools.bin}${delimiter}${previousPath ?? ""}`;
    process.env.CARGO_HOME = cargoHome;
    await initializeGitFixture(root);
    try {
      const operations = { validation_profiles: { test: { runner: "make", target: "test" } } } as const;
      const result = await service(root, operations).validate({ repo_id: "fixture", profile: "test" });
      const receiptPath = join(root, result.validation_artifact!.path);
      const latestPath = join(root, ".chatgpt", "validation", "latest.json");
      const receipt = JSON.parse(await readFile(receiptPath, "utf8")) as {
        receipt_sha256: string;
        eligibility: { status: "eligible" | "ineligible" | "unverified"; reasons: string[] };
        status: "passed" | "failed" | "skipped";
        commands: Array<{ status: "passed" | "failed" | "skipped"; [key: string]: unknown }>;
        counts: { total: number; passed: number; failed: number; skipped: number };
        [key: string]: unknown;
      };
      const pointer = JSON.parse(await readFile(latestPath, "utf8")) as {
        receipt_sha256: string;
        eligibility: "eligible" | "ineligible" | "unverified";
        [key: string]: unknown;
      };

      for (const eligibility of [
        { status: "ineligible" as const, reasons: [] },
        { status: "unverified" as const, reasons: [] }
      ]) {
        const unsignedReceipt = Object.fromEntries(Object.entries(receipt).filter(([key]) => key !== "receipt_sha256"));
        const unsignedCandidate = { ...unsignedReceipt, eligibility };
        const receiptSha256 = canonicalSha256(unsignedCandidate);
        const candidateReceipt = { ...unsignedCandidate, receipt_sha256: receiptSha256 };
        const candidatePointer = { ...pointer, eligibility: eligibility.status, receipt_sha256: receiptSha256 };

        expect(ValidationReceiptV2Schema.safeParse(candidateReceipt).success).toBe(true);
        expect(ValidationLatestPointerV2Schema.safeParse(candidatePointer).success).toBe(true);
        await writeFile(receiptPath, JSON.stringify(candidateReceipt, null, 2));
        await writeFile(latestPath, JSON.stringify(candidatePointer, null, 2));

        const review = await new GitReviewService(root, new OperationsPolicy({
          enabled: true,
          validation_enabled: true,
          ...operations
        })).review({ repo_id: "fixture" });
        expect(review.ship_readiness.validation).toMatchObject({ status: "unverified", eligibility: "unverified" });
      }

      const unsignedReceipt = Object.fromEntries(Object.entries(receipt).filter(([key]) => key !== "receipt_sha256"));
      const contradictoryEligibility = { status: "eligible" as const, reasons: ["contradictory reason"] };
      const receiptSha256 = canonicalSha256({ ...unsignedReceipt, eligibility: contradictoryEligibility });
      const contradictoryReceipt = {
        ...unsignedReceipt,
        eligibility: contradictoryEligibility,
        receipt_sha256: receiptSha256
      };
      const contradictoryPointer = {
        ...pointer,
        eligibility: contradictoryEligibility.status,
        receipt_sha256: receiptSha256
      };
      expect(ValidationReceiptV2Schema.safeParse(contradictoryReceipt).success).toBe(true);
      expect(ValidationLatestPointerV2Schema.safeParse(contradictoryPointer).success).toBe(true);
      await writeFile(receiptPath, JSON.stringify(contradictoryReceipt, null, 2));
      await writeFile(latestPath, JSON.stringify(contradictoryPointer, null, 2));
      const contradictoryReview = await new GitReviewService(root, new OperationsPolicy({
        enabled: true,
        validation_enabled: true,
        ...operations
      })).review({ repo_id: "fixture" });
      expect(contradictoryReview.ship_readiness.validation).toMatchObject({ status: "unverified", eligibility: "unverified" });

      const inconsistentFocusUnsigned = { ...unsignedReceipt, focused: true, test_paths: [] };
      const inconsistentFocusSha256 = canonicalSha256(inconsistentFocusUnsigned);
      const inconsistentFocusReceipt = {
        ...inconsistentFocusUnsigned,
        receipt_sha256: inconsistentFocusSha256
      };
      const inconsistentFocusPointer = {
        ...pointer,
        focused: true,
        test_paths: [],
        receipt_sha256: inconsistentFocusSha256
      };
      expect(ValidationReceiptV2Schema.safeParse(inconsistentFocusReceipt).success).toBe(false);
      expect(ValidationLatestPointerV2Schema.safeParse(inconsistentFocusPointer).success).toBe(false);
      await writeFile(receiptPath, JSON.stringify(inconsistentFocusReceipt, null, 2));
      await writeFile(latestPath, JSON.stringify(inconsistentFocusPointer, null, 2));
      const inconsistentFocusReview = await new GitReviewService(root, new OperationsPolicy({
        enabled: true,
        validation_enabled: true,
        ...operations
      })).review({ repo_id: "fixture" });
      expect(inconsistentFocusReview.ship_readiness.validation)
        .toMatchObject({ status: "unverified", eligibility: "unverified" });

      const inconsistentCountsUnsigned = {
        ...unsignedReceipt,
        counts: { ...receipt.counts, passed: 0, failed: receipt.counts.total }
      };
      const inconsistentCountsReceipt = {
        ...inconsistentCountsUnsigned,
        receipt_sha256: canonicalSha256(inconsistentCountsUnsigned)
      };
      expect(ValidationReceiptV2Schema.safeParse(inconsistentCountsReceipt).success).toBe(false);

      const failedCommandOutcomes = receipt.commands.map((command, index) => index === 0
        ? { ...command, status: "failed" as const }
        : command);
      const commandCounts = {
        total: failedCommandOutcomes.length,
        passed: failedCommandOutcomes.filter((command) => command.status === "passed").length,
        failed: failedCommandOutcomes.filter((command) => command.status === "failed").length,
        skipped: failedCommandOutcomes.filter((command) => command.status === "skipped").length
      };
      const inconsistentOutcomeUnsigned = {
        ...unsignedReceipt,
        status: "passed" as const,
        commands: failedCommandOutcomes,
        counts: commandCounts
      };
      const inconsistentOutcomeSha256 = canonicalSha256(inconsistentOutcomeUnsigned);
      const inconsistentOutcomeReceipt = {
        ...inconsistentOutcomeUnsigned,
        receipt_sha256: inconsistentOutcomeSha256
      };
      const inconsistentOutcomePointer = {
        ...pointer,
        receipt_sha256: inconsistentOutcomeSha256
      };
      expect(ValidationReceiptV2Schema.safeParse(inconsistentOutcomeReceipt).success).toBe(false);
      expect(ValidationLatestPointerV2Schema.safeParse(inconsistentOutcomePointer).success).toBe(true);
      await writeFile(receiptPath, JSON.stringify(inconsistentOutcomeReceipt, null, 2));
      await writeFile(latestPath, JSON.stringify(inconsistentOutcomePointer, null, 2));
      const inconsistentOutcomeReview = await new GitReviewService(root, new OperationsPolicy({
        enabled: true,
        validation_enabled: true,
        ...operations
      })).review({ repo_id: "fixture" });
      expect(inconsistentOutcomeReview.ship_readiness.validation)
        .toMatchObject({ status: "unverified", eligibility: "unverified" });
    } finally {
      process.env.PATH = previousPath;
      if (previousCargoHome === undefined) delete process.env.CARGO_HOME;
      else process.env.CARGO_HOME = previousCargoHome;
    }
  });

  test.skipIf(process.platform === "win32")("marks validation ineligible when the selected Make executable changes during execution", async () => {
    const root = await fixtureRepo({});
    await writeFile(join(root, "Makefile"), "smoke:\n\t@echo validation-ok\n");
    await initializeGitFixture(root);
    const bin = await createTempDir("validation-make-bin-");
    const make = join(bin, "make");
    await writeFile(make, `#!${process.execPath}\nconsole.log("fake-make-v1");\n`);
    await chmod(make, 0o755);
    const previousPath = process.env.PATH;
    process.env.PATH = `${bin}${delimiter}${previousPath ?? ""}`;
    const processSpy = vi.spyOn(processExec, "runProcessWithTail").mockImplementation(async () => {
      await writeFile(make, `#!${process.execPath}\nconsole.log("fake-make-v2");\n`);
      return {
        timed_out: false,
        cancelled: false,
        cleanup_confirmed: true,
        exit_code: 0,
        duration_ms: 1,
        stdout_tail: "validation-ok",
        stderr_tail: ""
      };
    });

    try {
      const result = await service(root, {
        validation_profiles: { smoke: { runner: "make", target: "smoke" } }
      }).validate({ repo_id: "fixture", profile: "smoke" });
      const receipt = JSON.parse(await readFile(join(root, result.validation_artifact!.path), "utf8")) as {
        status: string;
        eligibility: { status: string; reasons: string[] };
      };

      expect(result.status).toBe("passed");
      expect(receipt).toMatchObject({
        status: "passed",
        eligibility: { status: "ineligible", reasons: ["RUNNER_STATE_CHANGED_DURING_RUN"] }
      });
    } finally {
      processSpy.mockRestore();
      process.env.PATH = previousPath;
    }
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

  test("rejects focused paths that begin with npm or pytest option prefixes", async () => {
    const roots = [
      await fixtureRepo({ scripts: { test: "echo test" } }),
      await fixtureRepo({ pythonMarker: true, localPython: true })
    ];

    for (const root of roots) {
      await expect(service(root, { validation_test_path_globs: ["**"] }).validate({
        repo_id: "fixture",
        profile: "test",
        test_paths: ["--collect-only"],
        dry_run: true
      })).rejects.toMatchObject({
        code: "VALIDATION_TEST_PATH_NOT_ALLOWED",
        message: expect.stringContaining("runner option prefix")
      });
    }
  });

  test("rejects focused test paths for a declared just profile", async () => {
    const root = await fixtureRepo({ scripts: { test: "echo fallback" } });
    await writeFile(join(root, "justfile"), "test:\n    @echo test\n");

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
    const { startedPath, releasePath } = await createExternalValidationCoordination();
    const runner = [
      'const { appendFileSync, existsSync, watch } = require("node:fs");',
      'const { basename, dirname } = require("node:path");',
      `const releasePath = ${JSON.stringify(releasePath)};`,
      "let release;",
      "const released = new Promise(resolve => { release = resolve; });",
      "const releaseName = basename(releasePath);",
      "const releaseWatcher = watch(dirname(releasePath), (_event, filename) => {",
      "if (filename && filename.toString() !== releaseName) return;",
      "if (existsSync(releasePath)) { releaseWatcher.close(); release(); }",
      "});",
      "if (existsSync(releasePath)) { releaseWatcher.close(); release(); }",
      `appendFileSync(${JSON.stringify(startedPath)}, String(process.pid) + "\\n");`,
      "released.then(() => console.log(JSON.stringify({ pid: process.pid })));"
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
    const safeSettledSummary = settled.map((result) => {
      if (result.status === "fulfilled") {
        return {
          status: result.status,
          validation_status: result.value.status,
          validation_id: result.value.validation_id
        };
      }
      const reason = result.reason as { code?: unknown; name?: unknown } | null;
      return {
        status: result.status,
        error_name: reason && typeof reason.name === "string" ? reason.name : "unknown",
        error_code: reason && typeof reason.code === "string" ? reason.code : "UNCLASSIFIED_ERROR"
      };
    });
    expect(safeSettledSummary).toEqual([
      expect.objectContaining({ status: "fulfilled", validation_status: "passed" }),
      expect.objectContaining({ status: "fulfilled", validation_status: "passed" })
    ]);
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

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ESRCH") return false;
    throw error;
  }
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

async function initializeGitFixture(root: string): Promise<void> {
  execFileSync("git", ["init", "--quiet"], { cwd: root, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "Validation Fixture"], { cwd: root, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "validation-fixture@example.invalid"], { cwd: root, stdio: "ignore" });
  execFileSync("git", ["add", "-A"], { cwd: root, stdio: "ignore" });
  execFileSync("git", ["-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture"], { cwd: root, stdio: "ignore" });
}

async function createFakeRustToolchain(version: string, expectedCargoHome?: string, rustupLogPath?: string): Promise<{ bin: string; cargo: string; rustc: string; rustup: string; rustfmt: string }> {
  const runtimeRoot = await createTempDir("validation-rust-runtime-");
  const shimBin = join(runtimeRoot, "bin");
  const toolchainBin = join(runtimeRoot, "toolchain", "bin");
  await mkdir(shimBin, { recursive: true });
  await mkdir(toolchainBin, { recursive: true });
  const cargo = join(toolchainBin, process.platform === "win32" ? "cargo.exe" : "cargo");
  const rustc = join(toolchainBin, process.platform === "win32" ? "rustc.exe" : "rustc");
  const rustfmt = join(toolchainBin, process.platform === "win32" ? "rustfmt.exe" : "rustfmt");
  const rustup = join(shimBin, process.platform === "win32" ? "rustup.exe" : "rustup");
  const cargoHomeCheck = `process.env.CARGO_HOME === ${JSON.stringify(expectedCargoHome ?? "")}`;
  await writeFile(cargo, `#!${process.execPath}\nconst fs = require("node:fs");\nconst path = require("node:path");\nconst args = process.argv.slice(2);\nif (args[0] === "--version") console.log("cargo ${version} (fixture)");\nelse {\n  console.log("toolchain=" + process.env.RUSTUP_TOOLCHAIN + "; threads=" + process.env.RUST_TEST_THREADS + "; rustc=" + process.env.RUSTC + "; cargo-home-matches=" + (${cargoHomeCheck}));\n  if (args.includes("--list")) console.log("test fixture::smoke: test");\n  if (args[0] === "build") {\n    const binary = path.join(process.env.CARGO_TARGET_DIR || "target", "debug", "nscb");\n    fs.mkdirSync(path.dirname(binary), { recursive: true });\n    fs.writeFileSync(binary, "#!/bin/sh\\nexit 0\\n");\n    fs.chmodSync(binary, 0o755);\n  }\n}\n`);
  await writeFile(rustc, `#!${process.execPath}\nconsole.log("rustc ${version} (fixture)");\n`);
  await writeFile(rustfmt, `#!${process.execPath}\nconsole.log("rustfmt ${version} (fixture)");\n`);
  await writeFile(rustup, `#!${process.execPath}\nconst fs = require("node:fs");\nconst args = process.argv.slice(2);\nif (${JSON.stringify(rustupLogPath ?? "")} && args[0] === "which") fs.appendFileSync(${JSON.stringify(rustupLogPath ?? "")}, args.join(" ") + "\\n");\nif (args[0] === "--version") console.log("rustup 1.28.2 (fixture)");\nelse if (args[0] === "show") console.log("${version}-x86_64-unknown-linux-gnu (fixture)");\nelse if (args[0] === "which") {\n  const pinnedVersion = args[1] === "--toolchain" ? args[2] : process.env.RUSTUP_TOOLCHAIN;\n  const tool = args[1] === "--toolchain" ? args[3] : args[1];\n  if (pinnedVersion && pinnedVersion !== "${version}") process.exit(3);\n  const selected = { cargo: ${JSON.stringify(cargo)}, rustc: ${JSON.stringify(rustc)}, rustfmt: ${JSON.stringify(rustfmt)} }[tool];\n  if (selected) console.log(selected); else process.exit(2);\n} else process.exit(2);\n`);
  await chmod(cargo, 0o755);
  await chmod(rustc, 0o755);
  await chmod(rustfmt, 0o755);
  await chmod(rustup, 0o755);
  return { bin: shimBin, cargo, rustc, rustup, rustfmt };
}

async function fakeNvmRuntime(version: string): Promise<{ home: string; options: NodeRuntimeResolverOptions }> {
  const home = await createTempDir("gpt-runtime-home-");
  await fakeNodeExecutable(join(home, ".nvm", "versions", "node", `v${version}`, "bin", "node"), version);
  return { home, options: { home, env: {} } };
}

async function fakeWindowsNvmRuntime(version: string): Promise<{ bin: string; node: string; options: NodeRuntimeResolverOptions }> {
  const home = await createTempDir("gpt-windows-runtime-home-");
  const bin = await createTempDir("gpt-windows-runtime-bin-");
  const node = await fakeNodeExecutable(join(home, "nvm", `v${version}`, "node.exe"), version);
  return {
    bin,
    node,
    options: { platform: "win32", home, env: { NVM_HOME: join(home, "nvm"), PATH: bin } }
  };
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
