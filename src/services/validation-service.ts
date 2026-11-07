import { createHash, randomUUID } from "node:crypto";
import { access, lstat, mkdir, readFile, readdir, realpath, rm, stat } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { delimiter, dirname, isAbsolute, join, relative, sep, win32 } from "node:path";
import ignore from "ignore";
import {
  ValidateInputSchema,
  ValidationLatestPointerV2Schema,
  ValidationReceiptV2BaseSchema,
  ValidationReceiptV2Schema,
  type ValidateInput,
  type ValidateResult,
  type ValidationProfile,
  type ValidationRuntime
} from "../contracts/validation.contract.js";
import { RepoReaderError } from "../runtime/errors.js";
import { atomicWriteJson } from "../runtime/fs-helpers.js";
import { redactSensitiveText } from "../runtime/result-envelope.js";
import { OperationsPolicy } from "./operations-policy.js";
import { validateRepoPath } from "./path-sandbox.js";
import { IgnoreEngine } from "./ignore-engine.js";
import { GitService } from "./git-service.js";
import { NodeRuntimeResolver, type NodeRuntimeResolverOptions } from "./node-runtime-resolver.js";
import { RustRuntimeResolver, type RustRuntimeSelection } from "./rust-runtime-resolver.js";
import { canonicalSha256, captureExecutableIdentity, ValidationEvidenceService, type ValidationExecutableIdentity, type ValidationSourceSnapshot } from "./validation-evidence.js";
import { runProcessWithTail } from "./process-exec.js";

const DEFAULT_TIMEOUT_MS = 900_000;
const OUTPUT_TAIL_CHARS = 4_000;
const ALL_PROFILE_ORDER = ["typecheck", "lint", "test", "build", "smoke"] as const;
const VALIDATION_ROOT = ".chatgpt/validation";
type ConcreteProfile = typeof ALL_PROFILE_ORDER[number];

type CommandPlan = {
  profile: ValidationProfile;
  script: string;
  executable: string;
  command: string;
  args: string[];
  pathPrefix?: string;
  windowsNpmLifecycle?: true;
  pathPrefixes: string[];
  runtimeEnv?: NodeJS.ProcessEnv;
  runtime?: ValidationRuntime;
  rustRuntime?: RustRuntimeSelection;
  executableIdentity?: ValidationExecutableIdentity;
  runtimeExecutable?: string;
  runtimeExecutableIdentity?: ValidationExecutableIdentity;
  recipe?: { path: string; size_bytes: number; sha256: string };
  recipeSourcePaths?: string[];
};

type RunnerPostState = {
  profile: ValidationProfile;
  script: string;
  executable: string;
  status: "verified" | "unverified";
  reason?: string;
  executable_identity?: ValidationExecutableIdentity;
  runtime_executable_identity?: ValidationExecutableIdentity;
  recipe?: { path: string; size_bytes: number; sha256: string };
  runtime?: ValidationRuntime;
};

type SourceEvidence = {
  before?: ValidationSourceSnapshot;
  before_error?: string;
  after?: ValidationSourceSnapshot;
  after_error?: string;
};

const PYTHON_SCAN_EXCLUDES = new Set([".git", ".venv", "venv", "node_modules", "build", "dist", ".cache", ".pytest_cache", "__pycache__", ".tox"]);
const MAX_PYTHON_SCAN_ENTRIES = 2_000;
const MAX_PYTHON_SCAN_DEPTH = 6;

export class ValidationService {
  private readonly ignoreEngine = new IgnoreEngine();

  constructor(
    private readonly root: string,
    private readonly policy: OperationsPolicy,
    private readonly nodeRuntimeOptions: NodeRuntimeResolverOptions = {}
  ) {}

  private get platform(): NodeJS.Platform {
    return this.nodeRuntimeOptions.platform ?? process.platform;
  }

  private get validationEnvironment(): NodeJS.ProcessEnv {
    return this.nodeRuntimeOptions.env ?? process.env;
  }

  async validate(input: ValidateInput, options: { signal?: AbortSignal } = {}): Promise<ValidateResult> {
    options.signal?.throwIfAborted();
    const args = ValidateInputSchema.parse(input);
    this.policy.assertValidationAllowed();
    const scripts = await this.readScripts();
    options.signal?.throwIfAborted();
    const testPaths = args.test_paths ? this.validateFocusedTestPaths(args.profile, args.test_paths) : undefined;
    const commands = await this.resolveCommands(args.profile, scripts, testPaths, options.signal);
    options.signal?.throwIfAborted();

    if (args.dry_run === true) {
      return {
        ok: true,
        repo_id: args.repo_id,
        profile: args.profile,
        ...(testPaths ? { focused: true, test_paths: testPaths } : {}),
        dry_run: true,
        status: "skipped",
        commands: commands.map((command) => ({
          profile: command.profile,
          script: command.script,
          command: command.command,
          executable: command.executable,
          ...(command.executableIdentity ? { executable_identity: command.executableIdentity } : {}),
          ...(command.runtimeExecutableIdentity ? { runtime_executable_identity: command.runtimeExecutableIdentity } : {}),
          ...(command.recipe ? { recipe: command.recipe } : {}),
          ...(command.runtime ? { runtime: command.runtime } : {}),
          status: "skipped"
        })),
        counts: { total: commands.length, passed: 0, failed: 0, skipped: commands.length },
        warnings: ["VALIDATION_DRY_RUN"]
      };
    }

    const policyBefore = copyJson(this.policy.config);
    const sourceEvidence: SourceEvidence = {};
    await this.captureSourceSnapshot(sourceEvidence, "before", options.signal, commands);
    const rustCommands = commands.filter((command) => command.rustRuntime !== undefined);
    if (rustCommands.length > 0) {
      const preRunState = await this.captureRunnerPostState(rustCommands, options.signal);
      const plannedState = rustCommands.map((command) => ({
        profile: command.profile,
        script: command.script,
        executable: command.executable,
        executable_identity: command.executableIdentity,
        runtime_executable_identity: command.runtimeExecutableIdentity,
        recipe: command.recipe,
        runtime: command.runtime
      }));
      const currentState = preRunState.map((state) => ({
        profile: state.profile,
        script: state.script,
        executable: state.executable,
        executable_identity: state.executable_identity,
        runtime_executable_identity: state.runtime_executable_identity,
        recipe: state.recipe,
        runtime: state.runtime
      }));
      if (preRunState.some((state) => state.status === "unverified")
        || currentState.length !== plannedState.length
        || plannedState.some((state, index) => canonicalSha256(state) !== canonicalSha256(currentState[index]))) {
        throw new RepoReaderError("VALIDATION_RUNNER_UNAVAILABLE", "The selected Rust runner or toolchain changed after planning; validation was not started.");
      }
    }
    const results = [];
    for (const command of commands) {
      options.signal?.throwIfAborted();
      results.push(await this.runCommand(command, args.timeout_ms ?? DEFAULT_TIMEOUT_MS, options.signal));
    }
    options.signal?.throwIfAborted();
    const runnerPostState = await this.captureRunnerPostState(commands, options.signal);
    await this.captureSourceSnapshot(sourceEvidence, "after", options.signal, commands);
    const policyAfter = copyJson(this.policy.config);
    const failed = results.filter((result) => result.status === "failed").length;
    const passed = results.filter((result) => result.status === "passed").length;
    const validationId = createValidationId();
    const result: ValidateResult = {
      ok: true,
      repo_id: args.repo_id,
      validation_id: validationId,
      profile: args.profile,
      ...(testPaths ? { focused: true, test_paths: testPaths } : {}),
      dry_run: false,
      status: failed > 0 ? "failed" : "passed",
      commands: results,
      counts: { total: results.length, passed, failed, skipped: 0 },
      warnings: []
    };
    options.signal?.throwIfAborted();
    const artifactPath = await this.writeValidationArtifact(result, {
      sourceEvidence,
      policyBefore,
      policyAfter,
      runnerPostState
    }, options.signal);

    return {
      ...result,
      validation_artifact: { path: artifactPath }
    };
  }

  private async readScripts(): Promise<Record<string, string>> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(await readFile(join(this.root, "package.json"), "utf8"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return {};
      }
      throw new RepoReaderError("VALIDATION_PROFILE_UNAVAILABLE", "Validation requires a readable package.json or a detected Python test suite.", {
        diagnostics: { recovery_hint: error instanceof Error ? error.message : "package.json could not be read" }
      });
    }

    const scripts = (parsed as { scripts?: unknown }).scripts;
    if (!scripts || typeof scripts !== "object" || Array.isArray(scripts)) {
      return {};
    }
    return Object.fromEntries(
      Object.entries(scripts).filter((entry): entry is [string, string] => typeof entry[1] === "string")
    );
  }

  private async resolveCommands(profile: ValidationProfile, scripts: Record<string, string>, testPaths: string[] | undefined, signal?: AbortSignal): Promise<CommandPlan[]> {
    if (testPaths && profile !== "test") {
      throw new RepoReaderError("VALIDATION_TEST_PATHS_REQUIRE_TEST_PROFILE", "Focused test paths are only supported with profile test.");
    }
    const owned = this.policy.config.validation_profiles[profile];
    if (owned) {
      if (testPaths) {
        throw new RepoReaderError("VALIDATION_TEST_PATHS_DISABLED", "Focused test paths are not supported by the declared repository validation profile.");
      }
      const executable = this.platform === "win32"
        ? await resolveWindowsNativeExecutable(owned.runner, this.root, this.validationEnvironment.PATH ?? "")
        : owned.runner;
      if (!executable) {
        throw new RepoReaderError("VALIDATION_PROFILE_UNAVAILABLE", `The configured ${owned.runner} profile requires a native Windows executable.`, {
          diagnostics: { recovery_hint: `Install ${owned.runner} as a native .exe outside the repository and add its directory to the server PATH. Command shims are not supported.` }
        });
      }
      const recipe = await this.captureRecipe(await this.selectRunnerRecipe(owned.runner));
      const rustResolver = new RustRuntimeResolver(this.root);
      const recipeSourcePaths = await rustResolver.discoverRecipeSources([recipe.path], signal);
      const rustRuntime = await rustResolver.resolve({ recipe_paths: [recipe.path], signal });
      return [await this.prepareCommandPlan({
        profile,
        script: `${owned.runner}:${owned.target}`,
        executable,
        command: `${owned.runner} ${owned.target}`,
        args: [owned.target],
        pathPrefixes: rustRuntime?.path_prefixes ?? [],
        recipeSourcePaths,
        ...(rustRuntime ? { runtimeEnv: rustRuntime.execution_env, runtime: runtimeFromRust(rustRuntime), rustRuntime } : {}),
        recipe
      })];
    }
    const npmProfiles = profile === "all" ? ALL_PROFILE_ORDER.filter((candidate) => candidate in scripts) : [profile as ConcreteProfile].filter((candidate) => candidate in scripts);
    const selectedNode = npmProfiles.length > 0
      ? await new NodeRuntimeResolver(this.root, this.nodeRuntimeOptions).resolve()
      : undefined;
    const windowsNodeExecutable = this.platform === "win32" && npmProfiles.length > 0
      ? selectedNode ? nodeExecutablePath(selectedNode.bin_directory, this.platform) : process.execPath
      : undefined;
    const npmCli = windowsNodeExecutable
      ? await resolveTrustedWindowsNpmCli(windowsNodeExecutable, this.root)
      : undefined;
    const runtime = selectedNode
      ? { name: selectedNode.name, version: selectedNode.version, source: selectedNode.source }
      : undefined;
    const plans: CommandPlan[] = npmProfiles.map((candidate) => ({
      profile: candidate,
      script: candidate,
      executable: windowsNodeExecutable ?? "npm",
      command: testPaths && candidate === "test" ? `npm run test -- ${testPaths.join(" ")}` : `npm run ${candidate}`,
      args: windowsNodeExecutable
        ? [npmCli!, ...(testPaths && candidate === "test" ? ["run", candidate, "--", ...testPaths] : ["run", candidate])]
        : testPaths && candidate === "test" ? ["run", candidate, "--", ...testPaths] : ["run", candidate],
      pathPrefixes: selectedNode
        ? [selectedNode.bin_directory]
        : windowsNodeExecutable ? [dirname(windowsNodeExecutable)] : [],
      ...(npmProfiles.length > 0 ? { runtimeExecutable: windowsNodeExecutable ?? (selectedNode ? nodeExecutablePath(selectedNode.bin_directory, this.platform) : "node") } : {}),
      ...(windowsNodeExecutable ? { windowsNpmLifecycle: true as const } : {}),
      ...(runtime ? { runtime } : {})
    }));
    const needsPytest = !("test" in scripts) && (profile === "test" || profile === "all") && await this.hasPythonTestSuite();
    if (needsPytest) {
      const python = await this.selectPython();
      const pytestArgs = [...python.prefixArgs, "-m", "pytest", ...(testPaths ?? [])];
      const pytestPlan: CommandPlan = {
        profile: "test",
        script: "pytest",
        executable: python.executable,
        command: `${python.display} -m pytest${testPaths ? ` ${testPaths.join(" ")}` : ""}`,
        args: pytestArgs,
        pathPrefixes: []
      };
      if (profile === "all") {
        const testIndex = ALL_PROFILE_ORDER.indexOf("test");
        const insertionIndex = plans.findIndex((plan) => plan.profile !== "all" && ALL_PROFILE_ORDER.indexOf(plan.profile) > testIndex);
        plans.splice(insertionIndex === -1 ? plans.length : insertionIndex, 0, pytestPlan);
      } else {
        plans.push(pytestPlan);
      }
    }
    if (plans.length === 0 || (profile !== "all" && plans[0]?.profile !== profile)) {
      throw new RepoReaderError("VALIDATION_PROFILE_UNAVAILABLE", `Validation profile ${profile} is not available from an npm script or safe project runner.`, {
        diagnostics: { recovery_hint: "Add a matching package.json script or, for test, a pytest suite; otherwise choose an available allowlisted profile." }
      });
    }
    return Promise.all(plans.map((plan) => this.prepareCommandPlan(plan)));
  }

  private async prepareCommandPlan(plan: CommandPlan): Promise<CommandPlan> {
    try {
      const executableIdentity = await captureExecutableIdentity(this.root, plan.executable, executionPath(plan, process.env.PATH, this.platform), this.platform);
      const runtimeExecutableIdentity = plan.runtimeExecutable
        ? await captureExecutableIdentity(this.root, plan.runtimeExecutable, executionPath(plan, process.env.PATH, this.platform), this.platform)
        : undefined;
      return { ...plan, executableIdentity, ...(runtimeExecutableIdentity ? { runtimeExecutableIdentity } : {}) };
    } catch {
      throw new RepoReaderError("VALIDATION_RUNNER_UNAVAILABLE", `The selected validation executable ${plan.executable} could not be verified.`);
    }
  }

  private async selectRunnerRecipe(runner: "make" | "just"): Promise<string> {
    const candidates = runner === "make" ? ["GNUmakefile", "makefile", "Makefile"] : ["justfile", "Justfile", ".justfile"];
    for (const candidate of candidates) {
      try {
        const info = await lstat(join(this.root, candidate));
        if (!info.isFile() || info.isSymbolicLink() || info.size > 256 * 1024) {
          throw new RepoReaderError("VALIDATION_PROFILE_UNAVAILABLE", `The configured ${runner} recipe cannot be inspected safely.`);
        }
        return candidate;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      }
    }
    throw new RepoReaderError("VALIDATION_PROFILE_UNAVAILABLE", `The configured ${runner} recipe is missing from the repository root.`);
  }

  private async captureRecipe(path: string): Promise<NonNullable<CommandPlan["recipe"]>> {
    const absolute = join(this.root, path);
    const before = await lstat(absolute);
    if (!before.isFile() || before.isSymbolicLink() || before.size > 256 * 1024) {
      throw new RepoReaderError("VALIDATION_PROFILE_UNAVAILABLE", "The configured validation recipe is not a bounded regular file.");
    }
    const contents = await readFile(absolute);
    const after = await lstat(absolute);
    if (before.dev !== after.dev || before.ino !== after.ino || before.mode !== after.mode || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || contents.length !== after.size) {
      throw new RepoReaderError("VALIDATION_PROFILE_UNAVAILABLE", "The configured validation recipe changed while it was being inspected.");
    }
    return { path, size_bytes: contents.length, sha256: createHash("sha256").update(contents).digest("hex") };
  }

  private async captureSourceSnapshot(evidence: SourceEvidence, position: "before" | "after", signal?: AbortSignal, plans: CommandPlan[] = []): Promise<void> {
    try {
      const recipeSourcePaths = position === "before"
        ? plans.flatMap((plan) => plan.recipeSourcePaths ?? [])
        : await this.currentRecipeSourcePaths(plans, signal);
      evidence[position] = await new ValidationEvidenceService(this.root).captureSourceSnapshot(signal, [...new Set(recipeSourcePaths)].sort());
    } catch (error) {
      if (signal?.aborted || error instanceof DOMException && error.name === "AbortError") throw error;
      evidence[`${position}_error`] = "VALIDATION_EVIDENCE_UNAVAILABLE";
    }
  }

  private async currentRecipeSourcePaths(plans: CommandPlan[], signal?: AbortSignal): Promise<string[]> {
    const paths = new Set<string>();
    for (const plan of plans) {
      signal?.throwIfAborted();
      if (!plan.recipe) continue;
      const discovered = await new RustRuntimeResolver(this.root).discoverRecipeSources([plan.recipe.path], signal);
      for (const path of discovered) paths.add(path);
    }
    return [...paths].sort();
  }

  private async captureRunnerPostState(plans: CommandPlan[], signal?: AbortSignal): Promise<RunnerPostState[]> {
    const states: RunnerPostState[] = [];
    for (const plan of plans) {
      signal?.throwIfAborted();
      try {
        const executableIdentity = await captureExecutableIdentity(this.root, plan.executable, executionPath(plan, process.env.PATH, this.platform), this.platform);
        const runtimeExecutableIdentity = plan.runtimeExecutable
          ? await captureExecutableIdentity(this.root, plan.runtimeExecutable, executionPath(plan, process.env.PATH, this.platform), this.platform)
          : undefined;
        const recipe = plan.recipe ? await this.captureRecipe(plan.recipe.path) : undefined;
        let runtime = plan.runtime;
        if (plan.rustRuntime) {
          const selected = await new RustRuntimeResolver(this.root).resolve({ recipe_paths: plan.recipe ? [plan.recipe.path] : [], signal });
          if (!selected) throw new Error("Rust runtime selection unavailable after validation.");
          runtime = runtimeFromRust(selected);
        } else if (plan.runtime?.name === "node") {
          const selected = await new NodeRuntimeResolver(this.root, this.nodeRuntimeOptions).resolve();
          if (!selected) throw new Error("Node runtime selection unavailable after validation.");
          runtime = { name: selected.name, version: selected.version, source: selected.source };
        }
        states.push({
          profile: plan.profile,
          script: plan.script,
          executable: plan.executable,
          status: "verified",
          executable_identity: executableIdentity,
          ...(runtimeExecutableIdentity ? { runtime_executable_identity: runtimeExecutableIdentity } : {}),
          ...(recipe ? { recipe } : {}),
          ...(runtime ? { runtime } : {})
        });
      } catch (error) {
        if (signal?.aborted || error instanceof DOMException && error.name === "AbortError") throw error;
        states.push({ profile: plan.profile, script: plan.script, executable: plan.executable, status: "unverified", reason: "RUNNER_RECHECK_FAILED" });
      }
    }
    return states;
  }

  private async runCommand(command: CommandPlan, timeoutMs: number, signal?: AbortSignal): Promise<ValidateResult["commands"][number]> {
    const npmComSpec = command.windowsNpmLifecycle
      ? await resolveWindowsNpmComSpec()
      : undefined;
    const result = await runProcessWithTail({
      executable: command.executable,
      args: command.args,
      cwd: this.root,
      timeout_ms: timeoutMs,
      tail_bytes: OUTPUT_TAIL_CHARS * 4,
      signal,
      // Validation children receive a deliberately allowlisted environment rather than process.env.
      // HOME and XDG_CONFIG_HOME are forwarded only when the MCP server provides non-empty values
      // so standard developer tooling can resolve user-level configuration; all other host
      // environment variables remain excluded.
      env: {
        ...(command.runtimeEnv ?? {}),
        PATH: executionPath(command, process.env.PATH, this.platform),
        CI: "1",
        NO_COLOR: "1",
        npm_config_color: "false",
        ...(npmComSpec ? { ComSpec: npmComSpec } : {}),
        ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
        ...(process.env.XDG_CONFIG_HOME ? { XDG_CONFIG_HOME: process.env.XDG_CONFIG_HOME } : {})
      }
    });
    if (result.cleanup_confirmed !== true) {
      throw new RepoReaderError(
        "VALIDATION_PROCESS_CLEANUP_UNCONFIRMED",
        "Validation process cleanup could not be confirmed; no receipt was published."
      );
    }
    if (result.host_failure) {
      throw new RepoReaderError(
        "VALIDATION_PROCESS_SUPERVISION_FAILED",
        "Validation process supervision failed; no receipt was published."
      );
    }
    if (result.cancelled) {
      signal?.throwIfAborted();
      throw new DOMException("Validation was cancelled before completion.", "AbortError");
    }
    const passed = result.exit_code === 0 && !result.timed_out;
    return {
      profile: command.profile,
      script: command.script,
      command: command.command,
      executable: command.executable,
      ...(command.executableIdentity ? { executable_identity: command.executableIdentity } : {}),
      ...(command.runtimeExecutableIdentity ? { runtime_executable_identity: command.runtimeExecutableIdentity } : {}),
      ...(command.recipe ? { recipe: command.recipe } : {}),
      ...(command.runtime ? { runtime: command.runtime } : {}),
      status: passed ? "passed" : "failed",
      ...(typeof result.exit_code === "number" ? { exit_code: result.exit_code } : {}),
      duration_ms: result.duration_ms,
      stdout_tail: tail(result.stdout_tail),
      stderr_tail: tail(result.timed_out ? `${result.stderr_tail}\nCommand timed out after ${timeoutMs}ms.` : result.stderr_tail)
    };
  }

  private async hasPythonTestSuite(): Promise<boolean> {
    for (const marker of ["pyproject.toml", "pytest.ini", "tox.ini"]) {
      try {
        if ((await stat(join(this.root, marker))).isFile()) return true;
      } catch { /* marker absent or inaccessible */ }
    }
    let visited = 0;
    const scan = async (directory: string, depth: number): Promise<boolean> => {
      if (depth > MAX_PYTHON_SCAN_DEPTH || visited >= MAX_PYTHON_SCAN_ENTRIES) return false;
      let entries;
      try { entries = await readdir(directory, { withFileTypes: true }); } catch { return false; }
      for (const entry of entries) {
        if (++visited > MAX_PYTHON_SCAN_ENTRIES) return false;
        if (entry.isFile() && (entry.name.startsWith("test_") || entry.name.endsWith("_test.py")) && entry.name.endsWith(".py")) return true;
        if (entry.isDirectory() && !PYTHON_SCAN_EXCLUDES.has(entry.name) && await scan(join(directory, entry.name), depth + 1)) return true;
      }
      return false;
    };
    return scan(this.root, 0);
  }

  private async selectPython(): Promise<{ executable: string; prefixArgs: string[]; display: string }> {
    const localCandidates = this.platform === "win32"
      ? [[".venv", "Scripts", "python.exe"], ["venv", "Scripts", "python.exe"]]
      : [[".venv", "bin", "python"], ["venv", "bin", "python"]];
    for (const parts of localCandidates) {
      const candidate = join(this.root, ...parts);
      if (await this.isSafeLocalExecutable(candidate)) {
        return { executable: candidate, prefixArgs: [], display: parts.join("/") };
      }
    }
    if (this.platform === "win32") {
      const py = await resolveWindowsNativeExecutable("py", this.root, this.validationEnvironment.PATH ?? "");
      if (py) return { executable: py, prefixArgs: ["-3"], display: "py -3" };
      const python = await resolveWindowsNativeExecutable("python", this.root, this.validationEnvironment.PATH ?? "");
      if (python) return { executable: python, prefixArgs: [], display: "python" };
      throw new RepoReaderError("VALIDATION_PROFILE_UNAVAILABLE", "No supported native Windows Python executable was found.", {
        diagnostics: { recovery_hint: "Add python.exe or py.exe to the server PATH, or provide an executable .venv/Scripts/python.exe. Command shims are not supported." }
      });
    }
    if (await isExecutableOnPath("python3", this.platform, this.validationEnvironment.PATH)) return { executable: "python3", prefixArgs: [], display: "python3" };
    return { executable: "python", prefixArgs: [], display: "python" };
  }

  private async isSafeLocalExecutable(candidate: string): Promise<boolean> {
    if (!isWithinRoot(this.root, candidate)) return false;
    try {
      const linkInfo = await lstat(candidate);
      if (!linkInfo.isFile() && !linkInfo.isSymbolicLink()) return false;
      const [resolvedRoot, resolved] = await Promise.all([realpath(this.root), realpath(candidate)]);
      if (!isWithinRoot(resolvedRoot, resolved) || !(await stat(resolved)).isFile()) return false;
      if (this.platform !== "win32") await access(resolved, fsConstants.X_OK);
      return true;
    } catch {
      return false;
    }
  }

  private validateFocusedTestPaths(profile: ValidationProfile, paths: string[]): string[] {
    if (profile !== "test") {
      throw new RepoReaderError("VALIDATION_TEST_PATHS_REQUIRE_TEST_PROFILE", "Focused test paths are only supported with profile test.");
    }
    if (this.policy.config.validation_test_path_globs.length === 0) {
      throw new RepoReaderError("VALIDATION_TEST_PATHS_DISABLED", "Focused test paths are not enabled for this repository.");
    }
    if (paths.length === 0) {
      throw new RepoReaderError("VALIDATION_TEST_PATHS_REQUIRED", "At least one focused test path is required.");
    }
    if (paths.length > this.policy.config.max_paths_per_operation) {
      throw new RepoReaderError("VALIDATION_TOO_MANY_TEST_PATHS", `Too many focused test paths: ${paths.length}`);
    }
    const matcher = ignore().add(this.policy.config.validation_test_path_globs);
    return [...new Set(paths.map((path) => validateRepoPath(path)))].sort().map((path) => {
      if (path.startsWith("-")) {
        throw new RepoReaderError("VALIDATION_TEST_PATH_NOT_ALLOWED", "Focused test paths cannot start with a runner option prefix.");
      }
      if (this.ignoreEngine.isSensitiveCandidate(path)) {
        throw new RepoReaderError("SECRET_CANDIDATE_BLOCKED", `Validation test path blocks secret-looking path: ${path}`);
      }
      if (!matcher.ignores(path)) {
        throw new RepoReaderError("VALIDATION_TEST_PATH_NOT_ALLOWED", `Focused validation path is outside validation_test_path_globs: ${path}`);
      }
      return path;
    });
  }

  /**
   * Writes the validation artifact before updating the active `latest.json`
   * pointer. Cancellation before the pointer write removes the staged artifact.
   * Once the pointer write starts, it completes even if the caller cancels.
   *
   * The final abort check and the start of the pointer write run synchronously,
   * so cancellation cannot fall between them.
   */
  private async writeValidationArtifact(
  result: ValidateResult,
  evidence: { sourceEvidence: SourceEvidence; policyBefore: unknown; policyAfter: unknown; runnerPostState: RunnerPostState[] },
  signal?: AbortSignal
): Promise<string> {
  const validationId = result.validation_id;
  if (!validationId) {
    throw new RepoReaderError("VALIDATION_ARTIFACT_WRITE_FAILED", "Validation id missing before artifact write.");
  }
  signal?.throwIfAborted();
  const [headSha, worktreeFingerprint] = await Promise.all([
    this.currentHeadSha(),
    this.currentWorktreeFingerprint()
  ]);
  signal?.throwIfAborted();
  const artifactPath = VALIDATION_ROOT + "/" + validationId + "/result.json";
  const policySha = canonicalSha256(evidence.policyBefore);
  const policyAfterSha = canonicalSha256(evidence.policyAfter);
  const eligibilityReasons: string[] = [];
  let hasIneligibility = false;
  let hasUnverifiedEvidence = false;
  if (result.status !== "passed") {
    eligibilityReasons.push("VALIDATION_COMMAND_FAILED");
    hasIneligibility = true;
  }
  if (!evidence.sourceEvidence.before || !evidence.sourceEvidence.after) {
    eligibilityReasons.push("SOURCE_EVIDENCE_UNAVAILABLE");
    hasUnverifiedEvidence = true;
  } else if (evidence.sourceEvidence.before.sha256 !== evidence.sourceEvidence.after.sha256) {
    eligibilityReasons.push("SOURCE_STATE_CHANGED_DURING_RUN");
    hasIneligibility = true;
  }
  if (policySha !== policyAfterSha) {
    eligibilityReasons.push("EFFECTIVE_POLICY_CHANGED_DURING_RUN");
    hasIneligibility = true;
  }
  const beforeRunnerState = result.commands.map((command) => ({
    profile: command.profile,
    script: command.script,
    executable: command.executable,
    executable_identity: command.executable_identity,
      runtime_executable_identity: command.runtime_executable_identity,
    recipe: command.recipe,
    runtime: command.runtime
  }));
    const afterRunnerState = evidence.runnerPostState.map((state) => ({
      profile: state.profile,
      script: state.script,
      executable: state.executable,
      executable_identity: state.executable_identity,
      runtime_executable_identity: state.runtime_executable_identity,
      recipe: state.recipe,
      runtime: state.runtime
    }));
  if (evidence.runnerPostState.some((state) => state.status === "unverified") || afterRunnerState.length !== beforeRunnerState.length) {
    eligibilityReasons.push("RUNNER_RECHECK_UNAVAILABLE");
    hasUnverifiedEvidence = true;
  } else if (beforeRunnerState.some((state, index) => canonicalSha256(state) !== canonicalSha256(afterRunnerState[index]))) {
    eligibilityReasons.push("RUNNER_STATE_CHANGED_DURING_RUN");
    hasIneligibility = true;
  }
  const eligibility = {
    status: hasIneligibility ? "ineligible" as const : hasUnverifiedEvidence ? "unverified" as const : "eligible" as const,
    reasons: eligibilityReasons
  };
  const selectedHead = evidence.sourceEvidence.after?.head_sha ?? headSha;
  const timestamp = new Date().toISOString();
  const receiptContent = {
    schema_version: 2 as const,
    evidence_contract_version: 2 as const,
    validation_id: validationId,
    repo_id: result.repo_id,
    profile: result.profile,
    focused: result.focused === true,
    test_paths: result.test_paths ?? [],
    status: result.status,
    eligibility,
    ...(selectedHead ? { head_sha: selectedHead } : {}),
    worktree_fingerprint: worktreeFingerprint,
    timestamp,
    artifact_path: artifactPath,
    effective_policy: { sha256: policySha, after_sha256: policyAfterSha, value: evidence.policyBefore },
    source_evidence: {
      ...(evidence.sourceEvidence.before ? { before: evidence.sourceEvidence.before } : {}),
      ...(evidence.sourceEvidence.before_error ? { before_error: evidence.sourceEvidence.before_error } : {}),
      ...(evidence.sourceEvidence.after ? { after: evidence.sourceEvidence.after } : {}),
      ...(evidence.sourceEvidence.after_error ? { after_error: evidence.sourceEvidence.after_error } : {}),
      observation: "endpoint_snapshots_only" as const,
      continuous_detection: false as const,
      limitation: "Endpoint snapshots do not establish detection of transient change-and-revert activity." as const
    },
    runner_post_state: evidence.runnerPostState,
    commands: result.commands,
    counts: result.counts,
    warnings: result.warnings
  };
  const unsignedReceipt = ValidationReceiptV2BaseSchema.omit({ receipt_sha256: true }).parse(receiptContent);
  const receipt = ValidationReceiptV2Schema.parse({ ...unsignedReceipt, receipt_sha256: canonicalSha256(unsignedReceipt) });
  const latestPointer = ValidationLatestPointerV2Schema.parse({
    schema_version: 2,
    evidence_contract_version: 2,
    validation_id: validationId,
    repo_id: result.repo_id,
    profile: result.profile,
    focused: result.focused === true,
    test_paths: result.test_paths ?? [],
    status: result.status,
    eligibility: eligibility.status,
    ...(receipt.head_sha ? { head_sha: receipt.head_sha } : {}),
    worktree_fingerprint: worktreeFingerprint,
    artifact_path: artifactPath,
    timestamp,
    receipt_sha256: receipt.receipt_sha256
  });
  let receiptCommitAdmitted = false;
  const admitReceiptCommit = (): Promise<void> => {
    signal?.throwIfAborted();
    receiptCommitAdmitted = true;
    return atomicWriteJson(join(this.root, VALIDATION_ROOT, "latest.json"), latestPointer);
  };
  let artifactDirectoryCreated = false;
  try {
    artifactDirectoryCreated = await this.ensureValidationArtifactPath(validationId, false);
    await atomicWriteJson(join(this.root, artifactPath), receipt);
    await this.ensureValidationArtifactPath(validationId, true);
    signal?.throwIfAborted();
    await admitReceiptCommit();
  } catch (error) {
    // An admitted pointer write may have committed before it reported an error.
    if (signal?.aborted && !receiptCommitAdmitted && artifactDirectoryCreated) {
      await rm(join(this.root, VALIDATION_ROOT, validationId), { recursive: true, force: true }).catch(() => undefined);
    }
    throw error;
  }
  return artifactPath;
}

private async ensureValidationArtifactPath(validationId: string, artifactWritten: boolean): Promise<boolean> {
    const rootInfo = await lstat(this.root);
    const rootRealPath = await realpath(this.root);
    if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
      throw new RepoReaderError("VALIDATION_ARTIFACT_WRITE_FAILED", "The configured validation root is not a regular directory.");
    }
    let current = rootRealPath;
  let artifactDirectoryCreated = false;
  try {
    for (const component of [".chatgpt", "validation", validationId]) {
      current = join(current, component);
      let created = false;
      try {
        await mkdir(current, { mode: 0o700 });
        created = true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
      if (component === validationId) {
        artifactDirectoryCreated = created;
        if (!artifactWritten && !created) {
          throw new RepoReaderError("VALIDATION_ARTIFACT_WRITE_FAILED", "The validation artifact directory is not fresh.");
        }
      }
      const info = await lstat(current);
      if (!info.isDirectory() || info.isSymbolicLink() || !isWithinRoot(rootRealPath, await realpath(current))) {
        throw new RepoReaderError("VALIDATION_ARTIFACT_WRITE_FAILED", "The validation artifact path is not contained in the configured checkout.");
      }
      }
    const artifactPath = join(current, "result.json");
    try {
      const info = await lstat(artifactPath);
      if (!artifactWritten || !info.isFile() || info.isSymbolicLink() || !isWithinRoot(rootRealPath, await realpath(artifactPath))) {
        throw new RepoReaderError("VALIDATION_ARTIFACT_WRITE_FAILED", "The validation artifact path is not a fresh regular file inside the checkout.");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      if (artifactWritten) throw new RepoReaderError("VALIDATION_ARTIFACT_WRITE_FAILED", "The validation artifact was not written inside the checkout.");
      }
    const pointerPath = join(rootRealPath, VALIDATION_ROOT, "latest.json");
    try {
      const info = await lstat(pointerPath);
      if (!info.isFile() || info.isSymbolicLink() || !isWithinRoot(rootRealPath, await realpath(pointerPath))) {
        throw new RepoReaderError("VALIDATION_ARTIFACT_WRITE_FAILED", "The latest validation pointer is not a regular file inside the checkout.");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    return artifactDirectoryCreated;
  } catch (error) {
    if (artifactDirectoryCreated) {
      await rm(current, { recursive: true, force: true }).catch(() => undefined);
      }
    throw error;
    }
  }

  private async currentHeadSha(): Promise<string | undefined> {
    try {
      return (await new GitService(this.root).status()).head_sha;
    } catch {
      return undefined;
    }
  }

  private async currentWorktreeFingerprint(): Promise<string | undefined> {
    try {
      return await new GitService(this.root).worktreeFingerprint();
    } catch {
      return "unavailable";
    }
  }
}

function tail(value: string | Buffer | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const text = redactSensitiveText(String(value)).trimEnd();
  if (text.length === 0) {
    return undefined;
  }
  return text.length > OUTPUT_TAIL_CHARS ? text.slice(-OUTPUT_TAIL_CHARS) : text;
}

function executionPath(
  command: Pick<CommandPlan, "pathPrefixes">,
  pathValue = process.env.PATH ?? "",
  platform: NodeJS.Platform = process.platform
): string {
  const pathDelimiter = platform === "win32" ? ";" : delimiter;
  return [...new Set([...command.pathPrefixes, pathValue].filter(Boolean))].join(pathDelimiter);
}

function nodeExecutablePath(binDirectory: string, platform: NodeJS.Platform = process.platform): string {
  return join(binDirectory, platform === "win32" ? "node.exe" : "node");
}

function runtimeFromRust(selection: RustRuntimeSelection): ValidationRuntime {
  return {
    name: "rust",
    version: selection.version,
    source: selection.source,
    active_toolchain: selection.active_toolchain,
    ...(selection.rustup ? {
      rustup: {
        path_sha256: selection.rustup.path_sha256,
        real_path_sha256: selection.rustup.real_path_sha256,
        version: selection.rustup.version,
        sha256: selection.rustup.sha256
      }
    } : {}),
    cargo: {
      path_sha256: selection.cargo.path_sha256,
      real_path_sha256: selection.cargo.real_path_sha256,
      version: selection.cargo.version,
      sha256: selection.cargo.sha256
    },
    rustc: {
      path_sha256: selection.rustc.path_sha256,
      real_path_sha256: selection.rustc.real_path_sha256,
      version: selection.rustc.version,
      sha256: selection.rustc.sha256
    },
    cargo_home_path_sha256: selection.cargo_home_path_sha256,
    cargo_config_sha256: selection.cargo_config_sha256
  };
}

function copyJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function createValidationId(): string {
  return `validation-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomUUID().slice(0, 8)}`;
}

function isWithinRoot(root: string, candidate: string): boolean {
  const pathFromRoot = relative(root, candidate);
  return pathFromRoot === "" || (!pathFromRoot.startsWith(`..${sep}`) && pathFromRoot !== ".." && !isAbsolute(pathFromRoot));
}

async function isExecutableOnPath(name: "python3", platform: NodeJS.Platform, pathValue: string | undefined): Promise<boolean> {
  for (const directory of (pathValue ?? "").split(platform === "win32" ? ";" : delimiter).filter(Boolean)) {
    const candidate = join(directory, name);
    try {
      await access(candidate, fsConstants.X_OK);
      if ((await stat(candidate)).isFile()) return true;
    } catch { /* try the next fixed PATH entry */ }
  }
  return false;
}

async function resolveWindowsNpmComSpec(): Promise<string> {
  const systemRoot = process.env.SystemRoot;
  const recoveryHint = "Start the MCP server from a standard Windows environment with SystemRoot set to the Windows installation directory and cmd.exe available under System32.";
  if (!systemRoot || !win32.isAbsolute(systemRoot)) {
    throw new RepoReaderError("VALIDATION_PROFILE_UNAVAILABLE", "Windows npm validation requires the system command processor.", {
      diagnostics: { recovery_hint: recoveryHint }
    });
  }

  const comSpec = win32.join(systemRoot, "System32", "cmd.exe");
  if (process.platform === "win32") {
    try {
      if (!(await stat(comSpec)).isFile()) throw new Error("System command processor is not a file.");
    } catch {
      throw new RepoReaderError("VALIDATION_PROFILE_UNAVAILABLE", "Windows npm validation requires the system command processor.", {
        diagnostics: { recovery_hint: recoveryHint }
      });
    }
  }
  return comSpec;
}

async function resolveWindowsNativeExecutable(
  runner: "make" | "just" | "python" | "py",
  repositoryRoot: string,
  pathValue: string
): Promise<string | undefined> {
  const executableNames = {
    make: ["make.exe", "gmake.exe", "mingw32-make.exe"],
    just: ["just.exe"],
    python: ["python.exe"],
    py: ["py.exe"]
  }[runner];
  let canonicalRepositoryRoot: string;
  try {
    canonicalRepositoryRoot = await realpath(repositoryRoot);
  } catch {
    return undefined;
  }

  for (const directory of pathValue.split(";").filter(Boolean)) {
    if (!isAbsolute(directory)) continue;
    try {
      const canonicalDirectory = await realpath(directory);
      if (isWithinRoot(canonicalRepositoryRoot, canonicalDirectory)) continue;
      for (const executableName of executableNames) {
        const candidate = join(canonicalDirectory, executableName);
        const metadata = await lstat(candidate);
        if (!metadata.isFile() || metadata.isSymbolicLink()) continue;
        const resolved = await realpath(candidate);
        if (!isWithinRoot(canonicalDirectory, resolved) || isWithinRoot(canonicalRepositoryRoot, resolved)) continue;
        return resolved;
      }
    } catch {
      // Inaccessible PATH entries are skipped; absence of a native runner fails closed.
    }
  }
  return undefined;
}

async function resolveTrustedWindowsNpmCli(nodeExecutable: string, repositoryRoot: string): Promise<string> {
  const fail = (): never => {
    throw new RepoReaderError("VALIDATION_PROFILE_UNAVAILABLE", "The selected Node runtime has no trusted bundled npm CLI.", {
      diagnostics: { recovery_hint: "Install npm with the selected Node runtime. Validation does not invoke npm.cmd or substitute another Node installation." }
    });
  };
  try {
    if (!isAbsolute(nodeExecutable) || nodeExecutable.split(/[\\/]/).at(-1)?.toLowerCase() !== "node.exe") return fail();
    const canonicalRoot = await realpath(repositoryRoot);
    const canonicalNode = await realpath(nodeExecutable);
    if (isWithinRoot(canonicalRoot, canonicalNode) || !(await stat(canonicalNode)).isFile()) return fail();
    const runtimeRoot = dirname(canonicalNode);
    const candidate = join(runtimeRoot, "node_modules", "npm", "bin", "npm-cli.js");
    const metadata = await stat(candidate);
    if (!metadata.isFile()) return fail();
    const canonicalCli = await realpath(candidate);
    if (!isWithinRoot(runtimeRoot, canonicalCli) || isWithinRoot(canonicalRoot, canonicalCli)) return fail();
    return canonicalCli;
  } catch {
    return fail();
  }
}
