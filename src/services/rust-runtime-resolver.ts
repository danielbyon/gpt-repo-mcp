import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants, type Stats } from "node:fs";
import { access, lstat, opendir, readFile, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { RepoReaderError } from "../runtime/errors.js";

const PIN_FILE_LIMIT = 4 * 1024;
const RECIPE_FILE_LIMIT = 256 * 1024;
const CARGO_CONFIG_LIMIT = 64 * 1024;
const MAX_RECIPE_GRAPH_FILES = 64;
const MAX_RECIPE_GRAPH_BYTES = 2 * 1024 * 1024;
const MAX_RECIPE_GRAPH_DEPTH = 8;
const MAX_MODULE_DIRECTORY_ENTRIES = 512;
const TOOL_OUTPUT_LIMIT = 4 * 1024;
const TOOL_TIMEOUT_MS = 5_000;
const EXECUTABLE_HASH_LIMIT = 128 * 1024 * 1024;
const execFileAsync = promisify(execFile);

export type RustToolchainSource = "rust-toolchain" | "rust-toolchain.toml";

export type RustToolIdentity = {
  path: string;
  real_path: string;
  path_sha256: string;
  real_path_sha256: string;
  version: string;
  sha256: string;
};

export type RustRuntimeSelection = {
  name: "rust";
  version: string;
  source: RustToolchainSource;
  active_toolchain: string;
  rustup?: RustToolIdentity;
  cargo: RustToolIdentity;
  rustc: RustToolIdentity;
  path_prefixes: string[];
  cargo_home_path_sha256: string;
  cargo_config_sha256: string;
  execution_env: { RUSTUP?: string; RUSTUP_TOOLCHAIN: string; RUSTC: string; CARGO_HOME: string };
};

export type RustToolRunner = (
  executable: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  signal?: AbortSignal
) => Promise<string>;

export type RustRuntimeResolverOptions = {
  env?: NodeJS.ProcessEnv;
  runTool?: RustToolRunner;
};

/** Resolves a fixed rustup pin and proves that its Cargo and Rustc match it. */
export class RustRuntimeResolver {
  private readonly env: NodeJS.ProcessEnv;
  private readonly runTool: RustToolRunner;

  constructor(private readonly root: string, options: RustRuntimeResolverOptions = {}) {
    this.env = options.env ?? process.env;
    this.runTool = options.runTool ?? runTool;
  }

  /** Resolves only root-level pins and fails closed for floating or conflicting selections. */
  async resolve(options: { required?: boolean; recipe_paths?: string[]; signal?: AbortSignal } = {}): Promise<RustRuntimeSelection | undefined> {
    options.signal?.throwIfAborted();
    const recipeInspection = await this.inspectRecipeSources(options.recipe_paths ?? [], options.signal);
    if (recipeInspection.unresolved) {
      throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "A Make or Just helper could not be inspected within the checkout's bounded inventory.");
    }
    const rustRequired = options.required === true
      || recipeInspection.requiresRustVerification;
    if (!rustRequired) return undefined;

    const pin = await this.readPin(options.signal);
    if (!pin) {
      throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_UNPINNED", "Rust validation requires an exact root-level rust-toolchain pin.");
    }
    const requiresPinnedRustup = await this.assertRecipePins(pin.version, recipeInspection.paths, options.signal, new Set(recipeInspection.justPaths));
    const cargoHome = this.cargoHome();
    const cargoConfigSha256 = await this.assertNoCargoCompilerWrappers(cargoHome, options.signal);

    const path = this.env.PATH ?? "";
    const rustup = await findExecutable("rustup", path);
    if (requiresPinnedRustup && !rustup) {
      throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_UNAVAILABLE", "The approved Makefile toolchain recipe requires a verified rustup executable.");
    }
    const executionEnv: NodeJS.ProcessEnv = {
      PATH: path,
      ...(rustup ? { RUSTUP: rustup } : {}),
      RUSTUP_TOOLCHAIN: pin.version,
      CARGO_HOME: cargoHome
    };
    let activeToolchain: string;
    let cargoPath: string;
    let rustcPath: string;
    let rustupIdentityBeforeSelection: RustToolIdentity | undefined;
    let rustupIdentity: RustToolIdentity | undefined;
    if (rustup) {
      rustupIdentityBeforeSelection = await this.verifyTool("rustup", rustup, undefined, executionEnv, options.signal);
      const active = await this.invoke(rustup, ["show", "active-toolchain"], executionEnv, options.signal);
      activeToolchain = active.trim().split(/\s+/)[0] ?? "";
      if (!toolchainMatches(activeToolchain, pin.version)) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "rustup selected a toolchain different from the repository pin.");
      }
      cargoPath = await this.invoke(rustup, ["which", "--toolchain", pin.version, "cargo"], executionEnv, options.signal);
      rustcPath = await this.invoke(rustup, ["which", "--toolchain", pin.version, "rustc"], executionEnv, options.signal);
    } else {
      activeToolchain = `${pin.version} (verified by Cargo and Rustc versions)`;
      cargoPath = (await findExecutable("cargo", path)) ?? "";
      rustcPath = (await findExecutable("rustc", path)) ?? "";
    }

    const [cargo, rustc] = await Promise.all([
      this.verifyTool("cargo", cargoPath.trim(), pin.version, executionEnv, options.signal),
      this.verifyTool("rustc", rustcPath.trim(), pin.version, executionEnv, options.signal)
    ]);
    if (rustup) {
      const identityAfterSelection = await this.captureRustToolIdentity("rustup", rustup, rustupIdentityBeforeSelection!.version, options.signal);
      if (!rustupIdentityBeforeSelection || !sameToolIdentity(rustupIdentityBeforeSelection, identityAfterSelection)) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The selected rustup executable changed while resolving the pinned toolchain.");
      }
      rustupIdentity = identityAfterSelection;
    }
    options.signal?.throwIfAborted();
    return {
      name: "rust",
      version: pin.version,
      source: pin.source,
      active_toolchain: activeToolchain,
      ...(rustupIdentity ? { rustup: rustupIdentity } : {}),
      cargo,
      rustc,
      path_prefixes: [...new Set([dirname(cargo.real_path), dirname(rustc.real_path)])],
      cargo_home_path_sha256: sha256(cargoHome),
      cargo_config_sha256: cargoConfigSha256,
      execution_env: {
        ...(rustup ? { RUSTUP: rustup } : {}),
        RUSTUP_TOOLCHAIN: pin.version,
        RUSTC: rustc.real_path,
        CARGO_HOME: cargoHome
      }
    };
  }

  /** Returns the bounded recipe and helper source graph, failing when any path cannot be verified. */
  async discoverRecipeSources(recipePaths: string[], signal?: AbortSignal): Promise<string[]> {
    const inspection = await this.inspectRecipeSources(recipePaths, signal);
    if (inspection.unresolved) {
      throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "A Make or Just helper could not be inspected within the checkout's bounded inventory.");
    }
    return inspection.paths;
  }

  private cargoHome(): string {
    const configured = this.env.CARGO_HOME;
    if (configured !== undefined) {
      if (!configured || !isAbsolute(configured)) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The active Cargo home path cannot be verified safely.");
      }
      return configured;
    }
    const home = this.env.HOME ?? this.env.USERPROFILE ?? homedir();
    if (!home) throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The active Cargo home path cannot be resolved safely.");
    return join(isAbsolute(home) ? home : resolve(this.root, home), ".cargo");
  }

  private async readPin(signal?: AbortSignal): Promise<{ version: string; source: RustToolchainSource } | undefined> {
    const candidates: RustToolchainSource[] = ["rust-toolchain.toml", "rust-toolchain"];
    const present: Array<{ source: RustToolchainSource; content: string }> = [];
    for (const source of candidates) {
      signal?.throwIfAborted();
      const path = join(this.root, source);
      try {
        const info = await lstat(path);
        if (!info.isFile() || info.isSymbolicLink() || info.size > PIN_FILE_LIMIT) {
          throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_UNPINNED", "The root rust-toolchain pin is not a bounded regular file.");
        }
        present.push({ source, content: await readFile(path, "utf8") });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      }
    }
    if (present.length === 0) return undefined;
    if (present.length !== 1) {
      throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "Use one root-level rust-toolchain pin file so the selected toolchain is unambiguous.");
    }
    const selected = present[0]!;
    const version = selected.source === "rust-toolchain"
      ? parsePlainPin(selected.content)
      : parseTomlPin(selected.content);
    if (!version) {
      throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_UNPINNED", "Rust validation requires an exact numeric rust-toolchain version; floating channels are not eligible.");
    }
    return { version, source: selected.source };
  }

  private async inspectRecipeSources(
    recipePaths: string[],
    signal?: AbortSignal
  ): Promise<{ paths: string[]; justPaths: string[]; requiresRustVerification: boolean; unresolved: boolean }> {
    const root = await realpath(this.root);
    const pending = recipePaths.map((path) => ({ path, depth: 0, workingDirectory: "", justSource: isJustfilePath(path) }));
    const seen = new Map<string, string>();
    const paths: string[] = [];
    const justPaths = new Set<string>();
    let totalBytes = 0;
    let requiresRustVerification = false;
    let unresolved = false;

    while (pending.length > 0) {
      signal?.throwIfAborted();
      const next = pending.shift()!;
      const normalizedPath = normalizeRecipeSourcePath(root, "", next.path);
      if (!normalizedPath) {
        unresolved = true;
        continue;
      }
      const context = `${next.workingDirectory}\0${next.justSource ? "just" : "other"}`;
      const previousContext = seen.get(normalizedPath);
      if (previousContext !== undefined) {
        if (previousContext !== context) unresolved = true;
        continue;
      }
      if (seen.size >= MAX_RECIPE_GRAPH_FILES || next.depth > MAX_RECIPE_GRAPH_DEPTH) {
        unresolved = true;
        break;
      }
      seen.set(normalizedPath, context);

      let content: string;
      try {
        const info = await lstatContainedRecipePath(root, normalizedPath);
        if (!info.isFile() || info.isSymbolicLink() || info.size > RECIPE_FILE_LIMIT) {
          unresolved = true;
          continue;
        }
        totalBytes += info.size;
        if (totalBytes > MAX_RECIPE_GRAPH_BYTES) {
          unresolved = true;
          break;
        }
        const absolutePath = resolve(root, ...normalizedPath.split("/"));
        content = await readFile(absolutePath, "utf8");
        const after = await lstatContainedRecipePath(root, normalizedPath);
        if (!sameFileIdentity(info, after) || Buffer.byteLength(content, "utf8") !== after.size) {
          unresolved = true;
          continue;
        }
      } catch (error) {
        if (signal?.aborted) throw signal.reason ?? error;
        unresolved = true;
        continue;
      }
      paths.push(normalizedPath);
      const isJustSource = next.justSource || isJustfilePath(normalizedPath);
      if (isJustSource) justPaths.add(normalizedPath);
      const activeLines = activeRecipeLines(content);
      if (activeLines.some((line) =>
        /\b(?:cargo|rustc|CARGO(?:_[A-Z0-9_]+)?|RUST(?:_[A-Z0-9_]+)?|RUSTC(?:_[A-Z0-9_]+)?|RUSTUP(?:_[A-Z0-9_]+)?)\b/i.test(line)
        || /\bPATH\s*(?:\?=|:=|\+=|=)/i.test(line)
      )) requiresRustVerification = true;
      const helperBase = isJustSource ? next.workingDirectory : "";
      for (const reference of recipeFileReferences(content, normalizedPath)) {
        const normalizedReference = normalizeRecipeSourcePath(root, helperBase, reference);
        if (!normalizedReference) {
          unresolved = true;
          continue;
        }
        pending.push({
          path: normalizedReference,
          depth: next.depth + 1,
          workingDirectory: next.workingDirectory,
          justSource: isJustfilePath(normalizedReference)
        });
      }
      if (isJustSource) {
        const justGraph = await discoverJustSourceReferences(root, normalizedPath, content);
        if (justGraph.unresolved) unresolved = true;
        for (const reference of justGraph.references) {
          pending.push({
            path: reference.path,
            depth: next.depth + 1,
            workingDirectory: reference.kind === "module" ? recipeDirectory(reference.path) : next.workingDirectory,
            justSource: true
          });
        }
      }
    }
    return { paths, justPaths: [...justPaths].sort(), requiresRustVerification, unresolved };
  }

  private async assertNoCargoCompilerWrappers(cargoHome: string, signal?: AbortSignal): Promise<string> {
    const root = await realpath(this.root);
    const directories = new Set<string>();
    for (let directory = root; ; directory = dirname(directory)) {
      directories.add(join(directory, ".cargo"));
      if (directory === dirname(directory)) break;
    }
    directories.add(cargoHome);

    const configIdentities: Array<{ path_sha256: string; exists: boolean; content_sha256?: string }> = [];
    for (const directory of directories) {
      for (const name of ["config.toml", "config"]) {
        signal?.throwIfAborted();
        const path = join(directory, name);
        try {
          const before = await lstat(path);
          if (!before.isFile() || before.isSymbolicLink() || before.size > CARGO_CONFIG_LIMIT) {
            throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "Cargo configuration cannot be inspected safely.");
          }
          const content = await readFile(path, "utf8");
          const after = await lstat(path);
          if (!sameFileIdentity(before, after) || Buffer.byteLength(content, "utf8") !== after.size) {
            throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "Cargo configuration changed while it was being inspected.");
          }
          const activeLines = content.split(/\r?\n/).filter((line) => !/^\s*#/.test(line));
          if (activeLines.some((line) => /^\s*(?:include|"include"|'include')\s*=/.test(line))) {
            throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "Cargo configuration includes can load unchecked compiler overrides.");
          }
          if (activeLines.some((line) => /["']?\b(?:rustc|rustc-wrapper|rustc-workspace-wrapper)\b["']?\s*=/.test(line))) {
            throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "Cargo compiler overrides and wrappers are not eligible for pinned validation.");
          }
          configIdentities.push({ path_sha256: sha256(resolve(path)), exists: true, content_sha256: sha256(content) });
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") {
            configIdentities.push({ path_sha256: sha256(resolve(path)), exists: false });
            continue;
          }
          throw error;
        }
      }
    }
    return sha256(JSON.stringify(configIdentities.sort((left, right) => left.path_sha256.localeCompare(right.path_sha256))));
  }

  private async assertRecipePins(version: string, recipePaths: string[], signal?: AbortSignal, justPaths = new Set<string>()): Promise<boolean> {
    let usesApprovedPinnedRustupRecipe = false;
    for (const recipePath of recipePaths) {
      signal?.throwIfAborted();
      if (!isRustRecipePath(recipePath) && !justPaths.has(recipePath)) continue;
      const path = join(this.root, recipePath);
      let content: string;
      try {
        const info = await lstat(path);
        if (!info.isFile() || info.isSymbolicLink() || info.size > RECIPE_FILE_LIMIT) {
          throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "A configured runner recipe cannot be inspected safely.");
        }
        content = await readFile(path, "utf8");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      }
      const activeLines = activeRecipeLines(content);
      const trustedNscbLines = /(?:^|\/)(?:GNUmakefile|[Mm]akefile|[^/]+\.mk)$/.test(recipePath)
        ? approvedNscbMakefileLines(activeLines, version)
        : new Set<number>();
      if (trustedNscbLines.size > 0) usesApprovedPinnedRustupRecipe = true;
      const guardedLines = activeLines.filter((_line, index) => !trustedNscbLines.has(index));
      const selectors = [
        ...guardedLines.flatMap((line) => [...line.matchAll(/\b(?:RUSTUP_TOOLCHAIN|RUST_TOOLCHAIN|RUST_VERSION|RUSTC_VERSION)\s*(?:\?=|:=|=)\s*([^\s#]+)/gi)].map((match) => unquote(match[1]!))),
        ...guardedLines.flatMap((line) => [...line.matchAll(/\b(?:cargo|rustc)\s+\+([^\s]+)/gi)].map((match) => match[1]!)),
        ...guardedLines.flatMap((line) => [...line.matchAll(/\brustup\s+(?:run|toolchain\s+run)\s+([^\s]+)/gi)].map((match) => match[1]!))
      ];
      if (selectors.some((selector) => selector !== version)) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The configured runner recipe selects a toolchain different from the root rust-toolchain pin.");
      }
      const binaryOverrides = guardedLines.flatMap((line) => [...line.matchAll(/\b(?:CARGO|RUSTC|CARGO_BUILD_RUSTC)\s*(?:\?=|:=|=)\s*([^\s#;]*)/gi)].map((match) => unquote(match[1]!)));
      if (binaryOverrides.some((value) => !["cargo", "cargo.exe", "rustc", "rustc.exe"].includes(value.toLowerCase()))) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The configured runner recipe overrides Cargo or Rustc with an unverified executable.");
      }
      if (guardedLines.some((line) => /(?:^|[\s;&|])['"]?(?:\.{1,2}[\\/]|\/|[A-Za-z]:[\\/])[^\s'"#;|&]*[\\/](?:cargo|rustc)(?:\.exe)?(?=$|[\s;&|])/i.test(line))) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The configured runner recipe selects Cargo or Rustc by an unverified path.");
      }
      if (guardedLines.some((line) => /\bPATH\s*(?:\?=|:=|\+=|=)/i.test(line))) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The configured runner recipe changes the verified tool search path.");
      }
      if (guardedLines.some((line) => /\b(?:unset(?:\s+|=)[^\n]*\b(?:RUSTC|RUSTUP_TOOLCHAIN|CARGO_HOME|HOME|PATH)\b|env\s+(?:-i\b|--ignore-environment\b|(?:-u(?:\s+|=)|--unset(?:=|\s+))\s*(?:RUSTC|RUSTUP_TOOLCHAIN|CARGO_HOME|HOME|PATH)\b)|set\s+(?:RUSTC|RUSTUP_TOOLCHAIN|CARGO_HOME|HOME|PATH)\s*=)/i.test(line))) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The configured runner recipe can clear or replace the verified Rust execution environment.");
      }
      if (guardedLines.some((line) => /\benv\s+(?:-(?!-)[A-Za-z]*S[A-Za-z]*\S*|--split-string(?:=|\s))/i.test(line))) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The configured runner recipe uses an opaque env command that may replace the verified Rust environment.");
      }
      const wrapperOverrides = guardedLines.flatMap((line) => [...line.matchAll(/\b(?:RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|CARGO_BUILD_RUSTC_WRAPPER|CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER)\s*(?:\?=|:=|=)\s*([^\s#;]*)/gi)].map((match) => unquote(match[1]!)));
      if (wrapperOverrides.some((value) => value.length > 0)) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The configured runner recipe overrides the verified Rust compiler with a wrapper.");
      }
      if (guardedLines.some((line) => line.includes("--config")
          && /\b(?:build\.rustc|rustc-wrapper|rustc-workspace-wrapper)\s*=/.test(line))) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The configured runner recipe overrides Cargo's verified Rust compiler selection.");
      }
      if (guardedLines.some(hasCargoConfigFileArgument)) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "Cargo configuration files passed on the command line are not eligible because they can override the verified compiler.");
      }
      const homeOverrides = guardedLines.flatMap((line) => [...line.matchAll(/\b(?:CARGO_HOME|HOME)\s*(?:\?=|:=|=)\s*([^\s#;]*)/gi)].map((match) => unquote(match[1]!)));
      if (homeOverrides.length > 0) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The configured runner recipe changes Cargo configuration lookup paths.");
      }
      if (guardedLines.some(hasUntrustedRustToolSelectionAssignment)) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The configured runner recipe overrides a Rust tool selector or executable path outside the approved pinned Makefile structure.");
      }
    }
    return usesApprovedPinnedRustupRecipe;
  }

  private async verifyTool(name: "cargo" | "rustc" | "rustup", selectedPath: string, version: string | undefined, env: NodeJS.ProcessEnv, signal?: AbortSignal): Promise<RustToolIdentity> {
    if (!selectedPath || !isAbsolute(selectedPath)) {
      throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_UNAVAILABLE", `The pinned ${name} executable could not be resolved.`);
    }
    const rustupIdentityBeforeVersion = name === "rustup"
      ? await this.captureRustToolIdentity(name, selectedPath, "0.0.0", signal)
      : undefined;
    const resolved = await realpath(selectedPath);
    const output = await this.invoke(resolved, ["--version"], env, signal);
    const actualVersion = parseToolVersion(output, name);
    if (version && actualVersion !== version) {
      throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", `The selected ${name} version does not match the root rust-toolchain pin.`);
    }
    const identity = await this.captureRustToolIdentity(name, selectedPath, actualVersion, signal);
    if (rustupIdentityBeforeVersion && !sameToolIdentity({ ...rustupIdentityBeforeVersion, version: actualVersion }, identity)) {
      throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", "The selected rustup executable changed while its identity was being verified.");
    }
    return identity;
  }

  private async captureRustToolIdentity(
    name: "cargo" | "rustc" | "rustup",
    selectedPath: string,
    version: string,
    signal?: AbortSignal
  ): Promise<RustToolIdentity> {
    signal?.throwIfAborted();
    if (!selectedPath || !isAbsolute(selectedPath)) {
      throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_UNAVAILABLE", `The pinned ${name} executable could not be resolved.`);
    }
    let resolved: string;
    let info: Stats;
    let content: Buffer;
    try {
      resolved = await realpath(selectedPath);
      info = await lstat(resolved);
      if (!info.isFile()) throw new Error("not a regular file");
      await access(resolved, fsConstants.X_OK);
      if (info.size > EXECUTABLE_HASH_LIMIT) throw new Error("executable too large");
      content = await readFile(resolved);
      const after = await lstat(resolved);
      if (!sameFileIdentity(info, after) || Buffer.byteLength(content) !== after.size) {
        throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_MISMATCH", `The selected ${name} executable changed while its identity was being captured.`);
      }
    } catch (error) {
      if (error instanceof RepoReaderError) throw error;
      throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_UNAVAILABLE", `The selected ${name} executable is not a bounded executable file.`);
    }
    signal?.throwIfAborted();
    return {
      path: selectedPath,
      real_path: resolved,
      path_sha256: createHash("sha256").update(selectedPath).digest("hex"),
      real_path_sha256: createHash("sha256").update(resolved).digest("hex"),
      version,
      sha256: createHash("sha256").update(content).digest("hex")
    };
  }

  private async invoke(executable: string, args: string[], env: NodeJS.ProcessEnv, signal?: AbortSignal): Promise<string> {
    signal?.throwIfAborted();
    try {
      const output = await this.runTool(executable, args, this.root, env, signal);
      if (Buffer.byteLength(output, "utf8") > TOOL_OUTPUT_LIMIT) throw new Error("tool output too large");
      signal?.throwIfAborted();
      return output;
    } catch (error) {
      if (signal?.aborted) throw signal.reason ?? error;
      if (error instanceof RepoReaderError) throw error;
      throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_UNAVAILABLE", "The pinned Rust toolchain could not be queried.");
    }
  }
}

function parsePlainPin(content: string): string | undefined {
  const value = content.trim();
  return isExactVersion(value) ? value : undefined;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function sameFileIdentity(left: Stats, right: Stats): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function parseTomlPin(content: string): string | undefined {
  let inToolchain = false;
  const channels: string[] = [];
  for (const line of content.split(/\r?\n/)) {
    const uncommented = line.replace(/\s+#.*$/, "").trim();
    const section = /^\[([^\]]+)\]$/.exec(uncommented);
    if (section) {
      inToolchain = section[1] === "toolchain";
      continue;
    }
    if (!inToolchain) continue;
    const assignment = /^channel\s*=\s*(["'])([^"']+)\1$/.exec(uncommented);
    if (/^channel\s*=/.test(uncommented)) channels.push(assignment?.[2] ?? "");
  }
  if (channels.length !== 1 || !isExactVersion(channels[0]!)) return undefined;
  return channels[0];
}

function isExactVersion(value: string): boolean {
  return /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(value);
}

function toolchainMatches(selected: string, version: string): boolean {
  return selected === version || selected.startsWith(`${version}-`);
}

function parseToolVersion(output: string, tool: "cargo" | "rustc" | "rustup"): string {
  const match = new RegExp(`^${tool}\\s+((?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*))(?:\\s|$)`).exec(output.trim());
  if (!match) throw new RepoReaderError("VALIDATION_RUST_TOOLCHAIN_UNAVAILABLE", `The selected ${tool} version output could not be parsed.`);
  return match[1]!;
}

function sameToolIdentity(left: RustToolIdentity, right: RustToolIdentity): boolean {
  return left.path === right.path
    && left.real_path === right.real_path
    && left.version === right.version
    && left.sha256 === right.sha256;
}

function unquote(value: string): string {
  return value.replace(/^["']|["']$/g, "");
}

function hasCargoConfigFileArgument(line: string): boolean {
  const argumentsAfterConfig = /(?:^|\s)--config(?:=|\s+)(?:"([^"]*)"|'([^']*)'|([^\s;&|#]+))/g;
  return [...line.matchAll(argumentsAfterConfig)].some((match) => {
    const value = match[1] ?? match[2] ?? match[3] ?? "";
    return value.startsWith(".") || value.startsWith("/") || /^[A-Za-z]:[\\/]/.test(value) || !value.includes("=");
  });
}

function activeRecipeLines(content: string): string[] {
  return content.replace(/\\\r?\n[\t ]*/g, " ")
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0 && !/^\s*(?:#|\/\/)/.test(line));
}

/** Trusts only NSCB's complete pinned rustup-to-Cargo/Rustc variable chain. */
function approvedNscbMakefileLines(lines: string[], version: string): Set<number> {
  const expected = [
    "RUSTUP ?= rustup",
    `override RUST_TOOLCHAIN := ${version}`,
    "override RUST_TOOLCHAIN_BIN := $(patsubst %/,%,$(dir $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) cargo 2>/dev/null)))",
    "override CARGO_BIN := $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) cargo 2>/dev/null)",
    "override RUSTC_BIN := $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) rustc 2>/dev/null)",
    "override RUSTFMT_BIN := $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) rustfmt 2>/dev/null)",
    "TOOLCHAIN_ENV = env -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER RUSTUP_TOOLCHAIN=$(RUST_TOOLCHAIN) RUSTC=$(RUSTC_BIN) RUSTFMT=$(RUSTFMT_BIN) PATH=\"$(RUST_TOOLCHAIN_BIN):$$PATH\"",
    "override CARGO := $(TOOLCHAIN_ENV) $(CARGO_BIN)"
  ].map(normalizeRecipeWhitespace);
  const normalized = lines.map(normalizeRecipeWhitespace);
  const requiredIndexes: number[] = [];
  for (const expectedLine of expected) {
    const matches = normalized.flatMap((line, index) => line === expectedLine ? [index] : []);
    if (matches.length !== 1) return new Set();
    requiredIndexes.push(matches[0]!);
  }
  return new Set(requiredIndexes);
}

function normalizeRecipeWhitespace(value: string): string {
  return value.trim().replace(/[\t ]+/g, " ");
}

function isRustRecipePath(path: string): boolean {
  if (path.toLowerCase().endsWith(".py")) return false;
  const normalized = path.replace(/\\/g, "/");
  return /(?:^|\/)(?:GNUmakefile|[Mm]akefile|[^/]+\.mk|\.?[Jj]ustfile|[^/]+\.(?:just|sh|bash|zsh|py|js|mjs|cjs|ts|cmd|ps1))$/i.test(normalized);
}

function isJustfilePath(path: string): boolean {
  return /(?:^|\/)(?:\.?justfile|[^/]+\.just)$/i.test(path.replace(/\\/g, "/"));
}

function normalizeRecipeSourcePath(root: string, baseDirectory: string, path: string): string | undefined {
  if (!path || path.includes("\0") || path.includes("\\") || path.startsWith("~/") || /[~$*?{}\x5B\x5D]/.test(path)) return undefined;
  const base = baseDirectory ? resolve(root, ...baseDirectory.split("/")) : root;
  const absolute = isAbsolute(path) ? resolve(path) : resolve(base, path);
  const value = relative(root, absolute);
  if (!value || value === ".." || value.startsWith(`..${sep}`) || isAbsolute(value)) return undefined;
  return value.split(sep).join("/");
}

function recipeDirectory(path: string): string {
  const directory = dirname(path);
  return directory === "." ? "" : directory.replace(/\\/g, "/");
}

async function lstatContainedRecipePath(root: string, path: string): Promise<Stats> {
  let current = root;
  const components = path.split("/");
  for (let index = 0; index < components.length; index += 1) {
    current = join(current, components[index]!);
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error("recipe source path contains a symlink");
    if (index < components.length - 1 && !info.isDirectory()) throw new Error("recipe source parent is not a directory");
    if (index === components.length - 1) {
      const realPath = await realpath(current);
      const fromRoot = relative(root, realPath);
      if (fromRoot === ".." || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
        throw new Error("recipe source resolves outside the checkout");
      }
      return info;
    }
  }
  throw new Error("recipe source path is empty");
}

function hasUntrustedRustToolSelectionAssignment(line: string): boolean {
  const names = "RUSTUP|RUST_TOOLCHAIN_BIN|CARGO_BIN|RUSTC_BIN|RUSTFMT_BIN|TOOLCHAIN_ENV";
  if (new RegExp(`^\\s*(?:[@+-]\\s*)?(?:(?:override|export|private)\\s+)?(?:${names})\\s*(?:\\?=|:=|\\+=|=)`, "i").test(line)) {
    return true;
  }
  return tokenizeShellCommands(line).some((command) => command.some((token) =>
    !token.quoted && new RegExp(`^(?:${names})=`, "i").test(token.value)));
}

/** Finds executable helper paths and unittest discovery files without scanning string arguments as paths. */
function recipeFileReferences(content: string, recipePath: string): string[] {
  const references = new Set<string>();
  const isMakefile = /(?:^|\/)(?:GNUmakefile|[Mm]akefile|[^/]+\.mk)$/.test(recipePath);
  const isJustfile = isJustfilePath(recipePath);
  if (!isMakefile && !isJustfile && !/\.(?:sh|bash|zsh)$/i.test(recipePath)) return [];
  const lines = activeRecipeLines(content);

  for (const line of lines) {
    const trimmed = line.trim();
    const include = /^(?:-?include|sinclude)\s+(.+)$/i.exec(trimmed);
    if (include) {
      const value = include[1] ?? "";
      for (const token of tokenizeShellCommands(value).flatMap((command) => command.map((part) => part.value))) {
        if (token && !token.startsWith("-")) references.add(token);
      }
    }
  }

  for (const line of lines) {
    if (isMakefile && !/^\s*\t/.test(line)) continue;
    if (isJustfile && !/^\s{4,}/.test(line)) continue;
    if (isMakefile || isJustfile) {
      for (const command of tokenizeShellCommands(line.trim().replace(/^[+@-]+\s*/, ""))) {
        addCommandReferences(command, references);
      }
    } else {
      for (const command of tokenizeShellCommands(line)) addCommandReferences(command, references);
    }
  }
  return [...references];
}

type JustSourceReference = { path: string; kind: "import" | "module" };
type JustDirective = { kind: "import" | "module"; optional: boolean; name?: string; path?: string };

async function discoverJustSourceReferences(root: string, recipePath: string, content: string): Promise<{ references: JustSourceReference[]; unresolved: boolean }> {
  const references: JustSourceReference[] = [];
  let unresolved = false;
  for (const sourceLine of activeRecipeLines(content)) {
    if (/^\s/.test(sourceLine)) continue;
    const line = sourceLine.trim();
    if (!/^(?:import|mod)(?:\?|\s|$)/.test(line)) continue;
    const match = /^(import|mod)(\?)?\s+(.+)$/.exec(line);
    if (!match) {
      unresolved = true;
      continue;
    }
    const kind = match[1] === "import" ? "import" : "module";
    const tokens = tokenizeShellCommands(match[3]!);
    if (tokens.length !== 1) {
      unresolved = true;
      continue;
    }
    const args = tokens[0]!;
    const optional = match[2] === "?";
    let directive: JustDirective | undefined;
    if (kind === "import") {
      if (args.length === 1 && args[0]!.quoted) {
        directive = { kind, optional, path: args[0]!.value };
      }
    } else if ((args.length === 1 || args.length === 2)
        && !args[0]!.quoted
        && /^[A-Za-z_][A-Za-z0-9_-]*$/.test(args[0]!.value)
        && (args.length === 1 || args[1]!.quoted)) {
      directive = { kind, optional, name: args[0]!.value, ...(args[1] ? { path: args[1].value } : {}) };
    }
    if (!directive) {
      unresolved = true;
      continue;
    }

    if (directive.kind === "import") {
      const path = normalizeRecipeSourcePath(root, recipeDirectory(recipePath), directive.path!);
      if (!path) {
        unresolved = true;
        continue;
      }
      const source = await safeRecipePathInfo(root, path);
      if (source.state === "missing" && directive.optional) continue;
      if (source.state !== "present" || !source.info.isFile()) {
        unresolved = true;
        continue;
      }
      references.push({ path, kind: "import" });
      continue;
    }

    const modulePaths = await resolveJustModuleSources(root, recipePath, directive.name!, directive.path, directive.optional);
    if (!modulePaths) {
      unresolved = true;
      continue;
    }
    references.push(...modulePaths.map((path) => ({ path, kind: "module" as const })));
  }
  return { references, unresolved };
}

async function resolveJustModuleSources(
  root: string,
  containingRecipe: string,
  moduleName: string,
  explicitPath: string | undefined,
  optional: boolean
): Promise<string[] | undefined> {
  const baseDirectory = recipeDirectory(containingRecipe);
  if (explicitPath !== undefined) {
    const modulePath = normalizeRecipeSourcePath(root, baseDirectory, explicitPath);
    if (!modulePath) return undefined;
    const target = await safeRecipePathInfo(root, modulePath);
    if (target.state === "missing") return optional ? [] : undefined;
    if (target.state !== "present") return undefined;
    if (target.info.isFile()) return [modulePath];
    if (!target.info.isDirectory()) return undefined;
    return moduleFilesUnder(root, modulePath, optional);
  }

  const direct = normalizeRecipeSourcePath(root, baseDirectory, `${moduleName}.just`);
  const directory = normalizeRecipeSourcePath(root, baseDirectory, moduleName);
  if (!direct || !directory) return undefined;
  const directTarget = await safeRecipePathInfo(root, direct);
  const directoryTarget = await safeRecipePathInfo(root, directory);
  if (directTarget.state === "unsafe" || directoryTarget.state === "unsafe") return undefined;
  if (directTarget.state === "present" && !directTarget.info.isFile()) return undefined;
  if (directoryTarget.state === "present" && !directoryTarget.info.isDirectory()) return undefined;

  const candidates: string[] = [];
  if (directTarget.state === "present") candidates.push(direct);
  if (directoryTarget.state === "present") {
    const nested = await moduleFilesUnder(root, directory, true);
    if (!nested) return undefined;
    candidates.push(...nested);
  }
  if (candidates.length > 1) return undefined;
  if (candidates.length === 1) return candidates;
  return optional ? [] : undefined;
}

async function moduleFilesUnder(root: string, directory: string, optional: boolean): Promise<string[] | undefined> {
  const target = await safeRecipePathInfo(root, directory);
  if (target.state === "missing") return optional ? [] : undefined;
  if (target.state !== "present" || !target.info.isDirectory()) return undefined;
  let directoryHandle: Awaited<ReturnType<typeof opendir>> | undefined;
  const sourceNames: string[] = [];
  try {
    directoryHandle = await opendir(resolve(root, ...directory.split("/")));
    let entryCount = 0;
    for await (const entry of directoryHandle) {
      entryCount += 1;
      if (entryCount > MAX_MODULE_DIRECTORY_ENTRIES) return undefined;
      if (entry.name === "mod.just" || entry.name.toLowerCase() === "justfile" || entry.name.toLowerCase() === ".justfile") {
        sourceNames.push(entry.name);
      }
    }
  } catch {
    return undefined;
  } finally {
    await directoryHandle?.close().catch(() => undefined);
  }
  if (sourceNames.length > 1) return undefined;
  if (sourceNames.length === 0) return optional ? [] : undefined;
  const path = `${directory}/${sourceNames[0]!}`;
  const source = await safeRecipePathInfo(root, path);
  if (source.state !== "present" || !source.info.isFile()) return undefined;
  return [path];
}

async function safeRecipePathInfo(root: string, path: string): Promise<{ state: "missing" } | { state: "unsafe" } | { state: "present"; info: Stats }> {
  try {
    return { state: "present", info: await lstatContainedRecipePath(root, path) };
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? { state: "missing" } : { state: "unsafe" };
  }
}

type ShellToken = { value: string; quoted: boolean };

function tokenizeShellCommands(value: string): ShellToken[][] {
  const commands: ShellToken[][] = [[]];
  let token = "";
  let tokenWasQuoted = false;
  let quote: "'" | '"' | undefined;
  let escaped = false;
  const finishToken = () => {
    if (token.length > 0) commands.at(-1)!.push({ value: token, quoted: tokenWasQuoted });
    token = "";
    tokenWasQuoted = false;
  };
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]!;
    if (escaped) {
      token += character;
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (character === quote) quote = undefined;
      else token += character;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      tokenWasQuoted = true;
      continue;
    }
    if (character === "#" && (index === 0 || /\s/.test(value[index - 1]!))) break;
    if (/\s/.test(character)) {
      finishToken();
      continue;
    }
    if (character === ";" || character === "|" || character === "&") {
      finishToken();
      if (character === "|" && value[index + 1] === "|" || character === "&" && value[index + 1] === "&") index += 1;
      if (commands.at(-1)!.length > 0) commands.push([]);
      continue;
    }
    token += character;
  }
  finishToken();
  return commands.filter((command) => command.length > 0);
}

function addCommandReferences(tokens: ShellToken[], references: Set<string>): void {
  let index = 0;
  while (index < tokens.length && isEnvironmentAssignment(tokens[index]!.value)) index += 1;
  if (tokens[index]?.value === "env") {
    index += 1;
    while (index < tokens.length) {
      const value = tokens[index]!.value;
      if (value === "-u" || value === "--unset") { index += 2; continue; }
      if (value.startsWith("--unset=")) { index += 1; continue; }
      if (value.startsWith("-") || isEnvironmentAssignment(value)) { index += 1; continue; }
      break;
    }
  }
  const command = tokens[index]?.value;
  if (!command) return;
  if (isHelperScriptPath(command)) references.add(command);
  if (command === "source" || command === ".") {
    const source = tokens[index + 1]?.value;
    if (source) references.add(source);
    return;
  }
  if (/(?:^|[\\/])(?:python(?:\d+(?:\.\d+)*)?|pypy(?:\d+)?|node|sh|bash|zsh)(?:\.exe)?$/i.test(command)) {
    const args = tokens.slice(index + 1).map((entry) => entry.value);
    const moduleIndex = args.indexOf("-m");
    if (moduleIndex >= 0 && args[moduleIndex + 1] === "unittest") {
      const discoverIndex = args.indexOf("discover", moduleIndex + 2);
      if (discoverIndex >= 0) {
        const start = optionValue(args, discoverIndex + 1, ["-s", "--start-directory"]) ?? ".";
        const pattern = optionValue(args, discoverIndex + 1, ["-p", "--pattern"]);
        const hasPatternSyntax = pattern !== undefined && (["*", "?", "[", "]", "{", "}"].some((character) => pattern.includes(character)));
        if (pattern && /\.(?:py|sh|bash|zsh|js|mjs|cjs|ts|cmd|ps1)$/i.test(pattern) && !hasPatternSyntax) {
          references.add(start === "." ? pattern : join(start, pattern));
        }
      }
      return;
    }
    if (moduleIndex >= 0 || args.includes("-c")) return;
    const script = args.find((argument) => !argument.startsWith("-") && isHelperScriptPath(argument));
    if (script) references.add(script);
  }
}

function optionValue(args: string[], start: number, options: string[]): string | undefined {
  for (let index = start; index < args.length; index += 1) {
    const argument = args[index]!;
    for (const option of options) {
      if (argument === option) return args[index + 1];
      if (argument.startsWith(`${option}=`)) return argument.slice(option.length + 1);
    }
  }
  return undefined;
}

function isEnvironmentAssignment(value: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(value);
}

function isHelperScriptPath(value: string): boolean {
  return /\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|cmd|ps1|mk|just)$/i.test(value);
}

async function findExecutable(name: string, pathValue: string): Promise<string | undefined> {
  const suffixes = process.platform === "win32" && !name.endsWith(".exe") ? [".exe", ""] : [""];
  for (const directory of pathValue.split(delimiter).filter(Boolean)) {
    for (const suffix of suffixes) {
      const candidate = join(directory, `${name}${suffix}`);
      try {
        const resolved = await realpath(candidate);
        const info = await lstat(resolved);
        if (info.isFile()) {
          await access(resolved, fsConstants.X_OK);
          return resolved;
        }
      } catch {
        // Keep searching later PATH entries. Missing or unusable entries do not qualify.
      }
    }
  }
  return undefined;
}

const defaultRunTool: RustToolRunner = async (executable, args, cwd, env, signal) => {
  const result = await execFileAsync(executable, args, {
    cwd,
    env,
    timeout: TOOL_TIMEOUT_MS,
    maxBuffer: TOOL_OUTPUT_LIMIT,
    encoding: "utf8",
    signal
  });
  return result.stdout;
};

async function runTool(executable: string, args: string[], cwd: string, env: NodeJS.ProcessEnv, signal?: AbortSignal): Promise<string> {
  return defaultRunTool(executable, args, cwd, env, signal);
}
