import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, realpath, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";
import { RustRuntimeResolver } from "../src/services/rust-runtime-resolver.js";
import { copyNscbMakefileFixture, NSCB_MAKEFILE_SHA256, NSCB_RUST_TOOLCHAIN_SHA256 } from "./fixtures/nscb-makefile.js";
import { cleanupTempDirs, createTempDir } from "./fixtures/temp-dir.js";

const PIN = "1.98.1";

describe("RustRuntimeResolver", () => {
  afterEach(async () => cleanupTempDirs());

  test("resolves the exact root rust-toolchain.toml pin and selected Cargo and Rustc", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    const cargoHome = join(root, "cargo-home");
    await mkdir(cargoHome, { recursive: true });
    const runTool = fakeRustup(root, PIN);
    const cargoPath = await realpath(join(root, "toolchain", "bin", executableName("cargo")));
    const rustcPath = await realpath(join(root, "toolchain", "bin", executableName("rustc")));
    const rustupPath = await realpath(join(root, "bin", executableName("rustup")));

    const selection = await new RustRuntimeResolver(root, { env: { PATH: join(root, "bin"), CARGO_HOME: cargoHome }, runTool }).resolve({ required: true });

    expect(selection).toMatchObject({
      version: PIN,
      source: "rust-toolchain.toml",
      active_toolchain: expect.stringContaining(PIN),
      execution_env: { RUSTUP_TOOLCHAIN: PIN, RUSTC: rustcPath, CARGO_HOME: cargoHome },
      cargo_home_path_sha256: createHash("sha256").update(cargoHome).digest("hex"),
      cargo_config_sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      rustup: {
        path: rustupPath,
        real_path: rustupPath,
        path_sha256: createHash("sha256").update(rustupPath).digest("hex"),
        real_path_sha256: createHash("sha256").update(rustupPath).digest("hex"),
        version: "1.28.2",
        sha256: createHash("sha256").update(await readFile(rustupPath)).digest("hex")
      },
      cargo: { version: PIN, real_path: cargoPath },
      rustc: { version: PIN, real_path: rustcPath }
    });
    expect(runTool).toHaveBeenCalledWith(expect.any(String), expect.any(Array), root, expect.objectContaining({ RUSTUP_TOOLCHAIN: PIN }), undefined);
  });

  test("allows verified direct Cargo and Rustc selection when Rustup is unavailable", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    const cargoHome = join(root, "cargo-home");
    const toolchainBin = join(root, "toolchain", "bin");
    await mkdir(cargoHome, { recursive: true });
    const cargoPath = await realpath(join(toolchainBin, executableName("cargo")));
    const rustcPath = await realpath(join(toolchainBin, executableName("rustc")));
    const runTool = vi.fn(async (executable: string, args: string[]) => {
      const name = executable.split(/[\\/]/).at(-1)?.replace(/\.exe$/i, "");
      if (args[0] === "--version" && name === "cargo") return `cargo ${PIN} (fixture)\n`;
      if (args[0] === "--version" && name === "rustc") return `rustc ${PIN} (fixture)\n`;
      throw new Error(`Unexpected tool invocation: ${name} ${args.join(" ")}`);
    });

    const selection = await new RustRuntimeResolver(root, {
      env: { PATH: toolchainBin, CARGO_HOME: cargoHome },
      runTool
    }).resolve({ required: true });

    expect(selection).toMatchObject({
      version: PIN,
      cargo: { version: PIN, real_path: cargoPath },
      rustc: { version: PIN, real_path: rustcPath },
      execution_env: { RUSTUP_TOOLCHAIN: PIN, CARGO_HOME: cargoHome }
    });
    expect(selection?.rustup).toBeUndefined();
    expect(runTool).toHaveBeenCalledTimes(2);
  });

  test("accepts an exact rust-toolchain pin and rejects floating channels", async () => {
    const root = await createRuntimeFixture("rust-toolchain", `${PIN}\n`);
    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) }).resolve({ required: true }))
      .resolves.toMatchObject({ version: PIN, source: "rust-toolchain" });

    const floatingRoot = await createRuntimeFixture("rust-toolchain.toml", "[toolchain]\nchannel = \"stable\"\n");
    await expect(new RustRuntimeResolver(floatingRoot, { env: { PATH: join(floatingRoot, "bin") }, runTool: vi.fn() }).resolve({ required: true }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_UNPINNED" });
  });

  test("rejects a Make or Just recipe toolchain that disagrees with the root pin", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await writeFile(join(root, "Makefile"), "RUSTUP_TOOLCHAIN := 1.99.0\nall:\n\tcargo test\n");

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ required: true, recipe_paths: ["Makefile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test("resolves NSCB's exact pinned Makefile and maps unittest patterns under tests", async () => {
    const fixtureRoot = join(process.cwd(), "tests", "fixtures", "nscb-makefile");
    const makefile = await readFile(join(fixtureRoot, "Makefile"));
    expect(createHash("sha256").update(makefile).digest("hex")).toBe(NSCB_MAKEFILE_SHA256);
    const pin = await readFile(join(fixtureRoot, "rust-toolchain.toml"), "utf8");
    expect(createHash("sha256").update(pin).digest("hex")).toBe(NSCB_RUST_TOOLCHAIN_SHA256);
    expect(pin).toContain('channel = "1.98.1"');

    const root = await createRuntimeFixture("rust-toolchain.toml", pin);
    await copyNscbMakefileFixture(root);
    const runTool = fakeRustup(root, PIN);
    const cargoPath = await realpath(join(root, "toolchain", "bin", executableName("cargo")));
    const rustcPath = await realpath(join(root, "toolchain", "bin", executableName("rustc")));
    const rustupPath = await realpath(join(root, "bin", executableName("rustup")));

    const selection = await new RustRuntimeResolver(root, {
      env: { PATH: join(root, "bin") },
      runTool
    }).resolve({ required: true, recipe_paths: ["Makefile"] });

    expect(selection).toMatchObject({
      version: PIN,
      source: "rust-toolchain.toml",
      execution_env: { RUSTUP: rustupPath, RUSTUP_TOOLCHAIN: PIN, RUSTC: rustcPath },
      cargo: { version: PIN, real_path: cargoPath },
      rustc: { version: PIN, real_path: rustcPath }
    });
    await expect(readFile(join(root, "test_content_policy.py"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((await readFile(join(root, "tests", "test_content_policy.py"))).byteLength).toBeGreaterThan(0);
  });

  test("resolves aligned Just imports relative to each containing Justfile", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await mkdir(join(root, "nested"), { recursive: true });
    await writeFile(join(root, "justfile"), "import 'nested/level-one.just'\n");
    await writeFile(join(root, "nested", "level-one.just"), "import '../rust.just'\n");
    await writeFile(join(root, "rust.just"), "test:\n    cargo +1.98.1 test\n");

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ recipe_paths: ["justfile"] }))
      .resolves.toMatchObject({ version: PIN, cargo: { version: PIN }, rustc: { version: PIN } });
  });

  test("rejects an explicit Just module whose recipe selects another Rust toolchain", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await mkdir(join(root, "modules"), { recursive: true });
    await writeFile(join(root, "justfile"), "mod tools 'modules'\n");
    await writeFile(join(root, "modules", "mod.just"), "test:\n    cargo +1.99.0 test\n");

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ recipe_paths: ["justfile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test("checks Just's conventional module source and fails closed for ambiguous or escaping sources", async () => {
    const conventional = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await mkdir(join(conventional, "tools"), { recursive: true });
    await writeFile(join(conventional, "justfile"), "mod tools\n");
    await writeFile(join(conventional, "tools", "Justfile"), "test:\n    cargo +1.99.0 test\n");
    await expect(new RustRuntimeResolver(conventional, { env: { PATH: join(conventional, "bin") }, runTool: fakeRustup(conventional, PIN) })
      .resolve({ recipe_paths: ["justfile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });

    const ambiguous = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await mkdir(join(ambiguous, "tools"), { recursive: true });
    await writeFile(join(ambiguous, "justfile"), "mod tools\n");
    await writeFile(join(ambiguous, "tools.just"), "test:\n    cargo test\n");
    await writeFile(join(ambiguous, "tools", "mod.just"), "test:\n    cargo test\n");
    await expect(new RustRuntimeResolver(ambiguous, { env: { PATH: join(ambiguous, "bin") }, runTool: fakeRustup(ambiguous, PIN) })
      .resolve({ recipe_paths: ["justfile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });

    const escaping = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await writeFile(join(escaping, "justfile"), "import '../outside.just'\n");
    await expect(new RustRuntimeResolver(escaping, { env: { PATH: join(escaping, "bin") }, runTool: fakeRustup(escaping, PIN) })
      .resolve({ recipe_paths: ["justfile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });

    const symlinked = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    const outside = await createTempDir("rust-just-outside-");
    const outsideSource = join(outside, "outside.just");
    await writeFile(outsideSource, "test:\n    cargo +1.99.0 test\n");
    await symlink(outsideSource, join(symlinked, "outside.just"));
    await writeFile(join(symlinked, "justfile"), "import 'outside.just'\n");
    await expect(new RustRuntimeResolver(symlinked, { env: { PATH: join(symlinked, "bin") }, runTool: fakeRustup(symlinked, PIN) })
      .resolve({ recipe_paths: ["justfile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test("fails closed when Just module source discovery exceeds its directory-entry bound", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    const moduleDirectory = join(root, "tools");
    await mkdir(moduleDirectory, { recursive: true });
    await writeFile(join(root, "justfile"), "mod tools\n");
    await writeFile(join(moduleDirectory, "mod.just"), "test:\n    cargo test\n");
    for (let index = 0; index < 513; index += 1) {
      await writeFile(join(moduleDirectory, `entry-${index}.txt`), "");
    }

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ recipe_paths: ["justfile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test("rejects untrusted substitutions in an otherwise aligned NSCB Makefile", async () => {
    const fixtureRoot = join(process.cwd(), "tests", "fixtures", "nscb-makefile");
    const original = await readFile(join(fixtureRoot, "Makefile"), "utf8");
    const pin = await readFile(join(fixtureRoot, "rust-toolchain.toml"), "utf8");
    const untrustedRecipes = [
      original.replace("override RUST_TOOLCHAIN := 1.98.1", "override RUST_TOOLCHAIN := 1.99.0"),
      original.replace(
        "override RUSTC_BIN := $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) rustc 2>/dev/null)",
        "override RUSTC_BIN := /tmp/unverified-rustc"
      ),
      original.replace("RUSTUP ?= rustup", "override RUSTUP := /tmp/untrusted-rustup"),
      original.replace("PATH=\"$(RUST_TOOLCHAIN_BIN):$$PATH\"", "PATH=\"/tmp/untrusted-bin:$$PATH\""),
      `${original}\noverride CARGO := /tmp/untrusted-cargo\n`
    ];

    for (const recipe of untrustedRecipes) {
      const root = await createRuntimeFixture("rust-toolchain.toml", pin);
      await copyNscbMakefileFixture(root);
      await writeFile(join(root, "Makefile"), recipe);
      await expect(new RustRuntimeResolver(root, {
        env: { PATH: join(root, "bin") },
        runTool: fakeRustup(root, PIN)
      }).resolve({ required: true, recipe_paths: ["Makefile"] }))
        .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
    }
  });

  test("does not treat a script-looking string literal as a helper file", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await writeFile(join(root, "Makefile"), "test:\n\t@printf '%s\\n' 'missing-helper.py'\n\tcargo test\n");

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ required: true, recipe_paths: ["Makefile"] }))
      .resolves.toMatchObject({ version: PIN, cargo: { version: PIN }, rustc: { version: PIN } });
  });

  test("rejects a Rust recipe when the checkout has no exact root pin", async () => {
    const root = await createTempDir("rust-unpinned-recipe-");
    await writeFile(join(root, "Makefile"), "test:\n\tcargo test\n");

    await expect(new RustRuntimeResolver(root, { env: { PATH: "" }, runTool: vi.fn() })
      .resolve({ recipe_paths: ["Makefile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_UNPINNED" });
  });

  test("requires a root pin for indirect Rust execution in a Cargo checkout", async () => {
    const root = await createTempDir("rust-indirect-recipe-");
    await mkdir(join(root, "scripts"), { recursive: true });
    await writeFile(join(root, "Cargo.toml"), "[workspace]\nresolver = \"2\"\n");
    await writeFile(join(root, "Makefile"), "test:\n\t./scripts/run-tests.sh\n");
    await writeFile(join(root, "scripts", "run-tests.sh"), "#!/bin/sh\ncargo test\n");

    await expect(new RustRuntimeResolver(root, { env: { PATH: "" }, runTool: vi.fn() })
      .resolve({ recipe_paths: ["Makefile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_UNPINNED" });
  });

  test("rejects a compiler wrapper in Cargo configuration", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await mkdir(join(root, ".cargo"), { recursive: true });
    await writeFile(join(root, ".cargo", "config.toml"), '[build]\nrustc-wrapper = "sccache"\n');

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ required: true }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test("rejects a Cargo configuration that selects a different Rust compiler", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await mkdir(join(root, ".cargo"), { recursive: true });
    await writeFile(join(root, ".cargo", "config.toml"), '[build]\nrustc = "unverified-rustc"\n');

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ required: true }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test("rejects Cargo config includes in the active CARGO_HOME", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    const cargoHome = join(root, "custom-cargo-home");
    await mkdir(cargoHome, { recursive: true });
    await writeFile(join(cargoHome, "config.toml"), 'include = ["wrapper.toml"]\n');
    await writeFile(join(cargoHome, "wrapper.toml"), '[build]\nrustc-wrapper = "unverified-wrapper"\n');

    await expect(new RustRuntimeResolver(root, {
      env: { PATH: join(root, "bin"), CARGO_HOME: cargoHome },
      runTool: fakeRustup(root, PIN)
    }).resolve({ required: true }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test("rejects a Cargo command-line compiler override", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await writeFile(join(root, "Makefile"), "test:\n\tcargo --config build.rustc=/usr/bin/rustc test\n");

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ recipe_paths: ["Makefile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test("rejects Cargo configuration files passed on the command line", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await mkdir(join(root, "ci"), { recursive: true });
    await writeFile(join(root, "ci", "rustc.toml"), '[build]\nrustc-wrapper = "unverified-wrapper"\n');
    await writeFile(join(root, "Makefile"), "test:\n\tcargo --config ./ci/rustc.toml test\n");

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ recipe_paths: ["Makefile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test.each([
    "PATH=/tmp/alternate-bin:$PATH cargo test",
    "env PATH=/tmp/alternate-bin:$PATH cargo test",
    "env -SPATH=/tmp/alternate-bin:$PATH cargo test",
    "export PATH=/tmp/alternate-bin:$PATH",
    "set path=C:\\alternate-bin;%PATH% && cargo test"
  ])("rejects a Rust recipe that changes the verified Cargo search path with %s", async (command) => {
    const root = await createRuntimeFixture("rust-toolchain.toml", "[toolchain]\nchannel = \"" + PIN + "\"\n");
    await writeFile(join(root, "Makefile"), "test:\n\t" + command + "\n");

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ recipe_paths: ["Makefile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test("rejects path-qualified Cargo executables in the Make recipe", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await writeFile(join(root, "Makefile"), "test:\n\t/usr/local/bin/cargo test\n");

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ recipe_paths: ["Makefile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test.each([
    "env --unset=RUSTC cargo test",
    "env -i cargo test",
    "unset RUSTUP_TOOLCHAIN",
    "CARGO_HOME= cargo test"
  ])("rejects a recipe that clears Rust selection environment with %s", async (command) => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await writeFile(join(root, "Makefile"), "test:\n\t" + command + "\n");

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ recipe_paths: ["Makefile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test("rejects a compiler wrapper declared by a delegated Make helper", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await writeFile(join(root, "Cargo.toml"), "[workspace]\nresolver = \"2\"\n");
    await mkdir(join(root, "scripts"), { recursive: true });
    await writeFile(join(root, "Makefile"), "test:\n\t./scripts/run-tests.sh\n");
    await writeFile(join(root, "scripts", "run-tests.sh"), "RUSTC_WRAPPER=sccache cargo test\n");

    await expect(new RustRuntimeResolver(root, { env: { PATH: join(root, "bin") }, runTool: fakeRustup(root, PIN) })
      .resolve({ recipe_paths: ["Makefile"] }))
      .rejects.toMatchObject({ code: "VALIDATION_RUST_TOOLCHAIN_MISMATCH" });
  });

  test("does not require Rust tools for a pinned checkout's non-Rust Make profile", async () => {
    const root = await createRuntimeFixture("rust-toolchain.toml", `[toolchain]\nchannel = "${PIN}"\n`);
    await writeFile(join(root, "Cargo.toml"), "[workspace]\nresolver = \"2\"\n");
    await writeFile(join(root, "Makefile"), "test:\n\techo test suite\n");
    const runTool = vi.fn();

    await expect(new RustRuntimeResolver(root, { env: { PATH: "" }, runTool })
      .resolve({ recipe_paths: ["Makefile"] }))
      .resolves.toBeUndefined();
    expect(runTool).not.toHaveBeenCalled();
  });

  test("does not discover nested Rust manifests for a configured checkout", async () => {
    const root = await createTempDir("rust-nested-manifest-");
    await mkdir(join(root, "nested"), { recursive: true });
    await writeFile(join(root, "nested", "rust-toolchain.toml"), `[toolchain]\nchannel = "${PIN}"\n`);

    await expect(new RustRuntimeResolver(root, { env: { PATH: "" }, runTool: vi.fn() }).resolve())
      .resolves.toBeUndefined();
  });
});

async function createRuntimeFixture(pinFile: "rust-toolchain" | "rust-toolchain.toml", pin: string): Promise<string> {
  const root = await createTempDir("rust-runtime-");
  const shimBin = join(root, "bin");
  const toolchainBin = join(root, "toolchain", "bin");
  await mkdir(shimBin, { recursive: true });
  await mkdir(toolchainBin, { recursive: true });
  await writeFile(join(root, pinFile), pin);
  for (const name of ["rustup", "cargo", "rustc"]) {
    const file = join(name === "rustup" ? shimBin : toolchainBin, executableName(name));
    await writeFile(file, `fixture ${name}\n`);
    await chmod(file, 0o755);
  }
  return root;
}

function fakeRustup(root: string, pin: string) {
  const toolchainBin = join(root, "toolchain", "bin");
  return vi.fn(async (executable: string, args: string[]) => {
    const basename = executable.split(/[\\/]/).at(-1)?.replace(/\.exe$/i, "");
    if (basename === "rustup" && args[0] === "--version") return "rustup 1.28.2 (fixture)\n";
    if (basename === "rustup" && args[0] === "show") return `${pin}-x86_64-test (overridden by environment variable)\n`;
    if (basename === "rustup" && args[0] === "which") {
      const tool = args[1] === "--toolchain" ? args[3] : args[1];
      const selectedVersion = args[1] === "--toolchain" ? args[2] : pin;
      if (selectedVersion !== pin || !tool) throw new Error("Unexpected rustup toolchain selection");
      return join(toolchainBin, executableName(tool));
    }
    if (basename === "cargo") return `cargo ${pin} (fixture)\n`;
    if (basename === "rustc") return `rustc ${pin} (fixture)\n`;
    throw new Error(`Unexpected tool invocation: ${basename} ${args.join(" ")}`);
  });
}

function executableName(name: string): string {
  return process.platform === "win32" ? `${name}.exe` : name;
}
