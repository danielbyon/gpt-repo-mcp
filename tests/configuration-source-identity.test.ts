import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, test } from "vitest";

describe("configuration source identity", () => {
  test("preserves resolver precedence and rejects path expressions that lexical cleanup could redirect", async () => {
    const store = await import("../src/config/store.js");
    const identity = await import("../src/config/config-source-identity.js").catch(() => undefined);
    expect(store.resolveConfigPathSelection).toBeTypeOf("function");
    expect(identity).toBeDefined();
    if (!identity || !store.resolveConfigPathSelection) return;

    const cli = store.resolveConfigPathSelection({
      cliConfigPath: "./chosen.json",
      env: { GPT_REPO_CONFIG: "gpt.json", REPO_READER_CONFIG: "reader.json" },
      cwd: "/workspace/cli"
    });
    expect(cli).toMatchObject({ selected_by: "cli", selected_value: "./chosen.json", path: "/workspace/cli/chosen.json" });

    const emptyEnvironment = store.resolveConfigPathSelection({
      env: { GPT_REPO_CONFIG: "", REPO_READER_CONFIG: "reader.json" },
      cwd: "/workspace/cli"
    });
    expect(emptyEnvironment).toMatchObject({ selected_by: "GPT_REPO_CONFIG", selected_value: "", path: "/workspace/cli" });

    const defaultSelection = store.resolveConfigPathSelection({ env: {}, cwd: "/workspace/cli" });
    expect(defaultSelection).toMatchObject({
      selected_by: "default",
      selected_value: "./config.local.json",
      path: "/workspace/cli/config.local.json"
    });
    const serverWithoutFile = identity.createConfigurationSourceIdentity(undefined, "/workspace/cli", "linux");
    const cliDefault = identity.createConfigurationSourceIdentity(defaultSelection.path, "/workspace/cli", "linux");
    expect(serverWithoutFile.status).toBe("none");
    expect(identity.configurationSourcesMatch(serverWithoutFile, cliDefault)).toBe(false);

    const sourceInFirstCwd = identity.createConfigurationSourceIdentity("config.local.json", "/workspace/one", "linux");
    const sameSource = identity.createConfigurationSourceIdentity("./config.local.json", "/workspace/one", "linux");
    const sourceInSecondCwd = identity.createConfigurationSourceIdentity("config.local.json", "/workspace/two", "linux");
    expect(identity.configurationSourcesMatch(sourceInFirstCwd, sameSource)).toBe(true);
    expect(identity.configurationSourcesMatch(sourceInFirstCwd, sourceInSecondCwd)).toBe(false);

    const traversingSource = identity.createConfigurationSourceIdentity("link/../config.json", "/workspace/one", "linux");
    expect(traversingSource.status).toBe("unavailable");
  expect(identity.createConfigurationSourceIdentity("config.json", "relative/cwd", "linux"))
    .toEqual({ status: "unavailable", reason: "unsupported-path" });
    expect(identity.createConfigurationSourceIdentity(undefined, "/workspace/one", "linux").status).toBe("none");

    const differentlyCasedWindowsPaths = [
      identity.createConfigurationSourceIdentity("C:\\Workspace\\Config.json", "C:\\Workspace", "win32"),
      identity.createConfigurationSourceIdentity("c:\\workspace\\config.json", "C:\\Workspace", "win32")
    ] as const;
    expect(identity.configurationSourcesMatch(...differentlyCasedWindowsPaths)).toBe(false);

  for (const unsupportedPath of [
    String.raw`\\server\share\config.json`,
    "//server/share/config.json",
    "C:config.json",
    String.raw`\\?\C:\config.json`
  ]) {
    expect(identity.createConfigurationSourceIdentity(unsupportedPath, "C:\\Workspace", "win32"))
      .toEqual({ status: "unavailable", reason: "unsupported-path" });
  }
  });

  test("keeps filesystem resolution for symlink traversal and keeps identity when a file is replaced in place", async () => {
    const identity = await import("../src/config/config-source-identity.js").catch(() => undefined);
    expect(identity).toBeDefined();
    if (!identity) return;

    const root = await mkdtemp(join(tmpdir(), "configuration-source-identity-"));
    try {
      const target = join(root, "target");
      await mkdir(join(target, "child"), { recursive: true });
      await symlink(join(target, "child"), join(root, "link"), "dir");
      await writeFile(join(target, "config.json"), "filesystem target");
      await writeFile(join(root, "config.json"), "lexical target");

      const originalPath = `${root}/link/../config.json`;
      expect(await readFile(originalPath, "utf8")).toBe("filesystem target");
      expect(identity.createConfigurationSourceIdentity("link/../config.json", root, "linux").status).toBe("unavailable");

      const beforeReplacement = identity.createConfigurationSourceIdentity("config.json", root, "linux");
      await writeFile(join(root, "config.json"), "replacement");
      const afterReplacement = identity.createConfigurationSourceIdentity("config.json", root, "linux");
      expect(identity.configurationSourcesMatch(beforeReplacement, afterReplacement)).toBe(true);
      expect(await readFile(resolve(root, "config.json"), "utf8")).toBe("replacement");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("distinguishes differently cased files in a case-sensitive Windows directory when supported", async ({ skip }) => {
  if (process.platform !== "win32") skip();

  const directory = await mkdtemp(join(tmpdir(), "gpt-repo-mcp-case-sensitive-"));
  try {
    try {
      execFileSync("fsutil.exe", ["file", "setCaseSensitiveInfo", directory, "enable"], {
        windowsHide: true,
        stdio: "ignore"
      });
    } catch {
      skip();
    }

    const upperPath = join(directory, "Config.json");
    const lowerPath = join(directory, "config.json");
    await writeFile(upperPath, "upper", { flag: "wx" });
    try {
      await writeFile(lowerPath, "lower", { flag: "wx" });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") skip();
      throw error;
    }

    expect(await readFile(upperPath, "utf8")).toBe("upper");
    expect(await readFile(lowerPath, "utf8")).toBe("lower");

    const identity = await import("../src/config/config-source-identity.js");
    const upperIdentity = identity.createConfigurationSourceIdentity(upperPath, directory, "win32");
    const lowerIdentity = identity.createConfigurationSourceIdentity(lowerPath, directory, "win32");
    expect(identity.configurationSourcesMatch(upperIdentity, lowerIdentity)).toBe(false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
