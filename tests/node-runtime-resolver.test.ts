import { chmod, copyFile, mkdir, mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { NodeRuntimeResolver } from "../src/services/node-runtime-resolver.js";

const VERSION = process.platform === "win32" ? process.version.slice(1) : "24.18.0";

describe("NodeRuntimeResolver", () => {
  describe.skipIf(process.platform === "win32")("POSIX manager path fixtures", () => {
    test.each([
      ["nvm", [".nvm", "versions", "node", `v${VERSION}`, "bin", "node"]],
      ["mise", [".local", "share", "mise", "installs", "node", VERSION, "bin", "node"]],
      ["fnm", [".fnm", "node-versions", `v${VERSION}`, "installation", "bin", "node"]],
      ["Volta", [".volta", "tools", "image", "node", VERSION, "bin", "node"]],
      ["asdf", [".asdf", "installs", "nodejs", VERSION, "bin", "node"]]
    ])("selects an installed %s runtime", async (_manager, runtimeParts) => {
      const root = await mkdtemp(join(tmpdir(), "gpt-node-repo-"));
      const home = await mkdtemp(join(tmpdir(), "gpt-node-home-"));
      await writeFile(join(root, ".node-version"), `${VERSION}\n`);
      const executable = join(home, ...runtimeParts);
      await mkdir(join(executable, ".."), { recursive: true });
      await writeFile(executable, `#!${process.execPath}\nconsole.log("v${VERSION}");\n`);
      await chmod(executable, 0o755);

      await expect(new NodeRuntimeResolver(root, { home, env: {} }).resolve()).resolves.toEqual({
        name: "node",
        version: VERSION,
        source: ".node-version",
        executable: await realpath(executable),
        bin_directory: join(await realpath(executable), "..")
      });
    });
  });

  test("selects the exact Windows NVM runtime executable", async () => {
      const root = await mkdtemp(join(tmpdir(), "gpt-node-windows-repo-"));
      const home = await mkdtemp(join(tmpdir(), "gpt-node-windows-home-"));
      const nvmRoot = join(home, "nvm");
      const executable = await fakeWindowsNodeExecutable(join(nvmRoot, `v${VERSION}`, "node.exe"), VERSION);
      await writeFile(join(root, ".node-version"), `${VERSION}\n`);

      await expect(new NodeRuntimeResolver(root, {
        home,
        platform: "win32",
        env: { NVM_HOME: nvmRoot }
      }).resolve()).resolves.toEqual({
        name: "node",
        version: VERSION,
        source: ".node-version",
        executable: await realpath(executable),
        bin_directory: join(await realpath(executable), "..")
      });
    });

  test("selects the exact Windows fnm runtime from the configured roaming directory", async () => {
      const root = await mkdtemp(join(tmpdir(), "gpt-node-windows-fnm-repo-"));
      const home = await mkdtemp(join(tmpdir(), "gpt-node-windows-fnm-home-"));
      const appData = await mkdtemp(join(tmpdir(), "gpt-node-windows-fnm-appdata-"));
      const executable = await fakeWindowsNodeExecutable(
        join(appData, "fnm", "node-versions", `v${VERSION}`, "installation", "node.exe"),
        VERSION
      );
      await writeFile(join(root, ".node-version"), `${VERSION}\n`);

      await expect(new NodeRuntimeResolver(root, {
        home,
        platform: "win32",
        env: { APPDATA: appData }
      }).resolve()).resolves.toMatchObject({
        version: VERSION,
        executable: await realpath(executable)
      });
    });

  test("selects the exact Windows mise runtime through its identity-store alias", async () => {
      const root = await mkdtemp(join(tmpdir(), "gpt-node-windows-mise-repo-"));
      const home = await mkdtemp(join(tmpdir(), "gpt-node-windows-mise-home-"));
      const localAppData = await mkdtemp(join(tmpdir(), "gpt-node-windows-mise-local-"));
      const miseRoot = join(localAppData, "mise");
      const installStore = join(miseRoot, "i", `node-${VERSION}-identity`);
      const executable = await fakeWindowsNodeExecutable(join(installStore, "node.exe"), VERSION);
      const versionAlias = join(miseRoot, "installs", "node", VERSION);
      await mkdir(join(versionAlias, ".."), { recursive: true });
      await symlink(installStore, versionAlias, "dir");
      await writeFile(join(root, ".node-version"), `${VERSION}\n`);

      await expect(new NodeRuntimeResolver(root, {
        home,
        platform: "win32",
        env: { LOCALAPPDATA: localAppData }
      }).resolve()).resolves.toEqual({
        name: "node",
        version: VERSION,
        source: ".node-version",
        executable: await realpath(executable),
        bin_directory: join(await realpath(executable), "..")
      });
    });

  test("does not substitute the current Node when the pinned Windows version is unavailable", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-node-windows-unavailable-"));
    await writeFile(join(root, ".node-version"), "0.0.0\n");

    await expect(new NodeRuntimeResolver(root, {
      home: await mkdtemp(join(tmpdir(), "gpt-node-windows-home-")),
      platform: "win32",
      env: {}
    }).resolve()).rejects.toMatchObject({ code: "VALIDATION_NODE_RUNTIME_UNAVAILABLE" });
  });

  test.skipIf(process.platform !== "win32")("validates the exact running Windows Node runtime", async () => {
    const version = process.version.slice(1);
    const root = await mkdtemp(join(tmpdir(), "gpt-node-windows-current-"));
    await writeFile(join(root, ".node-version"), `${version}\n`);
    const home = await mkdtemp(join(tmpdir(), "gpt-node-windows-current-home-"));
    const env = {
      NVM_HOME: join(home, "nvm"),
      APPDATA: join(home, "roaming"),
      LOCALAPPDATA: join(home, "local"),
      FNM_DIR: join(home, "fnm"),
      VOLTA_HOME: join(home, "volta"),
      MISE_INSTALLS_DIR: join(home, "mise-installs"),
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {})
    };

    await expect(new NodeRuntimeResolver(root, { home, platform: "win32", env }).resolve()).resolves.toMatchObject({
      version,
      executable: await realpath(process.execPath)
    });
  });
});

async function fakeWindowsNodeExecutable(path: string, version: string): Promise<string> {
  await mkdir(join(path, ".."), { recursive: true });
  if (process.platform === "win32") {
    await copyFile(process.execPath, path);
  } else {
    await writeFile(path, `#!${process.execPath}\nconsole.log("v${version}");\n`);
    await chmod(path, 0o755);
  }
  return path;
}
