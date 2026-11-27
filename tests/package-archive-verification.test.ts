import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { verifyPackageArchiveInventory } from "../scripts/verify-windows-package.mjs";

const commonEntries = [
  "package/LICENSE",
  "package/README.md",
  "package/dist/cli/connect-gpt.js",
  "package/dist/server.js",
  "package/package.json"
];
const windowsHelpers = [
  "package/dist/windows-process-host.exe",
  "package/dist/windows-configuration-admin-host.exe"
];

describe("verifyPackageArchiveInventory", () => {
  test("passes the architecture defines checked by the native helper", async () => {
    const [buildScript, nativeSource] = await Promise.all([
      readFile(new URL("../scripts/build-windows-configuration-admin-host.mjs", import.meta.url), "utf8"),
      readFile(new URL("../native/windows/configuration-admin-host.cpp", import.meta.url), "utf8")
    ]);
    const buildDefines = [...buildScript.matchAll(/\/D(GPT_REPO_[A-Z0-9_]*_EXPECT_(?:X64|ARM64|X86))=1/g)]
      .map((match) => match[1])
      .sort();
    const nativeGuards = [...nativeSource.matchAll(/defined\((GPT_REPO_[A-Z0-9_]*_EXPECT_(?:X64|ARM64|X86))\)/g)]
      .map((match) => match[1])
      .sort();

    expect(buildDefines).toEqual(nativeGuards);
  });

  test("keeps the shared IPC error contract independent of platform transports", async () => {
    const [sharedClient, windowsTransport] = await Promise.all([
      readFile(new URL("../src/runtime/configuration-admin-client.ts", import.meta.url), "utf8"),
      readFile(new URL("../src/runtime/configuration-admin-windows.ts", import.meta.url), "utf8")
    ]);

    expect(sharedClient).not.toMatch(/from ["']\.\/configuration-admin-posix\.js["']/);
    expect(windowsTransport).not.toMatch(/from ["']\.\/configuration-admin-posix\.js["']/);
  });

  test("accepts the complete Windows runtime archive inventory", () => {
    expect(() => verifyPackageArchiveInventory([...commonEntries, ...windowsHelpers], "win32")).not.toThrow();
  });

  test("accepts the common runtime inventory on Darwin and Linux", () => {
    for (const platform of ["darwin", "linux"] as const) {
      expect(() => verifyPackageArchiveInventory(commonEntries, platform)).not.toThrow();
    }
  });

  test("rejects the Windows helper in a non-Windows package", () => {
    expect(() => verifyPackageArchiveInventory([...commonEntries, ...windowsHelpers], "darwin"))
      .toThrow(/Unexpected package entries:.*windows-configuration-admin-host\.exe/);
  });

  test("rejects a Windows archive missing its required process host", () => {
    expect(() => verifyPackageArchiveInventory(commonEntries, "win32"))
      .toThrow(/Missing package entries:.*windows-configuration-admin-host\.exe/);
  });

  test("rejects unexpected repository content", () => {
    expect(() => verifyPackageArchiveInventory([
      ...commonEntries,
      ...windowsHelpers,
      "package/src/secret.ts",
      "package/config.local.json"
    ], "win32")).toThrow(/Unexpected package entries/);
  });

  test("rejects duplicate archive entries", () => {
    expect(() => verifyPackageArchiveInventory([...commonEntries, ...windowsHelpers, "package/dist/server.js"], "win32"))
      .toThrow(/Duplicate package entries/);
  });
});
