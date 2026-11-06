import { describe, expect, test } from "vitest";
import { verifyPackageArchiveInventory } from "../scripts/verify-windows-package.mjs";

const commonEntries = [
  "package/LICENSE",
  "package/README.md",
  "package/dist/cli/connect-gpt.js",
  "package/dist/server.js",
  "package/package.json"
];
const windowsHelper = "package/dist/windows-process-host.exe";

describe("verifyPackageArchiveInventory", () => {
  test("accepts the complete Windows runtime archive inventory", () => {
    expect(() => verifyPackageArchiveInventory([...commonEntries, windowsHelper], "win32")).not.toThrow();
  });

  test("accepts the common runtime inventory on Darwin and Linux", () => {
    for (const platform of ["darwin", "linux"] as const) {
      expect(() => verifyPackageArchiveInventory(commonEntries, platform)).not.toThrow();
    }
  });

  test("rejects the Windows helper in a non-Windows package", () => {
    expect(() => verifyPackageArchiveInventory([...commonEntries, windowsHelper], "darwin"))
      .toThrow(/Unexpected package entries:.*windows-process-host\.exe/);
  });

  test("rejects a Windows archive missing its required process host", () => {
    expect(() => verifyPackageArchiveInventory(commonEntries, "win32"))
      .toThrow(/Missing package entries:.*windows-process-host\.exe/);
  });

  test("rejects unexpected repository content", () => {
    expect(() => verifyPackageArchiveInventory([
      ...commonEntries,
      windowsHelper,
      "package/src/secret.ts",
      "package/config.local.json"
    ], "win32")).toThrow(/Unexpected package entries/);
  });

  test("rejects duplicate archive entries", () => {
    expect(() => verifyPackageArchiveInventory([...commonEntries, windowsHelper, "package/dist/server.js"], "win32"))
      .toThrow(/Duplicate package entries/);
  });
});
