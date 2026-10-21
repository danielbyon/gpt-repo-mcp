import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { PathSandbox } from "../src/services/path-sandbox.js";
import { createTempDir } from "./fixtures/temp-dir.js";

describe("PathSandbox", () => {
  test("rejects absolute model-supplied paths", async () => {
    const root = await createTempDir("repo-reader-");
    const sandbox = new PathSandbox(root);

    await expect(sandbox.resolve("/etc/passwd")).rejects.toMatchObject({
      code: "ABSOLUTE_PATH_REJECTED"
    });
  });

  test("rejects path traversal", async () => {
    const root = await createTempDir("repo-reader-");
    const sandbox = new PathSandbox(root);

    await expect(sandbox.resolve("../outside.txt")).rejects.toMatchObject({
      code: "PATH_TRAVERSAL_REJECTED"
    });
  });

  test("rejects symlink escapes", async () => {
    const root = await createTempDir("repo-reader-");
    const outside = await createTempDir("repo-reader-outside-");
    await writeFile(join(outside, "secret.txt"), "secret");
    await symlink(join(outside, "secret.txt"), join(root, "linked-secret.txt"));

    const sandbox = new PathSandbox(root);

    await expect(sandbox.resolve("linked-secret.txt")).rejects.toMatchObject({
      code: "SYMLINK_ESCAPE_REJECTED"
    });
  });

  test("detects nested repositories without treating them as normal files", async () => {
    const root = await createTempDir("repo-reader-");
    await mkdir(join(root, "vendor", "lib", ".git"), { recursive: true });

    const sandbox = new PathSandbox(root);
    const result = await sandbox.classifyBoundary("vendor/lib");

    expect(result).toEqual({ kind: "nested_repo", path: "vendor/lib" });
  });
});
