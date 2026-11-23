import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { RootRegistry } from "../src/services/root-registry.js";

test("published repository policies and limits cannot be changed through retained references", async () => {
  const root = await mkdtemp(join(tmpdir(), "root-registry-immutable-"));
  try {
    const canonicalRoot = await realpath(root);
    const input = {
      repos: [{
        repo_id: "fixture",
        display_name: "Fixture",
        root,
        writes: { enabled: true, allowed_globs: ["docs/**"] }
      }],
      limits: { max_files: 12 }
    };
    const registry = await RootRegistry.fromConfig(input);
    const repo = registry.get("fixture");

    input.repos[0]!.root = "/changed-after-publication";
    input.repos[0]!.writes.allowed_globs.push(".chatgpt/**");

    expect(repo.root).toBe(canonicalRoot);
    expect(repo.writes?.allowed_globs).toEqual(["docs/**"]);
    expect(Object.isFrozen(registry)).toBe(true);
    expect(Object.isFrozen(repo)).toBe(true);
    expect(Object.isFrozen(repo.writes)).toBe(true);
    expect(Object.isFrozen(repo.writes?.allowed_globs)).toBe(true);
    expect(Object.isFrozen(registry.limits)).toBe(true);
    expect(Reflect.set(repo.writes!, "enabled", false)).toBe(false);
    expect(Reflect.set(repo.writes!.allowed_globs!, 0, "**")).toBe(false);
    expect(Reflect.set(registry.limits, "max_files", 1)).toBe(false);
    expect(registry.get("fixture")).toBe(repo);
    expect(repo.writes?.enabled).toBe(true);
    expect(registry.limits.max_files).toBe(12);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
