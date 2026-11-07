import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import process from "node:process";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { createReviewBundle, verifyReviewBundle } from "../scripts/create-review-bundle.mjs";

const scratch = [];
const runGit = (root, args) => execFileSync("git", ["-C", root, ...args], {
  encoding: "utf8", windowsHide: true
}).trim();

afterEach(async () => {
  for (const dir of scratch.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function fixture() {
  const parent = await mkdtemp(join(tmpdir(), "gpt-review-bundle-"));
  scratch.push(parent);
  const root = join(parent, "repo");
  await mkdir(join(root, "src"), { recursive: true });
  await mkdir(join(root, "docs"), { recursive: true });
  await mkdir(join(root, "tests"), { recursive: true });
  await writeFile(join(root, "src", "app.ts"), "export const value = 1;\n");
  await writeFile(join(root, "docs", "QUALITY.md"), "# Quality rules\n");
  runGit(root, ["init", "-q"]);
  runGit(root, ["config", "user.name", "Review Bundle Test"]);
  runGit(root, ["config", "user.email", "review-bundle@example.invalid"]);
  runGit(root, ["add", "--", "src/app.ts", "docs/QUALITY.md"]);
  runGit(root, ["commit", "-qm", "baseline"]);
  const base = runGit(root, ["rev-parse", "HEAD"]);
  await writeFile(join(root, "src", "app.ts"), "export const value = 2;\n");
  await writeFile(join(root, "tests", "new.test.ts"), "export const testValue = true;\n");
  await mkdir(join(root, ".serena"));
  await writeFile(join(root, ".serena", "state.yml"), "generated: true\n");
  return { parent, root, base, output: join(parent, "review") };
}

describe("content-addressed worktree review bundles", () => {
  test("captures tracked changes, eligible untracked source, and reference documents without changing Git", async () => {
    const fixtureRoot = await fixture();
    const before = runGit(fixtureRoot.root, ["status", "--porcelain"]);
    const result = await createReviewBundle({
      cwd: fixtureRoot.root,
      base: fixtureRoot.base,
      output: fixtureRoot.output,
      references: ["docs/QUALITY.md"],
      issues: ["#50"]
    });

    expect(result.tracked_path_count).toBe(1);
    expect(result.untracked_path_count).toBe(1);
    expect(result.excluded_untracked_count).toBe(1);
    const manifest = JSON.parse(await readFile(join(fixtureRoot.output, "manifest.json"), "utf8"));
    expect(manifest.head_sha).toBe(fixtureRoot.base);
    expect(manifest.issue_references).toEqual(["#50"]);
    expect(manifest.untracked_files.map((item) => item.source_path)).toEqual(["tests/new.test.ts"]);
    expect(manifest.excluded_untracked_paths).toEqual([".serena/state.yml"]);
    expect(await readFile(join(fixtureRoot.output, "untracked", "tests", "new.test.ts"), "utf8"))
      .toBe("export const testValue = true;\n");
    expect((await readFile(join(fixtureRoot.output, "tracked.patch"), "utf8")))
      .toContain("+export const value = 2;");
    expect(await verifyReviewBundle(fixtureRoot.output, result.manifest_sha256))
      .toMatchObject({ verified: true, head_sha: fixtureRoot.base });
    expect(runGit(fixtureRoot.root, ["status", "--porcelain"])).toBe(before);
  });

  test("detects bundle tampering using an external manifest digest", async () => {
    const f = await fixture();
    const result = await createReviewBundle({ cwd: f.root, base: f.base, output: f.output });
    await writeFile(join(f.output, "untracked", "tests", "new.test.ts"), "tampered");
    await expect(verifyReviewBundle(f.output, result.manifest_sha256))
      .rejects.toThrow(/content mismatch/i);
    await expect(verifyReviewBundle(f.output, "0".repeat(64)))
      .rejects.toThrow(/manifest digest mismatch/i);
  });

  test("does not write review bundles inside the source checkout", async () => {
    const f = await fixture();
    await expect(createReviewBundle({
      cwd: f.root, base: f.base, output: join(f.root, "review")
    })).rejects.toThrow(/outside the source checkout/);
  });

  test.skipIf(process.platform === "win32")("rejects untracked symlink sources without following their targets", async () => {
    const f = await fixture();
    await symlink(join(f.root, "src", "app.ts"), join(f.root, "tests", "symlink.test.ts"));
    await expect(createReviewBundle({
      cwd: f.root, base: f.base, output: f.output
    })).rejects.toThrow(/singly linked regular file/);
  });

  test("rejects restricted explicit references and preserves the checkout", async () => {
    const f = await fixture();
    await expect(createReviewBundle({
      cwd: f.root, base: f.base, output: f.output, references: [".serena/state.yml"]
    })).rejects.toThrow(/safe text document/);
  });
});
