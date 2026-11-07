import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { link, mkdtemp, mkdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
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

  test("fails closed for a Git-ignored source test in the scoped inventory", async () => {
    const f = await fixture();
    await writeFile(join(f.root, ".gitignore"), "tests/hidden.test.ts\n");
    await writeFile(join(f.root, "tests", "hidden.test.ts"), "test('hidden', () => {});\n");
    const before = runGit(f.root, ["status", "--porcelain"]);
    await expect(createReviewBundle({ cwd: f.root, base: f.base, output: f.output }))
      .rejects.toThrow(/Relevant ignored source/);
    await expect(stat(f.output)).rejects.toMatchObject({ code: "ENOENT" });
    expect(runGit(f.root, ["status", "--porcelain"])).toBe(before);
  });

  test("records only the bounded ignored-directory exclusion without descending into generated trees", async () => {
    const f = await fixture();
    await mkdir(join(f.root, "src", "build"), { recursive: true });
    await writeFile(join(f.root, ".gitignore"), "src/build/\n");
    await writeFile(join(f.root, "src", "build", "generated.js"), "generated\n");
    const result = await createReviewBundle({ cwd: f.root, base: f.base, output: f.output });
    const manifest = JSON.parse(await readFile(join(f.output, "manifest.json"), "utf8"));
    expect(manifest.schema_version).toBe(2);
    expect(manifest.ignored_inventory_roots).toContain("src/");
    expect(manifest.redacted_ignored_count).toBe(1);
    expect(manifest.excluded_ignored_paths).toEqual([]);
    expect(result.redacted_ignored_count).toBe(1);
  });

  test("detects HEAD advancement during capture and deletes the partial output", async () => {
    const f = await fixture();
    await expect(createReviewBundle({
      cwd: f.root, base: f.base, output: f.output,
      beforeFinalSnapshot: () => runGit(f.root, ["commit", "--allow-empty", "-qm", "advance"])
    })).rejects.toThrow(/HEAD changed/);
    await expect(stat(f.output)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("detects source drift after capture and deletes the partial output", async () => {
    const f = await fixture();
    await expect(createReviewBundle({
      cwd: f.root, base: f.base, output: f.output,
      beforeFinalSnapshot: () => writeFile(join(f.root, "tests", "new.test.ts"), "changed\n")
    })).rejects.toThrow(/Source changed/);
    await expect(stat(f.output)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("rejects restricted tracked modifications before output mutation", async () => {
    const f = await fixture();
    await writeFile(join(f.root, ".env"), "secret=not-a-real-secret\n");
    runGit(f.root, ["add", "-f", ".env"]);
    runGit(f.root, ["commit", "-qm", "add tracked restricted fixture"]);
    await writeFile(join(f.root, ".env"), "secret=changed\n");
    await expect(createReviewBundle({ cwd: f.root, base: f.base, output: f.output }))
      .rejects.toThrow(/Tracked change crosses/);
    await expect(stat(f.output)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("rejects multiply linked review source and cleans incomplete output", async () => {
    const f = await fixture();
    await link(join(f.root, "tests", "new.test.ts"), join(f.root, "tests", "link.test.ts"));
    const before = runGit(f.root, ["status", "--porcelain"]);
    await expect(createReviewBundle({ cwd: f.root, base: f.base, output: f.output }))
      .rejects.toThrow(/singly linked regular file/);
    await expect(stat(f.output)).rejects.toMatchObject({ code: "ENOENT" });
    expect(runGit(f.root, ["status", "--porcelain"])).toBe(before);
  });

  test("detects duplicate and inconsistent manifest entries even with a recomputed digest", async () => {
    const f = await fixture();
    const result = await createReviewBundle({ cwd: f.root, base: f.base, output: f.output });
    const path = join(f.output, "manifest.json");
    const manifest = JSON.parse(await readFile(path, "utf8"));
    manifest.untracked_files.push({ ...manifest.untracked_files[0] });
    const { content_digest_sha256: ignored, ...unsigned } = manifest;
    expect(ignored).toBeTruthy();
    manifest.content_digest_sha256 = createHash("sha256")
      .update(JSON.stringify(unsigned)).digest("hex");
    const bytes = JSON.stringify(manifest, null, 2) + "\n";
    await writeFile(path, bytes);
    const hash = createHash("sha256").update(bytes).digest("hex");
    await expect(verifyReviewBundle(f.output, hash)).rejects.toThrow(/duplicate|unexpected/);
    expect(result.manifest_sha256).not.toBe(hash);
  });

  test("rejects unexpected payload files", async () => {
    const f = await fixture();
    const result = await createReviewBundle({ cwd: f.root, base: f.base, output: f.output });
    await writeFile(join(f.output, "unexpected.txt"), "not declared\n");
    await expect(verifyReviewBundle(f.output, result.manifest_sha256))
      .rejects.toThrow(/unexpected files/);
  });

  test("bounds the untracked file count before copying source", async () => {
    const f = await fixture();
    for (let i = 0; i < 257; i++) {
      await writeFile(join(f.root, "tests", "extra-" + i + ".test.ts"), "export {};\n");
    }
    await expect(createReviewBundle({ cwd: f.root, base: f.base, output: f.output }))
      .rejects.toThrow(/file count limit/);
    await expect(stat(f.output)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("bounds cumulative included source bytes and removes the incomplete output", async () => {
    const f = await fixture();
    const payload = "x".repeat(1_900_000);
    for (let i = 0; i < 9; i++) {
      await writeFile(join(f.root, "tests", "large-" + i + ".test.ts"), payload);
    }
    const before = runGit(f.root, ["status", "--porcelain"]);
    await expect(createReviewBundle({ cwd: f.root, base: f.base, output: f.output }))
      .rejects.toThrow(/total untracked-source byte limit/);
    await expect(stat(f.output)).rejects.toMatchObject({ code: "ENOENT" });
    expect(runGit(f.root, ["status", "--porcelain"])).toBe(before);
  });


  test("53-D: skips synthetic Git directory ancestors of excluded generated content", async () => {
    const f = await fixture();
    await mkdir(join(f.root, "src", "feature", "build"), { recursive: true });
    await writeFile(join(f.root, ".gitignore"), "src/feature/build/\n");
    await writeFile(join(f.root, "src", "feature", "build", "generated.js"), "generated\n");
    const output = runGit(f.root, [
      "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "--", "src/"
    ]).split("\n");
    expect(output).toContain("src/feature/");
    expect(output).toContain("src/feature/build/");
    const before = runGit(f.root, ["status", "--porcelain"]);
    const result = await createReviewBundle({ cwd: f.root, base: f.base, output: f.output });
    const manifest = JSON.parse(await readFile(join(f.output, "manifest.json"), "utf8"));
    expect(manifest.excluded_ignored_paths).toEqual([]);
    expect(manifest.redacted_ignored_count).toBe(1);
    expect(result.redacted_ignored_count).toBe(1);
    expect(await verifyReviewBundle(f.output, result.manifest_sha256)).toMatchObject({ verified: true });
    expect(runGit(f.root, ["status", "--porcelain"])).toBe(before);
  });

  test("53-D: rejects an actually ignored source subtree", async () => {
    const f = await fixture();
    await mkdir(join(f.root, "src", "feature"), { recursive: true });
    await writeFile(join(f.root, ".gitignore"), "src/feature/\n");
    await writeFile(join(f.root, "src", "feature", "hidden.ts"), "export {};\n");
    const before = runGit(f.root, ["status", "--porcelain"]);
    await expect(createReviewBundle({ cwd: f.root, base: f.base, output: f.output }))
      .rejects.toThrow(/Relevant ignored source.*src\/feature\//);
    await expect(stat(f.output)).rejects.toMatchObject({ code: "ENOENT" });
    expect(runGit(f.root, ["status", "--porcelain"])).toBe(before);
  });

  test("53-D: preserves visible untracked source beside an ignored generated subtree", async () => {
    const f = await fixture();
    await mkdir(join(f.root, "src", "feature", "build"), { recursive: true });
    await writeFile(join(f.root, ".gitignore"), "src/feature/build/\n");
    await writeFile(join(f.root, "src", "feature", "new.ts"), "export const feature = 1;\n");
    await writeFile(join(f.root, "src", "feature", "build", "generated.js"), "generated\n");
    const before = runGit(f.root, ["status", "--porcelain"]);
    const result = await createReviewBundle({ cwd: f.root, base: f.base, output: f.output });
    const manifest = JSON.parse(await readFile(join(f.output, "manifest.json"), "utf8"));
    expect(manifest.untracked_files.map((entry) => entry.source_path))
      .toEqual(["src/feature/new.ts", "tests/new.test.ts"]);
    expect(manifest.redacted_ignored_count).toBe(1);
    expect(await readFile(join(f.output, "untracked", "src", "feature", "new.ts"), "utf8"))
      .toBe("export const feature = 1;\n");
    await expect(stat(join(f.output, "untracked", "src", "feature", "build", "generated.js")))
      .rejects.toMatchObject({ code: "ENOENT" });
    expect(result.untracked_path_count).toBe(2);
    expect(runGit(f.root, ["status", "--porcelain"])).toBe(before);
  });

  test("53-D: fails closed if a relevant ignored source appears during capture", async () => {
    const f = await fixture();
    await writeFile(join(f.root, ".gitignore"), "tests/late.test.ts\n");
    const before = runGit(f.root, ["status", "--porcelain"]);
    await expect(createReviewBundle({
      cwd: f.root, base: f.base, output: f.output,
      beforeFinalSnapshot: () =>
        writeFile(join(f.root, "tests", "late.test.ts"), "test('late', () => {});\n")
    })).rejects.toThrow(/Git worktree changed during review-bundle capture/);
    await expect(stat(f.output)).rejects.toMatchObject({ code: "ENOENT" });
    // Only the deliberately inserted test differs from the original checkout.
    expect(runGit(f.root, ["status", "--porcelain"])).toContain("?? .gitignore");
    expect(before).toContain("?? .gitignore");
  });

});
