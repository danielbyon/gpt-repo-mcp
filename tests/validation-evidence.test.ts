import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { ValidationEvidenceService } from "../src/services/validation-evidence.js";
import { cleanupTempDirs, createTempDir } from "./fixtures/temp-dir.js";

describe("ValidationEvidenceService", () => {
  afterEach(async () => cleanupTempDirs());

  test("binds committed, staged, working-tree, untracked, mode, and symlink state", async () => {
    const root = await createTempDir("validation-evidence-");
    await mkdir(root, { recursive: true });
    await writeFile(join(root, "tracked.txt"), "committed\n");
    await writeFile(join(root, "script.sh"), "#!/bin/sh\nexit 0\n");
    await writeFile(join(root, "target.txt"), "target\n");
    await chmod(join(root, "script.sh"), 0o755);
    if (process.platform !== "win32") await symlink("target.txt", join(root, "link.txt"));
    git(root, ["init", "--quiet"]);
    git(root, ["config", "user.name", "Validation Fixture"]);
    git(root, ["config", "user.email", "validation-fixture@example.invalid"]);
    git(root, ["add", "."]);
    git(root, ["commit", "--quiet", "-m", "fixture"]);

    await writeFile(join(root, "tracked.txt"), "staged\n");
    git(root, ["add", "tracked.txt"]);
    await writeFile(join(root, "tracked.txt"), "working tree\n");
    await writeFile(join(root, "untracked.txt"), "untracked source\n");

    const snapshot = await new ValidationEvidenceService(root).captureSourceSnapshot();
    const tracked = snapshot.files.find((entry) => entry.path === "tracked.txt");

    expect(snapshot.head_sha).toMatch(/^[a-f0-9]{40,64}$/);
    expect(snapshot.index.entries.find((entry) => entry.path === "tracked.txt")).toMatchObject({
      stage: 0,
      mode: "100644"
    });
    expect(tracked?.head?.object_id).not.toBe(snapshot.index.entries.find((entry) => entry.path === "tracked.txt")?.object_id);
    expect(tracked?.worktree).toMatchObject({
      kind: "file",
      content_sha256: sha256("working tree\n")
    });
    expect(snapshot.files.find((entry) => entry.path === "script.sh")?.worktree.mode_bits).toBe(0o755);
    expect(snapshot.files.find((entry) => entry.path === "untracked.txt")?.worktree.content_sha256).toBe(sha256("untracked source\n"));
    if (process.platform !== "win32") {
      expect(snapshot.files.find((entry) => entry.path === "link.txt")?.worktree).toMatchObject({
        kind: "symlink",
        symlink_target: "target.txt"
      });
    }
  });

  test("fails closed when the source inventory exceeds its configured bound", async () => {
    const root = await createTempDir("validation-evidence-bound-");
    await writeFile(join(root, "a.txt"), "a\n");
    await writeFile(join(root, "b.txt"), "b\n");
    git(root, ["init", "--quiet"]);
    git(root, ["config", "user.name", "Validation Fixture"]);
    git(root, ["config", "user.email", "validation-fixture@example.invalid"]);
    git(root, ["add", "."]);
    git(root, ["commit", "--quiet", "-m", "fixture"]);

    await expect(new ValidationEvidenceService(root, { limits: { max_entries: 1 } }).captureSourceSnapshot())
      .rejects.toMatchObject({ code: "VALIDATION_EVIDENCE_UNVERIFIED" });
  });

  test("changes the source digest when content changes without changing HEAD or the existing fingerprint model", async () => {
    const root = await createTempDir("validation-evidence-drift-");
    await writeFile(join(root, "tracked.txt"), "before\n");
    git(root, ["init", "--quiet"]);
    git(root, ["config", "user.name", "Validation Fixture"]);
    git(root, ["config", "user.email", "validation-fixture@example.invalid"]);
    git(root, ["add", "."]);
    git(root, ["commit", "--quiet", "-m", "fixture"]);

    const evidence = new ValidationEvidenceService(root);
    const before = await evidence.captureSourceSnapshot();
    await writeFile(join(root, "tracked.txt"), "after\n");
    const after = await evidence.captureSourceSnapshot();

    expect(after.head_sha).toBe(before.head_sha);
    expect(after.sha256).not.toBe(before.sha256);
  });

  test("excludes untracked Delegation result artifacts while retaining tracked content under the same control path", async () => {
    const root = await createTempDir("validation-evidence-delegation-control-");
    const trackedResult = ".chatgpt/codex-runs/tracked-run/RESULT.json";
    await mkdir(join(root, ".chatgpt", "codex-runs", "tracked-run"), { recursive: true });
    await writeFile(join(root, "tracked.txt"), "source\n");
    await writeFile(join(root, trackedResult), "{\"tracked\":true}\n");
    git(root, ["init", "--quiet"]);
    git(root, ["config", "user.name", "Validation Fixture"]);
    git(root, ["config", "user.email", "validation-fixture@example.invalid"]);
    git(root, ["add", "."]);
    git(root, ["commit", "--quiet", "-m", "fixture"]);

    const untrackedResult = ".chatgpt/codex-runs/untracked-run/RESULT.json";
    await mkdir(join(root, ".chatgpt", "codex-runs", "untracked-run"), { recursive: true });
    await writeFile(join(root, untrackedResult), "{\"first\":true}\n");
    const untrackedPaths = execFileSync("git", ["ls-files", "--others", "--exclude-standard", "--", untrackedResult], {
      cwd: root,
      encoding: "utf8"
    });
    expect(untrackedPaths.trim()).toBe(untrackedResult);

    const evidence = new ValidationEvidenceService(root);
    const before = await evidence.captureSourceSnapshot();
    await writeFile(join(root, untrackedResult), "{\"second\":true}\n");
    const after = await evidence.captureSourceSnapshot();

    expect(before.files.find((entry) => entry.path === trackedResult)?.worktree.content_sha256).toBe(sha256("{\"tracked\":true}\n"));
    expect(before.files.some((entry) => entry.path === untrackedResult)).toBe(false);
    expect(after.sha256).toBe(before.sha256);
  });
});

function git(root: string, args: string[]): void {
  execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: "pipe" });
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
