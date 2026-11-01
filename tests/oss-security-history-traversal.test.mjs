import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { describe, expect, test } from "vitest";
import {
  candidateEmailOccurrences,
  hasRestrictedPolicyPathSuffix,
  historyEmailOccurrences
} from "../scripts/oss-security-scan.mjs";

const execFileAsync = promisify(execFile);

async function git(repo, args) {
  const { stdout } = await execFileAsync("git", ["-C", repo, ...args], {
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_SYSTEM: "/dev/null"
    }
  });
  return stdout.trim();
}

async function commitFile(repo, contents, message) {
  await writeFile(join(repo, "notes.txt"), contents);
  await git(repo, ["add", "notes.txt"]);
  await git(repo, [
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.com",
    "commit",
    "-qm",
    message
  ]);
  return git(repo, ["rev-parse", "HEAD"]);
}

async function commitPath(repo, path, contents, message) {
  const absolutePath = join(repo, path);
  await mkdir(dirname(absolutePath), { recursive: true });
  await writeFile(absolutePath, contents);
  await git(repo, ["add", "--", path]);
  await git(repo, [
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.com",
    "commit",
    "-qm",
    message
  ]);
  return git(repo, ["rev-parse", "HEAD"]);
}

describe("OSS security scan history traversal", () => {
  test("preflights both names for a shared blob before blob reads", async () => {
    const repo = await mkdtemp(join(tmpdir(), "gpt-repo-history-shared-blob-"));
    const ordinaryPath = "notes.txt";
    const aliasPath = "security\\oss-security-policy.json";
    const contents = "neutral shared-blob sentinel@example.invalid\n";
    try {
      await git(repo, ["init", "-q"]);
      await writeFile(join(repo, ordinaryPath), contents);
      await writeFile(join(repo, aliasPath), contents);
      await git(repo, ["add", "--", ordinaryPath, aliasPath]);
      await git(repo, [
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.com",
        "commit",
        "-qm",
        "shared blob paths"
      ]);

      const ordinaryBlob = await git(repo, ["rev-parse", "HEAD:notes.txt"]);
      const aliasBlob = await git(repo, [
        "rev-parse",
        `HEAD:${aliasPath}`
      ]);
      expect(aliasBlob).toBe(ordinaryBlob);

      const treePaths = await git(repo, [
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        "--name-only",
        "HEAD"
      ]);
      expect(treePaths.split("\0")).toEqual(
        expect.arrayContaining([ordinaryPath, aliasPath])
      );

      const objectPaths = await git(repo, [
        "rev-list",
        "--objects",
        "--no-walk",
        "HEAD",
        "--",
        "."
      ]);
      const listedPaths = objectPaths.split("\n").flatMap((line) => {
        const separator = line.indexOf(" ");
        return separator < 0 ? [] : [line.slice(separator + 1)];
      });
      expect(listedPaths).toContain(ordinaryPath);
      expect(listedPaths).not.toContain(aliasPath);

      const tracePath = join(repo, "git-trace.log");
      const previousTrace = process.env.GIT_TRACE;
      await writeFile(tracePath, "");
      process.env.GIT_TRACE = tracePath;
      try {
        await expect(historyEmailOccurrences(
          repo,
          { commits: [await git(repo, ["rev-parse", "HEAD"])] },
          { includeBlobs: true, platform: "win32" }
        )).rejects.toMatchObject({ code: "RESTRICTED_POLICY_ALIAS_UNSUPPORTED" });
      } finally {
        if (previousTrace === undefined) delete process.env.GIT_TRACE;
        else process.env.GIT_TRACE = previousTrace;
      }
      expect(await readFile(tracePath, "utf8")).not.toMatch(/rev-list --objects|cat-file/);
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });

  test("scans only the listed commits and does not repeat ancestor blobs", async () => {
    const repo = await mkdtemp(join(tmpdir(), "gpt-repo-history-traversal-"));
    try {
      await git(repo, ["init", "-q"]);
      const root = await commitFile(repo, "ancestor@example.com\n", "root");
      const selected = await commitFile(repo, "selected@example.com\n", "selected");

      const subset = await historyEmailOccurrences(
        repo,
        { commits: [selected] },
        { includeBlobs: true }
      );
      const subsetAddresses = subset.map((entry) => entry.address);
      expect(subsetAddresses).toContain("selected@example.com");
      expect(subsetAddresses).toContain("fixture@example.com");
      expect(subsetAddresses).not.toContain("ancestor@example.com");

      const full = await historyEmailOccurrences(
        repo,
        { commits: [root, selected] },
        { includeBlobs: true }
      );
      const addresses = full.map((entry) => entry.address);
      expect(addresses.filter((address) => address === "ancestor@example.com")).toHaveLength(1);
      expect(addresses.filter((address) => address === "selected@example.com")).toHaveLength(1);
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });

  test("selected-history preflight ignores unsupported paths on unselected refs", async () => {
    const repo = await mkdtemp(join(tmpdir(), "gpt-repo-history-selected-refs-"));
    const aliasPath = "Security/OSS-SECURITY-POLICY.JSON";
    try {
      await git(repo, ["init", "-q"]);
      const selected = await commitFile(repo, "selected@example.com\n", "selected");
      const selectedBranch = await git(repo, ["branch", "--show-current"]);

      await git(repo, ["checkout", "-b", "unselected-alias"]);
      await commitPath(repo, aliasPath, "unselected@example.com\n", "unsupported alias");
      await git(repo, ["checkout", selectedBranch]);

      const occurrences = await historyEmailOccurrences(
        repo,
        { commits: [selected] },
        { includeBlobs: true, platform: "win32" }
      );
      expect(occurrences.map((entry) => entry.address)).toContain("selected@example.com");
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });

  test("local_all_refs scope still rejects an unsupported path on any local ref", async () => {
    const repo = await mkdtemp(join(tmpdir(), "gpt-repo-history-all-refs-"));
    const aliasPath = "Security/OSS-SECURITY-POLICY.JSON";
    try {
      await git(repo, ["init", "-q"]);
      await commitFile(repo, "selected@example.com\n", "selected");
      await git(repo, ["checkout", "-b", "unselected-alias"]);
      await commitPath(repo, aliasPath, "unselected@example.com\n", "unsupported alias");

      const commits = (await git(repo, ["rev-list", "--all"]))
        .split("\n")
        .filter(Boolean);
      await expect(historyEmailOccurrences(
        repo,
        { mode: "local_all_refs", commits },
        { includeBlobs: true, platform: "win32" }
      )).rejects.toMatchObject({ code: "RESTRICTED_POLICY_ALIAS_UNSUPPORTED" });
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });

  test("filters canonical suffixes and blocks alias spellings before candidate reads", async () => {
    const candidate = await mkdtemp(join(tmpdir(), "gpt-repo-candidate-policy-filter-"));
    const restrictedPaths = [
      "security/oss-security-policy.json",
      "nested/security/oss-security-policy.json",
      "Security/OSS-SECURITY-POLICY.JSON",
      "nested/Security/OSS-SECURITY-POLICY.JSON",
      "nested\\Security\\OSS-SECURITY-POLICY.JSON",
      "Security\\OSS-SECURITY-POLICY.JSON",
      "nested/Security\\OSS-SECURITY-POLICY.JSON",
      "nested\\Security/OSS-SECURITY-POLICY.JSON",
      "security\\oss-security-policy.json",
      "nested\\security/oss-security-policy.json"
    ];
    const canonicalPaths = restrictedPaths.slice(0, 2);
    const aliasPaths = restrictedPaths.slice(2);
    try {
      expect(restrictedPaths.every(hasRestrictedPolicyPathSuffix)).toBe(true);
      await expect(candidateEmailOccurrences(
        candidate,
        canonicalPaths.map((path) => ({ path, bytes: 20, sha256: "0".repeat(64) }))
      )).resolves.toEqual({
        occurrences: [],
        skipped: { large_files: 0, binary_files: 0 }
      });
      await expect(candidateEmailOccurrences(
        candidate,
        aliasPaths.map((path) => ({ path, bytes: 20, sha256: "0".repeat(64) }))
      )).rejects.toMatchObject({ code: "RESTRICTED_POLICY_ALIAS_UNSUPPORTED" });
    } finally {
      await rm(candidate, { recursive: true, force: true });
    }
  });
});
