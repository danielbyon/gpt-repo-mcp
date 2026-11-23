import { execFile } from "node:child_process";
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, test } from "vitest";
import { DEFAULT_LIMITS } from "../src/policies/limits.js";
import { SHIP_VALIDATION_TEST_PATH_GLOBS } from "../src/policies/operations-defaults.js";
import { RepoReaderConfigSchema } from "../src/config/schema.js";
import { validateConfigDocument } from "../src/config/validation.js";
import { RootRegistry } from "../src/services/root-registry.js";
import { runCli } from "./helpers/connect-gpt-cli.js";

type ParityFixture = { contents: string; document?: unknown };

type ParityScenario = {
  name: string;
  accepts: boolean;
  issueCodes?: string[];
  warningCodes?: string[];
  prepare: (sandbox: string) => Promise<ParityFixture>;
  assertRuntime?: (registry: RootRegistry) => void;
};

const configurableLimitKeys = [
  "max_files",
  "max_bytes_per_file",
  "max_total_bytes",
  "max_search_results",
  "max_tree_entries",
  "max_task_inventory_files",
  "max_task_inventory_tree_pages",
  "max_task_inventory_file_bytes",
  "max_project_brief_doc_bytes",
  "max_depth",
  "max_diff_bytes"
] as const;

const parityScenarios: ParityScenario[] = [
  {
    name: "malformed JSON",
    accepts: false,
    prepare: async () => ({ contents: "{" })
  },
  {
    name: "unknown top-level fields",
    accepts: false,
    issueCodes: ["SCHEMA_INVALID"],
    prepare: async () => jsonFixture({ repos: [], limits: {}, limitz: {} })
  },
  {
    name: "invalid canonical limit values",
    accepts: false,
    issueCodes: ["SCHEMA_INVALID"],
    prepare: async () => jsonFixture({ repos: [], limits: { max_files: 0 } })
  },
  {
    name: "duplicate repository IDs",
    accepts: false,
    issueCodes: ["DUPLICATE_REPO_ID"],
    prepare: async (sandbox) => {
      const firstRoot = join(sandbox, "first-root");
      const secondRoot = join(sandbox, "second-root");
      await Promise.all([mkdir(firstRoot), mkdir(secondRoot)]);
      return jsonFixture({
        repos: [
          configRepo("duplicate", firstRoot, { allow_non_git: true }),
          configRepo("duplicate", secondRoot, { allow_non_git: true })
        ],
        limits: {}
      });
    }
  },
  {
    name: "duplicate canonical roots",
    accepts: false,
    issueCodes: ["DUPLICATE_ROOT"],
    prepare: async (sandbox) => {
      const root = join(sandbox, "shared-root");
      await mkdir(root);
      return jsonFixture({
        repos: [
          configRepo("first", root, { allow_non_git: true }),
          configRepo("second", root, { allow_non_git: true })
        ],
        limits: {}
      });
    }
  },
  {
    name: "duplicate roots through a symlink alias",
    accepts: false,
    issueCodes: ["DUPLICATE_ROOT"],
    prepare: async (sandbox) => {
      const root = join(sandbox, "canonical-root");
      const alias = join(sandbox, "root-alias");
      await mkdir(root);
      await symlink(root, alias, process.platform === "win32" ? "junction" : "dir");
      return jsonFixture({
        repos: [
          configRepo("canonical", root, { allow_non_git: true }),
          configRepo("alias", alias, { allow_non_git: true })
        ],
        limits: {}
      });
    }
  },
  {
    name: "missing and non-directory roots",
    accepts: false,
    issueCodes: ["ROOT_MISSING", "ROOT_NOT_DIRECTORY"],
    prepare: async (sandbox) => {
      const fileRoot = join(sandbox, "root.txt");
      await writeFile(fileRoot, "not a directory\n");
      return jsonFixture({
        repos: [
          configRepo("missing", join(sandbox, "missing-root"), { allow_non_git: true }),
          configRepo("file", fileRoot, { allow_non_git: true })
        ],
        limits: {}
      });
    }
  },
  {
    name: "non-Git roots without allow_non_git",
    accepts: false,
    issueCodes: ["NOT_GIT_REPO"],
    prepare: async (sandbox) => {
      const root = join(sandbox, "plain-directory");
      await mkdir(root);
      return jsonFixture({ repos: [configRepo("plain", root)], limits: {} });
    }
  },
  {
    name: "non-Git roots with allow_non_git",
    accepts: true,
    prepare: async (sandbox) => {
      const root = join(sandbox, "allowed-directory");
      await mkdir(root);
      return jsonFixture({
        repos: [configRepo("plain", root, { allow_non_git: true })],
        limits: {}
      });
    }
  },
  {
    name: "blank allowed write globs",
    accepts: false,
    issueCodes: ["WRITE_GLOB_INVALID"],
    prepare: async (sandbox) => {
      const root = join(sandbox, "allowed-glob-root");
      await mkdir(root);
      return jsonFixture({
        repos: [configRepo("blank-allow", root, {
          allow_non_git: true,
          writes: { allowed_globs: [""] }
        })],
        limits: {}
      });
    }
  },
  {
    name: "blank denied write globs",
    accepts: false,
    issueCodes: ["WRITE_GLOB_INVALID"],
    prepare: async (sandbox) => {
      const root = join(sandbox, "denied-glob-root");
      await mkdir(root);
      return jsonFixture({
        repos: [configRepo("blank-deny", root, {
          allow_non_git: true,
          writes: { denied_globs: ["   "] }
        })],
        limits: {}
      });
    }
  },
  {
    name: "nonblank write glob syntax remains unchecked at config load",
    accepts: true,
    prepare: async (sandbox) => {
      const root = join(sandbox, "uncompiled-glob-root");
      await mkdir(root);
      return jsonFixture({
        repos: [configRepo("uncompiled-glob", root, {
          allow_non_git: true,
          writes: { allowed_globs: ["["] }
        })],
        limits: {}
      });
    },
    assertRuntime: (registry) => {
      expect(registry.get("uncompiled-glob").writes?.allowed_globs).toEqual(["["]);
    }
  },
  {
    name: "warning-only configuration",
    accepts: true,
    warningCodes: ["SHIP_VALIDATION_TEST_PATHS_NOT_CONFIGURED"],
    prepare: async (sandbox) => {
      const root = join(sandbox, "warning-root");
      await mkdir(root);
      return jsonFixture({
        repos: [configRepo("warning", root, {
          allow_non_git: true,
          operations: {
            enabled: true,
            git_stage_enabled: true,
            git_commit_enabled: true,
            cleanup_enabled: true,
            validation_enabled: true
          }
        })],
        limits: {}
      });
    }
  },
  {
    name: "legacy ship-like validation defaults",
    accepts: true,
    warningCodes: ["VALIDATION_NOT_ENABLED"],
    prepare: async (sandbox) => {
      const root = join(sandbox, "legacy-root");
      await mkdir(root);
      return jsonFixture({
        repos: [configRepo("legacy", root, {
          allow_non_git: true,
          operations: {
            enabled: true,
            git_stage_enabled: true,
            git_commit_enabled: true,
            cleanup_enabled: true
          }
        })],
        limits: {}
      });
    },
    assertRuntime: (registry) => {
      expect(registry.get("legacy").operations?.validation_enabled).toBe(true);
      expect(registry.get("legacy").operations?.validation_test_path_globs)
        .toEqual(SHIP_VALIDATION_TEST_PATH_GLOBS);
    }
  },
  {
    name: "explicit validation_enabled false",
    accepts: true,
    warningCodes: ["VALIDATION_NOT_ENABLED"],
    prepare: async (sandbox) => {
      const root = join(sandbox, "opt-out-root");
      await mkdir(root);
      return jsonFixture({
        repos: [configRepo("opt-out", root, {
          allow_non_git: true,
          operations: {
            enabled: true,
            git_stage_enabled: true,
            git_commit_enabled: true,
            cleanup_enabled: true,
            validation_enabled: false
          }
        })],
        limits: {}
      });
    },
    assertRuntime: (registry) => {
      expect(registry.get("opt-out").operations?.validation_enabled).toBe(false);
    }
  },
  {
    name: "explicitly selected empty repos array",
    accepts: true,
    prepare: async () => jsonFixture({ repos: [], limits: {} })
  },
  {
    name: "canonical configured limits and defaults",
    accepts: true,
    prepare: async () => {
      const limits = Object.fromEntries(configurableLimitKeys.map((key, index) => [key, index + 101]));
      return jsonFixture({ repos: [], limits });
    }
  },
  {
    name: "linked Git worktree root",
    accepts: true,
    prepare: async (sandbox) => {
      const linkedRoot = await createLinkedWorktree(sandbox);
      return jsonFixture({ repos: [configRepo("linked", linkedRoot)], limits: {} });
    }
  }
];

describe("CLI and file-backed startup validation parity", () => {
  test.each(parityScenarios)("$name", async (scenario) => {
    const sandbox = await mkdtemp(join(tmpdir(), "config-validation-parity-"));
    const configPath = join(sandbox, "config.json");

    try {
      const fixture = await scenario.prepare(sandbox);
      await writeFile(configPath, fixture.contents, "utf8");
      const [topLevelCheck, configCheck] = await Promise.all([
        runCli(["check", "--config", configPath], sandbox),
        runCli(["config", "check", "--config", configPath], sandbox)
      ]);
      const cliResults = [topLevelCheck, configCheck];
      expect(cliResults.map((result) => result.code === 0)).toEqual([scenario.accepts, scenario.accepts]);

      let registry: RootRegistry | undefined;
      let registryError: unknown;
      try {
        registry = await RootRegistry.fromFile(configPath);
      } catch (error) {
        registryError = error;
      }
      expect(registry !== undefined).toBe(scenario.accepts);

      const validation = fixture.document === undefined
        ? undefined
        : await validateConfigDocument(fixture.document);
      if (validation) {
        expect(validation.issues.map((issue) => issue.code)).toEqual(scenario.issueCodes ?? []);
      }

      if (!scenario.accepts) {
        expect(registryError).toBeInstanceOf(Error);
        for (const code of scenario.issueCodes ?? []) {
          for (const result of cliResults) expect(result.stderr).toContain(`[${code}]`);
          expect(String(registryError)).toContain(code);
        }
        return;
      }

      expect(validation?.issues).toEqual([]);
      expect(validation?.warnings.map((warning) => warning.code)).toEqual(scenario.warningCodes ?? []);
      for (const result of cliResults) {
        expect(extractWarningCodes(result.stdout)).toEqual(scenario.warningCodes ?? []);
      }
      await expectNormalizedRegistry(fixture.document, registry!);
      scenario.assertRuntime?.(registry!);
    } finally {
      await rm(sandbox, { recursive: true, force: true });
    }
  }, 15_000);
});

test("--config takes precedence over both environment variables for both check forms", async () => {
  const sandbox = await mkdtemp(join(tmpdir(), "connect-gpt-cli-config-precedence-"));
  const root = join(sandbox, "environment-root");
  const selectedPath = join(sandbox, "selected.json");
  const gptConfigPath = join(sandbox, "gpt.json");
  const legacyConfigPath = join(sandbox, "legacy.json");

  try {
    await mkdir(root);
    await writeFile(selectedPath, JSON.stringify({ repos: [], limits: {} }), "utf8");
    await writeFile(gptConfigPath, JSON.stringify({
      repos: [configRepo("gpt", root, { allow_non_git: true })],
      limits: {}
    }), "utf8");
    await writeFile(legacyConfigPath, JSON.stringify({
      repos: [
        configRepo("legacy-one", root, { allow_non_git: true }),
        configRepo("legacy-two", root, { allow_non_git: true })
      ],
      limits: {}
    }), "utf8");

    const env = { GPT_REPO_CONFIG: gptConfigPath, REPO_READER_CONFIG: legacyConfigPath };
    const [topLevelCheck, configCheck] = await Promise.all([
      runCli(["--config", "selected.json", "check"], sandbox, undefined, env),
      runCli(["config", "check", "--config", "selected.json"], sandbox, undefined, env)
    ]);

    for (const result of [topLevelCheck, configCheck]) {
      expect(result.code).toBe(0);
      expect(result.stdout).toContain("PASS 0 repo(s) validated.");
    }
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

function jsonFixture(document: unknown): ParityFixture {
  return { contents: JSON.stringify(document, null, 2), document };
}

function configRepo(repoId: string, root: string, extra: Record<string, unknown> = {}) {
  return { repo_id: repoId, display_name: repoId, root, ...extra };
}

async function expectNormalizedRegistry(document: unknown, registry: RootRegistry): Promise<void> {
  const normalized = RepoReaderConfigSchema.parse(document);
  const expectedRepos = await Promise.all(normalized.repos.map(async (repo) => ({
    ...repo,
    root: await realpath(repo.root)
  })));

  expect(registry.list()).toEqual(expectedRepos.map(({ repo_id, display_name, root }) => ({
    repo_id,
    display_name,
    root
  })));
  for (const repo of expectedRepos) expect(registry.get(repo.repo_id)).toEqual(repo);
  expect(registry.limits).toEqual({ ...DEFAULT_LIMITS, ...normalized.limits });
}

function extractWarningCodes(stdout: string): string[] {
  return [...stdout.matchAll(/WARN \[([^\]]+)\]/g)].map((match) => match[1] ?? "");
}

const exec = promisify(execFile);

async function createLinkedWorktree(sandbox: string): Promise<string> {
  const primaryRoot = join(sandbox, "primary-checkout");
  const linkedRoot = join(sandbox, "linked-checkout");
  await mkdir(primaryRoot);
  await exec("git", ["init"], { cwd: primaryRoot, encoding: "utf8" });
  await writeFile(join(primaryRoot, "README.md"), "linked worktree fixture\n", "utf8");
  await exec("git", ["add", "README.md"], { cwd: primaryRoot, encoding: "utf8" });
  await exec("git", [
    "-c", "user.name=Config Parity Tests",
    "-c", "user.email=config-parity@example.invalid",
    "commit", "-m", "Create worktree fixture"
  ], { cwd: primaryRoot, encoding: "utf8" });
  await exec("git", ["worktree", "add", "--detach", linkedRoot, "HEAD"], {
    cwd: primaryRoot,
    encoding: "utf8"
  });
  return linkedRoot;
}
