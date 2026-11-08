import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { OperationsPolicy } from "../src/services/operations-policy.js";
import { ValidationService } from "../src/services/validation-service.js";
import { GitReviewService } from "../src/services/git-review-service.js";
import { canonicalSha256 } from "../src/services/validation-evidence.js";
import { createTempDir } from "./fixtures/temp-dir.js";
import { createTrustedTestRunner, withTrustedRunnerPath } from "./fixtures/validation-test-tools.js";

type Context = {
  root: string;
  receiptPath: string;
  pointerPath: string;
  policy: OperationsPolicy;
};

type Mutation = {
  name: string;
  expectedStatus: "passed" | "stale" | "unverified";
  expectedEligibility: "eligible" | "ineligible" | "unverified";
  mutate(context: Context): Promise<Partial<Context> | void>;
};

async function fixture(): Promise<Context> {
  const root = await createTempDir("gpt-validation-matrix-");
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(join(root, "package.json"), JSON.stringify({
    type: "module",
    scripts: { test: "node -e \"console.log('validation-matrix-ok')\"" }
  }));
  await writeFile(join(root, ".gitignore"), "ignored-output/\n");
  await writeFile(join(root, "src", "dependency.txt"), "original\n");
  git(root, ["init", "--quiet"]);
  git(root, ["config", "user.name", "Validation Fixture"]);
  git(root, ["config", "user.email", "validation-fixture@example.invalid"]);
  git(root, ["add", "-A"]);
  git(root, ["-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture"]);

  const policy = new OperationsPolicy({ enabled: true, validation_enabled: true });
  const validation = await new ValidationService(root, policy).validate({ repo_id: "fixture", profile: "test" });
  expect(validation.status).toBe("passed");
  expect(validation.validation_artifact?.path).toBeTruthy();
  return {
    root,
    receiptPath: join(root, validation.validation_artifact!.path),
    pointerPath: join(root, ".chatgpt", "validation", "latest.json"),
    policy
  };
}

function git(root: string, args: string[]): void {
  execFileSync("git", args, { cwd: root, stdio: "pipe" });
}

async function rewriteReceiptAndPointer(context: Context, edit: (receipt: Record<string, unknown>) => void): Promise<void> {
  const receipt = JSON.parse(await readFile(context.receiptPath, "utf8")) as Record<string, unknown>;
  const pointer = JSON.parse(await readFile(context.pointerPath, "utf8")) as Record<string, unknown>;
  edit(receipt);
  const { receipt_sha256: _old, ...unsigned } = receipt;
  const digest = canonicalSha256(unsigned);
  receipt.receipt_sha256 = digest;
  pointer.receipt_sha256 = digest;
  pointer.eligibility = (receipt.eligibility as { status: string }).status;
  await writeFile(context.receiptPath, JSON.stringify(receipt));
  await writeFile(context.pointerPath, JSON.stringify(pointer));
}

const mutations: Mutation[] = [
  {
    name: "tracked source modified outside reviewed paths",
    expectedStatus: "stale", expectedEligibility: "ineligible",
    mutate: async ({ root }) => { await writeFile(join(root, "src", "dependency.txt"), "modified\n"); }
  },
  {
    name: "new untracked source dependency",
    expectedStatus: "stale", expectedEligibility: "ineligible",
    mutate: async ({ root }) => { await writeFile(join(root, "src", "new-dependency.txt"), "added\n"); }
  },
  {
    name: "logical index changed without changing final working bytes",
    expectedStatus: "stale", expectedEligibility: "ineligible",
    mutate: async ({ root }) => {
      await writeFile(join(root, "src", "dependency.txt"), "staged\n");
      git(root, ["add", "--", "src/dependency.txt"]);
      await writeFile(join(root, "src", "dependency.txt"), "original\n");
    }
  },
  {
    name: "tracked ignore rules changed",
    expectedStatus: "stale", expectedEligibility: "ineligible",
    mutate: async ({ root }) => { await writeFile(join(root, ".gitignore"), "ignored-output/\nnew-exclusion/\n"); }
  },
  {
    name: "declared validation script changed",
    expectedStatus: "stale", expectedEligibility: "ineligible",
    mutate: async ({ root }) => {
      const path = join(root, "package.json");
      const source = await readFile(path, "utf8");
      await writeFile(path, source.replace("validation-matrix-ok", "changed-command"));
    }
  },
  {
    name: "effective validation policy changed",
    expectedStatus: "stale", expectedEligibility: "ineligible",
    mutate: async () => ({
      policy: new OperationsPolicy({
        enabled: true,
        validation_enabled: true,
        validation_test_path_globs: ["tests/**"]
      })
    })
  },
  {
    name: "pointer artifact reference escapes its fixed path",
    expectedStatus: "unverified", expectedEligibility: "unverified",
    mutate: async ({ pointerPath }) => {
      const pointer = JSON.parse(await readFile(pointerPath, "utf8")) as Record<string, unknown>;
      pointer.artifact_path = "../../other-result.json";
      await writeFile(pointerPath, JSON.stringify(pointer));
    }
  },
  {
    name: "invalid eligibility with recomputed receipt and matching pointer digest",
    expectedStatus: "unverified", expectedEligibility: "unverified",
    mutate: async (context) => {
      await rewriteReceiptAndPointer(context, (receipt) => {
        receipt.eligibility = { status: "ineligible", reasons: [] };
      });
    }
  },
  {
    name: "omitted tracked dependency even when snapshot receipt and pointer hashes are recomputed",
    expectedStatus: "stale", expectedEligibility: "ineligible",
    mutate: async (context) => {
      await rewriteReceiptAndPointer(context, (receipt) => {
        const source = receipt.source_evidence as Record<string, unknown>;
        for (const key of ["before", "after"]) {
          const snapshot = source[key] as Record<string, unknown>;
          const files = (snapshot.files as Array<{ path: string }>).filter((file) => file.path !== "src/dependency.txt");
          const { sha256: _previous, ...unsigned } = { ...snapshot, files };
          source[key] = { ...unsigned, sha256: canonicalSha256(unsigned) };
        }
      });
    }
  },
  {
    name: "untracked generated output explicitly ignored by Git",
    expectedStatus: "passed", expectedEligibility: "eligible",
    mutate: async ({ root }) => {
      await mkdir(join(root, "ignored-output"), { recursive: true });
      await writeFile(join(root, "ignored-output", "build.log"), "generated\n");
    }
  },
  {
    name: "untracked generated Delegation result artifact",
    expectedStatus: "passed", expectedEligibility: "eligible",
    mutate: async ({ root }) => {
      const dir = join(root, ".chatgpt", "codex-runs", "2026-11-07T000000Z-matrix");
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, "RESULT.json"), "{\"status\":\"unverified\"}\n");
    }
  }
];

describe("V2 validation receipt adversarial input matrix", () => {
  test.each(mutations)("$name", async ({ mutate, expectedStatus, expectedEligibility }) => {
    const initial = await fixture();
    const baseline = await new GitReviewService(initial.root, initial.policy).review({ repo_id: "fixture" });
    expect(baseline.ship_readiness.validation).toMatchObject({ status: "passed", eligibility: "eligible" });

    const adjusted = await mutate(initial);
    const context = { ...initial, ...(adjusted ?? {}) };
    const reviewed = await new GitReviewService(context.root, context.policy).review({ repo_id: "fixture" });
    expect(reviewed.ship_readiness.validation).toMatchObject({
      status: expectedStatus,
      eligibility: expectedEligibility
    });
  }, 15_000);

  test("receipt is not reusable under another repository identity", async () => {
    const context = await fixture();
    const other = await new GitReviewService(context.root, context.policy).review({ repo_id: "different-repository" });
    expect(other.ship_readiness.validation).toMatchObject({ status: "unverified", eligibility: "unverified" });
  }, 15_000);

  test.skipIf(process.platform === "win32")("runner executable content change stales an otherwise identical checkout", async () => {
    const root = await createTempDir("gpt-just-receipt-matrix-");
    await writeFile(join(root, "justfile"), "test:\n    @echo test\n");
    git(root, ["init", "--quiet"]);
    git(root, ["config", "user.name", "Validation Fixture"]);
    git(root, ["config", "user.email", "validation-fixture@example.invalid"]);
    git(root, ["add", "."]);
    git(root, ["-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture"]);

    const runner = await createTrustedTestRunner("just", 'console.log("runner-ok");');
    await withTrustedRunnerPath(runner.bin, async () => {
      const policy = new OperationsPolicy({
        enabled: true,
        validation_enabled: true,
        validation_profiles: { test: { runner: "just", target: "test" } }
      });
      const validation = await new ValidationService(root, policy).validate({ repo_id: "fixture", profile: "test" });
      expect(validation.status).toBe("passed");
      const review = new GitReviewService(root, policy);
      expect((await review.review({ repo_id: "fixture" })).ship_readiness.validation)
        .toMatchObject({ status: "passed", eligibility: "eligible" });
      await writeFile(runner.executable, "#!" + process.execPath + '\nconsole.log("runner-updated");\n');
      expect((await review.review({ repo_id: "fixture" })).ship_readiness.validation)
        .toMatchObject({ status: "stale", eligibility: "ineligible" });
    });
  }, 15_000);
});
