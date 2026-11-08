import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import process from "node:process";
import { delimiter, join } from "node:path";
import { URL, fileURLToPath } from "node:url";
import { test } from "node:test";

const check = fileURLToPath(new URL("../check-issue-readiness.mjs", import.meta.url));
const repo = "danielbyon/gpt-repo-mcp";
const issue = { number: 25, title: "Selected validation", state: "OPEN", labels: [{ name: "ready-for-agent" }] };

function runCheck({ issueValue = issue, blockers = [[]], issueFailure = false, dependencyFailure = false, args = ["25", "--repo", repo] } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "gpt-issue-ready-"));
  const fakeGh = join(directory, "gh");
  writeFileSync(fakeGh, [
    "#!" + process.execPath,
    'const args = process.argv.slice(2);',
    'if (args[0] === "issue" && args[1] === "view") {',
    '  if (process.env.FAKE_ISSUE_FAILURE === "1") process.exit(7);',
    '  process.stdout.write(process.env.FAKE_ISSUE_JSON);',
    '} else if (args[0] === "api" && args.includes("--paginate") && args.includes("--slurp")) {',
    '  if (process.env.FAKE_DEPENDENCY_FAILURE === "1") process.exit(9);',
    '  process.stdout.write(process.env.FAKE_DEPENDENCY_JSON);',
    '} else process.exit(11);'
  ].join("\n") + "\n");
  chmodSync(fakeGh, 0o755);
  try {
    return spawnSync(process.execPath, [check, ...args], {
      encoding: "utf8",
      timeout: 20_000,
      env: {
        ...process.env,
        PATH: directory + delimiter + (process.env.PATH ?? ""),
        FAKE_ISSUE_JSON: typeof issueValue === "string" ? issueValue : JSON.stringify(issueValue),
        FAKE_DEPENDENCY_JSON: typeof blockers === "string" ? blockers : JSON.stringify(blockers),
        FAKE_ISSUE_FAILURE: issueFailure ? "1" : "0",
        FAKE_DEPENDENCY_FAILURE: dependencyFailure ? "1" : "0"
      }
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("open issue with no blockers is eligible", () => {
  const result = runCheck();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /READY.*#25/);
});

test("ready-for-agent label cannot override open native dependencies", () => {
  const result = runCheck({ blockers: [[{ number: 12, state: "open" }, { number: 15, state: "open" }]] });
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stderr, /#12/);
  assert.match(result.stderr, /#15/);
});

test("pagination does not hide an open blocker on a later page", () => {
  const result = runCheck({ blockers: [[{ number: 10, state: "closed" }], [{ number: 15, state: "open" }]] });
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stderr, /#15/);
});

test("closed issues cannot be selected", () => {
  const result = runCheck({ issueValue: { ...issue, state: "CLOSED" } });
  assert.equal(result.status, 2, result.stderr);
});

test("failed or malformed dependency evidence fails closed", () => {
  const unavailable = runCheck({ dependencyFailure: true });
  assert.equal(unavailable.status, 3);
  const malformed = runCheck({ blockers: '{"oops":true}' });
  assert.equal(malformed.status, 3);
  const missingPages = runCheck({ blockers: [] });
  assert.equal(missingPages.status, 3);
  const badState = runCheck({ blockers: [[{ number: 12, state: "unknown" }]] });
  assert.equal(badState.status, 3);
});

test("incorrect issue identity and unavailable issue lookup fail closed", () => {
  assert.equal(runCheck({ issueValue: { ...issue, number: 99 } }).status, 3);
  assert.equal(runCheck({ issueFailure: true }).status, 3);
});

test("invalid repo or issue arguments cannot be interpreted as gh flags", () => {
  assert.equal(runCheck({ args: ["--repo", repo, "--", "25"] }).status, 3);
  assert.equal(runCheck({ args: ["25", "--repo", "owner/repo;echo"] }).status, 3);
});
