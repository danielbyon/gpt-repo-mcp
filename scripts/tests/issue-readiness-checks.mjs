import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import process from "node:process";
import { fileURLToPath, URL } from "node:url";
import { test } from "node:test";
import { checkIssueReadiness } from "../check-issue-readiness.mjs";

const check = fileURLToPath(new URL("../check-issue-readiness.mjs", import.meta.url));
const repo = "danielbyon/gpt-repo-mcp";
const defaultIssue = { number: 25, title: "Selected validation", state: "OPEN", labels: [{ name: "ready-for-agent" }] };
const issueCommand = ["issue", "view", "25", "--repo", repo, "--json", "number,title,state,labels"];
const dependencyCommand = ["api", "--paginate", "--slurp", "repos/" + repo + "/issues/25/dependencies/blocked_by"];

function blocker(repository, number, state = "open") {
  const repositoryUrl = "https://api.github.com/repos/" + repository;
  return {
    number,
    state,
    repository: { full_name: repository },
    repository_url: repositoryUrl,
    url: repositoryUrl + "/issues/" + number
  };
}

function fakeGh({ issue = defaultIssue, blockers = [[]], issueFailure = false, dependencyFailure = false } = {}) {
  const calls = [];
  const invokeGh = (args) => {
    calls.push(args);
    if (assertArgs(args, issueCommand)) {
      if (issueFailure) throw new Error("Issue lookup unavailable.");
      return typeof issue === "string" ? issue : JSON.stringify(issue);
    }
    if (assertArgs(args, dependencyCommand)) {
      if (dependencyFailure) throw new Error("Dependency endpoint unavailable.");
      return typeof blockers === "string" ? blockers : JSON.stringify(blockers);
    }
    throw new Error("Unexpected gh invocation: " + JSON.stringify(args));
  };
  return { calls, invokeGh };
}

function assertArgs(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

function runCheck({ args = ["25", "--repo", repo], ...options } = {}) {
  const fixture = fakeGh(options);
  const stdout = [];
  const stderr = [];
  const status = checkIssueReadiness(args, {
    invokeGh: fixture.invokeGh,
    output: (line) => stdout.push(line),
    error: (line) => stderr.push(line)
  });
  return { status, stdout: stdout.join("\n"), stderr: stderr.join("\n"), calls: fixture.calls };
}

test("labeled open issue with no native blockers reports dependency clearance only", () => {
  const result = runCheck();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^DEPENDENCIES_CLEAR #25:/);
  assert.doesNotMatch(result.stdout, /\bREADY\b/);
  assert.match(result.stdout, /other task-admission requirements are not evaluated/);
  assert.deepEqual(result.calls, [issueCommand, dependencyCommand]);
});

test("unlabeled open issue can clear dependencies without asserting agent readiness", () => {
  const result = runCheck({ issue: { ...defaultIssue, labels: [] } });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /DEPENDENCIES_CLEAR/);
});

test("ready-for-agent label does not override native blockers", () => {
  const result = runCheck({ blockers: [[blocker(repo, 12), blocker(repo, 15)]] });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /danielbyon\/gpt-repo-mcp#12, danielbyon\/gpt-repo-mcp#15/);
});

test("unlabeled issue with native blockers remains blocked", () => {
  const result = runCheck({ issue: { ...defaultIssue, labels: [] }, blockers: [[blocker(repo, 12)]] });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /gpt-repo-mcp#12/);
});

test("later dependency pages cannot hide an open blocker", () => {
  const result = runCheck({ blockers: [[blocker(repo, 10, "closed")], [blocker(repo, 15)]] });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /gpt-repo-mcp#15/);
  assert.doesNotMatch(result.stderr, /gpt-repo-mcp#10/);
});

test("same-number blockers in distinct repositories are not conflated", () => {
  const result = runCheck({ blockers: [[blocker("other/project", 12), blocker(repo, 12)]] });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /danielbyon\/gpt-repo-mcp#12, other\/project#12/);
});

test("duplicate blocker entries across pages collapse by canonical repo and number", () => {
  const result = runCheck({ blockers: [[blocker(repo, 15), blocker("Other/Project", 12)], [blocker(repo, 15), blocker("other/project", 12)]] });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /gpt-repo-mcp#15, other\/project#12/);
  assert.equal(result.stderr.match(/gpt-repo-mcp#15/g)?.length, 1);
  assert.equal(result.stderr.match(/other\/project#12/g)?.length, 1);
});

test("closed dependencies do not count as blockers but their identity must be valid", () => {
  const result = runCheck({ blockers: [[blocker(repo, 10, "closed"), blocker(repo, 15), blocker("other/project", 20, "closed")]] });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /gpt-repo-mcp#15/);
  assert.doesNotMatch(result.stderr, /gpt-repo-mcp#10|other\/project#20/);
});

test("closed selected issues are never admitted", () => {
  const result = runCheck({ issue: { ...defaultIssue, state: "CLOSED" } });
  assert.equal(result.status, 2);
  assert.equal(result.calls.length, 1);
});

test("lookup failure, unexpected issue identity and malformed response fail closed", () => {
  assert.equal(runCheck({ issueFailure: true }).status, 3);
  assert.equal(runCheck({ issue: { ...defaultIssue, number: 99 } }).status, 3);
  assert.equal(runCheck({ issue: "{not-json" }).status, 3);
  assert.equal(runCheck({ issue: { ...defaultIssue, state: "unknown" } }).status, 3);
});

test("dependency lookup failures and incomplete pages fail closed", () => {
  assert.equal(runCheck({ dependencyFailure: true }).status, 3);
  assert.equal(runCheck({ blockers: "{not-json" }).status, 3);
  assert.equal(runCheck({ blockers: [] }).status, 3);
  assert.equal(runCheck({ blockers: "{}" }).status, 3);
  assert.equal(runCheck({ blockers: [[blocker(repo, 10)], {}] }).status, 3);
});

test("missing, malformed and inconsistent blocker repository identities fail closed", () => {
  const valid = blocker(repo, 12);
  assert.equal(runCheck({ blockers: [[{ ...valid, repository: undefined }]] }).status, 3);
  assert.equal(runCheck({ blockers: [[{ ...valid, repository_url: undefined }]] }).status, 3);
  assert.equal(runCheck({ blockers: [[{ ...valid, url: undefined }]] }).status, 3);
  assert.equal(runCheck({ blockers: [[{ ...valid, repository: { full_name: "other/repo" } }]] }).status, 3);
  assert.equal(runCheck({ blockers: [[{ ...valid, repository_url: "https://api.github.com/repos/other/repo" }]] }).status, 3);
  assert.equal(runCheck({ blockers: [[{ ...valid, url: valid.url.replace("/12", "/13") }]] }).status, 3);
  assert.equal(runCheck({ blockers: [[{ ...valid, state: "unknown" }]] }).status, 3);
});

test("incorrect endpoint, repository and argv shape are rejected by the strict test double", () => {
  const fixture = fakeGh();
  assert.throws(() => fixture.invokeGh(["api", "--paginate", "--slurp", "repos/" + repo + "/issues/25/dependencies/blocking"]));
  assert.throws(() => fixture.invokeGh(["api", "--paginate", "--slurp", "repos/other/repo/issues/25/dependencies/blocked_by"]));
  assert.throws(() => fixture.invokeGh(["issue", "view", "25", "--repo", "other/repo", "--json", "number,title,state,labels"]));
  assert.throws(() => fixture.invokeGh(["issue", "view", "25", "--repo", repo, "--json", "number,title,state"]));
  assert.throws(() => fixture.invokeGh(["api", "--slurp", "--paginate", dependencyCommand.at(-1)]));
  assert.throws(() => fixture.invokeGh(["api", "--paginate", "--slurp", dependencyCommand.at(-1), "--extra"]));
  assert.deepEqual(runCheck().calls, [issueCommand, dependencyCommand]);
});

test("bad issue CLI arguments cannot become GitHub flags", () => {
  assert.equal(runCheck({ args: ["--repo", repo, "--", "25"] }).status, 3);
  assert.equal(runCheck({ args: ["25", "--repo", "owner/repo;echo"] }).status, 3);
  assert.equal(runCheck({ args: ["25", "--repo", "bad/repo", "--extra"] }).status, 3);
  assert.equal(runCheck({ args: ["25", "--repo", "different/project"] }).status, 3);
});

test("Node CLI invalid-input smoke requires no gh binary on Windows or POSIX", () => {
  const result = spawnSync(process.execPath, [check, "--bad", "--repo", repo], { encoding: "utf8", timeout: 10_000 });
  assert.equal(result.status, 3, result.stderr);
  assert.match(result.stderr, /UNVERIFIED/);
});
