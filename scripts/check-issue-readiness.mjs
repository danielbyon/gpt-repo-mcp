#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import process from "node:process";
import { fileURLToPath, URL } from "node:url";

const MAX_BYTES = 1024 * 1024;
const GH_TIMEOUT_MS = 15_000;
const REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

/** Dependency clearance only; task ownership, priority, and specification readiness are separate. */
export function checkIssueReadiness(args, {
  invokeGh = runGh,
  output = (message) => globalThis.console.log(message),
  error = (message) => globalThis.console.error(message)
} = {}) {
  if (args.length !== 3 || !/^[1-9]\d{0,8}$/.test(args[0] ?? "")
      || args[1] !== "--repo" || !REPO_PATTERN.test(args[2] ?? "")) {
    error("UNVERIFIED: usage: node scripts/check-issue-readiness.mjs <issue-number> --repo <owner/repo>");
    return 3;
  }
  const number = Number(args[0]);
  const repo = args[2];

  try {
    const issue = JSON.parse(invokeGh(["issue", "view", String(number), "--repo", repo, "--json", "number,title,state,labels"]));
    if (!issue || typeof issue !== "object" || Array.isArray(issue)
        || issue.number !== number || !["OPEN", "CLOSED"].includes(issue.state)) {
      throw new Error("Issue identity or state is unavailable.");
    }
    if (issue.state === "CLOSED") {
      error("BLOCKED #" + number + ": the issue is closed.");
      return 2;
    }

    // --slurp preserves every response page; an empty page array is not proof of a complete query.
    const pages = JSON.parse(invokeGh(["api", "--paginate", "--slurp", "repos/" + repo + "/issues/" + number + "/dependencies/blocked_by"]));
    if (!Array.isArray(pages) || pages.length === 0 || !pages.every(Array.isArray)) {
      throw new Error("Dependency pagination is incomplete or malformed.");
    }
    const blockers = new Map();
    for (const page of pages) {
      for (const dependency of page) {
        const identity = dependencyIdentity(dependency);
        if (dependency.state === "open") blockers.set(identity.key, identity);
      }
    }
    const remaining = [...blockers.values()].sort((a, b) => {
      if (a.repository !== b.repository) return a.repository < b.repository ? -1 : 1;
      return a.number - b.number;
    });
    if (remaining.length > 0) {
      error("BLOCKED #" + number + ": open native dependencies "
        + remaining.map((value) => value.key).join(", ")
        + ". The ready-for-agent label does not override dependencies.");
      return 2;
    }
    output("DEPENDENCIES_CLEAR #" + number + ": no open native GitHub dependencies (" + repo
      + "); other task-admission requirements are not evaluated.");
    return 0;
  } catch {
    // Missing or contradictory identity/response data is not evidence of clearance.
    error("UNVERIFIED #" + number + ": unable to verify live GitHub issue/dependency state; check gh authentication and the native dependency API.");
    return 3;
  }
}

function dependencyIdentity(dependency) {
  if (!dependency || typeof dependency !== "object" || Array.isArray(dependency)
      || !Number.isSafeInteger(dependency.number) || dependency.number <= 0
      || !["open", "closed"].includes(dependency.state)
      || !dependency.repository || typeof dependency.repository !== "object"
      || Array.isArray(dependency.repository)
      || typeof dependency.repository.full_name !== "string"
      || !REPO_PATTERN.test(dependency.repository.full_name)
      || typeof dependency.repository_url !== "string"
      || typeof dependency.url !== "string") {
    throw new Error("Dependency identity or state is incomplete.");
  }
  const repository = dependency.repository.full_name.toLowerCase();
  const repositoryUrl = new URL(dependency.repository_url);
  const issueUrl = new URL(dependency.url);
  if (repositoryUrl.protocol !== "https:" || issueUrl.protocol !== "https:"
      || repositoryUrl.username || repositoryUrl.password || repositoryUrl.search || repositoryUrl.hash
      || issueUrl.username || issueUrl.password || issueUrl.search || issueUrl.hash
      || repositoryUrl.origin !== issueUrl.origin
      || repositoryUrl.pathname.toLowerCase() !== "/repos/" + repository
      || issueUrl.pathname.toLowerCase() !== repositoryUrl.pathname.toLowerCase() + "/issues/" + dependency.number) {
    throw new Error("Conflicting GitHub dependency repository or issue identity.");
  }
  return { repository, number: dependency.number, key: repository + "#" + dependency.number };
}

function runGh(args) {
  return execFileSync("gh", args, {
    encoding: "utf8",
    timeout: GH_TIMEOUT_MS,
    maxBuffer: MAX_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, GH_PROMPT_DISABLED: "1" }
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = checkIssueReadiness(process.argv.slice(2));
}
