#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import process from "node:process";

const MAX_BYTES = 1024 * 1024;
const GH_TIMEOUT_MS = 15_000;

function main(args) {
  if (args.length !== 3 || !/^[1-9]\d{0,8}$/.test(args[0] ?? "")
      || args[1] !== "--repo" || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(args[2] ?? "")) {
    globalThis.console.error("UNVERIFIED: usage: node scripts/check-issue-readiness.mjs <issue-number> --repo <owner/repo>");
    return 3;
  }
  const number = Number(args[0]);
  const repo = args[2];

  try {
    const issue = fetchJson(["issue", "view", String(number), "--repo", repo, "--json", "number,title,state,labels"]);
    if (!issue || typeof issue !== "object" || Array.isArray(issue)
        || issue.number !== number || !["OPEN", "CLOSED"].includes(issue.state)) {
      throw new Error("Issue identity or state is unavailable.");
    }
    if (issue.state === "CLOSED") {
      globalThis.console.error("BLOCKED #" + number + ": the issue is closed.");
      return 2;
    }

    // --slurp preserves all response pages. The current GitHub API returns
    // only open blockers, but validate state rather than trusting that filter.
    const pages = fetchJson(["api", "--paginate", "--slurp", "repos/" + repo + "/issues/" + number + "/dependencies/blocked_by"]);
    if (!Array.isArray(pages) || pages.length === 0 || !pages.every(Array.isArray)) {
      throw new Error("Dependency pagination is incomplete or malformed.");
    }
    const blockers = [];
    for (const page of pages) {
      for (const dependency of page) {
        if (!dependency || typeof dependency !== "object" || Array.isArray(dependency)
            || !Number.isSafeInteger(dependency.number) || dependency.number <= 0
            || !["open", "closed"].includes(dependency.state)) {
          throw new Error("Dependency record is incomplete or malformed.");
        }
        if (dependency.state === "open") blockers.push(dependency.number);
      }
    }
    const remaining = [...new Set(blockers)].sort((a, b) => a - b);
    if (remaining.length > 0) {
      globalThis.console.error("BLOCKED #" + number + ": open native dependencies "
        + remaining.map((value) => "#" + value).join(", ")
        + ". The ready-for-agent label does not override dependencies.");
      return 2;
    }
    globalThis.console.log("READY #" + number + ": open issue with no open GitHub dependencies (" + repo + ").");
    return 0;
  } catch {
    // No fallback to stale labels or cached issue bodies: inability to verify
    // live GitHub dependencies means the task cannot be admitted.
    globalThis.console.error("UNVERIFIED #" + number + ": unable to verify live GitHub issue/dependency state; check gh authentication and the native dependency API.");
    return 3;
  }
}

function fetchJson(args) {
  const text = execFileSync("gh", args, {
    encoding: "utf8",
    timeout: GH_TIMEOUT_MS,
    maxBuffer: MAX_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, GH_PROMPT_DISABLED: "1" }
  });
  return JSON.parse(text);
}

process.exitCode = main(process.argv.slice(2));
