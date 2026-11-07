import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const ROOT = resolve(fileURLToPath(new URL("../", import.meta.url)));

const REQUIREMENTS = Object.freeze([
  { step: "Windows package archive inventory regression",
    files: ["tests/package-archive-verification.test.ts"] },
  { step: "Windows exact Node runtime and shell-free npm dispatch",
    files: ["tests/node-runtime-resolver.test.ts", "tests/validation-service.test.ts"] },
  { step: "Windows process supervision",
    files: ["tests/windows-process-host.test.ts", "tests/windows-process-host-protocol.test.ts", "tests/process-exec.test.ts"] },
  { step: "HTTP, MCP, and server boundary behavior",
    files: ["tests/http-request-cancellation.test.ts", "tests/tool-handler-validation.test.ts", "tests/server-network-boundary.test.ts"] },
  { step: "Validation cancellation and receipt gates",
    files: ["tests/validation-service.test.ts"] },
  { step: "Contract tests",
    files: ["tests/tool-contracts.test.ts", "tests/mcp-contract.test.ts"] },
  { step: "Windows helper package hygiene",
    files: ["tests/package-hygiene.test.ts"] }
]);

const FILTERED_CASES = Object.freeze([
  {
    step: "Windows exact Node runtime and shell-free npm dispatch",
    file: "tests/validation-service.test.ts",
    titles: [
      "runs Windows npm through the exact running Node and bundled npm CLI",
      "does not start Windows npm validation when System32/cmd.exe is unavailable",
      "resolves the configured Windows make profile to its native executable",
      "resolves the configured Windows just profile to its native executable",
      "does not resolve Windows command shim %s",
      "does not select a repository-controlled make.exe from the worktree"
    ]
  },
  {
    step: "Validation cancellation and receipt gates",
    file: "tests/validation-service.test.ts",
    titles: [
      "cancels an npm validation tree without writing a receipt",
      "preserves the latest receipt when Windows cleanup is unconfirmed",
      "does not publish a validation receipt after process supervision fails",
      "cancellation immediately before commit admission preserves latest",
      "allows overlapping validations and preserves each receipt"
    ]
  },
  {
    step: "Windows helper package hygiene",
    file: "tests/package-hygiene.test.ts",
    titles: [
      "pins the repository package inventory to its runtime files",
      "requires the Windows process host only for Windows package builds",
      "checks the parent route before treating an absent Windows host as optional"
    ]
  }
]);

function commands(run) {
  return String(run || "").split("\n").map((line) => line.trim())
    .filter((line) => /^npm test --\s/.test(line));
}

function filterForCommand(line) {
  const match = line.match(/(?:^|\s)-t\s+(?:"([^"]+)"|'([^']+)')/);
  return match ? match[1] || match[2] : undefined;
}

function hasTestFile(line, path) {
  return line.split(/\s+/).includes(path);
}

/**
 * Checks the checked-in scope of Windows CI: a green filtered Vitest command
 * is insufficient when the filter silently stops selecting required tests.
 * POSIX-only process-exec-supervision tests belong to Linux's unfiltered suite.
 */
export function inspectQualificationWorkflow(workflow, readTest = (path) =>
  readFileSync(join(ROOT, path), "utf8")) {
  const findings = [];
  const jobs = workflow?.jobs;
  const winSteps = jobs?.["windows-test"]?.steps;
  const linuxSteps = jobs?.test?.steps;
  if (!Array.isArray(winSteps) || !Array.isArray(linuxSteps)) {
    return ["CI must define Linux test and Windows cancellation qualification jobs."];
  }

  const byName = new Map(winSteps.map((step) => [step.name, step]));
  for (const { step: name, files } of REQUIREMENTS) {
    const step = byName.get(name);
    if (!step || step["continue-on-error"]) {
      findings.push("Required Windows step missing or allowed to fail: " + name);
      continue;
    }
    const lines = commands(step.run);
    for (const file of files) {
      if (!lines.some((line) => hasTestFile(line, file))) {
        findings.push(name + " must execute " + file);
      }
    }
  }

  if (!linuxSteps.some((step) => step.name === "Test" &&
      String(step.run || "").trim() === "npm test" && !step["continue-on-error"])) {
    findings.push("Linux CI must run the unfiltered full suite, including POSIX-only supervision tests.");
  }

  for (const scope of FILTERED_CASES) {
    const step = byName.get(scope.step);
    const line = commands(step?.run).find((command) => hasTestFile(command, scope.file));
    if (!line) continue;
    const selected = filterForCommand(line);
    if (!selected) {
      // Running the entire file is strictly broader than the required selection.
      continue;
    }
    let selector;
    try {
      selector = new RegExp(selected);
    } catch {
      findings.push(scope.step + " uses an invalid Vitest test-name filter.");
      continue;
    }
    let source;
    try {
      source = readTest(scope.file);
    } catch {
      findings.push("Required Windows test source unavailable: " + scope.file);
      continue;
    }
    for (const title of scope.titles) {
      if (!source.includes(JSON.stringify(title)) && !source.includes("'" + title + "'")) {
        findings.push(scope.file + " is missing mandatory regression: " + title);
      } else if (!selector.test(title)) {
        findings.push(scope.step + " does not select mandatory regression: " + title);
      }
    }
  }

  for (const [name, runner] of [
    ["Validation security and CI coverage guardrails", "npm run check:validation-guardrails"],
    ["Verify actual Windows npm package archive", "npm run verify:package-archive"]
  ]) {
    const step = byName.get(name);
    if (!step || String(step.run || "").trim() !== runner || step["continue-on-error"]) {
      findings.push("Windows CI must run required non-optional step: " + name);
    }
  }
  if (!linuxSteps.some((step) => step.name === "Validation security and CI coverage guardrails" &&
      String(step.run || "").trim() === "npm run check:validation-guardrails" &&
      !step["continue-on-error"])) {
    findings.push("Linux CI must execute validation guardrails.");
  }

  return findings;
}

export function inspectQualificationFile(path = join(ROOT, ".github", "workflows", "ci.yml")) {
  const workflow = yaml.load(readFileSync(path, "utf8"));
  return inspectQualificationWorkflow(workflow);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const findings = inspectQualificationFile();
    if (findings.length > 0) {
      for (const finding of findings) process.stderr.write(finding + "\n");
      process.exitCode = 1;
    } else {
      process.stdout.write("Windows qualification selector guard passed.\n");
    }
  } catch (error) {
    process.stderr.write("Windows qualification guard failed: " +
      (error instanceof Error ? error.message : String(error)) + "\n");
    process.exitCode = 1;
  }
}
