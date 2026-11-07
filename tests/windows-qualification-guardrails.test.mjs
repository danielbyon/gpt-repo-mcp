import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, URL } from "node:url";
import yaml from "js-yaml";
import { describe, expect, test } from "vitest";
import { inspectQualificationWorkflow } from "../scripts/check-windows-qualification.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const load = () => yaml.load(readFileSync(join(root, ".github/workflows/ci.yml"), "utf8"));
const inspect = (workflow) => inspectQualificationWorkflow(workflow);

function windowsStep(workflow, name) {
  const step = workflow.jobs["windows-test"].steps.find((item) => item.name === name);
  if (!step) throw new Error("Missing fixture step " + name);
  return step;
}

describe("Windows qualification scope guard", () => {
  test("accepts the checked-in Linux and scoped Windows matrix", () => {
    expect(inspect(load())).toEqual([]);
  });

  test("rejects loss of a required Windows suite", () => {
    const workflow = load();
    windowsStep(workflow, "Windows process supervision").run =
      "npm test -- tests/windows-process-host.test.ts";
    expect(inspect(workflow)).toContain(
      "Windows process supervision must execute tests/windows-process-host-protocol.test.ts");
  });

  test("rejects a filtered selection that no longer runs shell-shim coverage", () => {
    const workflow = load();
    windowsStep(workflow, "Windows exact Node runtime and shell-free npm dispatch").run =
      "npm test -- tests/validation-service.test.ts -t \"canonical make verify\"";
    expect(inspect(workflow).some((message) =>
      message.includes("does not select mandatory regression: does not resolve Windows command shim %s"))).toBe(true);
  });

  test("rejects a required test that was renamed without updating the scope", () => {
    const workflow = load();
    const findings = inspectQualificationWorkflow(workflow, (path) =>
      path === "tests/package-hygiene.test.ts" ? "test('renamed', () => {});" :
        readFileSync(join(root, path), "utf8"));
    expect(findings.some((message) => message.includes("is missing mandatory regression:"))).toBe(true);
  });

  test("rejects optional Windows gates and loss of the full Linux suite", () => {
    const workflow = load();
    windowsStep(workflow, "Windows process supervision")["continue-on-error"] = true;
    workflow.jobs.test.steps.find((step) => step.name === "Test").run =
      "npm test -- tests/process-exec.test.ts";
    const findings = inspect(workflow);
    expect(findings.some((message) => message.includes("allowed to fail"))).toBe(true);
    expect(findings.some((message) => message.includes("unfiltered full suite"))).toBe(true);
  });

  test("rejects removal of the guardrail execution step", () => {
    const workflow = load();
    windowsStep(workflow, "Validation security and CI coverage guardrails").run = "npm run lint";
    expect(inspect(workflow)).toContain(
      "Windows CI must run required non-optional step: Validation security and CI coverage guardrails");
  });
});
