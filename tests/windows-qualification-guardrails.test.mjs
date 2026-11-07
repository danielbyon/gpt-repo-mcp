import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, URL } from "node:url";
import yaml from "js-yaml";
import { describe, expect, test } from "vitest";
import { collectWindowsTestTitles, inspectQualificationWorkflow } from "../scripts/check-windows-qualification.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const load = () => yaml.load(readFileSync(join(root, ".github/workflows/ci.yml"), "utf8"));
const inspect = (workflow) => inspectQualificationWorkflow(workflow);

function windowsStep(workflow, name) {
  const step = workflow.jobs["windows-test"].steps.find((item) => item.name === name);
  if (!step) throw new Error("Missing fixture step " + name);
  return step;
}

describe("Windows qualification scope guard", () => {

  test.each(["if", "continue-on-error"])("rejects a disabled Windows job via %s", (key) => {
    const workflow = load();
    workflow.jobs["windows-test"][key] = key === "if" ? "false" : true;
    expect(inspect(workflow).some((f) => f.includes("conditional, optional"))).toBe(true);
  });

  test.each(["if", "continue-on-error"])("rejects a disabled Windows step via %s", (key) => {
    const workflow = load();
    windowsStep(workflow, "Windows process supervision")[key] = key === "if" ? false : true;
    expect(inspect(workflow).some((f) => f.includes("conditional or optional"))).toBe(true);
  });

  test("rejects conditional Linux qualification", () => {
    const workflow = load();
    workflow.jobs.test.if = false;
    expect(inspect(workflow).some((f) => f.includes("conditional, optional"))).toBe(true);
  });

  test.each([
    '-t "canonical make verify"',
    '--testNamePattern="canonical make verify"',
    '-t="canonical make verify"',
    '--testNamePattern "canonical make verify"'
  ])("rejects an incorrect supported selector: %s", (flag) => {
    const workflow = load();
    windowsStep(workflow, "Windows exact Node runtime and shell-free npm dispatch").run =
      "npm test -- tests/validation-service.test.ts " + flag;
    expect(inspect(workflow).some((f) => f.includes("does not select mandatory regression"))).toBe(true);
  });

  test.each([
    "--passWithNoTests",
    '--exclude tests/validation-service.test.ts',
    '-t "Windows npm" --testNamePattern="Windows command shim"',
    '--testNamePattern="["'
  ])("rejects an unknown or ambiguous selector: %s", (flag) => {
    const workflow = load();
    windowsStep(workflow, "Windows exact Node runtime and shell-free npm dispatch").run =
      "npm test -- tests/validation-service.test.ts " + flag;
    expect(inspect(workflow).some((f) => f.includes("unaudited Vitest command"))).toBe(true);
  });

  test("requires named cases even when the whole test file is selected", () => {
    const workflow = load();
    windowsStep(workflow, "Windows helper package hygiene").run =
      "npm test -- tests/package-hygiene.test.ts";
    const problems = inspectQualificationWorkflow(workflow, (path) =>
      path === "tests/package-hygiene.test.ts" ? "test('renamed', () => {});" :
        readFileSync(join(root, path), "utf8"));
    expect(problems.some((p) => p.includes("missing or disabling mandatory regression"))).toBe(true);
  });

  test.each([
    "// test('pins the repository package inventory to its runtime files', () => {});",
    "test.skip('pins the repository package inventory to its runtime files', () => {});",
    "test.skipIf(process.platform === 'win32')('pins the repository package inventory to its runtime files', () => {});"
  ])("does not accept comments or disabled mandatory tests: %s", (testSource) => {
    const workflow = load();
    const problems = inspectQualificationWorkflow(workflow, (path) =>
      path === "tests/package-hygiene.test.ts" ? testSource :
        readFileSync(join(root, path), "utf8"));
    expect(problems.some((p) => p.includes("missing or disabling mandatory regression"))).toBe(true);
  });

  test("expands parameterized test.each native executable cases", () => {
    const declarations = collectWindowsTestTitles("fixture.ts",
      "test.each([['make','make.exe'],['just','just.exe']])('Windows %s runner', () => {});");
    expect(declarations.map((x) => x.title)).toEqual(["Windows make runner", "Windows just runner"]);
  });

  test("preserves explicitly Windows-enabled skipIf declarations", () => {
    const declarations = collectWindowsTestTitles("fixture.ts",
      "test.skipIf(process.platform !== 'win32')('on Windows', () => {});" +
      "test.skipIf(process.platform === 'win32')('off Windows', () => {});");
    expect(declarations).toEqual([
      { title: "on Windows", enabled: true }, { title: "off Windows", enabled: false }
    ]);
  });

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
