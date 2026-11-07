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

  test("rejects a conditionally skipped Windows lint stage", () => {
    const workflow = load();
    windowsStep(workflow, "Lint").if = "false";
    expect(inspect(workflow).some((f) => f.includes("conditional or optional"))).toBe(true);
  });

  test("rejects a missing Linux typecheck", () => {
    const workflow = load();
    workflow.jobs.test.steps.find((s) => s.name === "Typecheck").run = "echo skipped";
    expect(inspect(workflow).some((f) => f.includes("must execute required command"))).toBe(true);
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
    "-t Windows|echo skipped",
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

  test("rejects an exclusive test that would prevent unrelated mandatory cases from running", () => {
    const workflow = load();
    const findings = inspectQualificationWorkflow(workflow, (path) =>
      path === "tests/package-hygiene.test.ts"
        ? "test.only('extra', () => {}); test('pins the repository package inventory to its runtime files', () => {});"
        : readFileSync(join(root, path), "utf8"));
    expect(findings.some((f) => f.includes("Could not parse mandatory Vitest declarations"))).toBe(true);
  });

  test.each([
    ["disabled plain suite", "describe.skip('suite', () => { test('required', () => {}); });"],
    ["todo suite", "describe.todo('suite', () => { test('required', () => {}); });"],
    ["disabled skipIf suite", "describe.skipIf(true)('suite', () => { test('required', () => {}); });"],
    ["disabled runIf suite", "describe.runIf(false)('suite', () => { test('required', () => {}); });"],
    ["nested disabled suite", "describe('outer', () => { describe.skipIf(true)('inner', () => { test('required', () => {}); }); });"],
    ["unresolved suite predicate", "describe.skipIf(isDisabled)('suite', () => { test('required', () => {}); });"],
    ["false conditional", "if (false) { test('required', () => {}); }"],
    ["non-Windows conditional", "if (process.platform !== 'win32') { test('required', () => {}); }"],
    ["unknown conditional", "if (runtimeFlag) { test('required', () => {}); }"]
  ])("52-E does not count a required regression in %s", (_name, source) => {
    expect(collectWindowsTestTitles("fixture.ts", source))
      .toEqual([{ title: "required", enabled: false }]);
  });

  test.each([
    ["Windows-only skipIf", "describe.skipIf(process.platform !== 'win32')('suite', () => { test('required', () => {}); });"],
    ["Windows-only runIf", "describe.runIf(process.platform === 'win32')('suite', () => { test('required', () => {}); });"],
    ["enabled skipIf", "describe.skipIf(false)('suite', () => { test('required', () => {}); });"],
    ["enabled runIf", "describe.runIf(true)('suite', () => { test('required', () => {}); });"],
    ["nested enabled suite", "describe('outer', () => { describe.runIf(true)('inner', () => { test('required', () => {}); }); });"],
    ["true conditional", "if (true) { test('required', () => {}); }"],
    ["Windows branch", "if (process.platform === 'win32') { test('required', () => {}); }"],
    ["Windows else", "if (process.platform !== 'win32') {} else { test('required', () => {}); }"]
  ])("52-E permits a proven Windows-executable regression in %s", (_name, source) => {
    expect(collectWindowsTestTitles("fixture.ts", source))
      .toEqual([{ title: "required", enabled: true }]);
  });

  test("52-E tracks both statically decidable branches", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "if (false) { test('off', () => {}); } else { test('on', () => {}); }"))
      .toEqual([{ title: "off", enabled: false }, { title: "on", enabled: true }]);
  });

  test("52-E rejects a mandatory regression hidden in a disabled parent suite", () => {
    const workflow = load();
    const findings = inspectQualificationWorkflow(workflow, (path) =>
      path === "tests/package-hygiene.test.ts"
        ? "describe.skipIf(true)('disabled', () => { test('pins the repository package inventory to its runtime files', () => {}); });"
        : readFileSync(join(root, path), "utf8"));
    expect(findings.some((f) => f.includes("missing or disabling mandatory regression"))).toBe(true);
  });

  test.each([
    ["test.only", "test.only('extra', () => {});"],
    ["test bracket", "test['only']('extra', () => {});"],
    ["it bracket", "it[\"only\"]('extra', () => {});"],
    ["describe bracket", "describe['only']('suite', () => {});"],
    ["dynamic test selector", "test[modifier]('extra', () => {});"],
    ["dynamic describe selector", "describe[modifier]('suite', () => {});"]
  ])("52-F rejects exclusive or unverifiable Vitest execution: %s", (_name, source) => {
    expect(() => collectWindowsTestTitles("fixture.ts", source +
      " test('required', () => {});"))
      .toThrow(/Exclusive or dynamically selected Vitest/);
  });

  test("52-F accepts unrelated element access without exclusive Vitest selection", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "const flags = { ['only']: false }; test('required', () => {});"))
      .toEqual([{ title: "required", enabled: true }]);
  });

  test("52-F rejects bracket-exclusive tests at the workflow evidence boundary", () => {
    const workflow = load();
    const findings = inspectQualificationWorkflow(workflow, (path) =>
      path === "tests/package-hygiene.test.ts"
        ? "test['only']('extra', () => {}); test('pins the repository package inventory to its runtime files', () => {});"
        : readFileSync(join(root, path), "utf8"));
    expect(findings.some((f) => f.includes("Could not parse mandatory Vitest declarations"))).toBe(true);
  });


  test.each([
    ["unused function", "function unused() { test('required', () => {}); }"],
    ["uninvoked closure", "const deferred = () => { test('required', () => {}); };"],
    ["deferred timeout callback", "setTimeout(() => { test('required', () => {}); }, 0);"],
    ["promise callback", "Promise.resolve().then(() => test('required', () => {}));"],
    ["uninvoked IIFE-like closure", "(() => { test('required', () => {}); });"],
    ["nested unused suite callback", "describe('suite', () => { function later() { test('required', () => {}); } });"],
    ["uninvoked nested closure", "describe('suite', () => { const later = () => test('required', () => {}); });"],
    ["deferred nested callback", "describe('suite', () => { setTimeout(() => test('required', () => {}), 0); });"]
  ])("52-H excludes mandatory text in %s", (_name, code) => {
    expect(collectWindowsTestTitles("fixture.ts", code)).toEqual([]);
  });

  test.each([
    ["top-level registration", "test('required', () => {});"],
    ["enabled describe callback", "describe('suite', () => { test('required', () => {}); });"],
    ["nested enabled describe", "describe('outer', () => { describe('inner', () => { test('required', () => {}); }); });"],
    ["Windows-only describe", "describe.skipIf(process.platform !== 'win32')('suite', () => { test('required', () => {}); });"],
    ["Windows conditional", "if (process.platform === 'win32') { test('required', () => {}); }"],
    ["table-driven test", "test.each(['required'])('%s', () => {});"]
  ])("52-H retains proven registration in %s", (_name, code) => {
    expect(collectWindowsTestTitles("fixture.ts", code)).toEqual([
      { title: "required", enabled: true }
    ]);
  });

  test.each([
    ["unused function", "function unused() { test('pins the repository package inventory to its runtime files', () => {}); }"],
    ["deferred callback", "setTimeout(() => test('pins the repository package inventory to its runtime files', () => {}), 0);"],
    ["unused closure", "const later = () => test('pins the repository package inventory to its runtime files', () => {});"],
    ["unused describe callback", "describe('outer', () => { const later = () => test('pins the repository package inventory to its runtime files', () => {}); });"]
  ])("52-H rejects missing mandatory Windows coverage inside %s", (_name, code) => {
    const workflow = load();
    const findings = inspectQualificationWorkflow(workflow, (path) =>
      path === "tests/package-hygiene.test.ts" ? code :
        readFileSync(join(root, path), "utf8"));
    expect(findings.some((item) => item.includes("missing or disabling mandatory regression"))).toBe(true);
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
      message.includes("does not select mandatory regression: does not resolve Windows command shim make.cmd"))).toBe(true);
  });

  test("rejects a required test that was renamed without updating the scope", () => {
    const workflow = load();
    const findings = inspectQualificationWorkflow(workflow, (path) =>
      path === "tests/package-hygiene.test.ts" ? "test('renamed', () => {});" :
        readFileSync(join(root, path), "utf8"));
    expect(findings.some((message) => message.includes("is missing or disabling mandatory regression:"))).toBe(true);
  });

  test("rejects optional Windows gates and loss of the full Linux suite", () => {
    const workflow = load();
    windowsStep(workflow, "Windows process supervision")["continue-on-error"] = true;
    workflow.jobs.test.steps.find((step) => step.name === "Test").run =
      "npm test -- tests/process-exec.test.ts";
    const findings = inspect(workflow);
    expect(findings.some((message) => message.includes("conditional or optional"))).toBe(true);
    expect(findings.some((message) => message.includes("unfiltered full suite"))).toBe(true);
  });

  test("rejects removal of the guardrail execution step", () => {
    const workflow = load();
    windowsStep(workflow, "Validation security and CI coverage guardrails").run = "npm run lint";
    expect(inspect(workflow)).toContain(
      "Windows must run mandatory validation guardrails");
  });
});
