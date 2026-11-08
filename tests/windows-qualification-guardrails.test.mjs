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
    '--testNamePattern="["',
    '-t "$(Write-Output required)"',
    '-t "$env:REQUIRED"',
    '-t $env:REQUIRED',
    '-t $PID',
    '-t "$:REQUIRED|.*"',
    '-t "``$env:REQUIRED"',
    '-t "${REQUIRED}"',
    '-t "^(?:$é|REQUIRED)$"',
    "-t ('required'.Substring(0,0)+'nomatch')"
  ])("rejects an unknown or ambiguous selector: %s", (flag) => {
    const workflow = load();
    windowsStep(workflow, "Windows exact Node runtime and shell-free npm dispatch").run =
      "npm test -- tests/validation-service.test.ts " + flag;
    expect(inspect(workflow).some((f) => f.includes("unaudited Vitest command"))).toBe(true);
  });

  test("accepts a double-quoted regex selector with a literal dollar anchor", () => {
    const workflow = load();
    windowsStep(workflow, "Windows helper package hygiene").run =
      'npm test -- tests/package-hygiene.test.ts -t "^(pins the repository package inventory to its runtime files|requires the Windows process host only for Windows package builds|checks the parent route before treating an absent Windows host as optional)$"';
    expect(inspect(workflow)).toEqual([]);
  });

  test("accepts a double-quoted selector with a PowerShell-escaped dollar", () => {
    const workflow = load();
    windowsStep(workflow, "Windows helper package hygiene").run =
      'npm test -- tests/package-hygiene.test.ts -t "`$env:REQUIRED|^(pins the repository package inventory to its runtime files|requires the Windows process host only for Windows package builds|checks the parent route before treating an absent Windows host as optional)$"';
    expect(inspect(workflow)).toEqual([]);
  });

  test("accepts a literal dollar before punctuation in a double-quoted selector", () => {
    const workflow = load();
    windowsStep(workflow, "Windows helper package hygiene").run =
      'npm test -- tests/package-hygiene.test.ts -t "$!REQUIRED|^(pins the repository package inventory to its runtime files|requires the Windows process host only for Windows package builds|checks the parent route before treating an absent Windows host as optional)$"';
    expect(inspect(workflow)).toEqual([]);
  });

  test("preserves doubled single quotes inside a selector", () => {
    const workflow = load();
    windowsStep(workflow, "Windows helper package hygiene").run =
      "npm test -- tests/package-hygiene.test.ts -t 'pins the repository package inventory to its runtime files|requires the Windows process host only for Windows package builds|checks the parent route before treating an absent Windows host as optional|it''s' --reporter=verbose";
    expect(inspect(workflow)).toEqual([]);
  });

  test("rejects a trailing doubled single quote that changes the selector", () => {
    const workflow = load();
    windowsStep(workflow, "Windows helper package hygiene").run =
      "npm test -- tests/package-hygiene.test.ts -t '^(pins the repository package inventory to its runtime files|requires the Windows process host only for Windows package builds|checks the parent route before treating an absent Windows host as optional)$''' --reporter=verbose";
    expect(inspect(workflow).some((finding) =>
      finding.includes("does not select mandatory regression"))).toBe(true);
  });

  test("rejects filtering a required file without audited mandatory cases", () => {
    const workflow = load();
    const step = windowsStep(workflow, "Windows process supervision");
    step.run = step.run.replace(
      "tests/windows-process-host.test.ts",
      "tests/windows-process-host.test.ts -t no-such-test"
    );
    expect(inspect(workflow).some((finding) =>
      finding.includes("cannot be filtered without mandatory case coverage"))).toBe(true);
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
  ])("does not count a required regression in %s", (_name, source) => {
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
    ["negated Windows branch", "if (!(process.platform !== 'win32')) { test('required', () => {}); }"],
    ["Windows else", "if (process.platform !== 'win32') {} else { test('required', () => {}); }"]
  ])("permits a proven Windows-executable regression in %s", (_name, source) => {
    expect(collectWindowsTestTitles("fixture.ts", source))
      .toEqual([{ title: "required", enabled: true }]);
  });

  test("tracks both statically decidable branches", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "if (false) { test('off', () => {}); } else { test('on', () => {}); }"))
      .toEqual([{ title: "off", enabled: false }, { title: "on", enabled: true }]);
  });

  test.each([
    ["shadowed process parameter", "describe('suite', (process) => { if (process.platform === 'win32') { test('required', () => {}); } });"],
    ["shadowed process local", "describe('suite', () => { const process = { platform: 'win32' }; if (process.platform === 'win32') { test('required', () => {}); } });"]
  ])("treats %s as an unknown Windows predicate", (_name, source) => {
    expect(collectWindowsTestTitles("fixture.ts", source))
      .toEqual([{ title: "required", enabled: false }]);
  });

  test("accepts the verified node:process binding", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "import process from 'node:process'; if (process.platform === 'win32') { test('required', () => {}); }"))
      .toEqual([{ title: "required", enabled: true }]);
  });

  test("rejects a mandatory regression hidden in a disabled parent suite", () => {
    const workflow = load();
    const findings = inspectQualificationWorkflow(workflow, (path) =>
      path === "tests/package-hygiene.test.ts"
        ? "describe.skipIf(true)('disabled', () => { test('pins the repository package inventory to its runtime files', () => {}); });"
        : readFileSync(join(root, path), "utf8"));
    expect(findings.some((f) => f.includes("missing or disabling mandatory regression"))).toBe(true);
  });

  test.each([
    ["test.only", "test.only('extra', () => {});"],
    ["Vitest namespace test.only", "import * as vi from 'vitest'; vi.test.only('extra', () => {});"],
    ["test bracket", "test['only']('extra', () => {});"],
    ["it bracket", "it[\"only\"]('extra', () => {});"],
    ["describe bracket", "describe['only']('suite', () => {});"],
    ["dynamic test selector", "test[modifier]('extra', () => {});"],
    ["dynamic describe selector", "describe[modifier]('suite', () => {});"]
  ])("rejects exclusive or unverifiable Vitest execution: %s", (_name, source) => {
    expect(() => collectWindowsTestTitles("fixture.ts", source +
      " test('required', () => {});"))
      .toThrow(/Exclusive or dynamically selected Vitest/);
  });

  test.each([
    ["aliased test.only", "const register = test; register.only('extra', () => {});"],
    ["mutable alias assigned later", "let register; register = test; register.only('extra', () => {});"],
    ["nullish assignment alias", "let register; register ??= test; register.only('extra', () => {});"],
    ["logical OR assignment alias", "let register; register ||= test; register.only('extra', () => {});"],
    ["logical AND assignment alias", "let register = true; register &&= test; register.only('extra', () => {});"],
    ["aliased it.only", "const spec = it; spec.only('extra', () => {});"],
    ["aliased describe.only", "const suite = describe; suite.only('suite', () => {});"],
    ["aliased only property", "const register = test; const focused = register.only; focused('extra', () => {});"],
    ["destructured only", "const { only } = test; only('extra', () => {});"],
    ["deep destructured concurrent only", "const { concurrent: { only } } = test; only('extra', () => {});"],
    ["deep namespace destructured only", "import * as vi from 'vitest'; const { test: { only } } = vi; only('extra', () => {});"],
    ["destructured assignment only", "let focus; ({ only: focus } = test); focus('extra', () => {});"],
    ["deep destructured assignment only", "let only; ({ concurrent: { only } } = test); only('extra', () => {});"],
    ["renamed destructured only", "const register = test; const { only: focused } = register; focused('extra', () => {});"],
    ["computed destructured only", "const { ['only']: focused } = test; focused('extra', () => {});"],
    ["dynamic destructured selector", "const { [modifier]: focused } = test; focused('extra', () => {});"],
    ["destructured test rest", "const { ...runner } = test; runner.only('extra', () => {});"],
    ["Vitest namespace destructured test alias", "import * as vi from 'vitest'; const { test: register } = vi; register.only('extra', () => {});"],
    ["parameter destructured only default", "function focus({ only } = test) { only('extra', () => {}); } focus();"],
    ["parameter test alias default", "function focus(register = test) { register.only('extra', () => {}); } focus();"],
    ["binding-element test default", "const { register = test } = {}; register.only('extra', () => {});"],
    ["conditional test alias", "const register = condition ? test : fake; register.only('extra', () => {});"],
    ["conditional array test alias", "const [register] = condition ? [test] : [fake]; register.only('extra', () => {});"],
    ["nested object-property test alias", "const holder = { nested: { register: test } }; holder.nested.register.only('extra', () => {});"],
    ["property-assigned test alias", "const holder = {}; holder.register = test; holder.register.only('extra', () => {});"],
    ["property-assigned namespace runner", "import * as vi from 'vitest'; const holder = {}; holder.register = vi.test; holder.register.only('extra', () => {});"],
    ["bracket-assigned test alias", "const holder = {}; holder['register'] = test; holder.register.only('extra', () => {});"],
      ["member-target destructured test alias", "const holder = {}; ({ register: holder.register } = { register: test }); holder.register.only('extra', () => {});"],
      ["dynamic member-target destructured test alias", "const holder = {}; ({ register: holder[key] } = { register: test }); holder[key].only('extra', () => {});"],
      ["nested assignment default test alias", "let register; ({ outer: { register = test } = {} } = {}); register.only('extra', () => {});"],
      ["local function runner alias", "const makeRunner = () => test; makeRunner().only('extra', () => {});"],
      ["block-bodied runner factory", "const makeRunner = () => { return test; }; makeRunner().only('extra', () => {});"],
      ["spread namespace alias", "import * as vi from 'vitest'; const namespace = { ...vi }; namespace.test.only('extra', () => {});"],
    ["chained concurrent only", "test.concurrent.only('extra', () => {});"],
    ["decorated skipIf only", "test.skipIf(false).only('extra', () => {});"],
    ["decorated runIf only", "test.runIf(true).only('extra', () => {});"],
    ["chained sequential describe only", "describe.sequential.only('suite', () => {});"],
    ["angle-bracket asserted alias", "const register = <typeof test>test; register.only('extra', () => {});"],
    ["non-null asserted alias", "const register = test!; register.only('extra', () => {});"],
    ["object-destructured alias assignment", "let register; ({ register } = { register: test }); register.only('extra', () => {});"],
    ["identifier-backed object-destructured assignment", "const source = { register: test }; let register; ({ register } = source); register.only('extra', () => {});"],
    ["nested identifier-backed destructured assignment", "const source = { nested: { register: test } }; let register; ({ nested: { register } } = source); register.only('extra', () => {});"],
    ["array-destructured alias assignment", "let register; [register] = [test]; register.only('extra', () => {});"],
    ["object-destructured alias declaration", "const { runner: register } = { runner: test }; register.only('extra', () => {});"],
    ["array-destructured alias declaration", "const [register] = [test]; register.only('extra', () => {});"],
    ["namespace destructured alias assignment", "import * as vi from 'vitest'; let register; ({ test: register } = vi); register.only('extra', () => {});"],
    ["mutable namespace source assignment", "import * as vi from 'vitest'; const source = vi; let register; ({ test: register } = source); register.only('extra', () => {});"],
    ["nested destructured alias declaration", "import * as vi from 'vitest'; const { nested: { test: register } } = { nested: vi }; register.only('extra', () => {});"],
    ["nested namespace destructuring", "import * as vi from 'vitest'; const { wrapper: { module: namespace } } = { wrapper: { module: vi } }; namespace.test.only('extra', () => {});"],
    ["array namespace destructuring", "import * as vi from 'vitest'; const { wrapper: [namespace] } = { wrapper: [vi] }; namespace.test.only('extra', () => {});"],
    ["default namespace destructuring", "import * as vi from 'vitest'; const { module: namespace = vi } = {}; namespace.test.only('extra', () => {});"],
    ["namespace rest destructuring", "import * as vi from 'vitest'; const { helper, ...namespace } = vi; namespace.test.only('extra', () => {});"],
    ["nested namespace rest destructuring", "import * as vi from 'vitest'; const { wrapper: { helper, ...namespace } } = { wrapper: vi }; namespace.test.only('extra', () => {});"],
    ["array namespace rest destructuring", "import * as vi from 'vitest'; const [{ helper, ...namespace }] = [vi]; namespace.test.only('extra', () => {});"],
    ["nested destructured alias assignment", "import * as vi from 'vitest'; let register; ({ nested: { test: register } } = { nested: vi }); register.only('extra', () => {});"],
    ["mutable Vitest namespace alias", "import * as vi from 'vitest'; let namespace = vi; namespace.test.only('extra', () => {});"],
    ["object-property test alias", "const holder = { register: test }; holder.register.only('extra', () => {});"],
    ["comma test alias", "const register = (0, test); register.only('extra', () => {});"],
    ["mutable concurrent-only alias", "let register = test; register.concurrent.only('extra', () => {});"],
    ["destructured concurrent alias", "const { concurrent: register } = test; register.only('extra', () => {});"],
    ["mutable namespace destructuring", "import * as vi from 'vitest'; let namespace = vi; const { test: register } = namespace; register.only('extra', () => {});"],
    ["conditional namespace destructuring", "import * as vi from 'vitest'; const { test: register } = condition ? vi : fake; register.only('extra', () => {});"],
    ["namespace destructured parameter alias", "import * as vi from 'vitest'; function focus({ test: register } = vi) { register.only('extra', () => {}); } focus();"]
  ])("rejects exclusive selectors through %s", (_name, source) => {
    expect(() => collectWindowsTestTitles("fixture.ts", source))
      .toThrow(/Exclusive or dynamically selected Vitest/);
  });

  test("recognizes immutable aliases of test, it, and describe", () => {
    const source = [
      "const register = test;",
      "const spec = it;",
      "const suite = describe;",
      "register('top', () => {});",
      "spec('it alias', () => {});",
      "suite('suite alias', () => { register('nested', () => {}); });"
    ].join("\n");
    expect(collectWindowsTestTitles("fixture.ts", source)).toEqual([
      { title: "top", enabled: true },
      { title: "it alias", enabled: true },
      { title: "nested", enabled: true }
    ]);
  });

  test("recognizes an aliased Vitest import but leaves unresolved aliases unproven", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "import { test as register } from 'vitest'; register('required', () => {});"))
      .toEqual([{ title: "required", enabled: true }]);
    expect(collectWindowsTestTitles("fixture.ts",
      "const register = maybeTest; register('required', () => {});"))
      .toEqual([]);
  });

  test("does not treat a nested ordinary test property as a Vitest alias", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "const { nested: { test: register } } = { nested: { test: fakeRunner } }; " +
      "register.only('extra', () => {}); test('required', () => {});"))
      .toEqual([{ title: "required", enabled: true }]);
  });

  test("does not treat an assigned ordinary object as a Vitest alias", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "const holder = {}; holder.register = { only() {} }; " +
      "holder.register.only('extra', () => {}); test('required', () => {});"))
      .toEqual([{ title: "required", enabled: true }]);
  });

  test("terminates local runner-return cycles without inventing a runner", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "const makeRunner = () => makeRunner(); makeRunner().only('extra', () => {}); " +
      "test('required', () => {});"))
      .toEqual([{ title: "required", enabled: true }]);
  });

  test("retains legitimate concurrent and sequential registration", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "test.concurrent('concurrent', () => {}); test.sequential('sequential', () => {});"))
      .toEqual([
        { title: "concurrent", enabled: true },
        { title: "sequential", enabled: true }
      ]);
  });

  test("accepts unrelated element access without exclusive Vitest selection", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "const flags = { ['only']: false }; test('required', () => {});"))
      .toEqual([{ title: "required", enabled: true }]);
  });

  test("rejects an exclusive Vitest selector through a mutable alias", () => {
    expect(() => collectWindowsTestTitles("fixture.ts",
      "let register = test; register.only('extra', () => {}); test('required', () => {});"))
      .toThrow(/Exclusive or dynamically selected Vitest/);
  });

  test("rejects bracket-exclusive tests at the workflow evidence boundary", () => {
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
  ])("excludes mandatory text in %s", (_name, code) => {
    expect(collectWindowsTestTitles("fixture.ts", code)).toEqual([]);
  });

  test.each([
    ["top-level registration", "test('required', () => {});"],
    ["enabled describe callback", "describe('suite', () => { test('required', () => {}); });"],
    ["nested enabled describe", "describe('outer', () => { describe('inner', () => { test('required', () => {}); }); });"],
    ["Windows-only describe", "describe.skipIf(process.platform !== 'win32')('suite', () => { test('required', () => {}); });"],
    ["Windows conditional", "if (process.platform === 'win32') { test('required', () => {}); }"],
    ["table-driven test", "test.each(['required'])('%s', () => {});"]
  ])("retains proven registration in %s", (_name, code) => {
    expect(collectWindowsTestTitles("fixture.ts", code)).toEqual([
      { title: "required", enabled: true }
    ]);
  });

  test.each([
    ["unused function", "function unused() { test('pins the repository package inventory to its runtime files', () => {}); }"],
    ["deferred callback", "setTimeout(() => test('pins the repository package inventory to its runtime files', () => {}), 0);"],
    ["unused closure", "const later = () => test('pins the repository package inventory to its runtime files', () => {});"],
    ["unused describe callback", "describe('outer', () => { const later = () => test('pins the repository package inventory to its runtime files', () => {}); });"]
  ])("rejects missing mandatory Windows coverage inside %s", (_name, code) => {
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
