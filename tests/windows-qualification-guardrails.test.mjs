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

// Populate the parser cache before Vitest applies the per-test timeout. The
// first repository inspection parses several large test files.
inspect(load());

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
    ["skip option", "test('required', { skip: true }, () => {});"],
    ["todo option", "test('required', { todo: true }, () => {});"],
    ["unsupported option", "test('required', { enabled: false }, () => {});"],
    ["disabled suite options", "describe('suite', { skip: true }, () => { test('required', () => {}); });"],
    ["opaque test options", "const options = { skip: true }; test('required', options, () => {});"],
    ["options without a callback", "const options = { skip: true }; test('required', options);"],
    ["dynamic test options", "test('required', { [optionName]: true }, () => {});"]
  ])("does not count required regression with %s", (_name, source) => {
    expect(collectWindowsTestTitles("fixture.ts", source))
      .toEqual([{ title: "required", enabled: false }]);
  });

  test.each([
    ["disabled fields", "test('required', { skip: false, todo: false }, () => {});"],
    ["supported fields", "test('required', { only: false, timeout: 1000 }, () => {});"],
    ["suite fields", "describe('suite', { skip: false }, () => { test('required', () => {}); });"]
  ])("counts required regression with provably enabled %s", (_name, source) => {
    expect(collectWindowsTestTitles("fixture.ts", source))
      .toEqual([{ title: "required", enabled: true }]);
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
  test("uses the runtime global after an ambient process declaration", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "declare const process: any; if (process.platform === 'win32') { test('required', () => {}); }"))
      .toEqual([{ title: "required", enabled: true }]);
    expect(collectWindowsTestTitles("fixture.ts",
      "declare var process: any; if (process.platform === 'win32') { test('required', () => {}); }"))
      .toEqual([{ title: "required", enabled: true }]);
  });
  test("does not trust an initializerless process declaration", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "let process: any; if (process.platform === 'win32') { test('required', () => {}); }"))
      .toEqual([{ title: "required", enabled: false }]);
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
      ["Object.assign namespace copy", "import * as vi from 'vitest'; const namespace = {}; Object.assign(namespace, vi); namespace.test.only('extra', () => {});"],
      ["aliased Object.assign namespace copy", "import * as vi from 'vitest'; const assign = Object.assign; const namespace = {}; assign(namespace, vi); namespace.test.only('extra', () => {});"],
      ["returned Object.assign namespace copy", "import * as vi from 'vitest'; const namespace = Object.assign({}, vi); namespace.test.only('extra', () => {});"],
      ["spread Object.assign namespace copy", "import * as vi from 'vitest'; const namespace = {}; Object.assign(namespace, ...[vi]); namespace.test.only('extra', () => {});"],
      ["dynamic Vitest import", "const { test: dynamicTest } = await import('vitest'); dynamicTest.only('extra', () => {});"],
      ["destructured runner reassignment", "let { register } = {} as { register?: typeof test }; register = test; register.only('extra', () => {});"],
      ["parameter runner reassignment", "function focus(register: any) { register = test; register.only('extra', () => {}); } focus({});"],
      ["destructured Object.assign alias", "const { assign: copy } = Object; const namespace: any = {}; copy(namespace, { test }); namespace.test.only('extra', () => {});"],
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

test.each([
  ["Array.of apply through nested fixed spread", "import { test } from 'vitest'; Array.of.apply(Array, ...[[test]])[0].only('focused', () => {});"],
  ["Reflect.apply through nested fixed spread", "import { test } from 'vitest'; Reflect.apply(Array.of, Array, ...[[test]])[0].only('focused', () => {});"],
  ["bound Array.of apply through nested fixed spread", "import { test } from 'vitest'; const bound = Array.of.bind(Array); bound.apply(Array, ...[[test]])[0].only('focused', () => {});"],
  ["Reflect.apply call through nested fixed spread", "import { test } from 'vitest'; Reflect.apply.call(Reflect, Array.of, Array, ...[[test]])[0].only('focused', () => {});"],
  ["Reflect.apply apply through fixed spread", "import { test } from 'vitest'; Reflect.apply.apply(Reflect, ...[[Array.of, Array, [test]]])[0].only('focused', () => {});"],
  ["Reflect.apply through fixed target spread", "import { test } from 'vitest'; Reflect.apply(...[Array.of], Array, [test])[0].only('focused', () => {});"],
  ["destructured Array.of apply", "import { test } from 'vitest'; const { apply } = Array.of; apply.call(Array.of, Array, ...[[test]])[0].only('focused', () => {});"],
  ["member-held Array.of apply", "import { test } from 'vitest'; const tools = { apply: Array.of.apply }; tools.apply.call(Array.of, Array, [test])[0].only('focused', () => {});"],
  ["for-of array binding", "import { test } from 'vitest'; for (const register of [test]) { register.only('focused', () => {}); }",],
  ["for-of object destructuring", "import { test } from 'vitest'; for (const { register } of [{ register: test }]) { register.only('focused', () => {}); }"],
  ["for-of destructured exclusive method", "import { test } from 'vitest'; for (const { only } of [test]) only.call(test, 'focused', () => {});"],
  ["for-of nested array exclusive method", "import { test } from 'vitest'; for (const [{ only }] of [[test]]) only.call(test, 'focused', () => {});"],
  ["for-of assignment exclusive method", "import { test } from 'vitest'; for ({ only } of [test]) only.call(test, 'focused', () => {});"],
  ["for-of array destructuring", "import { test } from 'vitest'; for (const [register] of [[test]]) { register.only('focused', () => {}); }"],
  ["Array.of element", "import { test } from 'vitest'; Array.of(test)[0].only('focused', () => {});"],
  ["aliased Array.of element", "import { test } from 'vitest'; const make = Array.of; make(test)[0].only('focused', () => {});"],
  ["Array.of spread argument", "import { test } from 'vitest'; function focus(...values: any[]) { values[0].only('focused', () => {}); } focus(...Array.of(test));"],
  ["Array.of call spread argument", "import { test } from 'vitest'; function focus(...values: any[]) { values[0].only('focused', () => {}); } focus(...Array.of.call(Array, test));"],
  ["Array.of apply spread argument", "import { test } from 'vitest'; function focus(...values: any[]) { values[0].only('focused', () => {}); } focus(...Array.of.apply(Array, [test]));"],
  ["Reflect.apply Array.of spread argument", "import { test } from 'vitest'; function focus(...values: any[]) { values[0].only('focused', () => {}); } focus(...Reflect.apply(Array.of, Array, [test]));"],
  ["bound Array.of spread argument", "import { test } from 'vitest'; function focus(...values: any[]) { values[0].only('focused', () => {}); } const make = Array.of.bind(Array); focus(...make(test));"],
  ["conditional Array.of spread argument", "import { test } from 'vitest'; declare const condition: boolean; function focus(...values: any[]) { values[0].only('focused', () => {}); } focus(...(condition ? Array.of(test) : []));"],
  ["object method this receiver", "import { test } from 'vitest'; const tools = { register: test, focus() { this.register.only('focused', () => {}); } }; tools.focus();"],
  ["for-of function receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } for (const fn of [focus]) fn.call({ register: test });"],
  ["for-of Array.of function receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } for (const fn of Array.of(focus)) fn.call({ register: test });"],
  ["dual call receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } focus.call.call(focus, { register: test });"],
  ["generic apply call receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } Function.prototype.apply.call(focus, { register: test }, []);"],
  ["aliased generic call receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } const invoke = Function.prototype.call; invoke.call(focus, { register: test });"],
  ["destructured generic call receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } const { call: invoke } = Function.prototype; invoke.call(focus, { register: test });"],
  ["member-held generic call receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } const holder = { invoke: Function.prototype.call }; holder.invoke.call(focus, { register: test });"],
  ["immediate bound this receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } focus.bind({ register: test })();"],
  ["stored bound this receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } const bound = focus.bind({ register: test }); bound();"],
  ["stored bound this through call", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } const bound = focus.bind({ register: test }); bound.call(null);"],
  ["stored bound this through apply", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } const bound = focus.bind({ register: test }); bound.apply(null, []);"],
  ["spread bind receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } const receiver = { register: test }; focus.bind(...[receiver])();"],
  ["alternate spread bind receiver", "import { test } from 'vitest'; declare const condition: boolean; function focus(this: any) { this.register.only('focused', () => {}); } const receiver = condition ? { register: { only() {} } } : { register: test }; focus.bind(...[receiver])();"],
  ["runtime argument after explicit this", "function focus(this: unknown, register: typeof test) { register.only('focused', () => {}); } focus.call(null, test);"]
])("rejects exclusive selectors through %s", (_name, source) => {
  expect(() => collectWindowsTestTitles("fixture.ts", source + " test('required', () => {});"))
    .toThrow(/Exclusive or dynamically selected Vitest/);
});

test("accepts safe iteration, Array.of, and receiver-held test-like values", () => {
  const source = [
    "import { test } from 'vitest';",
    "const safe = { only() {} };",
    "for (const register of [safe]) register.only('safe', () => {});",
    "for (const { register } of [{ register: safe }]) register.only('safe', () => {});",
    "for (const [register] of [[safe]]) register.only('safe', () => {});",
    "for (const { only } of [safe]) only.call(safe, 'safe', () => {});",
    "for (const [{ only }] of [[safe]]) only.call(safe, 'safe', () => {});",
    "for ({ only } of [safe]) only.call(safe, 'safe', () => {});",
    "Array.of(safe)[0].only('safe', () => {});",
    "function safeSpread(...values: any[]) { values[0].only('safe', () => {}); } safeSpread(...Array.of.call(Array, safe));",
    "const make = Array.of.bind(Array); safeSpread(...make(safe));",
    "Array.of.apply(Array, ...[[safe]])[0].only('safe', () => {});",
    "Reflect.apply(Array.of, Array, ...[[safe]])[0].only('safe', () => {});",
    "const bounded = Array.of.bind(Array); bounded.apply(Array, ...[[safe]])[0].only('safe', () => {});",
    "Reflect.apply.call(Reflect, Array.of, Array, ...[[safe]])[0].only('safe', () => {});",
    "const { apply } = Array.of; apply.call(Array.of, Array, [[safe]])[0][0].only('safe', () => {});",
    "const applyTools = { apply: Array.of.apply }; applyTools.apply.call(Array.of, Array, [safe])[0].only('safe', () => {});",
    "function safeIterated(this: any) { this.only('safe', () => {}); } for (const fn of [safeIterated]) fn.call(safe);",
    "function safeDualCall(this: any) { this.only('safe', () => {}); } safeDualCall.call.call(safeDualCall, safe);",
    "function safeGeneric(this: any) { this.only('safe', () => {}); } const { call: invoke } = Function.prototype; invoke.call(safeGeneric, safe);",
    "const invokeHolder = { invoke: Function.prototype.call }; invokeHolder.invoke.call(safeGeneric, safe);",
    "{ const Array = { of(...values: any[]) { return values; } }; Array.of(safe)[0].only('safe', () => {}); }",
    "const uninvoked = { register: test, focus() { this.register.only('not registration', () => {}); } };",
    "const tools = { register: safe, focus() { this.register.only('safe', () => {}); } };",
    "tools.focus();",
    "function boundFocus(this: any) { this.only('safe', () => {}); } const boundFocusCall = boundFocus.bind(safe); boundFocusCall();",
    "boundFocus.bind(...[safe])();",
    "function positionalSafe(this: unknown, register: any) { register.only('safe', () => {}); } positionalSafe.call(null, safe);",
    "test('required', () => {});"
  ].join("\n");
  expect(collectWindowsTestTitles("fixture.ts", source))
    .toEqual([{ title: "required", enabled: true }]);
}, 20_000);

  test("recognizes direct Vitest namespace registration", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "import * as V from 'vitest'; V.test('required', () => {});"))
      .toEqual([{ title: "required", enabled: true }]);
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

  test("does not treat unrelated Object.assign copies as Vitest aliases", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "import * as vi from 'vitest'; const namespace = {}; " +
      "Object.assign(namespace, { helper: true }); namespace.helper(); " +
      "test('required', () => {});"))
      .toEqual([{ title: "required", enabled: true }]);
    expect(collectWindowsTestTitles("fixture.ts",
      "import * as vi from 'vitest'; const namespace = {}; " +
      "Object.assign(namespace, [vi]); namespace.test.only('extra', () => {}); " +
      "test('required', () => {});"))
      .toEqual([{ title: "required", enabled: true }]);
  });

  test("terminates local runner-return and member cycles without inventing a runner", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "const makeRunner = () => makeRunner(); makeRunner().only('extra', () => {}); " +
      "const holder: any = {}; holder.value = holder.value; " +
      "holder.value.only('extra', () => {}); " +
      "const namespace: any = {}; namespace.test = namespace.test; " +
      "namespace.test.only('extra', () => {}); " +
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
  }, 20_000);

  test("accepts current-main distribution build and health smoke contract", () => {
    const workflow = load();
    const build = workflow.jobs.test.steps.find((step) => step.name === "Build");
    build.name = "Distribution build and health smoke";
    build.run = "npm run verify:dist";
    expect(inspect(workflow)).toEqual([]);
  }, 20_000);

  test.each([
    ["missing build verification", (workflow) => {
      workflow.jobs.test.steps.splice(
        workflow.jobs.test.steps.findIndex((step) => step.name === "Build"), 1
      );
    }, "exactly one required build or distribution verification step"],
    ["duplicate build verification", (workflow) => {
      const build = workflow.jobs.test.steps.find((step) => step.name === "Build");
      build.name = "Distribution build and health smoke";
      build.run = "npm run verify:dist";
      workflow.jobs.test.steps.push({ ...build });
    }, "exactly one required build or distribution verification step"],
    ["mismatched legacy step", (workflow) => {
      workflow.jobs.test.steps.find((step) => step.name === "Build").run =
        "npm run verify:dist";
    }, "approved build verification command"],
    ["mismatched current-main step", (workflow) => {
      const build = workflow.jobs.test.steps.find((step) => step.name === "Build");
      build.name = "Distribution build and health smoke";
    }, "approved build verification command"],
    ["command substitution", (workflow) => {
      const build = workflow.jobs.test.steps.find((step) => step.name === "Build");
      build.name = "Distribution build and health smoke";
      build.run = "npm run verify:dist && echo skipped";
    }, "approved build verification command"],
    ["conditional current-main step", (workflow) => {
      const build = workflow.jobs.test.steps.find((step) => step.name === "Build");
      build.name = "Distribution build and health smoke";
      build.run = "npm run verify:dist";
      build.if = "false";
    }, "conditional or optional build or distribution verification step"]
  ])("rejects %s", (_name, mutate, expected) => {
    const workflow = load();
    mutate(workflow);
    expect(inspect(workflow).some((finding) => finding.includes(expected))).toBe(true);
  }, 20_000);

  test("rejects a weakened verify:dist script", () => {
    const workflow = load();
    const build = workflow.jobs.test.steps.find((step) => step.name === "Build");
    build.name = "Distribution build and health smoke";
    build.run = "npm run verify:dist";
    const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    packageJson.scripts["verify:dist"] = "npm run build";
    const findings = inspectQualificationWorkflow(
      workflow,
      (path) => readFileSync(join(root, path), "utf8"),
      JSON.stringify(packageJson)
    );
    expect(findings.some((finding) =>
      finding.includes("verify:dist must build and smoke-test the distribution"))).toBe(true);
  }, 20_000);

  test("rejects weakened verify:dist script under legacy build contract", () => {
    const workflow = load();
    const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    packageJson.scripts["verify:dist"] = "npm run build";
    const findings = inspectQualificationWorkflow(
      workflow,
      (path) => readFileSync(join(root, path), "utf8"),
      JSON.stringify(packageJson)
    );
    expect(findings.some((finding) =>
      finding.includes("verify:dist must build and smoke-test the distribution"))).toBe(true);
  }, 20_000);

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
  }, 20_000);

  test("rejects removal of the guardrail execution step", () => {
    const workflow = load();
    windowsStep(workflow, "Validation security and CI coverage guardrails").run = "npm run lint";
    expect(inspect(workflow)).toContain(
      "Windows must run mandatory validation guardrails");
  });

  test("rejects mandatory registration after an early Windows return", () => {
    expect(collectWindowsTestTitles("fixture.ts",
      "describe('suite', () => { if (process.platform === 'win32') return; test('required', () => {}); });"))
      .toEqual([{ title: "required", enabled: false }]);
  });

  test.each([
["reflected test.only", "import { test } from 'vitest'; Reflect.get(test, 'only')('focused', () => {});"],
["constant Reflect.get property", "import { test } from 'vitest'; const key = 'only'; Reflect.get(test, key)('focused', () => {});"],
["comma-selected Reflect.get property", "import { test } from 'vitest'; Reflect.get(test, (0, 'only'))('focused', () => {});"],
    ["reflected runner held by object", "import { test } from 'vitest'; const holder: any = { test }; Reflect.get(holder, 'test').only('focused', () => {});"],
    ["aliased Reflect.get", "import { test } from 'vitest'; const read = Reflect.get; const holder: any = { test }; read(holder, 'test').only('focused', () => {});"],
    ["forward Reflect.get alias", "import { test } from 'vitest'; const readAgain = read; const read = Reflect.get; const holder: any = { test }; readAgain(holder, 'test').only('focused', () => {});"],
    ["property-held Reflect.get", "import { test } from 'vitest'; const tools = { read: Reflect.get }; const holder: any = { test }; tools.read(holder, 'test').only('focused', () => {});"],
    ["destructured Reflect.get", "import { test } from 'vitest'; const { get: read } = Reflect; const holder: any = { test }; read(holder, 'test').only('focused', () => {});"],
    ["object-destructured Reflect.get", "import { test } from 'vitest'; const { read } = { read: Reflect.get }; const holder: any = { test }; read(holder, 'test').only('focused', () => {});"],
    ["descriptor value", "import { test } from 'vitest'; const holder: any = { test }; Object.getOwnPropertyDescriptor(holder, 'test').value.only('focused', () => {});"],
    ["descriptor bag value", "import { test } from 'vitest'; const holder: any = { test }; Object.getOwnPropertyDescriptors(holder).test.value.only('focused', () => {});"],
    ["values array", "import { test } from 'vitest'; const holder: any = { test }; Object.values(holder)[0].only('focused', () => {});"],
    ["entries array", "import { test } from 'vitest'; const holder: any = { test }; Object.entries(holder)[0][1].only('focused', () => {});"],
    ["entries round trip", "import { test } from 'vitest'; const holder: any = { test }; Object.fromEntries(Object.entries(holder)).test.only('focused', () => {});"],
    ["aliased fromEntries", "import { test } from 'vitest'; const rebuild = Object.fromEntries; const holder: any = { test }; rebuild(Object.entries(holder)).test.only('focused', () => {});"],
    ["fails chain", "import { test } from 'vitest'; test.fails.only('focused', () => {});"],
    ["option-only test", "import { test } from 'vitest'; test('focused', { only: true }, () => {});"],
    ["option-only suite", "import { describe } from 'vitest'; describe('suite', { only: true }, () => {});"],
    ["created test runner", "import { test } from 'vitest'; Object.create(test).only('focused', () => {});"],
    ["assigned test runner", "import { test } from 'vitest'; Object.assign({}, test).only('focused', () => {});"],
    ["proxied test runner", "import { test } from 'vitest'; Proxy(test, {}).only('focused', () => {});"],
    ["stored descriptor value", "import { test } from 'vitest'; const holder: any = { test }; const descriptor = Object.getOwnPropertyDescriptor(holder, 'test'); const value = descriptor.value; value.only('focused', () => {});"],
    ["stored descriptor bag value", "import { test } from 'vitest'; const holder: any = { test }; const descriptors = Object.getOwnPropertyDescriptors(holder); const descriptor = descriptors.test; const value = descriptor.value; value.only('focused', () => {});"],
    ["stored values value", "import { test } from 'vitest'; const holder: any = { test }; const values = Object.values(holder); const value = values[0]; value.only('focused', () => {});"],
    ["stored entries value", "import { test } from 'vitest'; const holder: any = { test }; const entries = Object.entries(holder); const entry = entries[0]; const value = entry[1]; value.only('focused', () => {});"],
    ["stored entries round trip", "import { test } from 'vitest'; const holder: any = { test }; const entries = Object.entries(holder); const rebuilt = Object.fromEntries(entries); const runner = rebuilt.test; runner.only('focused', () => {});"],
    ["destructured descriptor value", "import { test } from 'vitest'; const holder: any = { test }; const { value } = Object.getOwnPropertyDescriptor(holder, 'test'); value.only('focused', () => {});"],
    ["renamed destructured descriptor value", "import { test } from 'vitest'; const holder: any = { test }; const { value: runner } = Object.getOwnPropertyDescriptor(holder, 'test'); runner.only('focused', () => {});"],
    ["renamed descriptor bag value", "import { test } from 'vitest'; const holder: any = { test }; const { test: runner } = Object.getOwnPropertyDescriptors(holder); runner.value.only('focused', () => {});"],
    ["destructured values result", "import { test } from 'vitest'; const holder: any = { test }; const [runner] = Object.values(holder); runner.only('focused', () => {});"],
    ["destructured entries value", "import { test } from 'vitest'; const holder: any = { test }; const [, runner] = Object.entries(holder)[0]; runner.only('focused', () => {});"],
    ["reflective descriptor call", "import { test } from 'vitest'; const holder: any = { test }; const read = Object.getOwnPropertyDescriptor; const descriptor = read.call(Object, holder, 'test'); descriptor.value.only('focused', () => {});"],
    ["bound descriptor call", "import { test } from 'vitest'; const holder: any = { test }; const read = Object.getOwnPropertyDescriptor.bind(Object); const descriptor = read(holder, 'test'); descriptor.value.only('focused', () => {});"],
    ["Object.assign-held descriptor method", "import { test } from 'vitest'; const tools = Object.assign({}, { read: Object.getOwnPropertyDescriptors }); const holder: any = { test }; const descriptors = tools.read(holder); const value = descriptors.test.value; value.only('focused', () => {});"],
    ["spread Object.assign descriptor method", "import { test } from 'vitest'; const tools = Object.assign({}, ...[{ read: Object.getOwnPropertyDescriptors }]); const holder: any = { test }; const value = tools.read(holder).test.value; value.only('focused', () => {});"],
    ["computed descriptor method", "import { test } from 'vitest'; const key = 'read'; const tools = { [key]: Object.getOwnPropertyDescriptors }; const holder: any = { test }; const value = tools.read(holder).test.value; value.only('focused', () => {});"],
    ["computed descriptor access", "import { test } from 'vitest'; const key = 'read'; const tools = { [key]: Object.getOwnPropertyDescriptors }; const holder: any = { test }; const value = tools[key](holder).test.value; value.only('focused', () => {});"],
["numeric computed runner assignment", "import { test } from 'vitest'; const holder: any = {}; holder[1 + 2] = test; holder[3].only('focused', () => {});"],
["comma computed runner assignment", "import { test } from 'vitest'; const holder: any = {}; holder[(0, 1)] = test; holder[1].only('focused', () => {});"],
  ["runner helper argument", "import { test } from 'vitest'; function focus(register: typeof test) { register.only('focused', () => {}); } focus(test);"],
  ["chained runner helper arguments", "import { test } from 'vitest'; function inner(register: typeof test) { register.only('focused', () => {}); } function outer(register: typeof test) { inner(register); } outer(test);"],
  ["runner helper before empty spread", "import { test } from 'vitest'; function focus(register: typeof test, ignored: unknown) { register.only('focused', () => {}); } focus(test, ...[]);"],
  ["runner helper through fixed array spread", "import { test } from 'vitest'; function focus(register: typeof test, ignored: unknown) { register.only('focused', () => {}); } focus(...[test, null]);"],
  ["destructured runner helper argument", "import { test } from 'vitest'; function focus({ register }: { register: typeof test }) { register.only('focused', () => {}); } focus({ register: test });"],
  ["nested destructured runner helper argument", "import { test } from 'vitest'; function focus({ nested: { register } }: any) { register.only('focused', () => {}); } focus({ nested: { register: test } });"],
  ["defaulted destructured runner helper argument", "import { test } from 'vitest'; function focus({ register = test } = {}) { register.only('focused', () => {}); } focus({});"],
  ["object-rest runner helper argument", "import { test } from 'vitest'; function focus({ ...rest }: any) { rest.register.only('focused', () => {}); } focus({ register: test });"],
  ["array-rest runner helper argument", "import { test } from 'vitest'; function focus([, ...rest]: any) { rest[0].only('focused', () => {}); } focus([null, test]);"],
  ["globalThis Reflect.get", "import { test } from 'vitest'; globalThis.Reflect.get(test, 'only')('focused', () => {});"],
  ["globalThis Object descriptor", "import { test } from 'vitest'; const holder: any = { test }; globalThis.Object.getOwnPropertyDescriptor(holder, 'test').value.only('focused', () => {});"],
  ["globalThis Object descriptor bag", "import { test } from 'vitest'; const holder: any = { test }; globalThis.Object.getOwnPropertyDescriptors(holder).test.value.only('focused', () => {});"],
  ["globalThis Object assign", "import { test } from 'vitest'; globalThis.Object.assign({}, test).only('focused', () => {});"],
  ["member-held runner factory", "import { test } from 'vitest'; const make = () => test; const tools = { make }; tools.make().only('focused', () => {});"],
  ["method-held runner factory", "import { test } from 'vitest'; const tools = { make() { return test; } }; tools.make().only('focused', () => {});"],
  ["assigned member-held runner factory", "import { test } from 'vitest'; const tools: any = {}; tools.make = () => test; tools.make().only('focused', () => {});"],
  ["computed dynamic namespace", "const V = await import('vi' + 'test'); V.test.only('focused', () => {});"],
  ["nested array binding", "import { test } from 'vitest'; const [{ only }] = [test]; only.call(test, 'focused', () => {});"],
  ["nested array assignment", "import { test } from 'vitest'; let only; [{ only }] = [test]; only.call(test, 'focused', () => {});"],
  ["nested Array.of binding", "import { test } from 'vitest'; const [{ only }] = Array.of([test]); only.call(test, 'focused', () => {});"],
  ["destructured Array.of apply bind", "import { test } from 'vitest'; const { apply } = Array.of; const invoke = apply.bind(Array.of); invoke(Array, [test])[0].only('focused', () => {});"],
  ["member-held Array.of apply bind", "import { test } from 'vitest'; const tools = { apply: Array.of.apply }; const invoke = tools.apply.bind(Array.of); invoke(Array, [test])[0].only('focused', () => {});"],
  ["spread-bound destructured Array.of apply", "import { test } from 'vitest'; const { apply } = Array.of; const invoke = apply.bind(...[Array.of]); invoke(Array, [test])[0].only('focused', () => {});"],
  ["Reflect.apply destructured Array.of apply", "import { test } from 'vitest'; const { apply } = Array.of; Reflect.apply(apply, Array.of, [Array, [test]])[0].only('focused', () => {});"],
  ["Reflect.get Array.of apply call", "import { test } from 'vitest'; Reflect.get(Array.of, 'apply').call(Array.of, Array, [test])[0].only('focused', () => {});"],
  ["deep object binding", "import { test } from 'vitest'; const { x: { only } } = { x: test }; only.call(test, 'focused', () => {});"],
  ["deep nested array binding", "import { test } from 'vitest'; const [[{ only }]] = [[test]]; only.call(test, 'focused', () => {});"],
  ["deep nested array assignment", "import { test } from 'vitest'; let only; [[{ only }]] = [[test]]; only.call(test, 'focused', () => {});"],
  ["deep nested for-of Array.of binding", "import { test } from 'vitest'; for (const [[{ only }]] of Array.of([test])) only.call(test, 'focused', () => {});"],
  ["deep for-of Array.of binding", "import { test } from 'vitest'; for (const [{ only }] of Array.of(test)) only.call(test, 'focused', () => {});"],
  ["deep for-of Array.of assignment", "import { test } from 'vitest'; for ([[{ only }]] of Array.of([test])) only.call(test, 'focused', () => {});"],
  ["deep nested parameter default", "import { test } from 'vitest'; function focus({ nested: { only } = test } = {}) { only('focused', () => {}); } focus();"],
  ["deep nested parameter default without outer initializer", "import { test } from 'vitest'; function focus({ nested: { only } = test }) { only('focused', () => {}); } focus({});"],
  ["deep nested array parameter default", "import { test } from 'vitest'; function focus([{ only } = test] = []) { only('focused', () => {}); } focus();"],
  ["array default on undefined", "import { test } from 'vitest'; const [{ only } = test] = [undefined]; only('focused', () => {});"],
  ["object nested default on undefined", "import { test } from 'vitest'; const { nested: { only } = test } = { nested: undefined }; only('focused', () => {});"],
  ["object nested rest array", "import { test } from 'vitest'; const { nested: [...[{ only }]] } = { nested: [test] }; only('focused', () => {});"],
  ["object nested rest array after skipped element", "import { test } from 'vitest'; const { nested: [skip, ...[{ only }]] } = { nested: [null, test] }; only('focused', () => {});"],
  ["object nested rest Array.of after skipped element", "import { test } from 'vitest'; const { nested: [skip, ...[{ only }]] } = { nested: Array.of(null, test) }; only('focused', () => {});"],
  ["stored bound Array.of apply invoked through call", "import { test } from 'vitest'; const invoke = Array.of.apply.bind(Array.of); const [register] = invoke.call(null, Array, [test]); register.only('focused', () => {});"]
  ])("rejects exclusive registration through %s", (_name, source) => {
    expect(() => collectWindowsTestTitles("fixture.ts", source))
      .toThrow(/Exclusive or dynamically selected Vitest/);
  });

  test.each([
    ["descriptor getter call", "const descriptor = Object.getOwnPropertyDescriptor(test, 'only'); descriptor?.get?.call(test);"],
    ["descriptor getter apply", "const descriptor = Object.getOwnPropertyDescriptor(test, 'only'); descriptor?.get?.apply(test, []);"],
    ["descriptor getter invocation", "const descriptor = Object.getOwnPropertyDescriptor(test, 'only'); descriptor?.get?.();"],
    ["stored descriptor getter", "const descriptor = Object.getOwnPropertyDescriptor(test, 'only'); const get = descriptor.get; get.call(test);"],
    ["destructured descriptor getter", "const { get } = Object.getOwnPropertyDescriptor(test, 'only'); get.call(test);"],
    ["reflect-applied descriptor getter", "const descriptor = Object.getOwnPropertyDescriptor(test, 'only'); Reflect.apply(descriptor.get, test, []);"],
    ["bound descriptor getter", "const get = Object.getOwnPropertyDescriptor(test, 'only').get.bind(test); get();"],
    ["reflected descriptor getter", "const descriptor = Object.getOwnPropertyDescriptor(test, 'only'); Reflect.get(descriptor, 'get').call(test);"],
    ["direct descriptor getter", "const descriptor = Object.getOwnPropertyDescriptor(test, 'only'); const get = descriptor.get; get?.()('focused', () => {});"],
    ["assigned descriptor getter", "let get; get = Object.getOwnPropertyDescriptor(test, 'only').get; get.call(test);"],
    ["destructured assignment descriptor getter", "let get; ({ get } = Object.getOwnPropertyDescriptor(test, 'only')); get.call(test);"],
    ["returned local descriptor getter", "const invokeAccessor = (getter: any) => getter; const descriptor = Object.getOwnPropertyDescriptor(test, 'only'); const register = invokeAccessor(descriptor.get); register.call(test);"],
    ["called local descriptor getter", "function invokeAccessor(getter: any) { getter.call(test); } const descriptor = Object.getOwnPropertyDescriptor(test, 'only'); invokeAccessor(descriptor.get);"],
    ["factory-returned descriptor getter", "const getter = () => Object.getOwnPropertyDescriptor(test, 'only').get; getter().call(test);"],
    ["object-held descriptor getter", "const descriptor = Object.getOwnPropertyDescriptor(test, 'only'); const held = { getter: descriptor.get }; held.getter.call(test);"],
    ["array-held descriptor getter", "const descriptor = Object.getOwnPropertyDescriptor(test, 'only'); const held = [descriptor.get]; const register = held[0]; register.call(test);"],
  ])("rejects descriptor accessor exclusive registration through %s", (_name, source) => {
    const fixture = "import { test } from 'vitest'; " + source +
      " (() => {})('focused', () => {});";
    expect(() => collectWindowsTestTitles("fixture.ts", fixture))
      .toThrow(/Exclusive or dynamically selected Vitest/);
  });

  test("accepts ordinary objects containing test-named values", () => {
    expect(collectWindowsTestTitles("fixture.ts", [
      "import { test } from 'vitest';",
      "const holder: any = { test: true };",
      "Reflect.get(holder, 'test');",
      "Object.getOwnPropertyDescriptor(holder, 'test').value;",
      "Object.getOwnPropertyDescriptors(holder).test.value;",
      "const ordinaryDescriptor = Object.getOwnPropertyDescriptor(holder, 'test'); ordinaryDescriptor?.get?.call(holder);",
      "Object.getOwnPropertyDescriptor(test, 'length')?.get?.call(test);",
      "const safeGetter = ordinaryDescriptor.get; safeGetter?.call(holder);",
      "safeGetter?.()(holder);",
      "const { get: safeDestructuredGetter } = ordinaryDescriptor; safeDestructuredGetter?.call(holder);",
      "let assignedSafeGetter; ({ get: assignedSafeGetter } = ordinaryDescriptor); assignedSafeGetter?.call(holder);",
    "const invokeSafeAccessor = (getter: any) => getter;",
    "const safeReturnedGetter = invokeSafeAccessor(ordinaryDescriptor.get); safeReturnedGetter.call(holder);",
    "function invokeOrdinaryAccessor(getter: any) { getter.call(holder); }",
    "invokeOrdinaryAccessor(ordinaryDescriptor.get);",
    "const safeGetterFactory = () => Object.getOwnPropertyDescriptor(holder, 'test').get;",
    "safeGetterFactory().call(holder);",
    "const safeHeldGetter = { getter: ordinaryDescriptor.get }; safeHeldGetter.getter.call(holder);",
    "const safeGetterArray = [ordinaryDescriptor.get]; const safeArrayGetter = safeGetterArray[0]; safeArrayGetter.call(holder);",
      "Reflect.get(ordinaryDescriptor, 'get')?.call(holder);",
      "Object.values(holder)[0];",
      "Object.entries(holder)[0][1];",
      "Object.fromEntries(Object.entries(holder)).test;",
      "const { read } = { read: Reflect.get };",
      "read({ value: 1 }, 'value');",
      "const key = 'test'; const computedHolder: any = { [key]: true };",
      "const { value: ordinaryValue } = Object.getOwnPropertyDescriptor(holder, 'test');",
      "const { value: renamedDescriptorValue } = Object.getOwnPropertyDescriptor(holder, 'test');",
      "const safeTools = Object.assign({}, { read: Object.getOwnPropertyDescriptors });",
      "const safeCycle = Object.assign(safeCycle, { helper: true });",
"const reflectedLength = Reflect.get(test, 'length');",
      "const globalReflectedLength = globalThis.Reflect.get(test, 'length');",
      "const globalDescriptorValue = globalThis.Object.getOwnPropertyDescriptor(holder, 'test').value;",
      "const globalAssignedValue = globalThis.Object.assign({}, { value: 1 });",
"const numericMetadata: any = {}; numericMetadata[1 + 2] = true;",
      "const testLike = { only() {} };",
      "const [{ only: nullOnly }] = [null];",
      "const [{ only: ordinaryOnly }] = [testLike];",
      "let assignedOnly; [{ only: assignedOnly }] = [testLike];",
      "const [{ only: arrayOfOnly }] = Array.of([testLike]);",
      "const { x: { only: deepSafeOnly } } = { x: testLike };",
      "const [[{ only: deepArraySafeOnly }]] = [[testLike]];",
      "for (const [[{ only: deepForOfSafeOnly }]] of Array.of([testLike])) deepForOfSafeOnly('safe', () => {});",
  "for (const [{ only: deepSingleForOfSafeOnly }] of Array.of(testLike)) deepSingleForOfSafeOnly('safe', () => {});",
  "function safeNestedDefault({ nested: { only } = testLike } = {}) { only('safe', () => {}); } safeNestedDefault();",
  "function safeNestedArrayDefault([{ only } = testLike] = []) { only('safe', () => {}); } safeNestedArrayDefault();",
  "const [{ only: selectedSafeOnly } = test] = [testLike]; selectedSafeOnly('safe', () => {});",
  "const { nested: { only: selectedSafeNestedOnly } = test } = { nested: testLike }; selectedSafeNestedOnly('safe', () => {});",
  "const { nested: [...[{ only: selectedSafeRestOnly }]] } = { nested: [testLike] }; selectedSafeRestOnly('safe', () => {});",
  "const { nested: [skipSafe, ...[{ only: selectedSafeRestAfterSkip }]] } = { nested: [null, testLike] }; selectedSafeRestAfterSkip('safe', () => {});",
      "const { apply } = Array.of; const invokeSafe = apply.bind(Array.of);",
      "invokeSafe(Array, [testLike])[0].only('safe', () => {});",
      "const safeTools = { apply: Array.of.apply }; const invokeHeldSafe = safeTools.apply.bind(Array.of);",
      "invokeHeldSafe(Array, [testLike])[0].only('safe', () => {});",
      "const invokeSpreadSafe = apply.bind(...[Array.of]);",
      "invokeSpreadSafe(Array, [testLike])[0].only('safe', () => {});",
      "Reflect.apply(apply, Array.of, [Array, [testLike]])[0].only('safe', () => {});",
      "Reflect.get(Array.of, 'apply').call(Array.of, Array, [testLike])[0].only('safe', () => {});",
      "const invokeStoredSafe = Array.of.apply.bind(Array.of); const [storedSafeRegister] = invokeStoredSafe.call(null, Array, [testLike]);",
      "test('required', () => {});"
    ].join("\n"))).toEqual([{ title: "required", enabled: true }]);
  }, 20_000);

  test("keeps globalThis and local member provenance bounded", () => {
    const source = [
      "import { test } from 'vitest';",
      "const globalThis = {",
      "  Object: { getOwnPropertyDescriptor() { return { value: { only() {} } }; }, assign() { return { only() {} }; } },",
      "  Reflect: { get() { return { only() {} }; } },",
      "  Math: { max() { return 0; } }",
      "};",
      "globalThis.Reflect.get({ value: 1 }, 'value');",
      "globalThis.Object.getOwnPropertyDescriptor({ value: 1 }, 'value').value;",
      "globalThis.Object.assign({}, { value: 1 });",
      "globalThis.Math.max(1, 2);",
      "function inspect(register: typeof test) { return register.length; }",
      "inspect(test);",
      "function inspectRecord({ register }: { register: typeof test }) { return register.length; }",
      "inspectRecord({ register: test });",
      "function inspectOrdinaryRecord({ value }: { value: { length: number } }) { return value.length; }",
      "inspectOrdinaryRecord({ value: { length: 1 } });",
      "function inspectRest({ register, ...rest }: any) { return rest.register?.length; }",
      "inspectRest({ register: test, metadata: { length: 1 } });",
      "const make = () => ({ safe: true });",
      "const tools = { make };",
      "tools.make().safe;",
      "const methodTools = { make() { return { safe: true }; } };",
      "methodTools.make().safe;",
      "test('required', () => {});"
    ].join("\n");
    expect(collectWindowsTestTitles("fixture.ts", source))
      .toEqual([{ title: "required", enabled: true }]);
  });

  test("parses unfiltered mandatory files for exclusive registration", () => {
    const workflow = load();
    const findings = inspectQualificationWorkflow(workflow, (path) =>
      path === "tests/package-archive-verification.test.ts"
        ? "test.only('focused', () => {});"
        : readFileSync(join(root, path), "utf8"));
    expect(findings).toContain(
      "Could not parse mandatory Vitest declarations: tests/package-archive-verification.test.ts");
  });

  test("rejects a required job that depends on another job", () => {
    const workflow = load();
    workflow.jobs["skip-preflight"] = {
      if: "false",
      "runs-on": "ubuntu-latest",
      steps: [{ uses: "actions/checkout@v6" }]
    };
    workflow.jobs.test.needs = "skip-preflight";
    workflow.jobs["windows-test"].needs = "skip-preflight";
    expect(inspect(workflow)).toEqual(expect.arrayContaining([
      "Required CI job must not depend on another job: test",
      "Required CI job must not depend on another job: windows-test"
    ]));
  });

  test("requires pull request workflow execution", () => {
    const workflow = load();
    delete workflow.on.pull_request;
    expect(inspect(workflow)).toContain(
      "CI must run for every pull request without event filters");
  });

  test.each([
    ["fixed-array hole", "import { test } from 'vitest'; function focus(ignored, register) { register.only('focused', () => {}); } focus(...[, test]);"],
    ["identifier rest parameter", "import { test } from 'vitest'; function focus(...args) { const [register] = args; register.only('focused', () => {}); } focus(test);"],
    ["rest parameter after fixed argument", "import { test } from 'vitest'; function focus(prefix, ...args) { args[0].only('focused', () => {}); } focus(null, test);"],
    ["destructured rest parameter", "import { test } from 'vitest'; function focus(...[register]) { register.only('focused', () => {}); } focus(test);"],
    ["array-rest binding", "import { test } from 'vitest'; function focus([...rest]) { rest[0].only('focused', () => {}); } focus([test]);"],
    ["opaque spread before capability", "import { test } from 'vitest'; declare const args: any[]; function focus(register) { register.only('focused', () => {}); } focus(...args, test);"],
    ["helper call", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } focus.call(null, test);"],
    ["helper apply", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } focus.apply(null, [test]);"],
    ["helper apply returned arguments", "import { test } from 'vitest'; const args = () => [test]; function focus(register) { register.only('focused', () => {}); } focus.apply(null, args());"],
    ["helper apply array-like arguments", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } focus.apply(null, { 0: test, length: 1 });"],
    ["helper apply sparse array-like arguments", "import { test } from 'vitest'; function focus(ignored, register) { register.only('focused', () => {}); } focus.apply(null, { 1: test, length: 2 });"],
    ["helper apply spread array-like arguments", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } focus.apply(null, { ...{ 0: test }, length: 1 });"],
    ["helper apply overriding spread argument", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } focus.apply(null, { 0: testLike, ...{ 0: test }, length: 1 });"],
    ["helper bind", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } focus.bind(null, test)();"],
    ["stored helper bind", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } const bound = focus.bind(null, test); bound();"],
  ["stored helper bind later argument", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } const bound = focus.bind(null); bound(test);"],
  ["aliased stored helper bind later argument", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } const bind = focus.bind; const bound = bind(null); bound(test);"],
  ["Reflect-created stored helper bind later argument", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } const bound = Reflect.apply(focus.bind, focus, [null]); bound(test);"],
  ["getter-held helper bind later argument", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } const tools = { get bind() { return focus.bind; } }; const bound = tools.bind(null); bound(test);"],
  ["function-returned helper bind later argument", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } function getBind() { return focus.bind; } const bound = getBind()(null); bound(test);"],
    ["stored helper bind apply", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } const bound = focus.bind(null); bound.apply(null, [test]);"],
    ["Reflect.apply helper", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } Reflect.apply(focus, null, [test]);"],
    ["Reflect.apply call", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } Reflect.apply.call(null, focus, null, [test]);"],
    ["Reflect.apply apply", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } Reflect.apply.apply(null, [focus, null, [test]]);"],
    ["aliased Reflect.apply", "import { test } from 'vitest'; const invoke = Reflect.apply; function focus(register) { register.only('focused', () => {}); } invoke(focus, null, [test]);"],
    ["member-held Reflect.apply", "import { test } from 'vitest'; const tools = { invoke: Reflect.apply }; function focus(register) { register.only('focused', () => {}); } tools.invoke(focus, null, [test]);"],
    ["function arguments object", "import { test } from 'vitest'; function focus() { arguments[0].only('focused', () => {}); } focus(test);"],
    ["arrow function arguments object", "import { test } from 'vitest'; function focus() { const read = () => arguments[0]; read().only('focused', () => {}); } focus(test);"],
    ["local capability forwarding", "import { test } from 'vitest'; function invoke(fn, arg) { return fn.call(null, arg); } function focus(register) { register.only('focused', () => {}); } invoke(focus, test);"],
    ["rest arguments forwarding", "import { test } from 'vitest'; function invoke(fn, ...args) { return fn.apply(null, args); } function focus(register) { register.only('focused', () => {}); } invoke(focus, test);"],
    ["arguments apply forwarding", "import { test } from 'vitest'; function invoke(fn) { return fn.apply(null, arguments); } function focus(register) { register.only('focused', () => {}); } invoke(focus, test);"],
    ["returned array-like arguments", "import { test } from 'vitest'; const args = () => ({ 0: test, length: 1 }); function focus(register) { register.only('focused', () => {}); } focus.apply(null, args());"],
    ["aliased array-like arguments", "import { test } from 'vitest'; const args = { 0: test, length: 1 }; function focus(register) { register.only('focused', () => {}); } focus.apply(null, args);"],
    ["getter array-like arguments", "import { test } from 'vitest'; const args = { get 0() { return test; }, length: 1 }; function focus(register) { register.only('focused', () => {}); } focus.apply(null, args);"],
    ["aliased arguments object", "import { test } from 'vitest'; function focus() { const args = arguments; args[0].only('focused', () => {}); } focus(test);"],
    ["returned arguments object", "import { test } from 'vitest'; function focus() { const read = () => arguments; read()[0].only('focused', () => {}); } focus(test);"],
    ["destructured Reflect.apply", "import { test } from 'vitest'; const { apply } = Reflect; function focus(register) { register.only('focused', () => {}); } apply(focus, null, [test]);"],
    ["getter-held Reflect.apply", "import { test } from 'vitest'; const tools = { get invoke() { return Reflect.apply; } }; function focus(register) { register.only('focused', () => {}); } tools.invoke(focus, null, [test]);"],
    ["stored bound Reflect.apply", "import { test } from 'vitest'; const invoke = Reflect.apply.bind(null, function focus(register) { register.only('focused', () => {}); }, null); invoke([test]);"],
    ["fixed bound Reflect.apply receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } Reflect.apply.bind(null, focus, { register: test })([]);"],
    ["deferred bound Reflect.apply receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } const invoke = Reflect.apply.bind(null, focus); invoke({ register: test }, []);"],
    ["spread-bound Reflect.apply receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } Reflect.apply.bind(...[null, focus, { register: test }])([]);"],
    ["member-held bound Reflect.apply receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } const invoke = Reflect.apply.bind(null, focus); const tools = { invoke }; tools.invoke({ register: test }, []);"],
    ["inline member-held bound Reflect.apply receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } const tools = { invoke: Reflect.apply.bind(null, focus) }; tools.invoke({ register: test }, []);"],
    ["assigned member-held bound Reflect.apply receiver", "import { test } from 'vitest'; function focus(this: any) { this.register.only('focused', () => {}); } const tools: any = {}; tools.invoke = Reflect.apply.bind(null, focus); tools.invoke({ register: test }, []);"],
    ["nested rest runner binding", "import { test } from 'vitest'; const [[...[{ register }]]] = [[{ register: test }]]; register.only('focused', () => {});"],
    ["nested rest runner for-of", "import { test } from 'vitest'; for (const [[...[{ register }]]] of [[[{ register: test }]]]) { register.only('focused', () => {}); }"],
    ["nested rest runner parameter", "import { test } from 'vitest'; function focus(...[, { register }]) { register.only('focused', () => {}); } focus(null, { register: test });"],
    ["explicit undefined object default", "import { test } from 'vitest'; const { register = test } = { register: undefined }; register.only('focused', () => {});"],
    ["void object default", "import { test } from 'vitest'; const { register = test } = { register: void 0 }; register.only('focused', () => {});"],
    ["explicit undefined array default", "import { test } from 'vitest'; const [register = test] = [undefined]; register.only('focused', () => {});"],
    ["stored Array.of result", "import { test } from 'vitest'; const args = Array.of(test); args[0].only('focused', () => {});"],
    ["Reflect.get call", "import { test } from 'vitest'; globalThis.Reflect.get.call(null, test, 'only')('focused', () => {});"],
    ["Reflect.get apply", "import { test } from 'vitest'; globalThis.Reflect.get.apply(null, [test, 'only'])('focused', () => {});"],
    ["Reflect.get bind", "import { test } from 'vitest'; globalThis.Reflect.get.bind(null, test, 'only')()('focused', () => {});"],
    ["Reflect.get static spread", "import { test } from 'vitest'; globalThis.Reflect.get(...[test, 'only'])('focused', () => {});"],
    ["Reflect.apply of Reflect.get", "import { test } from 'vitest'; Reflect.apply(Reflect.get, null, [test, 'only'])('focused', () => {});"],
    ["Reflect.apply of Reflect.get with array-like arguments", "import { test } from 'vitest'; Reflect.apply(Reflect.get, null, { 0: test, 1: 'only', length: 2 })('focused', () => {});"],
    ["Object.assign call", "import { test } from 'vitest'; globalThis.Object.assign.call(Object, {}, test).only('focused', () => {});"],
    ["Object.assign apply", "import { test } from 'vitest'; globalThis.Object.assign.apply(Object, [{}, test]).only('focused', () => {});"],
    ["Object.assign bind", "import { test } from 'vitest'; globalThis.Object.assign.bind(Object, {}, test)().only('focused', () => {});"],
    ["comma-wrapped Object.assign bind", "import { test } from 'vitest'; const copy = (0, globalThis.Object.assign.bind(Object, {}, test))(); copy.only('focused', () => {});"],
    ["comma-expression spread argument", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } focus.apply(null, [...(0, [test])]);"],
    ["comma-expression spread side effect", "import { test } from 'vitest'; const testLike = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus.apply(null, [...(test.only('focused', () => {}), [testLike])]);"],
    ["Object.assign static spread", "import { test } from 'vitest'; globalThis.Object.assign.call(Object, ...[{}, test]).only('focused', () => {});"],
    ["Reflect.apply of Object.assign", "import { test } from 'vitest'; Reflect.apply(Object.assign, Object, [{}, test]).only('focused', () => {});"],
    ["Reflect.apply of Object.assign with array-like arguments", "import { test } from 'vitest'; Reflect.apply(Object.assign, Object, { 0: {}, 1: test, length: 2 }).only('focused', () => {});"],
    ["member factory argument", "import { test } from 'vitest'; const make = (_unused: unknown) => test; const tools = { make }; tools.make(1).only('focused', () => {});"],
  ["getter factory", "import { test } from 'vitest'; const tools = { get make() { return test; } }; tools.make().only('focused', () => {});"],
  ["getter-held test runner", "import { test } from 'vitest'; const tools = { get runner() { return test; } }; tools.runner.only('focused', () => {});"],
  ["getter-backed helper argument", "import { test } from 'vitest'; const tools = { get runner() { return test; } }; function focus(register) { register.only('focused', () => {}); } focus(tools.runner);"],
  ["getter-held helper function", "import { test } from 'vitest'; const tools = { get focus() { return (register) => register.only('focused', () => {}); } }; tools.focus(test);"],
  ["getter-returned capability carrier", "import { test } from 'vitest'; const tools = { get carrier() { return { runner: test }; } }; tools.carrier.runner.only('focused', () => {});"],
  ["nested local function returns", "import { test } from 'vitest'; const make = () => () => test; make()().only('focused', () => {});"],
  ["aliased nested local function returns", "import { test } from 'vitest'; const make = () => () => test; const inner = make(); inner().only('focused', () => {});"],
  ["getter-held Object constructor", "import { test } from 'vitest'; const tools = { get ctor() { return globalThis.Object; } }; tools.ctor.create(test).only('focused', () => {});"],
    ["getter this capability", "import { test } from 'vitest'; const tools = { runner: test, get read() { return this.runner; } }; function focus(register) { register.only('focused', () => {}); } focus(tools.read);"],
    ["getter this capability through spread array", "import { test } from 'vitest'; const tools = { runner: test, get read() { return this.runner; } }; const values = [...[tools.read]]; function focus(register) { register.only('focused', () => {}); } focus(values[0]);"],
    ["Object.create inherited array-like", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } const args = Object.create({ 0: test, length: 1 }); focus.apply(null, args);"],
    ["rest forwarding through getter", "import { test } from 'vitest'; const tools = { get runner() { return test; } }; function inner(...args) { args[0].only('focused', () => {}); } function outer(...args) { inner(...args); } outer(tools.runner);"],
    ["rest forwarding unknown prefix", "import { test } from 'vitest'; function inner(...args) { args[0].only('focused', () => {}); } function outer(...args) { inner(...args); } declare const prefix: any[]; outer(...prefix, test);"],
    ["rest forwarding after fixed argument", "import { test } from 'vitest'; function inner(head, ...args) { args[0].only('focused', () => {}); } function outer(...args) { inner('head', ...args); } outer(test);"],
  ["reflected Function.prototype.bind", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } const bound = Reflect.apply(Function.prototype.bind, focus, [null]); bound(test);"],
  ["aliased reflected Function.prototype.bind", "import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } const bind = Function.prototype.bind; const bound = Reflect.apply(bind, focus, [null]); bound(test);"],
    ["generic bind unknown prefix", "import { test } from 'vitest'; declare const prefix: any[]; function focus(register) { register.only('focused', () => {}); } const bind = Function.prototype.bind; const bound = bind.call(focus, ...prefix, test); bound();"],
    ["factory carrier", "import { test } from 'vitest'; const tools = { make: () => ({ runtime: test }) }; tools.make().runtime.only('focused', () => {});"],
  ["destructured factory carrier", "import { test } from 'vitest'; const make = () => ({ runtime: test }); const { runtime } = make(); runtime.only('focused', () => {});"],
  ["tagged-template member receiver", "import { test } from 'vitest'; const tools = { register: test, focus() { this.register.only('focused', () => {}); } }; tools.focus`ticket`; test('required', () => {});"],
  ["tagged-template substitution argument", "import { test } from 'vitest'; function focus(strings, register) { register.only('focused', () => {}); } const tools = { focus }; tools.focus`ticket ${test}`; test('required', () => {});"],
  ["new member factory", "import { test } from 'vitest'; function focus() { return test; } const tools = { focus }; new tools.focus().only('focused', () => {}); test('required', () => {});"],
  ["Reflect.construct member factory", "import { test } from 'vitest'; function focus() { return test; } const tools = { focus }; Reflect.construct(tools.focus, []).only('focused', () => {}); test('required', () => {});"],
  ["array-rest runner binding", "import { test } from 'vitest'; const [, ...rest] = [null, test]; rest[0].only('focused-only', () => {}); test('required', () => {});"],
  ["Array.of rest runner binding", "import { test } from 'vitest'; const [, ...rest] = Array.of(null, test); rest[0].only('focused-only', () => {}); test('required', () => {});"],
  ["array-rest unknown tail before runner", "import { test } from 'vitest'; declare const tail: any[]; const [, ...rest] = [null, ...tail, test]; rest[0].only('focused-only', () => {}); test('required', () => {});"],
  ["array-rest unknown tail after runner", "import { test } from 'vitest'; declare const tail: any[]; const [, ...rest] = [null, test, ...tail]; rest[0].only('focused-only', () => {}); test('required', () => {});"],
  ["aliased undefined default", "import { test } from 'vitest'; const U = undefined; const { register = test } = { register: U }; register.only('focused-only', () => {}); test('required', () => {});"],
  ["aliased void default", "import { test } from 'vitest'; const U = void 0; const { register = test } = { register: U }; register.only('focused-only', () => {}); test('required', () => {});"]
  ])('rejects bounded Vitest provenance through %s', (_name, source) => {
    expect(() => collectWindowsTestTitles('fixture.ts', source))
      .toThrow(/Exclusive or dynamically selected Vitest/);
  });

  const staticProvenanceCases = [
    ['conditional spread alternatives', (capability) =>
      `import { test } from 'vitest'; declare const condition: boolean; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...(condition ? [safe] : [${capability}]));`],
    ['logical AND spread alternatives', (capability) =>
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...(true && [${capability}]));`],
    ['logical OR spread alternatives', (capability) =>
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...(false || [${capability}]));`],
    ['nullish spread alternatives', (capability) =>
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...(null ?? [${capability}]));`],
    ['zero BigInt logical OR spread alternatives', (capability) =>
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...(0n || [${capability}]));`],
    ['numeric zero logical OR spread alternatives', (capability) =>
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...(0 || [${capability}]));`],
    ['truthy numeric logical AND spread alternatives', (capability) =>
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...(1 && [${capability}]));`],
    ['truthy string logical AND spread alternatives', (capability) =>
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...('value' && [${capability}]));`],
    ['negated false logical AND spread alternatives', (capability) =>
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...(!false && [${capability}]));`],
    ['truthy array logical OR spread alternatives', (capability) =>
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...([${capability}] || [safe]));`],
    ['truthy array logical AND spread alternatives', (capability) =>
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...([safe] && [${capability}]));`],
    ['non-null array logical nullish spread alternatives', (capability) =>
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...([${capability}] ?? [safe]));`],
    ['nested unknown spread followed by capability', (capability) =>
      `import { test } from 'vitest'; declare const args: any[]; function focus(register) { register.only('focused', () => {}); } focus(...[...args, ${capability}]);`],
    ['unknown prefix indexed capability', (capability) =>
      `import { test } from 'vitest'; declare const args: any[]; const values = [...args, ${capability}]; values[0].only('focused', () => {});`],
    ['getter this capability through alias', (capability) =>
      `import { test } from 'vitest'; const tools = { runtime: ${capability}, get read() { const self = this; return self.runtime; } }; tools.read.only('focused', () => {});`],
    ['Object.create inherited index', (capability) =>
      `import { test } from 'vitest'; const args = Object.create({ 0: ${capability}, length: 1 }); args[0].only('focused', () => {});`],
    ['Object.create inherited getter', (capability) =>
      `import { test } from 'vitest'; const args = Object.create({ runtime: ${capability}, get read() { return this.runtime; } }); args.read.only('focused', () => {});`],
    ['aliased Object.create', (capability) =>
      `import { test } from 'vitest'; const create = Object.create; const args = create({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['destructured Object.create', (capability) =>
      `import { test } from 'vitest'; const { create } = Object; const args = create({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['assigned destructured Object.create', (capability) =>
      `import { test } from 'vitest'; let create; ({ create } = Object); const args = create({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['returned Object.create from local helper', (capability) =>
      `import { test } from 'vitest'; function wrap(prototype) { return Object.create(prototype); } wrap({ runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['defaulted helper parameter supplied Object.create capability', (capability) =>
      `import { test } from 'vitest'; function wrap(prototype = {}) { return Object.create(prototype); } wrap({ runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['member-held Object.create', (capability) =>
      `import { test } from 'vitest'; const tools = { create: Object.create }; const args = tools.create({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['getter-held Object.create', (capability) =>
      `import { test } from 'vitest'; const tools = { get create() { return Object.create; } }; const args = tools.create({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['Object.create call', (capability) =>
      `import { test } from 'vitest'; const args = Object.create.call(Object, { runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['Object.create apply', (capability) =>
      `import { test } from 'vitest'; const args = Object.create.apply(Object, [{ runtime: ${capability} }]); args.runtime.only('focused', () => {});`],
    ['Object.create bind', (capability) =>
      `import { test } from 'vitest'; const args = Object.create.bind(Object)({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['Object.create bind captured prototype', (capability) =>
      `import { test } from 'vitest'; const args = Object.create.bind(Object, { runtime: ${capability} })(); args.runtime.only('focused', () => {});`],
    ['Reflect.apply Object.create', (capability) =>
      `import { test } from 'vitest'; const args = Reflect.apply(Object.create, Object, [{ runtime: ${capability} }]); args.runtime.only('focused', () => {});`],
    ['generic bind call Object.create', (capability) =>
      `import { test } from 'vitest'; const create = Function.prototype.bind.call(Object.create, Object); const args = create({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['generic bind call Object.create captured prototype', (capability) =>
      `import { test } from 'vitest'; const create = Function.prototype.bind.call(Object.create, Object, { runtime: ${capability} }); const args = create(); args.runtime.only('focused', () => {});`],
    ['generic bind apply Object.create', (capability) =>
      `import { test } from 'vitest'; const create = Function.prototype.bind.apply(Object.create, [Object]); const args = create({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['generic bind apply Object.create captured prototype', (capability) =>
      `import { test } from 'vitest'; const create = Function.prototype.bind.apply(Object.create, [Object, { runtime: ${capability} }]); const args = create(); args.runtime.only('focused', () => {});`],
    ['generic bind Reflect.apply Object.create', (capability) =>
      `import { test } from 'vitest'; const create = Reflect.apply(Function.prototype.bind, Object.create, [Object]); const args = create({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['generic bind Reflect.apply Object.create captured prototype', (capability) =>
      `import { test } from 'vitest'; const create = Reflect.apply(Function.prototype.bind, Object.create, [Object, { runtime: ${capability} }]); const args = create(); args.runtime.only('focused', () => {});`],
    ['aliased Object.assign', (capability) =>
      `import { test } from 'vitest'; const assign = Object.assign; assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['destructured Object.assign', (capability) =>
      `import { test } from 'vitest'; const { assign } = Object; assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['assigned destructured Object.assign', (capability) =>
      `import { test } from 'vitest'; let assign; ({ assign } = Object); assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['returned Object.assign from local helper', (capability) =>
      `import { test } from 'vitest'; function copy(source) { return Object.assign({}, source); } copy({ runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['member-held Object.assign', (capability) =>
      `import { test } from 'vitest'; const tools = { assign: Object.assign }; tools.assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['getter-held Object.assign', (capability) =>
      `import { test } from 'vitest'; const tools = { get assign() { return Object.assign; } }; tools.assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['Object.assign call', (capability) =>
      `import { test } from 'vitest'; Object.assign.call(Object, {}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['Object.assign apply', (capability) =>
      `import { test } from 'vitest'; Object.assign.apply(Object, [{}, { runtime: ${capability} }]).runtime.only('focused', () => {});`],
    ['Object.assign bind', (capability) =>
      `import { test } from 'vitest'; Object.assign.bind(Object, {}, { runtime: ${capability} })().runtime.only('focused', () => {});`],
    ['Reflect.apply Object.assign', (capability) =>
      `import { test } from 'vitest'; Reflect.apply(Object.assign, Object, [{}, { runtime: ${capability} }]).runtime.only('focused', () => {});`],
    ['generic bind call Object.assign', (capability) =>
      `import { test } from 'vitest'; const assign = Function.prototype.bind.call(Object.assign, Object); assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['generic bind call Object.assign captured source', (capability) =>
      `import { test } from 'vitest'; const assign = Function.prototype.bind.call(Object.assign, Object, {}, { runtime: ${capability} }); assign().runtime.only('focused', () => {});`],
    ['generic bind apply Object.assign', (capability) =>
      `import { test } from 'vitest'; const assign = Function.prototype.bind.apply(Object.assign, [Object]); assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['generic bind apply Object.assign captured source', (capability) =>
      `import { test } from 'vitest'; const assign = Function.prototype.bind.apply(Object.assign, [Object, {}, { runtime: ${capability} }]); assign().runtime.only('focused', () => {});`],
    ['generic bind Reflect.apply Object.assign', (capability) =>
      `import { test } from 'vitest'; const assign = Reflect.apply(Function.prototype.bind, Object.assign, [Object]); assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['generic bind Reflect.apply Object.assign captured source', (capability) =>
      `import { test } from 'vitest'; const assign = Reflect.apply(Function.prototype.bind, Object.assign, [Object, {}, { runtime: ${capability} }]); assign().runtime.only('focused', () => {});`],
    ['Object.create apply with unknown prefix', (capability) =>
      `import { test } from 'vitest'; declare const args: any[]; const created = Object.create.apply(Object, [...args, { runtime: ${capability} }]); created.runtime.only('focused', () => {});`],
    ['detached Object.create bind call', (capability) =>
      `import { test } from 'vitest'; const bind = Object.create.bind; const create = bind.call(Object.create, Object); const args = create({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['detached Object.create bind call captured arguments', (capability) =>
      `import { test } from 'vitest'; const bind = Object.create.bind; const create = bind.call(Object.create, Object, { runtime: ${capability} }); create().runtime.only('focused', () => {});`],
    ['detached Object.create bind apply', (capability) =>
      `import { test } from 'vitest'; const bind = Object.create.bind; const create = bind.apply(Object.create, [Object]); const args = create({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['detached Object.create Reflect.apply', (capability) =>
      `import { test } from 'vitest'; const bind = Object.create.bind; const create = Reflect.apply(bind, Object.create, [Object]); const args = create({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['detached Object.assign bind call', (capability) =>
      `import { test } from 'vitest'; const bind = Object.assign.bind; const assign = bind.call(Object.assign, Object); assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['detached Object.assign bind call captured arguments', (capability) =>
      `import { test } from 'vitest'; const bind = Object.assign.bind; const assign = bind.call(Object.assign, Object, {}, { runtime: ${capability} }); assign().runtime.only('focused', () => {});`],
    ['detached Object.assign bind apply', (capability) =>
      `import { test } from 'vitest'; const bind = Object.assign.bind; const assign = bind.apply(Object.assign, [Object]); assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['detached Object.assign Reflect.apply', (capability) =>
      `import { test } from 'vitest'; const bind = Object.assign.bind; const assign = Reflect.apply(bind, Object.assign, [Object]); assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['conditional stored helper bind', (capability) =>
      `import { test } from 'vitest'; declare const condition: boolean; const safe = () => ({ only() {} }); function focus(register) { register.only('focused', () => {}); } const chosen = condition ? focus.bind(null) : safe.bind(null); chosen(${capability});`],
    ['nested destructured Object.create', (capability) =>
      `import { test } from 'vitest'; let create; ({ outer: { create } } = { outer: { create: Object.create } }); create({ runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['nested destructured Object.assign', (capability) =>
      `import { test } from 'vitest'; let assign; ({ outer: { assign } } = { outer: { assign: Object.assign } }); assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['nested computed destructured Object.create', (capability) =>
      `import { test } from 'vitest'; const key = 'create'; let create; ({ outer: { [key]: create } } = { outer: { create: Object.create } }); create({ runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['nested computed destructured Object.assign', (capability) =>
      `import { test } from 'vitest'; const key = 'assign'; let assign; ({ outer: { [key]: assign } } = { outer: { assign: Object.assign } }); assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['immutable computed destructured Object.create', (capability) =>
      `import { test } from 'vitest'; const key = 'create'; let create; ({ [key]: create } = Object); create({ runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['later-assigned stored helper bind', (capability) =>
      `import { test } from 'vitest'; function focus(register) { register.only('focused', () => {}); } let bound; bound = focus.bind(null); bound(${capability});`],
    ['alternative stored helper bind assignments', (capability) =>
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } let bound; bound = focus.bind(null, safe); bound = focus.bind(null); bound(${capability});`],
    ['later-assigned member-held Object.create', (capability) =>
      `import { test } from 'vitest'; const tools = {}; tools.create = Object.create; const args = tools.create({ runtime: ${capability} }); args.runtime.only('focused', () => {});`],
    ['later-assigned member-held Object.assign', (capability) =>
      `import { test } from 'vitest'; const tools = {}; tools.assign = Object.assign; tools.assign({}, { runtime: ${capability} }).runtime.only('focused', () => {});`],
    ['comma undefined default', (capability) =>
      `import { test } from 'vitest'; const U = (0, undefined); const { register = ${capability} } = { register: U }; register.only('focused', () => {}); test('required', () => {});`],
    ['logical undefined default', (capability) =>
      `import { test } from 'vitest'; const U = true && undefined; const { register = ${capability} } = { register: U }; register.only('focused', () => {}); test('required', () => {});`],
    ['conditional undefined default', (capability) =>
      `import { test } from 'vitest'; const U = true ? undefined : 1; const { register = ${capability} } = { register: U }; register.only('focused', () => {}); test('required', () => {});`],
    ['unknown conditional undefined or capability source', (capability) =>
      `import { test } from 'vitest'; declare const condition: boolean; const { register = ${capability} } = { register: condition ? undefined : ${capability} }; register.only('focused', () => {}); test('required', () => {});`],
    ['class constructor through new', (capability) =>
      `import { test } from 'vitest'; class C { constructor() { return ${capability}; } } new C().only('focused', () => {}); test('required', () => {});`],
    ['class constructor through Reflect.construct', (capability) =>
      `import { test } from 'vitest'; const C = class { constructor() { return ${capability}; } }; Reflect.construct(C, []).only('focused', () => {}); test('required', () => {});`],
    ['static class factory', (capability) =>
      `import { test } from 'vitest'; class C { static focus() { return ${capability}; } } C.focus().only('focused', () => {}); test('required', () => {});`],
    ['static class property', (capability) =>
      `import { test } from 'vitest'; const C = class { static register = ${capability}; }; C.register.only('focused', () => {}); test('required', () => {});`],
    ['instance class factory', (capability) =>
      `import { test } from 'vitest'; class C { focus() { return ${capability}; } } const tools = new C(); tools.focus().only('focused', () => {}); test('required', () => {});`],
    ['instance class property', (capability) =>
      `import { test } from 'vitest'; class C { register = ${capability}; } new C().register.only('focused', () => {}); test('required', () => {});`],
    ['static class tagged-template receiver', (capability) =>
      `import { test } from 'vitest'; class C { static register = ${capability}; static focus(strings) { this.register.only('focused', () => {}); } } C.focus\`ticket\`; test('required', () => {});`],
    ['instance class tagged-template receiver', (capability) =>
      `import { test } from 'vitest'; class C { register = ${capability}; focus(strings) { this.register.only('focused', () => {}); } } new C().focus\`ticket\`; test('required', () => {});`],
    ['static class getter', (capability) =>
      `import { test } from 'vitest'; class C { static register = ${capability}; static get focus() { return this.register; } } C.focus.only('focused', () => {}); test('required', () => {});`],
    ['instance class getter', (capability) =>
    `import { test } from 'vitest'; class C { register = ${capability}; get focus() { return this.register; } } new C().focus.only('focused', () => {}); test('required', () => {});`],
  ['mutable undefined default', (capability) =>
    `import { test } from 'vitest'; let U = undefined; const { register = ${capability} } = { register: U }; register.only('focused', () => {}); test('required', () => {});`]
  ];

  test.each(staticProvenanceCases)(
    'rejects bounded static provenance through %s', (_name, makeSource) => {
      expect(() => collectWindowsTestTitles('fixture.ts', makeSource('test')))
        .toThrow(/Exclusive or dynamically selected Vitest/);
    });

  test.each(staticProvenanceCases)(
    'accepts safe bounded static provenance through %s', (_name, makeSource) => {
      expect(() => collectWindowsTestTitles(
        'fixture.ts', makeSource('({ only() {} })')
      )).not.toThrow();
    });

test.each([
  ['push', `const args = []; args.push(test); focus(...args);`],
  ['index assignment', `const args = [safe]; args[0] = test; focus(...args);`],
      ['splice insertion', `const args = []; args.splice(0, 0, test); focus(...args);`],
      ['spread push', `const args = []; args.push(...[test]); focus(...args);`],
      ['aliased push', `const args = []; const alias = args; alias.push(test); focus(...args);`],
      ['later-assigned aliased push', `let alias; const args = []; alias = args; alias.push(test); focus(...args);`],
      ['dynamic index assignment', `const args = []; let index = 0; args[index] = test; focus(...args);`],
      ['apply read', `const args = []; args.push(test); focus.apply(null, args);`],
      ['later safe write', `const args = []; args.push(test); args[0] = { only() {} }; focus(...args);`],
      ['splice deletion', `const args = [safe, test]; args.splice(0, 1); focus(...args);`],
      ['negative splice deletion', `const args = [test, safe]; args.splice(-1, 1); focus(...args);`],
      ['read before safe write', `const args = [test]; focus(...args); args[0] = { only() {} };`],
      ['fill insertion', `const args = [safe]; args.fill(test); focus(...args);`],
      ['copyWithin reorder', `const args = [test, safe]; args.copyWithin(1, 0); focus(...args);`],
      ['reverse reorder', `const args = [test, safe]; args.reverse(); focus(...args);`],
  ['unshift insertion', `const args = []; args.unshift(test); focus(...args);`],
  ['sort reorder', `const args = [test, safe]; args.sort(); focus(...args);`],
  ['pop deletion', `const args = [test, safe]; args.pop(); focus(...args);`],
      ['pop removes runner safely', `const args = [safe, test]; args.pop(); focus(...args);`],
      ['shift removes runner safely', `const args = [test, safe]; args.shift(); focus(...args);`],
      ['splice removes runner safely', `const args = [test, safe]; args.splice(0, 1); focus(...args);`],
      ['splice removes all values', `const args = [safe, test]; args.splice(0); focus(...args);`],
      ['negative splice removes runner', `const args = [safe, test]; args.splice(-1, 1); focus(...args);`],
      ['fill replaces runner', `const args = [test]; args.fill(safe); focus(...args);`],
      ['alternative array source with runner', `declare const condition: boolean; let args = [safe]; if (condition) args = [test]; focus(...args);`],
      ['alternative array source before safe push', `declare const condition: boolean; let args = [safe]; if (condition) args = [test]; args.push(safe); focus(...args);`],
      ['conditional safe write', `declare const condition: boolean; const args = [test]; if (condition) args[0] = safe; focus(...args);`]
])('rejects capability-bearing mutable array %s', (_name, mutation) => {
  const source = `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } ${mutation}`;
  expect(() => collectWindowsTestTitles('fixture.ts', source))
    .toThrow(/Exclusive or dynamically selected Vitest/);
});

test.each([
  ['push', `const args = []; args.push(safe); focus(...args);`],
  ['index assignment', `const args = [safe]; args[0] = safe; focus(...args);`],
      ['splice insertion', `const args = []; args.splice(0, 0, safe); focus(...args);`],
      ['spread push', `const args = []; args.push(...[safe]); focus(...args);`],
      ['aliased push', `const args = []; const alias = args; alias.push(safe); focus(...args);`],
      ['later-assigned aliased push', `let alias; const args = []; alias = args; alias.push(safe); focus(...args);`],
      ['self spread', `const args = [safe]; args.push(...args); focus(...args);`],
      ['apply read', `const args = []; args.push(safe); focus.apply(null, args);`],
      ['fill', `const args = []; args.fill(safe); focus(...args);`],
      ['copyWithin', `const args = [safe, safe]; args.copyWithin(1, 0); focus(...args);`],
      ['reverse', `const args = [safe, safe]; args.reverse(); focus(...args);`],
  ['unshift', `const args = []; args.unshift(safe); focus(...args);`],
  ['sort', `const args = [safe, safe]; args.sort(); focus(...args);`],
  ['pop', `const args = [safe]; args.pop(); focus(...args);`],
  ['shift', `const args = [safe]; args.shift(); focus(...args);`],
  ['assignment replaces runner', `const args = [test]; args[0] = safe; focus(...args);`],
  ['assignment replays before safe push', `const args = [test]; args[0] = safe; args.push(safe); focus(...args);`],
  ['alternative safe array sources', `declare const condition: boolean; let args = [safe]; if (condition) args = [safe]; focus(...args);`],
  ['alternative safe array sources before safe push', `declare const condition: boolean; let args = [safe]; if (condition) args = [safe]; args.push(safe); focus(...args);`],
      ['conditional write', `declare const condition: boolean; const args = [safe]; if (condition) args[0] = safe; focus(...args);`]
])('accepts safe mutable array %s', (_name, mutation) => {
  const source = `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } ${mutation}`;
  expect(collectWindowsTestTitles('fixture.ts', source)).toEqual([]);
});

test.each([
  ['logical OR assignment', `const args = []; args[0] ||= test; focus(...args);`],
  ['logical AND assignment', `const args = []; args[0] &&= test; focus(...args);`],
  ['nullish assignment', `const args = []; args[0] ??= test; focus(...args);`],
  ['logical OR preserves prior runner', `const args = [test]; args[0] ||= safe; focus(...args);`],
  ['logical AND preserves prior runner', `const args = [test]; args[0] &&= safe; focus(...args);`],
  ['nullish assignment preserves prior runner', `const args = [test]; args[0] ??= safe; focus(...args);`],
  ['push call', `const args = []; args.push.call(args, test); focus(...args);`],
  ['push apply', `const args = []; args.push.apply(args, [test]); focus(...args);`],
  ['Reflect.apply push', `const args = []; Reflect.apply(args.push, args, [test]); focus(...args);`],
  ['Array.prototype push apply', `const args = []; Array.prototype.push.apply(args, [test]); focus(...args);`],
  ['Array.prototype push call', `const args = []; Array.prototype.push.call(args, test); focus(...args);`],
  ['bound push', `const args = []; const push = args.push.bind(args); push(test); focus(...args);`],
  ['rebound push', `const args = []; const push = args.push.bind(args).bind({}); push(test); focus(...args);`],
    ['unbound member alias', `const args = []; const push = args.push; push.call(args, test); focus(...args);`],
    ['destructured member alias', `const args = []; const { push } = args; push.call(args, test); focus(...args);`],
    ['unproven apply values', `declare const values: any[]; const args = []; args.push.apply(args, values); focus(...args);`],
    ['unproven spread values', `declare const values: any[]; const args = []; args.push(...values); focus(...args);`],
    ['helper-returned array', `const args = []; const get = () => args; get().push(test); focus(...args);`],
    ['helper-returned alias', `const args = []; function get() { return args; } const alias = get(); alias.push(test); focus(...args);`],
    ['Object.assign array write', `const args = []; Object.assign(args, { 0: test, length: 1 }); focus(...args);`],
    ['Reflect.set array write', `const args = []; Reflect.set(args, 0, test); focus(...args);`],
  ['member-held bound push', `const args = []; const methods = { push: args.push.bind(args) }; methods.push(test); focus(...args);`],
  ['helper push', `const args = []; function put(list, value) { list.push(value); } put(args, test); focus(...args);`],
  ['helper unshift', `const args = []; function put(list, value) { list.unshift(value); } put(args, test); focus(...args);`],
  ['helper splice', `const args = []; function put(list, value) { list.splice(0, 0, value); } put(args, test); focus(...args);`],
  ['helper index write', `const args = []; function put(list, value) { list[0] = value; } put(args, test); focus(...args);`],
  ['helper alias', `const args = []; function put(list, value) { const alias = list; alias.push(value); } put(args, test); focus(...args);`],
  ['object-held array', `const holder = { args: [] }; holder.args.push(test); focus(...holder.args);`],
  ['new Array index write', `const args = new Array(); args[0] = test; focus(...args);`]
  , ['sized new Array index write', `const args = new Array(1); args[0] = test; focus(...args);`]
  , ['new Array initial runner', `const args = new Array(test); focus(...args);`]
])('rejects capability-bearing indirect array mutation %s', (_name, mutation) => {
  const source = `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } ${mutation}`;
  expect(() => collectWindowsTestTitles('fixture.ts', source))
    .toThrow(/Exclusive or dynamically selected Vitest/);
});

test.each([
  ['logical OR assignment', `const args = []; args[0] ||= safe; focus(...args);`],
  ['logical AND assignment', `const args = []; args[0] &&= safe; focus(...args);`],
  ['nullish assignment', `const args = []; args[0] ??= safe; focus(...args);`],
  ['index write', `const args = []; args[0] = safe; focus(...args);`],
  ['push call', `const args = []; args.push.call(args, safe); focus(...args);`],
  ['push apply', `const args = []; args.push.apply(args, [safe]); focus(...args);`],
  ['Reflect.apply push', `const args = []; Reflect.apply(args.push, args, [safe]); focus(...args);`],
  ['Array.prototype push apply', `const args = []; Array.prototype.push.apply(args, [safe]); focus(...args);`],
  ['Array.prototype push call', `const args = []; Array.prototype.push.call(args, safe); focus(...args);`],
  ['bound push', `const args = []; const push = args.push.bind(args); push(safe); focus(...args);`],
  ['rebound push', `const args = []; const push = args.push.bind(args).bind({}); push(safe); focus(...args);`],
    ['unbound member alias', `const args = []; const push = args.push; push.call(args, safe); focus(...args);`],
    ['destructured member alias', `const args = []; const { push } = args; push.call(args, safe); focus(...args);`],
    ['known apply values', `const values = [safe]; const args = []; args.push.apply(args, values); focus(...args);`],
    ['known spread values', `const values = [safe]; const args = []; args.push(...values); focus(...args);`],
    ['helper-returned array', `const args = []; const get = () => args; get().push(safe); focus(...args);`],
    ['helper-returned alias', `const args = []; function get() { return args; } const alias = get(); alias.push(safe); focus(...args);`],
    ['Object.assign array write', `const args = []; Object.assign(args, { 0: safe, length: 1 }); focus(...args);`],
    ['Reflect.set array write', `const args = []; Reflect.set(args, 0, safe); focus(...args);`],
  ['member-held bound push', `const args = []; const methods = { push: args.push.bind(args) }; methods.push(safe); focus(...args);`],
  ['helper push', `const args = []; function put(list, value) { list.push(value); } put(args, safe); focus(...args);`],
  ['helper unshift', `const args = []; function put(list, value) { list.unshift(value); } put(args, safe); focus(...args);`],
  ['helper splice', `const args = []; function put(list, value) { list.splice(0, 0, value); } put(args, safe); focus(...args);`],
  ['helper index write', `const args = []; function put(list, value) { list[0] = value; } put(args, safe); focus(...args);`],
  ['helper alias', `const args = []; function put(list, value) { const alias = list; alias.push(value); } put(args, safe); focus(...args);`],
  ['object-held array', `const holder = { args: [] }; holder.args.push(safe); focus(...holder.args);`],
  ['new Array without runner', `const args = new Array(); focus(...args);`],
  ['new Array safe initial value', `const args = new Array(safe); focus(...args);`],
  ['unrelated helper arguments', `function put(list, value) { list.push(value); } const args = []; put(args, safe); put({}, test); focus(...args);`],
  ['custom method named push', `function use(custom) { const args = []; custom.push.call(args, test); focus(...args); } const custom = { push() {} }; use(custom);`],
  ['omitted apply arguments', `const args = []; args.push.apply(args); focus(...args);`],
  ['method call before later array assignment', `let args = { push() {} }; args.push.call(args, test); args = []; focus(...args);`],
  ['prototype bound helper arguments', `function put(list, value) { const push = Array.prototype.push.bind(list); push(value); } const args = []; put(args, safe); put({}, test); focus(...args);`]
])('accepts safe indirect array mutation %s', (_name, mutation) => {
  const source = `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } ${mutation}`;
  expect(collectWindowsTestTitles('fixture.ts', source)).toEqual([]);
});

test.each([
  ['nested Object.assign assignment', `let create; ({ outer: { create } } = Object.assign({}, { outer: Object })); create({ runtime: test }).runtime.only('focused', () => {});`],
  ['nested Object.create assignment', `let create; ({ outer: { create } } = Object.create({ outer: Object })); create({ runtime: test }).runtime.only('focused', () => {});`],
  ['computed Object.assign declaration', `const key = 'create'; const { outer: { [key]: create } } = Object.assign({}, { outer: Object }); create({ runtime: test }).runtime.only('focused', () => {});`],
  ['computed Object.create assignment', `const key = 'create'; let create; ({ outer: { [key]: create } } = Object.create({ outer: Object })); create({ runtime: test }).runtime.only('focused', () => {});`]
])('rejects capability from intrinsic invocation result: %s', (_name, mutation) => {
  const source = `import { test } from 'vitest'; ${mutation}`;
  expect(() => collectWindowsTestTitles('fixture.ts', source))
    .toThrow(/Exclusive or dynamically selected Vitest/);
});

test.each([
  ['local Object create', `const Object = { create() {} }; const { create } = Object.create; test('required', () => {});`, [{ title: 'required', enabled: true }]],
  ['local Object computed destructuring', `const Object = { create() {} }; const key = 'value'; let value; ({ [key]: value } = Object.create); test('required', () => {});`, [{ title: 'required', enabled: true }]],
  ['local Reflect shadow', `const Reflect = { get() { return {}; } }; const bind = Reflect.get(Object.create, 'bind'); const create = bind.call(Object.create, Object); const args = create({ runtime: test }); args.runtime.only('safe', () => {});`, []],
  ['later Object assignment', `let Object; let create; const key = 'create'; ({ [key]: create } = Object); Object = globalThis.Object; test('required', () => {});`, [{ title: 'required', enabled: true }]]
])('ignores non-intrinsic or later capability source: %s', (_name, mutation, expected) => {
  const source = `import { test } from 'vitest'; ${mutation}`;
  expect(collectWindowsTestTitles('fixture.ts', source)).toEqual(expected);
});

test.each([
  ['destructured bind call', `const { bind } = Object.create; const create = bind.call(Object.create, Object); create({ runtime: test }).runtime.only('focused', () => {});`],
  ['comma-selected bind apply', `const bind = (0, Object.create.bind); const create = bind.apply(Object.create, [Object]); create({ runtime: test }).runtime.only('focused', () => {});`],
  ['reflected bind apply', `const bind = Reflect.get(Object.create, 'bind'); const create = Reflect.apply(bind, Object.create, [Object]); create({ runtime: test }).runtime.only('focused', () => {});`],
    ['aliased Reflect.get bind', `const get = Reflect.get; const bind = get(Object.create, 'bind'); const create = bind.call(Object.create, Object); create({ runtime: test }).runtime.only('focused', () => {});`],
    ['destructured Reflect.get bind', `const { get } = Reflect; const bind = get(Object.create, 'bind'); const create = bind.call(Object.create, Object); create({ runtime: test }).runtime.only('focused', () => {});`],
  ['destructured bind call with captured prototype', `const { bind } = Object.create; const create = bind.call(Object.create, Object, { runtime: test }); create().runtime.only('focused', () => {});`],
  ['destructured bind apply with captured prototype', `const { bind } = Object.create; const create = bind.apply(Object.create, [Object, { runtime: test }]); create().runtime.only('focused', () => {});`],
  ['reflected bind apply with captured prototype', `const bind = Reflect.get(Object.create, 'bind'); const create = Reflect.apply(bind, Object.create, [Object, { runtime: test }]); create().runtime.only('focused', () => {});`]
])('rejects detached bind neighbor: %s', (_name, mutation) => {
  const source = `import { test } from 'vitest'; ${mutation}`;
  expect(() => collectWindowsTestTitles('fixture.ts', source))
    .toThrow(/Exclusive or dynamically selected Vitest/);
});

test.each([
  ['bind call', `const { bind } = Object.create; const create = bind.call(Object.create, Object, { runtime: safe }); create().runtime.only('safe', () => {});`],
  ['bind apply', `const { bind } = Object.create; const create = bind.apply(Object.create, [Object, { runtime: safe }]); create().runtime.only('safe', () => {});`],
  ['reflected bind apply', `const bind = Reflect.get(Object.create, 'bind'); const create = Reflect.apply(bind, Object.create, [Object, { runtime: safe }]); create().runtime.only('safe', () => {});`]
])('accepts detached bind without runner selection: %s', (_name, mutation) => {
  const source = `import { test } from 'vitest'; const safe = { only() {} }; ${mutation}`;
  expect(collectWindowsTestTitles('fixture.ts', source)).toEqual([]);
});

test.each([
  ['logical OR', `const chosen = focus.bind(null) || safe.bind(null); chosen(test);`],
  ['nullish coalescing', `const chosen = focus.bind(null) ?? safe.bind(null); chosen(test);`],
  ['logical AND branch order', `const chosen = safe.bind(null) && focus.bind(null); chosen(test);`]
    , ['custom bind result', `const custom = { bind() { return null; } }; const chosen = custom.bind() ?? focus.bind(null); chosen(test);`]
    , ['overridden function bind', `const safe = () => {}; safe.bind = () => null; const chosen = safe.bind() ?? focus.bind(null); chosen(test);`]
    , ['unknown condition logical AND', `declare const condition: boolean; const chosen = condition && focus.bind(null); chosen(test);`]
    , ['unknown condition logical OR', `declare const condition: boolean; const chosen = condition || focus.bind(null); chosen(test);`]
])('evaluates stored logical helper selection: %s', (_name, mutation) => {
  const source = `import { test } from 'vitest'; function safe() {} function focus(register) { register.only('focused', () => {}); } ${mutation}`;
  expect(() => collectWindowsTestTitles('fixture.ts', source))
    .toThrow(/Exclusive or dynamically selected Vitest/);
});

test.each([
  ['logical OR', `const chosen = safe.bind(null) || focus.bind(null); chosen(test);`],
  ['nullish coalescing', `const chosen = safe.bind(null) ?? focus.bind(null); chosen(test);`],
  ['logical AND branch order', `const chosen = focus.bind(null) && safe.bind(null); chosen(test);`]
    , ['false logical AND', `const chosen = false && focus.bind(null); chosen(test);`]
    , ['true logical OR', `const chosen = true || focus.bind(null); chosen(test);`]
])('accepts stored safe logical helper selection: %s', (_name, mutation) => {
  const source = `import { test } from 'vitest'; function safe() {} function focus(register) { register.only('focused', () => {}); } ${mutation}`;
  expect(collectWindowsTestTitles('fixture.ts', source)).toEqual([]);
});

test.each([
  ['logical OR', `[safe] || [test]`],
  ['logical AND', `[test] && [safe]`],
  ['nullish coalescing', `[safe] ?? [test]`]
])('evaluates stored logical array selection: %s', (_name, selection) => {
  const source = `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } const chosen = ${selection}; focus(...chosen);`;
  expect(collectWindowsTestTitles('fixture.ts', source)).toEqual([]);
});

test.each([
  ['mutable key', `let key = 'create';`],
  ['conditional key', `declare const condition: boolean; const key = condition ? 'create' : 'assign';`]
])('rejects dynamically selected global destructuring with %s', (_name, key) => {
  const source = `import { test } from 'vitest'; ${key} let create; ({ [key]: create } = Object); create({ runtime: test }).runtime.only('focused', () => {});`;
  expect(() => collectWindowsTestTitles('fixture.ts', source))
    .toThrow(/Exclusive or dynamically selected Vitest/);
});

test('rejects dynamically selected nested global capability destructuring', () => {
  const source = `import { test } from 'vitest'; let key = 'create'; let create; ({ outer: { [key]: create } } = { outer: { create: Object.create } });`;
  expect(() => collectWindowsTestTitles('fixture.ts', source))
    .toThrow(/Exclusive or dynamically selected Vitest/);
});

  test.each([
    ['logical AND', '[test] && [safe]'],
    ['logical OR', 'false || [safe]'],
    ['nullish coalescing', 'null ?? [safe]']
  ])('accepts statically unreachable %s spread operand', (_name, spread) => {
    expect(collectWindowsTestTitles('fixture.ts',
      `import { test } from 'vitest'; const safe = { only() {} }; function focus(register) { register.only('focused', () => {}); } focus(...(${spread}));`)) .toEqual([]);
  });

test("accepts non-call Object.create.apply member access", () => {
  const source = "import { test } from 'vitest'; const values = [Object.create.apply.foo]; values[0].only('focused', () => {});";
  expect(collectWindowsTestTitles('fixture.ts', source)).toEqual([]);
});

test("accepts ordinary holes, rests, helpers, factories, and opaque spreads without test capability", () => {
    const source = [
      "import { test } from 'vitest';",
      "declare const args: any[];",
      "const testLike = { only() {} };",
      "function pick([, value]: [null, string]) { return value.length; } pick([null, 'value']);",
      "function inspect(...values: any[]) { return values[0]?.length; } inspect(null, 'value');",
      "function inspectTail(prefix: any, ...values: any[]) { return values[0]?.length; } inspectTail(null, 'value');",
      "function inspectRest([...values]: any[]) { return values.length; } inspectRest(['value']);",
      "function focus(register: any) { register.only('not a registration', () => {}); } focus(...args, testLike);",
      "focus.call(null, testLike); focus.apply(null, [testLike]); focus.bind(null, testLike)(); Reflect.apply(focus, null, [testLike]);",
      "const safeArgs = () => [testLike]; focus.apply(null, safeArgs()); focus.apply(null, { 0: testLike, length: 1 });",
      "function ignoredTail(a: any, b: any, c: any, d: any, e: any, register: any) { return register?.length; } ignoredTail.apply(null, { 5: test, length: 1 });",
      "function ignoredLater(ignored: any, register: any) { return register?.length; } ignoredLater.apply(null, { 0: testLike, 1: test, length: 1 });",
      "function duplicateLength(a: any, b: any, c: any, d: any, e: any, register: any) { return register?.length; } duplicateLength.apply(null, { 5: test, length: 2, length: 1 });",
      "function safeSpread(register: any) { return register?.length; } safeSpread.apply(null, { ...{ 0: testLike }, length: 1 });",
      "function overwrittenSpread(register: any) { return register?.length; } overwrittenSpread.apply(null, { 0: test, ...{ 0: testLike }, length: 1 });",
      "function overwrittenLength(a: any, b: any, c: any, d: any, e: any, register: any) { return register?.length; } overwrittenLength.apply(null, { ...{ length: 6 }, 5: test, length: 1 });",
      "const safeBound = focus.bind(null, testLike); safeBound(); const invoke = Reflect.apply; invoke(focus, null, [testLike]);",
      "const safeLaterBound = focus.bind(null); safeLaterBound(testLike); safeLaterBound.apply(null, [testLike]);",
      "const safeTools = { invoke: Reflect.apply }; safeTools.invoke(focus, null, [testLike]);",
      "Reflect.apply.call(null, focus, null, [testLike]);",
      "Reflect.apply.apply(null, [focus, null, [testLike]]);",
      "function focusArguments() { arguments[0].only('not registration', () => {}); } focusArguments(testLike);",
      "function focusArrowArguments() { const read = () => arguments[0]; read().only('not registration', () => {}); } focusArrowArguments(testLike);",
      "function invokeSafe(fn: any, arg: any) { return fn.call(null, arg); } invokeSafe(focus, testLike);",
      "function invokeRest(fn: any, ...args: any[]) { return fn.apply(null, args); } invokeRest(focus, testLike);",
      "function invokeArguments(fn: any) { return fn.apply(null, arguments); } invokeArguments(focus, testLike);",
      "const safeArrayLike = () => ({ 0: testLike, length: 1 }); focus.apply(null, safeArrayLike());",
      "const aliasedArrayLike = { 0: testLike, length: 1 }; focus.apply(null, aliasedArrayLike);",
      "const getterArrayLike = { get 0() { return testLike; }, length: 1 }; focus.apply(null, getterArrayLike);",
      "function focusAliasedArguments() { const values = arguments; values[0].only('not registration', () => {}); } focusAliasedArguments(testLike);",
      "function focusReturnedArguments() { const read = () => arguments; read()[0].only('not registration', () => {}); } focusReturnedArguments(testLike);",
      "const { apply: reflectedApply } = Reflect; reflectedApply(focus, null, [testLike]);",
      "const reflectiveTools = { get invoke() { return Reflect.apply; } }; reflectiveTools.invoke(focus, null, [testLike]);",
      "const boundReflectApply = Reflect.apply.bind(null, focus, null); boundReflectApply([testLike]);",
      "globalThis.Reflect.get.call(null, test, 'length')('value');",
      "globalThis.Reflect.get(...[{ value: 1 }, 'value']);",
      "Reflect.apply(Reflect.get, null, [test, 'length'])('value');",
      "Reflect.apply(Reflect.get, null, { 0: test, 1: 'length', length: 2 })('value');",
      "globalThis.Object.assign.call(Object, {}, { value: testLike }).value.only('safe', () => {});",
      "globalThis.Object.assign.call(Object, ...[{}, { value: testLike }]).value.only('safe', () => {});",
      "Reflect.apply(Object.assign, Object, [{}, { value: testLike }]).value.only('safe', () => {});",
      "Reflect.apply(Object.assign, Object, { 0: {}, 1: { value: testLike }, length: 2 }).value.only('safe', () => {});",
      "const commaSafeCopy = (0, globalThis.Object.assign.bind(Object, {}, testLike))();",
      "commaSafeCopy.only('safe', () => {});",
      "function focusCommaSpread(register: any) { register.only('safe', () => {}); }",
      "focusCommaSpread.apply(null, [...(0, [testLike])]);",
      "const make = (_unused: unknown) => testLike; const tools = { make }; tools.make(1).only('safe', () => {});",
      "const getters = { get make() { return testLike; } }; getters.make().only('safe', () => {});",
    "const carrier = { make: () => ({ runtime: testLike }) }; carrier.make().runtime.only('safe', () => {});",
    "const safeTools = { get runner() { return testLike; } };",
    "function focusSafe(register: any) { register.only('safe', () => {}); }",
    "focusSafe(safeTools.runner);",
    "const nestedSafe = () => () => testLike;",
    "nestedSafe()().only('safe', () => {});",
"const innerSafe = nestedSafe();",
"innerSafe().only('safe', () => {});",
    "const helperTools = { get focus() { return focusSafe; } };",
    "helperTools.focus(testLike);",
    "const carrierTools = { get carrier() { return { runner: testLike }; } };",
    "carrierTools.carrier.runner.only('safe', () => {});",
"const objectTools = { get ctor() { return globalThis.Object; } };",
"objectTools.ctor.create({ safe: true });",
    "const safeBind = focusSafe.bind;",
    "const safeBound = safeBind(null);",
    "safeBound(testLike);",
    "const safeBindTools = { get bind() { return focusSafe.bind; } };",
    "const getterSafeBound = safeBindTools.bind(null);",
    "getterSafeBound(testLike);",
    "function getSafeBind() { return focusSafe.bind; }",
    "const returnedSafeBound = getSafeBind()(null);",
    "returnedSafeBound(testLike);",
    "const reflectedSafeBound = Reflect.apply(focusSafe.bind, focusSafe, [null]);",
    "reflectedSafeBound(testLike);",
"const genericBind = Function.prototype.bind;",
"const genericSafeBound = Reflect.apply(genericBind, focusSafe, [null]);",
"genericSafeBound(testLike);",
      "declare const prefix: any[];",
      "const prefixSafeBound = genericBind.call(focusSafe, ...prefix, testLike);",
      "prefixSafeBound();",
      "const getterSafeTools = { runner: testLike, get read() { return this.runner; } };",
      "function focusGetterSafe(register: any) { register.only('safe', () => {}); }",
      "focusGetterSafe(getterSafeTools.read);",
      "const spreadGetterSafeTools = { runner: testLike, get read() { return this.runner; } };",
      "const spreadGetterSafeValues = [...[spreadGetterSafeTools.read]];",
      "function focusSpreadGetterSafe(register: any) { register.only('safe', () => {}); }",
      "focusSpreadGetterSafe(spreadGetterSafeValues[0]);",
      "const createSafeArgs = Object.create({ 0: testLike, length: 1 });",
      "function focusCreateSafe(register: any) { register.only('safe', () => {}); }",
      "focusCreateSafe.apply(null, createSafeArgs);",
      "const restSafeTools = { get runner() { return testLike; } };",
      "function restSafeInner(...args: any[]) { args[0].only('safe', () => {}); }",
      "function restSafeOuter(...args: any[]) { restSafeInner(...args); }",
      "restSafeOuter(restSafeTools.runner);",
      "declare const restSafePrefix: any[];",
      "function restTailSafeInner(...args: any[]) { args[0].only('safe', () => {}); }",
      "function restTailSafeOuter(...args: any[]) { restTailSafeInner(...args); }",
      "restTailSafeOuter(...restSafePrefix, testLike);",
      "function restAfterHeadSafeInner(head: any, ...args: any[]) { args[0].only('safe', () => {}); }",
      "function restAfterHeadSafeOuter(...args: any[]) { restAfterHeadSafeInner('head', ...args); }",
      "restAfterHeadSafeOuter(testLike);",
  "const taggedTools = { register: testLike, focus() { this.register.only('safe', () => {}); } };",
  "taggedTools.focus`ticket`;",
  "function taggedArgumentSafe(strings: unknown, register: any) { register.only('safe', () => {}); }",
  "const taggedArgumentTools = { taggedArgumentSafe };",
  "taggedArgumentTools.taggedArgumentSafe`ticket ${testLike}`;",
  "function constructedSafe() { return testLike; }",
  "const constructedTools = { constructedSafe };",
  "new constructedTools.constructedSafe().only('safe', () => {});",
  "Reflect.construct(constructedTools.constructedSafe, []).only('safe', () => {});",
  "const [, ...safeRest] = [null, testLike];",
  "safeRest[0].only('safe', () => {});",
  "declare const safeRestTail: any[];",
  "const [, ...safeRestWithTail] = [null, testLike, ...safeRestTail];",
  "safeRestWithTail[0].only('safe', () => {});",
  "declare const opaqueRestSource: any[];",
  "const [, ...opaqueRest] = opaqueRestSource;",
  "opaqueRest[0]?.length;",
  "const U = undefined;",
  "const { register: defaultSafe = testLike } = { register: U };",
  "defaultSafe.only('safe', () => {});",
    "test('required', () => {});"
    ].join('\n');
    expect(collectWindowsTestTitles('fixture.ts', source))
      .toEqual([{ title: 'required', enabled: true }]);
}, 20_000);
test.each([
["member-held bound Reflect.apply receiver", "import { testLike } from 'vitest'; function focus(this: any) { this.register.only('safe', () => {}); } const invoke = Reflect.apply.bind(null, focus); const tools = { invoke }; tools.invoke({ register: testLike }, []);"],
["spread-bound Reflect.apply receiver", "import { testLike } from 'vitest'; const noop = () => {}; const invoke = Reflect.apply.bind(...[null, noop, null]); invoke([testLike]);"],
["nested rest runner binding", "import { testLike } from 'vitest'; const [[...[{ register }]]] = [[{ register: testLike }]]; register.only('safe', () => {});"],
["nested rest runner for-of", "import { testLike } from 'vitest'; for (const [[...[{ register }]]] of [[[{ register: testLike }]]]) { register.only('safe', () => {}); }"],
["nested rest runner parameter", "import { testLike } from 'vitest'; function focus(...[, { register }]) { register.only('safe', () => {}); } focus(null, { register: testLike });"],
["explicit undefined object default", "import { testLike } from 'vitest'; const { register = testLike } = { register: undefined }; register.only('safe', () => {});"],
["explicit undefined array default", "import { testLike } from 'vitest'; const [register = testLike] = [undefined]; register.only('safe', () => {});"],
["stored Array.of result", "import { testLike } from 'vitest'; const args = Array.of(testLike); args[0].only('safe', () => {});"]
])('accepts bounded safe provenance through %s', (_name, source) => {
const titles = collectWindowsTestTitles('fixture.ts', source);
expect(titles).toEqual([]);
});
});
