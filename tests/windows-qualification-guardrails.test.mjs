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

  test.each([
    ["shadowed process object", "const process={platform:'linux'}; if(process.platform==='win32'){test('required',()=>{});}"],
    ["shadowed callback parameter", "describe('outer',(process)=>{if(process.platform==='win32'){test('required',()=>{});}});"],
    ["shadowed process import", "import process from 'other'; if(process.platform==='win32'){test('required',()=>{});}"],
    ["mutable process binding", "let process={platform:'linux'}; if(process.platform==='win32'){test('required',()=>{});}"],
    ["unverified p.platform", "const p={platform:'win32'}; if(p.platform==='win32'){test('required',()=>{});}"],
    ["unproven runIf predicate", "const process={platform:'win32'}; test.runIf(process.platform==='win32')('required',()=>{});"],
    ["unproven skipIf predicate", "const process={platform:'linux'}; test.skipIf(process.platform!=='win32')('required',()=>{});"]
  ])("independent review C does not count unproven Windows platform predicate: %s", (_name, source) => {
    expect(collectWindowsTestTitles("fixture.ts", source)).toEqual([
      { title: "required", enabled: false }
    ]);
  });

  test.each([
    ["global process", "if(process.platform==='win32'){test('required',()=>{});}"],
    ["node:process default", "import process from 'node:process'; if(process.platform==='win32'){test('required',()=>{});}"],
    ["node:process alias", "import p from 'node:process'; if(p.platform==='win32'){test('required',()=>{});}"],
    ["node:process namespace", "import * as p from 'node:process'; if(p.platform==='win32'){test('required',()=>{});}"],
    ["node:process named platform", "import {platform as osPlatform} from 'node:process';if(osPlatform==='win32'){test('required',()=>{});}"],
    ["immutable process alias", "const p=process;if(p.platform==='win32'){test('required',()=>{});}"],
    ["Windows else", "if(process.platform!=='win32'){} else {test('required',()=>{});}"],
    ["Windows skipIf", "test.skipIf(process.platform!=='win32')('required',()=>{});"],
    ["Windows runIf", "test.runIf(process.platform==='win32')('required',()=>{});"]
  ])("independent review C preserves verified Windows predicates: %s", (_name, source) => {
    expect(collectWindowsTestTitles("fixture.ts", source)).toEqual([
      { title: "required", enabled: true }
    ]);
  });

  test.each([
    ["test alias", "const t=test;t.only('extra',()=>{});test('required',()=>{});"],
    ["it computed exclusive", "const t=it;t['only']('extra',()=>{});test('required',()=>{});"],
    ["describe alias", "const t=describe;t.only('extra',()=>{});test('required',()=>{});"],
    ["transitive const alias", "const t=test;const u=t;u.only('extra',()=>{});test('required',()=>{});"],
    ["destructured exclusive", "const {only}=test;only('extra',()=>{});test('required',()=>{});"],
    ["aliased destructured exclusive", "const {only:isolated}=it;isolated('extra',()=>{});test('required',()=>{});"],
    ["destructured const alias", "const t=test;const {only:isolated}=t;isolated('extra',()=>{});"],
    ["property exclusive alias", "const exclusive=test.only;exclusive('extra',()=>{});"],
    ["mutable test alias", "let t=test;t.only('extra',()=>{});"],
    ["computed unknown alias", "const t=test;t[modifier]('extra',()=>{});"]
  ])("independent review D rejects aliased exclusive Vitest execution: %s", (_name, source) => {
    expect(() => collectWindowsTestTitles("fixture.ts", source))
      .toThrow(/Exclusive or dynamically selected Vitest|Mutable Vitest/);
  });

  test.each([
    ["immutable test alias", "const t=test;t('required',()=>{});"],
    ["aliased describe callback", "const s=describe;s('suite',()=>{const t=test;t('required',()=>{});});"],
    ["named Vitest import", "import {test as scenario} from 'vitest';scenario('required',()=>{});"],
    ["aliased test.each", "const t=test;t.each(['required'])('%s',()=>{});"],
    ["unrelated .only method", "const o={only(){}};o.only('hello');test('required',()=>{});"],
    ["unrelated only destructuring", "const {only}=other;only('hello');test('required',()=>{});"],
    ["original test.each", "test.each(['required'])('%s',()=>{});"]
  ])("independent review D preserves verified Vitest registration: %s", (_name, source) => {
    expect(collectWindowsTestTitles("fixture.ts", source)).toEqual([
      { title: "required", enabled: true }
    ]);
  });

  test.each([
    ["shadowed test function", "const test=(_name,_fn)=>{}; test('required',()=>{});"],
    ["unproven alias", "const t=other; t('required',()=>{});"],
    ["non-Vitest import", "import {test} from 'other'; test('required',()=>{});"]
  ])("independent review D never counts unproven aliases as mandatory coverage: %s", (_name, source) => {
    expect(collectWindowsTestTitles("fixture.ts", source)).toEqual([]);
  });

  test.each([
    ["PowerShell subexpression", '-t ".*|$(Write-Output SELECTOR_MUTATION)"'],
    ["PowerShell environment variable", '-t "$env:SELECTOR_MUTATION"'],
    ["PowerShell braced variable", '-t "${pattern}"'],
    ["PowerShell embedded variable", '-t "foo$bar"'],
    ["PowerShell unquoted substitution", '-t $(Write-Output selector)'],
    ["PowerShell equals selector", '--testNamePattern=".*|$(Write-Output selector)"'],
    ["PowerShell escape character", '-t "foo`$bar"']
  ])("independent review E rejects expanded PowerShell selectors: %s", (_name, selector) => {
    const workflow = load();
    windowsStep(workflow, "Windows helper package hygiene").run =
      "npm test -- tests/package-hygiene.test.ts " + selector + " --reporter=verbose";
    expect(inspect(workflow).some((f) =>
      f.includes("unaudited Vitest command") && f.includes("PowerShell"))).toBe(true);
  });

  test.each([
    ["double-quoted regex end anchor", '-t ".*$"'],
    ["single-quoted regex end anchor", "-t '.*$'"],
    ["single-quoted literal dollar expression", "-t '.*|$(literal)'"],
    ["valid regex alternation", '-t "^(pins|requires|checks).*$"']
  ])("independent review E preserves nonexpanded PowerShell regex selectors: %s", (_name, selector) => {
    const workflow = load();
    windowsStep(workflow, "Windows helper package hygiene").run =
      "npm test -- tests/package-hygiene.test.ts " + selector + " --reporter=verbose";
    expect(inspect(workflow)).toEqual([]);
  });

  test.each([
    ["test", "V.test.only('extra', () => {});"],
    ["it", "V.it.only('extra', () => {});"],
    ["describe", "V.describe.only('extra', () => {});"],
    ["bracket test", "V['test'].only('extra', () => {});"],
    ["bracket only", "V.it['only']('extra', () => {});"],
    ["computed only", "V.test[modifier]('extra', () => {});"],
    ["computed namespace", "V[modifier].only('extra', () => {});"],
    ["namespace const alias", "const W = V; W.test.only('extra', () => {});"],
    ["transitive namespace alias", "const W = V; const N = W; N.it.only('extra', () => {});"],
    ["member const alias", "const t = V.test; t.only('extra', () => {});"],
    ["destructured member", "const { test: t } = V; t.only('extra', () => {});"],
    ["computed literal destructure", "const { ['test']: t } = V; t.only('extra', () => {});"],
    ["computed unresolved destructure", "const { [member]: t } = V; t.only('extra', () => {});"],
    ["computed alias", "const t = V[member]; t.only('extra', () => {});"]
  ])("independent finding D rejects Vitest namespace exclusive selection: %s", (_name, mutation) => {
    const source = "import * as V from 'vitest'; import { test } from 'vitest'; " +
      mutation + " test('required', () => {});";
    expect(() => collectWindowsTestTitles("fixture.ts", source))
      .toThrow(/Exclusive or dynamically selected Vitest tests are unaudited/);
  });

  test.each([
    ["namespace test", "V.test('required', () => {});"],
    ["namespace it", "V.it('required', () => {});"],
    ["namespace describe", "V.describe('suite', () => { V.test('required', () => {}); });"],
    ["immutable namespace", "const W = V; W.test('required', () => {});"],
    ["immutable function", "const t = V.test; t('required', () => {});"],
    ["destructured named", "const { test: t } = V; t('required', () => {});"],
    ["computed destructure", "const { ['test']: t } = V; t('required', () => {});"],
    ["namespace each", "V.test.each(['required'])('%s', () => {});"],
    ["conditional suite", "V.describe.skipIf(process.platform !== 'win32')('suite', () => { V.test('required', () => {}); });"],
    ["conditional test", "V.test.runIf(process.platform === 'win32')('required', () => {});"],
    ["aliased named import", "import { test as t } from 'vitest'; t('required', () => {});"],
    ["unrelated exclusive", "import * as Other from 'other'; Other.test.only('extra', () => {}); test('required', () => {});"],
    ["shadowed namespace", "{ const V = { test: { only() {} } }; V.test.only('extra'); } test('required', () => {});"],
    ["type-only namespace", "import type * as Types from 'vitest'; type T = Types.Suite; test('required', () => {});"]
  ])("independent finding D keeps eligible namespace registrations: %s", (_name, mutation) => {
    const source = "import * as V from 'vitest'; " + mutation;
    expect(collectWindowsTestTitles("fixture.ts", source))
      .toEqual([{ title: "required", enabled: true }]);
  });

  test("independent finding D never counts mutable or unknown namespace aliases", () => {
    expect(() => collectWindowsTestTitles("fixture.ts",
      "import * as V from 'vitest'; let W = V; W.test('required', () => {});"))
      .toThrow(/Mutable Vitest namespace aliases/);
    expect(collectWindowsTestTitles("fixture.ts",
      "const W = other; W.test('required', () => {});"))
      .toEqual([]);
    expect(collectWindowsTestTitles("fixture.ts",
      "import * as W from 'other'; W.test('required', () => {});"))
      .toEqual([]);
  });

  test.each([
    ["test", "V.test.only('extra', () => {});"],
    ["it", "V.it.only('extra', () => {});"],
    ["describe", "V.describe.only('extra', () => {});"],
    ["immutable namespace", "const W = V; W.test.only('extra', () => {});"],
    ["immutable function", "const t = V.test; t.only('extra', () => {});"],
    ["unresolved selector", "V[modifier].only('extra', () => {});"],
    ["computed destructuring", "const { [member]: t } = V; t.only('extra', () => {});"]
  ])("independent finding D blocks namespace-exclusive workflow evidence: %s", (_name, mutation) => {
    const workflow = load();
    const mandatory = [
      "pins the repository package inventory to its runtime files",
      "requires the Windows process host only for Windows package builds",
      "checks the parent route before treating an absent Windows host as optional"
    ].map((name) => "test(" + JSON.stringify(name) + ", () => {});").join("\n");
    const source = "import * as V from 'vitest'; import { test } from 'vitest'; " +
      mutation + mandatory;
    const findings = inspectQualificationWorkflow(workflow, (path) =>
      path === "tests/package-hygiene.test.ts" ? source :
        readFileSync(join(root, path), "utf8"));
    expect(findings).toContain("Could not parse mandatory Vitest declarations: tests/package-hygiene.test.ts");
  });

  test("independent finding D accepts verified namespace registrations in Windows workflow", () => {
    const source = "import * as V from 'vitest'; const W = V; " +
      "W.test('pins the repository package inventory to its runtime files', () => {}); " +
      "V.it('requires the Windows process host only for Windows package builds', () => {}); " +
      "W.test.each(['checks the parent route before treating an absent Windows host as optional'])('%s', () => {});";
    const findings = inspectQualificationWorkflow(load(), (path) =>
      path === "tests/package-hygiene.test.ts" ? source :
        readFileSync(join(root, path), "utf8"));
    expect(findings).toEqual([]);
  });
});
