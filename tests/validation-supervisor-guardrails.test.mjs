import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, URL } from "node:url";
import { describe, expect, test } from "vitest";
import { inspectSupervisorSource, inspectSupervisorSources, SUPERVISOR_SOURCES } from "../scripts/check-supervisor-dispatch.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));

describe("validation supervisor direct-execution guard", () => {
  test("accepts the production supervisor source inventory", () => {
    expect(inspectSupervisorSources()).toEqual([]);
    expect(SUPERVISOR_SOURCES).toContain("src/services/windows-process-host.ts");
    expect(SUPERVISOR_SOURCES).toContain("src/services/process-exec.ts");
    for (const path of SUPERVISOR_SOURCES) {
      expect(readFileSync(join(root, path), "utf8").length).toBeGreaterThan(0);
    }
  });

  test.each([
    ["shell launch option", "import { spawn } from 'node:child_process'; spawn('node.exe', [], { shell: true });"],
    ["shell option from a variable", "spawn('node.exe', [], { shell });"],
    ["shell string execution", "import { exec } from 'node:child_process'; exec('node -v');"],
    ["shell string sync execution", "import { execSync } from 'node:child_process'; execSync('node -v');"],
    ["aliased shell execution", "import { exec as runCommand } from 'node:child_process'; runCommand('node -v');"],
    ["CommonJS execution alias", "const cp = require('node:child_process'); cp.exec('node -v');"],
    ["direct command interpreter", "spawn('cmd.exe', ['/c', 'dir']);"],
    ["PowerShell interpreter", "spawn('powershell.exe', ['-Command', 'Get-ChildItem']);"],
    ["batch wrapper", "spawn('C:\\\\Tools\\\\npm.cmd', ['test']);"],
    ["cross-spawn import", "import crossSpawn from 'cross-spawn';"],
    ["cross-spawn require", "const crossSpawn = require('cross-spawn');"],
    ["private shim parsing", "crossSpawn._parse('npm', [], {});"]
  ])("rejects %s", (_case, source) => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source).length).toBeGreaterThan(0);
  });


  test.each([
    ["alias across local declarations", "import { execFile as safe } from 'node:child_process'; const runner = safe; runner('cmd.exe', []);"],
    ["dynamic import", "const p = import('node:child_process');"],
    ["dynamic require", "const p = require(moduleName);"],
    ["aliased require", "const loader = require; const cp = loader(\"node:child_process\");"],
    ["parenthesized require alias", "const loader = (require); const cp = loader('node:child_process'); cp.exec('cmd.exe');"],
    ["type-asserted require alias", "const loader = require as unknown as (name: string) => any; const cp = loader('node:child_process'); cp.exec('cmd.exe');"],
    ["parenthesized require call", "(require)('node:module');"],
    ["type-asserted require call", "(require as any)('node:child_process');"],
    ["comma require call", "(0, require)('node:child_process');"],
    ["comma require alias", "const loader = (0, require); loader('node:child_process');"],
    ["assigned require alias", "let loader; loader = require; loader('node:child_process');"],
    ["object-destructured require alias", "let loader; ({ loader } = { loader: require }); loader('node:child_process');"],
    ["array-destructured require alias", "let loader; [loader] = [require]; loader('node:child_process');"],
    ["function constructor", "const create = Function(\"return 1\");"],
    ["require with computed member", "const p = require('node:child_process'); p['exec']('echo nope');"],
    ["namespace import", "import * as cp from 'node:child_process'; cp.exec('echo nope');"],
    ["function evaluation", "new Function('return require(\\\"node:child_process\\\")')();"],
    ["global Function property alias", "const make = globalThis['Function']; make(\"return process.getBuiltinModule('node:child_process')\")();"],
    ["bare Function alias", "const make = Function; make(\"return process.getBuiltinModule('node:child_process')\")();"],
    ["mutable global Function property alias", "let make = globalThis['Function']; make(\"return process.getBuiltinModule('node:child_process')\")();"],
    ["mutable bare Function alias", "let make = Function; make(\"return process.getBuiltinModule('node:child_process')\")();"],
    ["computed global Function constructor", "globalThis['Fun' + 'ction'](\"return process.getBuiltinModule('node:child_process')\")();"],
    ["constructor-chain Function", "globalThis.constructor.constructor(\"return process.getBuiltinModule('node:child_process')\")();"],
  ["object constructor chain", "({}).constructor.constructor(\"return 42\")();"],
  ["async function constructor", "(async () => {}).constructor(\"return 42\")();"],
  ["destructured function value constructor", "const { make } = { make: () => {} }; make.constructor(\"return 42\")();"],
  ["inherited destructured object constructor", "const { constructor: Base } = {}; Base.constructor(\"return 42\")();"],
  ["shadowed destructured object constructor", "function safeFunction() {} const { constructor: Base } = { constructor: safeFunction }; Base.constructor(\"return 42\")();"],
  ["nested destructured object constructor", "const { nested: { constructor: Base } } = { nested: {} }; Base.constructor(\"return 42\")();"],
  ["aliased async function constructor", "const AsyncFunction = (async () => {}).constructor; AsyncFunction(\"return 42\")();"],
      ["member-valued function constructor", "const holder = { make() {} }; holder.make.constructor(\"return 42\")();"],
      ["class-instance method constructor", "class Holder { make() {} } new Holder().make.constructor(\"return 42\")();"],
      ["assigned class-instance method constructor", "class Holder { make() {} } const holder = new Holder(); holder.make.constructor(\"return 42\")();"],
  ["global Object constructor", "Object.constructor(\"return 42\")();"],
  ["function prototype constructor", "const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor; AsyncFunction(\"return 42\")();"],
      ["aliased function prototype getter", "const getProto = Object.getPrototypeOf; const AsyncFunction = getProto(async function () {}).constructor; AsyncFunction(\"return 42\")();"],
      ["destructured function prototype getter", "const { getPrototypeOf: getProto } = Object; const AsyncFunction = getProto(async function () {}).constructor; AsyncFunction(\"return 42\")();"],
      ["stored function prototype", "const proto = Object.getPrototypeOf(async function () {}); const AsyncFunction = proto.constructor; AsyncFunction(\"return 42\")();"],
      ["dunder function prototype", "const AsyncFunction = (async function () {}).__proto__.constructor; AsyncFunction(\"return 42\")();"],
  ["destructured async function constructor", "const { constructor: make } = async function () {}; make(\"return 42\")();"],
  ["destructured constructor assignment", "let Base; ({ constructor: Base } = {}); Base.constructor(\"return 42\")();"],
      ["destructured member constructor assignment", "const holder = {}; ({ constructor: holder.make } = {}); holder.make.constructor(\"return 42\")();"],
      ["dynamic destructured constructor target", "const holder = {}; ({ constructor: holder[key] } = {}); holder[key].constructor(\"return 42\")();"],
  ["array-destructured function assignment", "let make; [make] = [() => {}]; make.constructor(\"return 42\")();"],
  ["aliased object constructor chain", "const Base = {}.constructor; Base.constructor(\"return 42\")();"],
  ["split constructor alias", "const ctor = globalThis.constructor; ctor.constructor(\"return process.getBuiltinModule('node:child_process')\")();"],
  ["comma constructor alias", "const ctor = (0, globalThis.constructor); ctor.constructor(\"return 42\")();"],
  ["destructured constructor capability", "const { constructor: ctor } = globalThis; ctor.constructor(\"return 42\")();"],
  ["destructured constructor default", "const { constructor: ctor = globalThis.constructor } = {}; ctor.constructor(\"return 42\")();"],
  ["comma global object alias", "const runtime = (0, globalThis); runtime.eval('process');"],
    ["object-destructured global object", "const { runtime } = { runtime: globalThis }; runtime.eval('process');"],
    ["mutable process object alias", "let runtime = process; runtime.getBuiltinModule('node:child_process').exec('node -v');"]
  ])("rejects an unaudited loading route: %s", (_case, source) => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)).not.toEqual([]);
  });

  test.each([
    ["computed double-quoted shell", "spawn('node.exe', [], { [\"shell\"]: true });"],
    ["computed single-quoted shell", "spawn('node.exe', [], { ['shell']: false });"],
    ["computed template shell", "spawn('node.exe', [], { [`shell`]: true });"],
    ["aliased spawn", "import { spawn as runNative } from 'node:child_process'; runNative('node.exe', [], { ['shell']: true });"],
    ["aliased execFile", "import { execFile as runNative } from 'node:child_process'; runNative('node.exe', [], { ['shell']: true });"],
    ["unknown computed option", "spawn('node.exe', [], { [optionName]: true });"],
    ["unknown computed expression", "spawn('node.exe', [], { ['sh' + 'ell']: true });"],
    ["opaque option object", "const opts = { stdio: 'pipe' }; spawn('node.exe', [], opts);"],
    ["spread process options", "spawn('node.exe', [], { ...runtimeOptions });"]
  ])("rejects shell-capable or unverifiable native launch options: %s", (_name, code) => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", code))
      .not.toEqual([]);
  });

  test.each([
    ["global process method", "process.getBuiltinModule('node:child_process');"],
    ["node:process import", "import process from 'node:process'; process.getBuiltinModule('node:child_process');"],
    ["named default process import", "import { default as runtime } from 'node:process'; runtime.getBuiltinModule('node:child_process');"],
    ["namespace default process object", "import * as processModule from 'node:process'; processModule.default.getBuiltinModule('node:child_process');"],
    ["element access", "process['getBuiltinModule']('node:child_process');"],
    ["dynamic element access", "process[loaderName]('node:child_process');"],
    ["destructured capability", "const { getBuiltinModule } = process; getBuiltinModule('node:child_process');"],
    ["destructured process object alias", "process.default = process; const { default: runtime } = process; runtime.getBuiltinModule('node:child_process');"],
    ["destructured default alias", "const { getBuiltinModule: load = fallback } = process; load('node:child_process');"],
    ["computed destructuring", "const { [loaderName]: load } = process; load('node:child_process');"],
    ["process object rest", "const { ...processApi } = process; processApi.getBuiltinModule('node:child_process');"],
    ["process object spread", "const processApi = { ...process }; processApi.getBuiltinModule('node:child_process');"],
    ["logical process object alias", "const runtime = process || {}; runtime.getBuiltinModule('node:child_process');"],
    ["nullish process object alias", "const runtime = process ?? {}; runtime.getBuiltinModule('node:child_process');"],
  ["conditional process object alias", "const runtime = enabled ? process : {}; runtime.getBuiltinModule('node:child_process');"],
  ["comma process object alias", "const runtime = (0, process); runtime.getBuiltinModule('node:child_process');"],
  ["object-property process value", "const holder = { runtime: process }; holder.runtime.getBuiltinModule('node:child_process');"],
["numeric computed process object access", "const holder = { 0: process }; holder[0 + 0].getBuiltinModule('node:child_process').exec('cmd.exe');"],
["comma computed process object access", "const holder = { 0: process }; holder[(0, 0)].getBuiltinModule('node:child_process').exec('cmd.exe');"],
    ["object-destructured process value", "const { runtime } = { runtime: process }; runtime.getBuiltinModule('node:child_process');"],
  ["nested object process destructuring", "const { nested: { getBuiltinModule } } = { nested: process }; getBuiltinModule('node:child_process');"],
  ["identifier-backed process destructuring", "const source = { runtime: process }; const { runtime } = source; runtime.getBuiltinModule('node:child_process');"],
  ["identifier-backed process assignment", "const source = { runtime: process }; let runtime; ({ runtime } = source); runtime.getBuiltinModule('node:child_process');"],
  ["nested process destructuring default", "const { missing: { getBuiltinModule: load } = process } = {}; load('node:child_process');"],
    ["process destructuring default", "const { process: runtime = process } = {}; runtime.getBuiltinModule('node:child_process');"],
    ["aliased process object", "const runtime = process; runtime.getBuiltinModule('node:child_process');"],
    ["process object assigned later", "let runtime = {}; runtime = process; runtime.getBuiltinModule('node:child_process').exec('node -v');"],
    ["process object assigned by nullish assignment", "let runtime; runtime ??= process; runtime.getBuiltinModule('node:child_process').exec('node -v');"],
    ["process object assigned to an object property", "const holder = {}; holder.runtime = process; holder.runtime.getBuiltinModule('node:child_process').exec('node -v');"],
    ["process object nullish-assigned to an object property", "const holder = {}; holder.runtime ??= process; holder.runtime.getBuiltinModule('node:child_process').exec('node -v');"],
    ["numeric computed process assignment", "const holder = {}; holder[1 + 2] = process; holder[3].getBuiltinModule('node:child_process').exec('cmd.exe');"],
    ["named numeric computed process assignment", "const one = 1, two = 2; const holder = {}; holder[one + two] = process; holder[3].getBuiltinModule('node:child_process').exec('cmd.exe');"],
      ["process object destructured into an object property", "const holder = {}; ({ runtime: holder.runtime } = { runtime: process }); holder.runtime.getBuiltinModule('node:child_process').exec('node -v');"],
      ["process object returned by a local function", "const runtime = () => process; runtime().getBuiltinModule('node:child_process').exec('node -v');"],
      ["process object returned by a block-bodied function", "const runtime = () => { return process; }; runtime().getBuiltinModule('node:child_process').exec('node -v');"],
    ["destructured process object assignment", "let runtime; ({ runtime } = { runtime: process }); runtime.getBuiltinModule('node:child_process').exec('node -v');"],
    ["nested process destructuring assignment default", "let runtime; ({ outer: { runtime = process } } = { outer: {} }); runtime.getBuiltinModule('node:child_process').exec('node -v');"],
    ["destructured process capability assignment", "let load; ({ getBuiltinModule: load } = process); load('node:child_process');"],
    ["computed process capability assignment", "let load; ({ [loaderName]: load } = process); load('node:child_process');"],
    ["process object rest assignment", "let processApi; ({ ...processApi } = process); processApi.getBuiltinModule('node:child_process');"],
    ["array-destructured process object", "const [runtime] = [process]; runtime.getBuiltinModule('node:child_process');"],
    ["array-destructured process object assignment", "let runtime; [runtime] = [process]; runtime.getBuiltinModule('node:child_process');"],
    ["array rest process capability", "let runtime; [, ...runtime] = [safe, process]; runtime[0].getBuiltinModule('node:child_process');"],
    ["parameter destructured capability", "function load({ getBuiltinModule } = process) { getBuiltinModule('node:child_process'); } load();"],
    ["parameter process alias default", "function load(runtime = process) { runtime.getBuiltinModule('node:child_process'); } load();"],
    ["destructured process through globalThis", "const { process: runtime } = globalThis; runtime.getBuiltinModule('node:child_process');"],
    ["destructured process through globalThis assignment", "let runtime; ({ process: runtime } = globalThis); runtime.getBuiltinModule('node:child_process');"],
    ["destructured global object assignment", "let runtimeGlobal = {}; ({ runtimeGlobal } = { runtimeGlobal: globalThis }); runtimeGlobal.Function(\"return process.getBuiltinModule('node:child_process')\")();"],
    ["globalThis process object", "globalThis.process.getBuiltinModule('node:child_process').exec('node -v');"],
    ["node:process runtime re-export", "export { getBuiltinModule } from 'node:process';"],
    ["node:process default re-export", "export { default as runtime } from 'node:process';"],
    ["imported process local re-export", "import process from 'node:process'; export { process };"],
    ["aliased capability", "const load = process.getBuiltinModule; const loader = load; loader('node:child_process');"],
      ["node:vm dynamic evaluation", "import vm from 'node:vm'; vm.runInThisContext(\"process.getBuiltinModule('node:child_process')\");"]
  ])("rejects process module loading through %s", (_case, source) => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)).not.toEqual([]);
  });

test.each([
  ["Object.assign", "const copy = Object.assign({}, process); copy.getBuiltinModule('node:child_process').exec('id');"],
  ["Object.create", "const copy = Object.create(process); copy.getBuiltinModule('node:child_process').exec('id');"]
])("rejects process capability copies through %s", (_name, source) => {
  expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)
    .some((finding) => finding.includes("process.getBuiltinModule"))).toBe(true);
});

test.each([
  ["ambient process", "declare const process: any; process.getBuiltinModule('node:child_process');"],
  ["ambient var process", "declare var process: any; process.getBuiltinModule('node:child_process');"],
  ["ambient globalThis", "declare const globalThis: any; globalThis.Function('return 42')();"],
  ["ambient Object", "declare const Object: any; Reflect.get(Object, 'constructor')('return 42')();"]
])("treats %s as the erased runtime global", (_name, source) => {
  expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)).not.toEqual([]);
});

  test("accepts unrelated process use and unrelated getBuiltinModule methods", () => {
    const source = [
      "process.cwd();",
      "process.argv.slice(2);",
      "const processLike = { getBuiltinModule() { return undefined; } };",
      "processLike.getBuiltinModule();",
      "const data = {};",
      "data.constructor('ordinary');",
      "const ordinaryValue = 42;",
      "const { constructor: Ordinary } = { constructor: ordinaryValue };",
      "Ordinary.constructor('ordinary');",
      "const copied = { ...processLike }; copied.getBuiltinModule();",
      "const holder = {}; holder.api = { getBuiltinModule() { return undefined; } }; holder.api.getBuiltinModule();",
      "const descriptors = Object.getOwnPropertyDescriptors({ value: 1 });",
      "const descriptor = Object.getOwnPropertyDescriptor({ value: 1 }, 'value');",
      "const entries = Object.fromEntries(Object.entries({ value: 1 }));",
      "const { getOwnPropertyDescriptors: plainDescriptors } = Object;",
      "plainDescriptors({ value: 1 });",
      "const { get: plainGet } = Reflect;",
      "plainGet({ value: 1 }, 'value');",
      "import { spawn } from 'node:child_process'; spawn('node.exe', ['--version']);"
    ].join("\n");
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)).toEqual([]);
  });

  test("terminates local function-return cycles without inventing process capability", () => {
    const source = "const runtime = () => runtime(); runtime().getBuiltinModule('node:child_process');";
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)).toEqual([]);
  });

test.each([
  ["process helper argument",
    "function load(runtime: typeof process) { return runtime.getBuiltinModule('node:child_process'); } load(process).exec('cmd.exe');",
    /process\.getBuiltinModule/],
  ["require helper argument",
    "function load(factory) { return factory('node:child_process'); } const cp = load(require); cp.exec('cmd.exe');",
    /child_process require/],
  ["chained process helper arguments",
    "function inner(runtime) { return runtime.getBuiltinModule('node:child_process'); } function outer(runtime) { return inner(runtime); } outer(process).exec('cmd.exe');",
    /process\.getBuiltinModule/],
  ["chained require helper arguments",
    "function inner(factory) { return factory('node:child_process'); } function outer(factory) { return inner(factory); } outer(require).exec('cmd.exe');",
    /child_process require/],
  ["process helper before empty spread",
    "function load(runtime, ignored) { return runtime.getBuiltinModule('node:child_process'); } load(process, ...[]).exec('cmd.exe');",
    /process\.getBuiltinModule/],
  ["require helper before empty spread",
    "function load(factory, ignored) { return factory('node:child_process'); } load(require, ...[]).exec('cmd.exe');",
    /child_process require/],
  ["process helper through fixed array spread",
    "function load(runtime, ignored) { return runtime.getBuiltinModule('node:child_process'); } load(...[process, null]).exec('cmd.exe');",
    /process\.getBuiltinModule/],
  ["destructured process helper argument",
    "function load({ runtime }) { return runtime.getBuiltinModule('node:child_process'); } load({ runtime: process }).exec('cmd.exe');",
    /process\.getBuiltinModule/],
  ["nested destructured process helper argument",
    "function load({ nested: { runtime } }) { return runtime.getBuiltinModule('node:child_process'); } load({ nested: { runtime: process } }).exec('cmd.exe');",
    /process\.getBuiltinModule/],
  ["destructured require helper argument",
    "function load({ factory }) { return factory('node:child_process'); } load({ factory: require }).exec('cmd.exe');",
    /child_process require/],
  ["global helper argument",
    "function evaluate(runtime) { return runtime.eval('process'); } evaluate(globalThis);",
    /global dynamic evaluation/],
  ["member-held process factory",
    "const make = () => process; const tools = { make }; tools.make().getBuiltinModule('node:child_process').exec('id');",
    /process\.getBuiltinModule/],
  ["member-held global factory",
    "const make = () => globalThis; const tools = { make }; tools.make().eval('process');",
    /global dynamic evaluation/]
])("rejects capability provenance through %s", (_name, source, finding) => {
  expect(inspectSupervisorSource("src/services/windows-process-host.ts", source))
    .toEqual(expect.arrayContaining([expect.stringMatching(finding)]));
});

test("accepts ordinary helper arguments and member factories", () => {
  const source = [
    "function read(runtime) { return runtime.getBuiltinModule(); }",
    "read({ getBuiltinModule() { return undefined; } });",
    "function inspectRecord({ runtime }) { return runtime.cwd(); }",
    "inspectRecord({ runtime: { cwd() { return '.'; } } });",
    "const make = () => ({ safe: true });",
    "const tools = { make };",
    "tools.make().safe;",
    "const methodTools = { make() { return { safe: true }; } };",
    "methodTools.make().safe;",
    "import { spawn } from 'node:child_process';",
    "spawn('node.exe', ['--version'], { stdio: 'pipe' });"
  ].join("\n");
  expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)).toEqual([]);
});

  test("terminates reflective container cycles without overflowing", () => {
    const source = [
      "const tools = Object.assign(tools, { read: Object.getOwnPropertyDescriptors });",
      "const methods = [methods];",
      "const holder: any = {}; holder.value = holder.value;",
      "holder.value.getBuiltinModule('node:child_process').exec('id');",
      "const app: any = {}; app.global = app.global; app.global.eval('process');"
    ].join("\n");
    expect(() => inspectSupervisorSource("src/services/windows-process-host.ts", source))
      .not.toThrow();
  });

  test.each([
    ["top-level block var", "{ var spawn = localRunner; }\nspawn('cmd.exe', ['/c', 'dir']);", false],
    ["function-local var", "function runLocal() { var spawn = localRunner; }\nspawn('cmd.exe', ['/c', 'dir']);", true]
  ])("resolves %s without crossing its hoisting scope", (_name, source, flagsInterpreter) => {
    const findings = inspectSupervisorSource("src/services/windows-process-host.ts", source);
    expect(findings.some((finding) =>
      finding.includes("direct interpreter or command-shim dispatch is forbidden")))
      .toBe(flagsInterpreter);
  });

  test.each([
    ["immutable executable alias", "const executable = 'cmd.exe'; spawn(executable, ['/c', 'dir']);"],
    ["chained immutable executable alias", "const executable = 'cmd.exe'; const command = executable; spawn(command, ['/c', 'dir']);"]
  ])("rejects an interpreter hidden by an %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)).not.toEqual([]);
  });

  test.each(["node:module", "module"])("rejects aliased createRequire imports from %s", (module) => {
    const source = [
      `import { createRequire as loadModule } from '${module}';`,
      "const requireFromHere = loadModule(import.meta.url);",
      "const childProcess = requireFromHere('node:child_process');",
      "childProcess.exec('node -v');"
    ].join("\n");
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source))
      .toEqual([expect.stringContaining("node:module loading is forbidden")]);
  });

  test.each(["node:module", "module"])("rejects CommonJS module loading through %s", (module) => {
    const source = [
      `const { createRequire: loadModule } = require('${module}');`,
      "const requireFromHere = loadModule(import.meta.url);",
      "const childProcess = requireFromHere('node:child_process');",
      "childProcess.exec('node -v');"
    ].join("\n");
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source))
      .toEqual([expect.stringContaining("node:module loading is forbidden")]);
  });

  test.each([
    ["direct eval", "eval('process');"],
    ["immutable alias", "const evaluator = eval; evaluator('process');"],
    ["mutable alias", "let evaluator = eval; evaluator('process');"],
    ["computed global eval property", "globalThis['e' + 'val']('process');"],
    ["escaping reference", "registerCapability(eval);"],
    ["indirect comma call", "(0, eval)('process');"],
    ["globalThis eval", "globalThis.eval('process');"],
    ["aliased globalThis eval", "const dynamicEval = globalThis['eval']; dynamicEval('process');"],
    ["aliased Node global eval", "const dynamicEval = global.eval; dynamicEval('process');"],
    ["mutable global object alias", "let runtimeGlobal = globalThis; runtimeGlobal.eval('process');"],
    ["destructured global eval", "const { eval: dynamicEval } = globalThis; dynamicEval('process');"],
    ["destructured global eval assignment", "let dynamicEval; ({ eval: dynamicEval } = globalThis); dynamicEval('process');"],
    ["destructured global Function assignment", "let make; ({ Function: make } = globalThis); make(\"return process.getBuiltinModule('node:child_process')\")();"],
    ["computed global capability assignment", "let dynamicEval; ({ [loaderName]: dynamicEval } = globalThis); dynamicEval('process');"],
    ["global object rest assignment", "let runtimeGlobal; ({ ...runtimeGlobal } = globalThis); runtimeGlobal.eval('process');"],
    ["array-destructured global object", "const [runtimeGlobal] = [globalThis]; runtimeGlobal.eval('process');"],
    ["array-destructured global object assignment", "let runtimeGlobal; [runtimeGlobal] = [global]; runtimeGlobal.eval('process');"],
    ["array rest global capability", "let runtimeGlobal; [, ...runtimeGlobal] = [safe, globalThis]; runtimeGlobal[0].eval('process');"],
    ["parameter destructured global eval", "function evaluate({ eval: run } = globalThis) { run('process'); } evaluate();"],
    ["parameter global alias default", "function evaluate(runtime = globalThis) { runtime.eval('process'); } evaluate();"],
    ["dynamic computed global access", "const capability = getCapability(); globalThis[capability]('process');"],
    ["deferred global object assignment", "let runtimeGlobal; runtimeGlobal = globalThis; runtimeGlobal.eval('process');"],
    ["deferred destructured global object assignment", "let runtimeGlobal; ({ runtimeGlobal } = { runtimeGlobal: globalThis }); runtimeGlobal.Function('x');"],
    ["globalThis self alias", "const runtimeGlobal = globalThis.globalThis; runtimeGlobal.eval('process');"],
    ["Node global self alias", "const runtimeGlobal = global.global; runtimeGlobal.Function('x');"],
    ["destructured Node global alias", "const { global: runtimeGlobal } = globalThis; runtimeGlobal.eval('process');"],
    ["destructured globalThis alias assignment", "let runtimeGlobal; ({ globalThis: runtimeGlobal } = global); runtimeGlobal.eval('process');"]
  ])("rejects dynamic evaluation through %s", (_case, source) => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)).not.toEqual([]);
  });

  test("accepts ordinary eval-named methods and evaluate functions", () => {
    const source = [
      "const parser = { eval(value) { return value; } };",
      "parser.eval('literal');",
      "const { Math: math } = globalThis; math.max(1, 2);",
      "function evaluate(value) { return value; }",
      "evaluate('literal');"
    ].join("\n");
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)).toEqual([]);
  });

  test("accepts type-only node:module imports", () => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts",
      "import type { Module } from 'node:module';")).toEqual([]);
    expect(inspectSupervisorSource("src/services/windows-process-host.ts",
      "import { type Module } from 'node:module';")).toEqual([]);
  });

  test("accepts type-only shell and process capability imports", () => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts",
      "import type { Options } from 'execa';")).toEqual([]);
    expect(inspectSupervisorSource("src/services/windows-process-host.ts",
      "import type { getBuiltinModule } from 'node:process';")).toEqual([]);
  });

  test.each([
    ["Reflect.get Function",
      "const make = Reflect.get(globalThis, 'Function'); make('return process')();"],
    ["Reflect.get intrinsic constructor",
      "const make = Reflect.get(Object, 'constructor'); make('return 42')();"],
    ["Reflect.get process loader",
      "const load = Reflect.get(process, 'getBuiltinModule'); load('node:child_process');"],
    ["property descriptor Function",
      "const make = Object.getOwnPropertyDescriptor(globalThis, 'Function').value; make('return process')();"],
    ["property descriptor bag global eval",
     "const descriptors = Object.getOwnPropertyDescriptors(globalThis); descriptors.eval.value('process');"],
    ["property descriptor bag process capability",
     "const descriptors = Object.getOwnPropertyDescriptors(globalThis); const runtime = descriptors.process.get.call(globalThis); runtime.getBuiltinModule('node:child_process').exec('id');"],
    ["process descriptor bag",
     "const descriptors = Object.getOwnPropertyDescriptors(process); descriptors.getBuiltinModule.value('node:child_process').exec('id');"],
    ["process entries copy",
     "const copy = Object.fromEntries(Object.entries(process)); copy.getBuiltinModule('node:child_process').exec('id');"],
    ["destructured descriptor method",
     "const { getOwnPropertyDescriptors: descriptors } = Object; descriptors(globalThis).eval.value('process');"],
    ["property-held descriptor method",
     "const tools = { read: Object.getOwnPropertyDescriptors }; tools.read(globalThis).eval.value('process');"],
    ["Object.assign-held descriptor method",
     "const tools = Object.assign({}, { read: Object.getOwnPropertyDescriptors }); tools.read(globalThis).eval.value('process');"],
    ["spread Object.assign descriptor method",
     "const tools = Object.assign({}, ...[{ read: Object.getOwnPropertyDescriptors }]); const descriptors = tools.read.call(Object, globalThis); descriptors.eval.value('process');"],
    ["computed descriptor method",
     "const key = 'read'; const tools = { [key]: Object.getOwnPropertyDescriptors }; tools.read(globalThis).eval.value('process');"],
    ["deterministic comma computed descriptor method",
     "const key = (0, 'read'); const tools = { [key]: Object.getOwnPropertyDescriptors }; tools[key](globalThis).eval.value('process');"],
    ["computed descriptor destructuring",
     "const key = 'getOwnPropertyDescriptors'; const { [key]: read } = Object; read(globalThis).eval.value('process');"],
    ["Object.assign-held reflective call",
     "const tools = Object.assign({}, { read: Object.getOwnPropertyDescriptors }); const descriptors = tools.read.call(Object, globalThis); descriptors.eval.value('process');"],
    ["array-held descriptor method",
     "const methods = [Object.getOwnPropertyDescriptors]; const read = methods[0]; read.call(Object, globalThis).eval.value('process');"],
    ["factory-returned descriptor method",
     "const make = () => Object.getOwnPropertyDescriptors; const read = make(); read.call(Object, globalThis).eval.value('process');"],
    ["destructured Reflect get",
     "const { get: reflectGet } = Reflect; reflectGet(globalThis, 'Function')('return process')();"],
    ["destructured process entries",
     "const { entries, fromEntries } = Object; fromEntries(entries(process)).getBuiltinModule('node:child_process').exec('id');"],
    ["reflective call",
     "const descriptors = Object.getOwnPropertyDescriptors.call(Object, globalThis); descriptors.eval.value('process');"],
    ["reflective apply",
     "const descriptors = Object.getOwnPropertyDescriptors.apply(Object, [globalThis]); descriptors.eval.value('process');"],
    ["reflective bind",
     "const descriptors = Object.getOwnPropertyDescriptors.bind(Object); descriptors(globalThis).eval.value('process');"],
    ["reassigned Reflect alias",
      "let R: any = null; R = Reflect; const make = R.get(globalThis, 'Function'); make('return process')();"],
    ["reassigned Object alias",
      "let O: any = null; O = Object; const make = O.getOwnPropertyDescriptor(globalThis, 'Function').value; make('return process')();"]
  ])("rejects reflective capability access through %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)
      .some((finding) => finding.includes("reflective access to dynamic execution or process")))
      .toBe(true);
  });

  test.each([
    ["parameter assignment",
      "function load(runtime: any = {}) { runtime = process; return runtime.getBuiltinModule('node:child_process'); }"],
    ["destructured assignment",
      "let { runtime } = { runtime: {} as any }; runtime = process; runtime.getBuiltinModule('node:child_process');"]
  ])("rejects process capability reassignment through %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)
      .some((finding) => finding.includes("process.getBuiltinModule"))).toBe(true);
  });

  test("rejects a shadowed String.raw launcher tag", () => {
    const production = readFileSync(join(root, "src/services/process-exec.ts"), "utf8");
    const shadow = "const String = Object.assign(" +
      "(value: unknown) => globalThis.String(value), " +
      "{ raw: () => \"spawn('cmd.exe', [])\" });\n";
    expect(inspectSupervisorSource("src/services/process-exec.ts", shadow + production)
      .some((finding) => finding.includes("must be a static String.raw template"))).toBe(true);
  });

  test("rejects a lexically shadowed process.execPath launch source", () => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts",
      "const process = { env: {}, execPath: 'cmd.exe' }; " +
      "spawn(process.execPath, ['/c', 'node -v'], { stdio: 'ignore' });")
      .some((finding) => finding.includes("untrusted process.execPath"))).toBe(true);
    expect(inspectSupervisorSource("src/services/windows-process-host.ts",
      "const shadowed = { execPath: 'cmd.exe' }; let executable: any = 'safe'; " +
      "executable = shadowed.execPath; spawn(executable, ['/c', 'node -v']);")
      .some((finding) => finding.includes("untrusted process.execPath"))).toBe(true);
  });

  test("accepts a locally shadowed require reference", () => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts",
      "function load(require: (value: string) => unknown) { const alias = require; alias('ordinary-value'); }"))
      .toEqual([]);
  });

  test("accepts native execution and unrelated computed objects", () => {
    const source = [
      "import { spawn as runNative, execFile as execNative } from 'node:child_process';",
      "const metadata = { shell: 'not a launch option', ['shell']: 'computed metadata', [variable]: 1 };",
      "runNative('node.exe', [], { cwd: '.', stdio: 'pipe' });",
      "execNative('node.exe', ['--version'], { windowsHide: true });",
      "spawn('node.exe', ['--version']);"
    ].join("\n");
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source))
      .toEqual([]);
  });

  test("accepts switch statements in supervisor source", () => {
    expect(inspectSupervisorSource(
      "src/services/windows-process-host.ts",
      "switch (mode) { case 'a': consume(); break; default: consume(); }"
    )).toEqual([]);
  });


  test.each([
    ["opaque second-argument options", "spawn('node.exe', getOptions());"],
    ["opaque second with explicit third options", "spawn('node.exe', getOptions(), { stdio: 'pipe' });"],
    ["parenthesized type assertion", "spawn('node.exe', ({ ['shell']: true } as any));"],
    ["angle-bracket type assertion", "spawn('node.exe', <any>({ shell: true }));"],
    ["satisfies options", "spawn('node.exe', ({ shell: true } satisfies object));"],
    ["opaque synchronous options", "spawnSync('node.exe', getOptions());"],
    ["opaque execFile options", "execFile('node.exe', getOptions(), () => {});"],
    ["opaque execFileSync options", "execFileSync('node.exe', getOptions());"],
    ["aliased execFile second options", "import { execFile as native } from 'node:child_process'; native('node.exe', getOptions());"],
    ["aliased synchronous third options", "import { spawnSync as native } from 'node:child_process'; native('node.exe', ['--version'], getOptions());"],
    ["spoofed input.args", "const input = { args: getOptions() }; spawn('node.exe', input.args, { stdio: 'pipe' });"],
    ["spoofed windowsHostArgs", "function windowsHostArgs() { return getOptions(); } spawn('node.exe', windowsHostArgs(), { stdio: 'pipe' });"],
    ["spoofed helperArgs", "const launch = { args: getOptions() }; const helperArgs = launch?.args ?? getOptions(); spawn('node.exe', helperArgs, { stdio: 'pipe' });"]
  ])("rejects unproven process-launch overload: %s", (_name, code) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", code)).not.toEqual([]);
  });

  test.each([
    ["literal array", "spawn('node.exe', ['--version']);"],
    ["literal array and options", "spawnSync('node.exe', (['--version'] as string[]), ({ stdio: 'ignore' } satisfies object));"],
    ["options in second position", "spawn('node.exe', ({ stdio: 'pipe' } as object));"],
    ["callback alone", "execFile('node.exe', () => {});"],
    ["args and callback", "execFile('node.exe', ['--version'], () => {});"],
    ["options and callback", "execFile('node.exe', ({ timeout: 100 } as object), () => {});"],
    ["args, options, callback", "execFile('node.exe', ['--version'], { windowsHide: true }, () => {});"],
    ["sync arguments and options", "execFileSync('node.exe', ['--version'], ({ windowsHide: true } satisfies object));"],
    ["safe argv identifier", "const args = ['--version']; spawn('node.exe', args, { stdio: 'pipe' });"],
    ["safe native argv slice", "spawn('node.exe', process.argv.slice(2), { stdio: 'pipe' });"]
  ])("accepts provably native overload: %s", (_name, code) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", code)).toEqual([]);
  });

  test.each([
    ["reassigned let", "let args: string[] | { shell?: boolean } = ['--version']; args = { shell: true }; spawn('node.exe', args);"],
    ["mutable var", "var args = ['--version']; spawn('node.exe', args);"],
    ["shadowed function argument", "const args = ['--version']; function runNative(args: { shell?: boolean }) { spawn('node.exe', args); }"],
    ["nested function argument", "const args = ['--version']; function outer() { function inner(args: { shell?: boolean }) { spawn('node.exe', args); } }"],
    ["shadowed block binding", "const args = ['--version']; { const args = { shell: true }; spawn('node.exe', args); }"],
    ["shadowed let in block", "const args = ['--version']; { let args = { shell: true }; spawn('node.exe', args); }"],
    ["same name in sibling block", "{ const args = ['--version']; } { spawn('node.exe', args); }"],
    ["alias of mutable binding", "let args = ['--version']; const alias = args; spawn('node.exe', alias);"],
    ["mutable alias of immutable binding", "const args = ['--version']; let alias = args; spawn('node.exe', alias);"],
    ["cyclic aliases", "const args = alias; const alias = args; spawn('node.exe', args);"],
    ["hoisted nested var", "const args = ['--version']; function call() { if (true) { var args = { shell: true }; } spawn('node.exe', args); }"],
    ["opaque options", "const args = getOptions(); spawn('node.exe', args, { stdio: 'pipe' });"],
    ["shadowed process global", "const process = { argv: { slice: () => ({shell:true}) } }; spawn('node.exe', process.argv.slice(2));"],
    ["computed shell via shadowed const", "const args = ['--version']; { const args = { shell: true }; spawn('node.exe', (args as any)); }"]
  ])("rejects mutable or lexically unproven argv provenance: %s", (_name, source) => {
    const findings = inspectSupervisorSource("src/services/node-runtime-resolver.ts", source);
    expect(findings.some((finding) =>
      finding.includes("unresolved process-launch argv may be options"))).toBe(true);
  });

  test.each([
    ["immutable local argv", "const args = ['--version']; spawn('node.exe', args, {stdio:'pipe'});"],
    ["nested immutable reference", "const args = ['--version']; { const nested = args; spawn('node.exe', nested, {stdio:'pipe'}); }"],
    ["nested immutable shadow", "const args = { ['shell']: true }; { const args = ['--version']; spawn('node.exe', args); }"],
    ["different outer names", "const outer = ['--version']; function run() { const inner = outer; spawn('node.exe', inner); }"],
    ["conditional immutable arrays", "const left = ['a']; const right = ['b']; spawn('node.exe', true ? left : right);"],
    ["nullish immutable arrays", "const primary = ['a']; const fallback = ['b']; spawn('node.exe', primary ?? fallback);"],
    ["native literal argv", "spawn('node.exe', ['--version'], {stdio:'pipe'});"],
    ["native callback overload", "execFile('node.exe', ['--version'], {windowsHide:true}, () => {});"]
  ])("accepts proven immutable lexical argv: %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", source)).toEqual([]);
  });

  test.each([
    ["parentheses", "import { spawn } from 'node:child_process'; (spawn)('cmd.exe', []);", "direct interpreter"],
    ["as assertion", "import { spawn } from 'node:child_process'; (spawn as any)('/bin/sh', ['-c','true']);", "direct interpreter"],
    ["satisfies", "import { execFile } from 'node:child_process'; (execFile satisfies Function)('cmd.exe', []);", "direct interpreter"],
    ["call", "import { spawn } from 'node:child_process'; spawn.call(undefined, '/bin/sh', ['-c','true']);", "indirect or escaping"],
    ["computed apply", "import { spawn } from 'node:child_process'; spawn['apply'](undefined, ['/bin/sh', ['-c','true']]);", "indirect or escaping"],
    ["bind", "import { spawn } from 'node:child_process'; const launch = spawn.bind(undefined, '/bin/sh'); launch(['-c','true']);", "indirect or escaping"],
    ["Reflect.apply", "import { spawn } from 'node:child_process'; Reflect.apply(spawn, null, ['/bin/sh', ['-c','true']]);", "indirect or escaping"],
    ["wrapped bind", "import { spawn as native } from 'node:child_process'; (native as any).bind(undefined, '/bin/sh');", "indirect or escaping"],
    ["spoofed promisify", "import { execFile } from 'node:child_process'; const promisify = (f: any) => f; promisify(execFile);", "indirect or escaping"],
    ["callback escape", "import { execFile } from 'node:child_process'; register(execFile);", "indirect or escaping"],
    ["object escape", "import { spawn } from 'node:child_process'; const obj = {spawn};", "indirect or escaping"],
    ["array escape", "import { spawn } from 'node:child_process'; const arr = [spawn];", "indirect or escaping"],
    ["return escape", "import { spawn } from 'node:child_process'; function get() { return spawn; }", "indirect or escaping"],
    ["reexport", "import { spawn } from 'node:child_process'; export {spawn};", "indirect or escaping"],
    ["exported alias", "import { spawn } from 'node:child_process'; export const runner = spawn;", "indirect or escaping"],
    ["mutable alias", "import { spawn } from 'node:child_process'; let runner = spawn; runner('/bin/sh', []);", "indirect or escaping"],
    ["alias call", "import { spawn } from 'node:child_process'; const runner = spawn; runner.call(null, '/bin/sh', []);", "indirect or escaping"],
    ["optional invoke", "import { spawn } from 'node:child_process'; spawn?.('/bin/sh', []);", "indirect or escaping"],
    ["require destructure apply", "const { spawn: runner } = require('node:child_process'); runner.apply(null, ['/bin/sh', []]);", "indirect or escaping"],
    ["mutable require binding", "let {spawn} = require('node:child_process'); spawn('node.exe', []);", "immutable"],
    ["destructured default", "const {spawn: native = fallback} = require('node:child_process'); native('node.exe', []);", "unsupported child_process destructuring"],
    ["binding default escape", "import {spawn} from 'node:child_process'; const {value = spawn} = {};", "indirect or escaping"],
    ["parameter default escape", "import {spawn} from 'node:child_process'; function f(value = spawn) {}", "indirect or escaping"],
    ["spread spawn invocation", "import {spawn} from 'node:child_process'; const packed: any[] = ['/bin/sh', []]; spawn(...packed);", "spread process-runner call arguments"],
    ["wrapped spread execFile invocation", "import {execFile} from 'node:child_process'; const packed: any[] = ['/bin/sh', []]; (execFile as any)(...packed);", "spread process-runner call arguments"]
  ])("rejects runner bypass: %s", (_name, source, reason) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", source)
      .some((finding) => finding.includes(reason))).toBe(true);
  });

  test.each([
    ["dash", "spawn('/bin/dash', ['-c', 'id']);"],
    ["env wrapper", "spawn('/usr/bin/env', ['sh', '-c', 'id']);"],
    ["fixed array indirection", "const program = ['cmd.exe']; spawn(program[0], ['/c', 'dir']);"]
  ])("rejects shell dispatch through %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)
      .some((finding) => finding.includes("direct interpreter or command-shim"))).toBe(true);
  });

  test.each([
    ["parenthesized", "import {spawn} from 'node:child_process'; (spawn)('node.exe', []);"],
    ["as assertion", "import {spawn as s} from 'node:child_process'; (s as any)('node.exe', [], {stdio:'pipe'});"],
    ["angle assertion", "import {execFile as e} from 'node:child_process'; (<any>e)('node.exe', [], () => {});"],
    ["non-null", "import {spawn as s} from 'node:child_process'; s!('node.exe', []);"],
    ["satisfies", "import {execFile} from 'node:child_process'; (execFile satisfies Function)('node.exe', [], {windowsHide:true});"],
    ["immutable aliases", "import {spawn as s} from 'node:child_process'; const a = s; const b=(a as any); b('node.exe', []);"],
    ["CommonJS aliases", "const {spawn:s, execFile:e}=require('node:child_process'); s('node.exe', []); e('node.exe', [], () => {});"],
    ["trusted promisify", "import {execFile} from 'node:child_process'; import {promisify as p} from 'node:util'; const e=p(execFile); e('node.exe', [], {timeout:100});"],
    ["shadowed parameter", "import {spawn} from 'node:child_process'; function local(spawn: () => void) { spawn(); } spawn('node.exe', []);"]
  ])("accepts audited runner reference: %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", source)).toEqual([]);
  });

  test("audits indirect calls inside POSIX_GROUP_LAUNCHER", () => {
    const valid = "const POSIX_GROUP_LAUNCHER = String.raw" + String.fromCharCode(96) +
      "const { spawn } = require('node:child_process'); spawn.bind(undefined, '/bin/sh');" +
      String.fromCharCode(96) + ";";
    expect(inspectSupervisorSource("src/services/process-exec.ts", valid))
      .toEqual([expect.stringContaining("indirect or escaping child_process runner")]);
  });
test.each([
  ["call", "const cp = require.call(null, 'node:child_process'); cp.exec('id');"],
  ["apply", "const cp = require.apply(null, ['node:child_process']); cp.exec('id');"],
  ["bind", "const load = require.bind(null); const cp = load('node:child_process'); cp.exec('id');"],
  ["Reflect.apply", "const cp = Reflect.apply(require, null, ['node:child_process']); cp.exec('id');"],
  ["global alias", "const cp = globalThis.require('node:child_process'); cp.exec('id');"],
  ["global destructuring", "const { require: load } = globalThis; const cp = load('node:child_process'); cp.exec('id');"],
  ["object-held require", "const holder = { load: require }; const cp = holder.load('node:child_process'); cp.exec('id');"],
  ["shorthand-held require", "const holder = { require }; const cp = holder.require('node:child_process'); cp.exec('id');"],
  ["array-held require", "const holder = [require]; const cp = holder[0]('node:child_process'); cp.exec('id');"],
  ["assigned member require", "const holder = {}; holder.load = require; const cp = holder.load('node:child_process'); cp.exec('id');"],
  ["computed assigned member require", "const key = 'load'; const holder = {}; holder[key] = require; holder.load('node:child_process').exec('id');"],
  ["conditional assigned member require", "const holder = {}; holder.load = true ? require : () => {}; holder.load('node:child_process').exec('id');"],
  ["factory-returned require", "const holder = { load: () => require }; const cp = holder.load()('node:child_process'); cp.exec('id');"],
  ["helper parameter require", "function load(factory) { return factory('node:child_process'); } const cp = load(require); cp.exec('id');"]
])("rejects indirect require through %s inside POSIX_GROUP_LAUNCHER", (_name, body) => {
  const quoted = "const POSIX_GROUP_LAUNCHER = String.raw" + String.fromCharCode(96) +
    body + String.fromCharCode(96) + ";";
  expect(inspectSupervisorSource("src/services/process-exec.ts", quoted))
    .toEqual(expect.arrayContaining([
      expect.stringMatching(
        /require capability|dynamic require|child_process require|aliasing require/
      )
    ]));
});

  test.each([
    ["node:child_process wildcard", "export * from \"node:child_process\";"],
    ["node:child_process namespace", "export * as cp from \"node:child_process\";"],
    ["node:child_process named shell runner", "export { exec } from \"node:child_process\";"],
    ["node:child_process aliased shell runner", "export { exec as launch } from \"node:child_process\";"],
    ["node:child_process supported native runner", "export { spawn } from \"node:child_process\";"],
    ["node:child_process mixed type and value", "export { type ChildProcess, spawn } from \"node:child_process\";"],
    ["node:child_process empty runtime clause", "export {} from \"node:child_process\";"],
    ["child_process wildcard", "export * from \"child_process\";"],
    ["child_process namespace", "export * as cp from \"child_process\";"],
    ["child_process named shell runner", "export { exec } from \"child_process\";"],
    ["child_process aliased shell runner", "export { exec as launch } from \"child_process\";"],
    ["child_process supported native runner", "export { spawn } from \"child_process\";"],
    ["child_process mixed type and value", "export { type ChildProcess, spawn } from \"child_process\";"],
    ["child_process empty runtime clause", "export {} from \"child_process\";"],
    ["cross-spawn wildcard", "export * from \"cross-spawn\";"],
    ["cross-spawn namespace", "export * as runner from \"cross-spawn\";"],
    ["cross-spawn aliased named", "export { default as runner } from \"cross-spawn\";"],
    ["shelljs wildcard", "export * from \"shelljs\";"],
    ["shelljs namespace", "export * as runner from \"shelljs\";"],
    ["shelljs aliased named", "export { default as runner } from \"shelljs\";"],
    ["execa wildcard", "export * from \"execa\";"],
    ["execa namespace", "export * as runner from \"execa\";"],
    ["execa aliased named", "export { default as runner } from \"execa\";"]
  ])("rejects runtime module re-exports: %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", source))
      .toEqual([expect.stringContaining("runtime process-runner re-export")]);
  });

  test.each([
    ["spawn", "export const { spawn } = require(\"node:child_process\");"],
    ["spawnSync", "export const { spawnSync } = require(\"node:child_process\");"],
    ["execFile", "export const { execFile } = require(\"node:child_process\");"],
    ["execFileSync", "export const { execFileSync } = require(\"node:child_process\");"],
    ["short module alias", "export const { spawn: native } = require(\"child_process\");"],
    ["multiple exported declarations", "export const version = 1, { spawn: native, execFile: runFile } = require(\"node:child_process\");"]
  ])("rejects exported CommonJS bindings: %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", source))
      .toEqual([expect.stringContaining("exported child_process require bindings")]);
  });

  test.each([
    ["imported alias export", "import { spawn as native } from \"node:child_process\"; export { native as launch };"],
    ["CommonJS local export", "const { spawn: native } = require(\"node:child_process\"); export { native as launch };"],
    ["mixed local type and runner export", "import { spawn, type ChildProcess } from \"node:child_process\"; export { type ChildProcess, spawn as launch };"],
    ["value export after type export", "import { spawn } from \"node:child_process\"; export type { spawn }; export { spawn };"]
  ])("retains local runtime export rejection: %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", source))
      .toEqual([expect.stringContaining("indirect or escaping child_process runner")]);
  });

  test.each([
    ["unrelated wildcard", "export * from \"node:fs\";"],
    ["unrelated namespace", "export * as paths from \"node:path\";"],
    ["unrelated named", "export { readFileSync } from \"node:fs\";"],
    ["unrelated aliased runner name", "export { label as spawn } from \"./metadata.js\";"],
    ["unrelated source with matching local runner", "import { spawn } from \"node:child_process\"; export { spawn as label } from \"./metadata.js\"; spawn(\"node\", []);"],
    ["local public alias matching runner name", "const label = \"native\"; export { label as spawn };"],
    ["unrelated value declaration", "export const version = 1;"],
    ["unrelated CommonJS destructuring", "export const { readFileSync } = require(\"node:fs\");"],
    ["unrelated CommonJS binding named spawn", "export const { join: spawn } = require(\"node:path\");"],
    ["type-only named", "export type { ChildProcess } from \"node:child_process\";"],
    ["type-only alias", "export type { ChildProcess as ProcessHandle } from \"child_process\";"],
    ["type-only wildcard", "export type * from \"node:child_process\";"],
    ["type-only namespace", "export type * as ProcessTypes from \"child_process\";"],
    ["type-only runner name", "export type { spawn } from \"node:child_process\";"],
    ["inline type-only names", "export { type ChildProcess, type spawn as NativeRunner } from \"node:child_process\";"],
    ["shell module type-only wildcard", "export type * from \"shelljs\";"],
    ["shell module type-only namespace", "export type * as SpawnTypes from \"cross-spawn\";"],
    ["shell module inline type-only", "export { type Options } from \"execa\";"],
    ["local type-only runner export", "import { spawn } from \"node:child_process\"; export type { spawn as NativeRunner }; spawn(\"node\", []);"],
    ["mixed local type and unrelated value", "import { spawn } from \"node:child_process\"; const version = 1; export { type spawn, version }; spawn(\"node\", []);"],
    ["exported function using audited native call", "import { spawn } from \"node:child_process\"; export function launch() { return spawn(\"node\", []); }"],
    ["nonexported CommonJS native alias", "const { spawn: native } = require(\"node:child_process\"); const launch = native; launch(\"node\", []);"]
  ])("accepts unrelated or type-only exports: %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", source)).toEqual([]);
  });

  test.each([
    ["wildcard", "export * from \"node:child_process\";", "runtime process-runner re-export"],
    ["namespace", "export * as cp from \"child_process\";", "runtime process-runner re-export"],
    ["named", "export { exec } from \"node:child_process\";", "runtime process-runner re-export"],
    ["aliased", "export { spawn as native } from \"child_process\";", "runtime process-runner re-export"],
    ["shell-capable module", "export * from \"execa\";", "runtime process-runner re-export"],
    ["exported CommonJS", "export const { spawn } = require(\"node:child_process\");", "exported child_process require bindings"],
    ["exported CommonJS alias", "export const { execFile: native } = require(\"child_process\");", "exported child_process require bindings"]
  ])("rejects runtime exports inside POSIX_GROUP_LAUNCHER: %s", (_name, source, reason) => {
    const launcher = "const POSIX_GROUP_LAUNCHER = String.raw`" + source + "`;";
    expect(inspectSupervisorSource("src/services/process-exec.ts", launcher))
      .toEqual([expect.stringContaining("#POSIX_GROUP_LAUNCHER:1: " + reason)]);
  });

  test("audits the embedded POSIX launcher and rejects shell dispatch inside it", () => {
    const valid = "const POSIX_GROUP_LAUNCHER = String.raw`" +
      "const { spawn } = require('node:child_process'); spawn('node', []);" + "`;";
    const invalid = valid.replace("spawn('node', [])", "spawn('cmd.exe', ['/c'])");
    expect(inspectSupervisorSource("src/services/process-exec.ts", valid)).toEqual([]);
    expect(inspectSupervisorSource("src/services/process-exec.ts", invalid))
      .toEqual([expect.stringContaining("direct interpreter")]);
  });

  test("rejects a nonliteral or missing POSIX launcher", () => {
    expect(inspectSupervisorSource("src/services/process-exec.ts",
      "const POSIX_GROUP_LAUNCHER = buildLauncher();")).not.toEqual([]);
    expect(inspectSupervisorSource("src/services/process-exec.ts",
      "const unrelated = 1;")).not.toEqual([]);
  });

  test("ignores shell names in documentation and npm lifecycle environment strings", () => {
    const source = "const recoveryHint = 'npm may require cmd.exe for repository scripts';" +
      "const env = { ComSpec: 'C:\\\\Windows\\\\System32\\\\cmd.exe' };";
    expect(inspectSupervisorSource("src/services/validation-service.ts", source)).toEqual([]);
  });

  test("allows RegExp.exec while blocking shell command execution", () => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts",
      "const parsed = /v([0-9]+)/.exec(version);")).toEqual([]);
  });

  test("does not mistake safe execFile and direct spawn for a shell", () => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts",
      "import { execFile } from 'node:child_process'; execFile('node.exe', ['--version']);" +
      "spawn('node.exe', ['-e', 'console.log(1)'], { stdio: 'pipe' });")).toEqual([]);
  });

  test.each([
    ["fixed-array hole", "function load(ignored, runtime) { return runtime.getBuiltinModule('node:child_process'); } load(...[, process]).exec('id');"],
    ["identifier rest parameter", "function load(...args) { return args[1].getBuiltinModule('node:child_process'); } load(null, process).exec('id');"],
    ["rest parameter after fixed argument", "function load(prefix, ...args) { return args[0].getBuiltinModule('node:child_process'); } load(null, process).exec('id');"],
    ["destructured rest parameter", "function load(...[runtime]) { return runtime.getBuiltinModule('node:child_process'); } load(process).exec('id');"],
    ["array-rest binding", "function load([...rest]) { return rest[0].getBuiltinModule('node:child_process'); } load([process]).exec('id');"],
    ["object-rest binding", "function load({ ignored, ...rest }) { return rest.runtime.getBuiltinModule('node:child_process'); } load({ ignored: null, runtime: process }).exec('id');"],
    ["opaque spread before capability", "declare const args: any[]; function load(runtime) { return runtime.getBuiltinModule('node:child_process'); } load(...args, process).exec('id');"],
    ["helper call", "function load(runtime) { return runtime.getBuiltinModule('node:child_process'); } load.call(null, process).exec('id');"],
    ["helper apply", "function load(runtime) { return runtime.getBuiltinModule('node:child_process'); } load.apply(null, [process]).exec('id');"],
    ["helper bind", "function load(runtime) { return runtime.getBuiltinModule('node:child_process'); } load.bind(null, process)().exec('id');"],
    ["Reflect.apply helper", "function load(runtime) { return runtime.getBuiltinModule('node:child_process'); } Reflect.apply(load, null, [process]).exec('id');"],
    ["member factory argument", "const make = (_unused: unknown) => process; const tools = { make }; tools.make(1).getBuiltinModule('node:child_process').exec('id');"],
    ["getter factory", "const tools = { get make() { return process; } }; tools.make().getBuiltinModule('node:child_process').exec('id');"],
    ["getter global factory", "const tools = { get make() { return globalThis; } }; tools.make().eval('process').exec('id');"],
    ["factory carrier", "const tools = { make: () => ({ runtime: process }) }; tools.make().runtime.getBuiltinModule('node:child_process').exec('id');"],
    ["destructured factory carrier", "const make = () => ({ runtime: process }); const { runtime } = make(); runtime.getBuiltinModule('node:child_process').exec('id');"],
    ["Object.assign call", "const copy = globalThis.Object.assign.call(Object, {}, process); copy.getBuiltinModule('node:child_process').exec('id');"],
    ["Object.assign apply", "const copy = globalThis.Object.assign.apply(Object, [{}, process]); copy.getBuiltinModule('node:child_process').exec('id');"],
    ["Object.assign bind", "const copy = globalThis.Object.assign.bind(Object, {}, process)(); copy.getBuiltinModule('node:child_process').exec('id');"],
    ["Object.assign static spread", "const copy = globalThis.Object.assign.call(Object, ...[{}, process]); copy.getBuiltinModule('node:child_process').exec('id');"]
  ])('rejects bounded process provenance through %s', (_name, source) => {
    expect(inspectSupervisorSource('src/services/windows-process-host.ts', source))
      .not.toEqual([]);
  });

  test("accepts ordinary holes, rests, helpers, factories, and opaque spreads without process capability", () => {
    const source = [
      "declare const args: any[];",
      "const processLike = { getBuiltinModule() { return undefined; } };",
      "function pick([, value]) { return value.length; } pick([null, 'abc']);",
      "function inspect(...values) { return values[0]?.length; } inspect(null, 'ok');",
      "function inspectTail(prefix, ...values) { return values[0]?.length; } inspectTail(null, 'ok');",
      "function inspectRest([...values]) { return values.length; } inspectRest(['ok']);",
      "function inspectObject({ ignored, ...rest }) { return rest.value; } inspectObject({ ignored: null, value: 1 });",
      "function load(runtime) { return runtime.getBuiltinModule(); } load(...args, processLike);",
      "load.call(null, processLike); load.apply(null, [processLike]); load.bind(null, processLike)(); Reflect.apply(load, null, [processLike]);",
      "const make = (_unused: unknown) => processLike; const tools = { make }; tools.make(1).getBuiltinModule();",
      "const getters = { get make() { return processLike; } }; getters.make().getBuiltinModule();",
      "const carrier = { make: () => ({ runtime: processLike }) }; carrier.make().runtime.getBuiltinModule();",
      "globalThis.Object.assign.call(Object, {}, processLike).getBuiltinModule();",
      "globalThis.Object.assign.call(Object, ...[{}, processLike]).getBuiltinModule();"
    ].join("\n");
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)).toEqual([]);
  });
});
