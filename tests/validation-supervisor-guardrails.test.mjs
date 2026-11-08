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
    ["function constructor", "const create = Function(\"return 1\");"],
    ["require with computed member", "const p = require('node:child_process'); p['exec']('echo nope');"],
    ["namespace import", "import * as cp from 'node:child_process'; cp.exec('echo nope');"],
    ["function evaluation", "new Function('return require(\\\"node:child_process\\\")')();"]
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
  ])("52-D rejects shell-capable or unverifiable native launch options: %s", (_name, code) => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", code))
      .not.toEqual([]);
  });

  test("52-D accepts native execution and unrelated computed objects", () => {
    const source = [
      "import { spawn as runNative, execFile as execNative } from 'node:child_process';",
      "const metadata = { ['shell']: 'not a launch option', [variable]: 1 };",
      "runNative('node.exe', [], { cwd: '.', stdio: 'pipe' });",
      "execNative('node.exe', ['--version'], { windowsHide: true });",
      "spawn('node.exe', ['--version']);"
    ].join("\n");
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source))
      .toEqual([]);
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
  ])("52-G rejects unproven process-launch overload: %s", (_name, code) => {
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
  ])("52-G accepts provably native overload: %s", (_name, code) => {
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
  ])("52-I rejects mutable or lexically unproven argv provenance: %s", (_name, source) => {
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
  ])("52-I accepts proven immutable lexical argv: %s", (_name, source) => {
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
  ])("52-J rejects runner bypass: %s", (_name, source, reason) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", source)
      .some((finding) => finding.includes(reason))).toBe(true);
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
  ])("52-J accepts audited runner reference: %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", source)).toEqual([]);
  });

  test("52-J audits indirect calls inside POSIX_GROUP_LAUNCHER", () => {
    const valid = "const POSIX_GROUP_LAUNCHER = String.raw" + String.fromCharCode(96) +
      "const { spawn } = require('node:child_process'); spawn.bind(undefined, '/bin/sh');" +
      String.fromCharCode(96) + ";";
    expect(inspectSupervisorSource("src/services/process-exec.ts", valid))
      .toEqual([expect.stringContaining("indirect or escaping child_process runner")]);
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
  ])("52-K rejects runtime module re-exports: %s", (_name, source) => {
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
  ])("52-K rejects exported CommonJS bindings: %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", source))
      .toEqual([expect.stringContaining("exported child_process require bindings")]);
  });

  test.each([
    ["imported alias export", "import { spawn as native } from \"node:child_process\"; export { native as launch };"],
    ["CommonJS local export", "const { spawn: native } = require(\"node:child_process\"); export { native as launch };"],
    ["mixed local type and runner export", "import { spawn, type ChildProcess } from \"node:child_process\"; export { type ChildProcess, spawn as launch };"],
    ["value export after type export", "import { spawn } from \"node:child_process\"; export type { spawn }; export { spawn };"]
  ])("52-K retains local runtime export rejection: %s", (_name, source) => {
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
  ])("52-K accepts unrelated or type-only exports: %s", (_name, source) => {
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
  ])("52-K rejects runtime exports inside POSIX_GROUP_LAUNCHER: %s", (_name, source, reason) => {
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
    ["direct builtin loader", "process.getBuiltinModule('node:child_process').exec('cmd.exe');"],
    ["computed builtin loader", "process['getBuiltinModule']('child_process').exec('cmd.exe');"],
    ["destructured loader", "const { getBuiltinModule: load } = process; load('child_process');"],
    ["loader alias", "const load = process.getBuiltinModule; load('child_process');"],
    ["immutable process alias", "const p = process; p.getBuiltinModule('node:child_process');"],
    ["globalThis process alias", "const g = globalThis; const p = g.process; p.getBuiltinModule('child_process');"],
    ["require node:process alias", "const p = require('node:process'); p.getBuiltinModule('child_process');"],
    ["destructured require", "const {getBuiltinModule: load} = require('node:process'); load('child_process');"],
    ["imported loader", "import { getBuiltinModule as load } from 'node:process'; load('child_process');"],
    ["node:process default", "import p from 'node:process'; p.getBuiltinModule('child_process');"],
    ["node:process namespace", "import * as p from 'node:process'; p.getBuiltinModule('child_process');"],
    ["unknown computed process member", "process[member]('child_process');"]
  ])("independent review A rejects built-in module loader capability: %s", (_name, source) => {
    const findings = inspectSupervisorSource("src/services/node-runtime-resolver.ts", source);
    expect(findings.some((f) => f.includes("built-in module loader"))).toBe(true);
    expect(findings.every((f) => !f.includes("source cannot be parsed"))).toBe(true);
  });

  test.each([
    ["eval alias", "const evaluate = eval; evaluate('console.log(1)');"],
    ["eval callback escape", "register(eval);"],
    ["indirect eval call", "(0, eval)('console.log(1)');"],
    ["globalThis eval alias", "const evaluate = globalThis.eval; evaluate('console.log(1)');"],
    ["global alias eval element", "const g = globalThis; const evaluate = g['eval']; evaluate('1');"],
    ["destructured global eval", "const { eval: evaluate } = globalThis; evaluate('1');"],
    ["global Function destructure", "const { Function: build } = globalThis; build('return 1');"],
    ["Function alias", "const build = Function; build('return 1');"]
  ])("independent review B rejects dynamic evaluation escapes: %s", (_name, source) => {
    const findings = inspectSupervisorSource("src/services/node-runtime-resolver.ts", source);
    expect(findings.some((f) => f.includes("dynamic evaluation"))).toBe(true);
    expect(findings.every((f) => !f.includes("source cannot be parsed"))).toBe(true);
  });

  test.each([
    ["native spawn/execFile", "import {spawn, execFile} from 'node:child_process'; spawn('node.exe',['--version']); execFile('node.exe',['--version']);"],
    ["ordinary process properties", "const p=process; p.platform; p.argv; p.cwd();"],
    ["unrelated loader method", "const o={getBuiltinModule(){return 1;}}; o.getBuiltinModule();"],
    ["ordinary evaluate function", "const evaluate=(x)=>x; evaluate('hello');"],
    ["ordinary launch method", "const custom={launch(x){return x;}}; custom.launch('node');"],
    ["safe process destructuring", "const { platform } = process;"],
    ["type-only process import", "import type { Process } from 'node:process'; export type { Process };"],
    ["unrelated eval method alias", "const g={eval(x){return x}}; const e=g.eval; e('hello');"]
  ])("independent review A/B preserves supported unrelated behavior: %s", (_name, source) => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts", source)).toEqual([]);
  });

  test.each([
    ["builtin loader", "process.getBuiltinModule('node:child_process').exec('cmd.exe');", "built-in module loader"],
    ["eval alias", "const evaluate = eval; evaluate('1');", "dynamic evaluation"]
  ])("independent review A/B enforces embedded POSIX launcher: %s", (_name, source, reason) => {
    const launcher = "const POSIX_GROUP_LAUNCHER = String.raw`" + source + "`;";
    const findings = inspectSupervisorSource("src/services/process-exec.ts", launcher);
    expect(findings.some((f) => f.includes("#POSIX_GROUP_LAUNCHER:1: " + reason))).toBe(true);
    expect(findings.every((f) => !f.includes("source cannot be parsed"))).toBe(true);
  });
});
