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
    ["require with computed member", "const p = require('node:child_process'); p['exec']('echo nope');"],
    ["namespace import", "import * as cp from 'node:child_process'; cp.exec('echo nope');"],
    ["function evaluation", "new Function('return require(\\\"node:child_process\\\")')();"]
  ])("rejects an unaudited loading route: %s", (_case, source) => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source)).not.toEqual([]);
  });

  test("audits the embedded POSIX launcher and rejects shell dispatch inside it", () => {
    const valid = "const POSIX_GROUP_LAUNCHER = String.raw\`" +
      "const { spawn } = require('node:child_process'); spawn('node', []);" + "\`;";
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
});
