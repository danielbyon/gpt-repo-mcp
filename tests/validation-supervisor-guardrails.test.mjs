import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
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
    ["direct command interpreter", "spawn('cmd.exe', ['/c', 'dir']);"],
    ["PowerShell interpreter", "spawn('powershell.exe', ['-Command', 'Get-ChildItem']);"],
    ["batch wrapper", "spawn('C:\\\\Tools\\\\npm.cmd', ['test']);"],
    ["cross-spawn import", "import crossSpawn from 'cross-spawn';"],
    ["cross-spawn require", "const crossSpawn = require('cross-spawn');"],
    ["private shim parsing", "crossSpawn._parse('npm', [], {});"]
  ])("rejects %s", (_case, source) => {
    expect(inspectSupervisorSource("src/services/windows-process-host.ts", source).length).toBeGreaterThan(0);
  });

  test("ignores shell names in documentation and npm lifecycle environment strings", () => {
    const source = "const recoveryHint = 'npm may require cmd.exe for repository scripts';" +
      "const env = { ComSpec: 'C:\\\\Windows\\\\System32\\\\cmd.exe' };";
    expect(inspectSupervisorSource("src/services/validation-service.ts", source)).toEqual([]);
  });

  test("does not mistake safe execFile and direct spawn for a shell", () => {
    expect(inspectSupervisorSource("src/services/node-runtime-resolver.ts",
      "import { execFile } from 'node:child_process'; execFile('node.exe', ['--version']);" +
      "spawn('node.exe', ['-e', 'console.log(1)'], { stdio: 'pipe' });")).toEqual([]);
  });
});
