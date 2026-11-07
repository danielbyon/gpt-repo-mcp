import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const ROOT = resolve(fileURLToPath(new URL("../", import.meta.url)));
export const SUPERVISOR_SOURCES = Object.freeze([
  "src/services/process-exec.ts",
  "src/services/windows-process-host.ts",
  "src/services/node-runtime-resolver.ts",
  "src/services/validation-service.ts"
]);

const SHELL_MODULES = new Set(["cross-spawn", "shelljs", "execa"]);
const SHELL_COMMAND = /(?:^|[\\/])(?:cmd|command|powershell|pwsh|bash|sh|zsh)(?:\.exe)?$/i;
const SHELL_SHIM = /\.(?:cmd|bat|ps1|psm1|sh)$/i;

function nameOf(expression) {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return undefined;
}

/**
 * Mechanical guard for the direct-execution boundary, not for repository-owned
 * npm scripts and recipes. Behavior and executable trust still need runtime tests.
 */
export function inspectSupervisorSource(filename, source) {
  const file = ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const findings = [];

  const add = (node, message) => {
    const position = file.getLineAndCharacterOfPosition(node.getStart(file));
    findings.push(filename + ":" + (position.line + 1) + ": " + message);
  };

  const visit = (node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) &&
        SHELL_MODULES.has(node.moduleSpecifier.text)) {
      add(node, "shell-capable runner imports are not allowed in validation supervision");
    }

    if (ts.isCallExpression(node)) {
      const callee = nameOf(node.expression);
      if ((callee === "exec" || callee === "execSync") &&
          (ts.isIdentifier(node.expression) ||
            (ts.isPropertyAccessExpression(node.expression) &&
              ts.isIdentifier(node.expression.expression) &&
              node.expression.expression.text === "childProcess"))) {
        add(node, "shell-string process execution is forbidden in validation supervision");
      }
      if (callee === "_parse") {
        add(node, "private command/shim parsing is forbidden in validation supervision");
      }
      if ((callee === "require" || node.expression.kind === ts.SyntaxKind.ImportKeyword) &&
          node.arguments.length > 0 && ts.isStringLiteral(node.arguments[0]) &&
          SHELL_MODULES.has(node.arguments[0].text)) {
        add(node, "shell-capable runner imports are not allowed in validation supervision");
      }
      if (["spawn", "spawnSync", "execFile", "execFileSync"].includes(callee) &&
          node.arguments.length > 0 && ts.isStringLiteralLike(node.arguments[0])) {
        const command = node.arguments[0].text;
        if (SHELL_COMMAND.test(command) || SHELL_SHIM.test(command)) {
          add(node, "direct shell or command-shim launch is forbidden");
        }
      }
    }

    if (ts.isPropertyAssignment(node) && node.name &&
        (node.name.getText(file).replace(/^["']|["']$/g, "") === "shell")) {
      add(node, "shell dispatch option is forbidden in validation supervision");
    }
    if (ts.isShorthandPropertyAssignment(node) && node.name.text === "shell") {
      add(node, "shell dispatch option is forbidden in validation supervision");
    }

    ts.forEachChild(node, visit);
  };

  visit(file);
  return findings;
}

export function inspectSupervisorSources(readSource = (path) => readFileSync(join(ROOT, path), "utf8")) {
  return SUPERVISOR_SOURCES.flatMap((path) => inspectSupervisorSource(path, readSource(path)));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const findings = inspectSupervisorSources();
    if (findings.length > 0) {
      for (const finding of findings) process.stderr.write(finding + "\n");
      process.exitCode = 1;
    } else {
      process.stdout.write("Validation supervisor direct-execution guard passed.\n");
    }
  } catch (error) {
    process.stderr.write("Validation supervisor guard failed: " +
      (error instanceof Error ? error.message : String(error)) + "\n");
    process.exitCode = 1;
  }
}
