import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath, URL } from "node:url";
import ts from "typescript";

const ROOT = resolve(fileURLToPath(new URL("../", import.meta.url)));
export const SUPERVISOR_SOURCES = Object.freeze([
  "src/services/process-exec.ts",
  "src/services/windows-process-host.ts",
  "src/services/node-runtime-resolver.ts",
  "src/services/validation-service.ts"
]);

const PROCESS_MODULES = new Set(["node:child_process", "child_process"]);
const SHELL_MODULES = new Set(["cross-spawn", "shelljs", "execa"]);
const SAFE_PROCESS_EXPORTS = new Set(["spawn", "spawnSync", "execFile", "execFileSync"]);
const DISALLOWED_PROGRAMS = /(?:^|[\\/])(?:cmd|command|powershell|pwsh|bash|sh|zsh)(?:\.exe)?$/i;
const DISALLOWED_SHIMS = /\.(?:cmd|bat|ps1|psm1|sh)$/i;

const moduleLiteral = (node) => node && ts.isStringLiteralLike(node) ? node.text : undefined;
const nameOf = (node) => ts.isIdentifier(node) ? node.text : undefined;
const callName = (node) => nameOf(node) ||
  (ts.isPropertyAccessExpression(node) ? node.name.text : undefined);
const propertyName = (node, file) => node.name?.getText(file).replace(/^["']|["']$/g, "");
const launchOptionName = (name) => {
  if (name && (ts.isIdentifier(name) || ts.isStringLiteralLike(name) ||
      ts.isNumericLiteral(name))) return name.text;
  if (name && ts.isComputedPropertyName(name) && ts.isStringLiteralLike(name.expression)) {
    return name.expression.text;
  }
  return undefined;
};

function inspectJavaScript(filename, source, isLauncher = false) {
  const file = ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true,
    isLauncher ? ts.ScriptKind.JS : ts.ScriptKind.TS);
  const findings = [];
  const processFunctions = new Map();
  let launcherCount = 0;

  const add = (node, message) => {
    const pos = file.getLineAndCharacterOfPosition(node.getStart(file));
    findings.push(filename + ":" + (pos.line + 1) + ": " + message);
  };
  if (file.parseDiagnostics.length > 0) {
    return [filename + ": source cannot be parsed for process-execution inspection"];
  }

  const processBinding = (binding, exported, node) => {
    if (!SAFE_PROCESS_EXPORTS.has(exported)) {
      add(node, "unaudited child_process export: " + exported);
    } else if (binding) {
      processFunctions.set(binding, exported);
    }
  };

  const inspectRequire = (node) => {
    if (!ts.isCallExpression(node) || callName(node.expression) !== "require") return;
    if (node.arguments.length !== 1 || !moduleLiteral(node.arguments[0])) {
      add(node, "dynamic require is forbidden in supervisor source");
      return;
    }
    const module = moduleLiteral(node.arguments[0]);
    if (SHELL_MODULES.has(module)) {
      add(node, "shell-capable runner imports are forbidden");
    } else if (PROCESS_MODULES.has(module)) {
      const declaration = node.parent;
      if (!ts.isVariableDeclaration(declaration) || declaration.initializer !== node ||
          !ts.isObjectBindingPattern(declaration.name)) {
        add(node, "child_process require must destructure audited named exports");
        return;
      }
      for (const element of declaration.name.elements) {
        const exported = element.propertyName?.getText(file) ?? element.name.getText(file);
        processBinding(nameOf(element.name), exported, element);
      }
    }
  };

  const unwrap = (node) => {
    while (node && (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) ||
           ts.isTypeAssertionExpression(node) || ts.isSatisfiesExpression(node) ||
           ts.isNonNullExpression(node))) node = node.expression;
    return node;
  };
  const isCallback = (node) => ts.isFunctionExpression(node) || ts.isArrowFunction(node);

  // A second argument must be provably an argv array: Node treats a non-array
  // object there as its options, even when a third argument is supplied.
  const arrayBindings = new Map();
  const collectBindings = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
      const entries = arrayBindings.get(node.name.text) ?? [];
      entries.push(node.initializer);
      arrayBindings.set(node.name.text, entries);
    }
    ts.forEachChild(node, collectBindings);
  };
  collectBindings(file);

  const isArrayArguments = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
    if (ts.isArrayLiteralExpression(node)) return true;
    if (ts.isConditionalExpression(node)) {
      return isArrayArguments(node.whenTrue, seen) &&
        isArrayArguments(node.whenFalse, seen);
    }
    if (ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) {
      return isArrayArguments(node.left, seen) && isArrayArguments(node.right, seen);
    }
    if (ts.isPropertyAccessExpression(node)) {
      // These expressions have array-valued contracts in the audited modules.
      return ["input.args", "launch?.args"].includes(node.getText(file).replace(/\s+/g, ""));
    }
    if (ts.isCallExpression(node)) {
      const target = node.expression.getText(file).replace(/\s+/g, "");
      return target === "process.argv.slice" || target === "windowsHostArgs";
    }
    if (ts.isIdentifier(node) && !seen.has(node.text)) {
      const bindings = arrayBindings.get(node.text);
      if (bindings?.length === 1) {
        const next = new Set(seen);
        next.add(node.text);
        return isArrayArguments(bindings[0], next);
      }
    }
    return false;
  };

  const inspectOptionObject = (node) => {
    if (!ts.isObjectLiteralExpression(node)) {
      add(node, "unresolved process-launch options cannot prove shell-free dispatch");
      return;
    }
    for (const property of node.properties) {
      if (!("name" in property)) {
        add(property, "spread process-launch options cannot prove shell-free dispatch");
        continue;
      }
      const name = launchOptionName(property.name);
      if (name === undefined) {
        add(property, "unresolved computed process-launch option");
      } else if (name === "shell") {
        add(property, "shell dispatch option is forbidden");
      }
    }
  };

  const inspectLaunchOptions = (call, runner) => {
    const second = unwrap(call.arguments[1]);
    const third = unwrap(call.arguments[2]);
    const fourth = unwrap(call.arguments[3]);
    const callbackRunner = runner === "execFile";

    if (!second) {
      if (third || fourth) add(call, "unsupported process-launch overload");
      return;
    }
    if (callbackRunner && isCallback(second)) {
      if (third || fourth) add(call, "unsupported execFile callback overload");
      return;
    }
    if (ts.isObjectLiteralExpression(second)) {
      inspectOptionObject(second);
      if (third && !(callbackRunner && isCallback(third) && !fourth)) {
        add(third, "unsupported process-launch overload after options");
      }
      if (fourth) add(fourth, "unsupported process-launch callback position");
      return;
    }

    if (!isArrayArguments(second)) {
      add(second, "unresolved process-launch argv may be options");
    }
    if (third && !(callbackRunner && isCallback(third))) {
      inspectOptionObject(third);
    }
    if (fourth && !(callbackRunner && third && !isCallback(third) && isCallback(fourth))) {
      add(fourth, "unsupported process-launch callback position");
    }
  };

  const visit = (node) => {
    if (ts.isImportDeclaration(node)) {
      const module = moduleLiteral(node.moduleSpecifier);
      if (SHELL_MODULES.has(module)) add(node, "shell-capable runner imports are forbidden");
      if (PROCESS_MODULES.has(module) && !node.importClause?.isTypeOnly) {
        const bindings = node.importClause?.namedBindings;
        if (node.importClause?.name || !bindings || !ts.isNamedImports(bindings)) {
          add(node, "child_process imports must use audited named exports");
        } else {
          for (const element of bindings.elements) {
            if (!element.isTypeOnly) {
              processBinding(element.name.text, element.propertyName?.text ?? element.name.text, element);
            }
          }
        }
      }
    }

    if (ts.isImportEqualsDeclaration(node)) {
      add(node, "import-equals loading is unaudited in supervisor source");
    }
    if (ts.isCallExpression(node)) {
      const called = callName(node.expression);
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        add(node, "dynamic import is forbidden in supervisor source");
      }
      if (called === "require") inspectRequire(node);
      if (["createRequire", "eval"].includes(called) || called === "_parse") {
        add(node, "indirect process loading, eval, or private shim parsing is forbidden");
      }
      if (ts.isIdentifier(node.expression) && processFunctions.has(node.expression.text) &&
          ["exec", "execSync"].includes(processFunctions.get(node.expression.text))) {
        add(node, "shell-string child_process execution is forbidden");
      }
      const direct = ts.isIdentifier(node.expression)
        ? processFunctions.get(node.expression.text) ?? node.expression.text
        : undefined;
      if (SAFE_PROCESS_EXPORTS.has(direct)) inspectLaunchOptions(node, direct);
      if (SAFE_PROCESS_EXPORTS.has(direct) && moduleLiteral(node.arguments[0]) &&
          (DISALLOWED_PROGRAMS.test(moduleLiteral(node.arguments[0])) ||
           DISALLOWED_SHIMS.test(moduleLiteral(node.arguments[0])))) {
        add(node, "direct interpreter or command-shim dispatch is forbidden");
      }
    }
    if (ts.isVariableDeclaration(node) &&
        node.initializer && ts.isIdentifier(node.initializer) &&
        node.initializer.text === "require") {
      add(node, "aliasing require to bypass import inspection is forbidden");
    }
    if (ts.isCallExpression(node) && callName(node.expression) === "Function") {
      add(node, "dynamic function construction is unaudited");
    }
    if (ts.isNewExpression(node) && nameOf(node.expression) === "Function") {
      add(node, "dynamic function construction is unaudited");
    }
    if (ts.isPropertyAssignment(node) && propertyName(node, file) === "shell") {
      add(node, "shell dispatch option is forbidden");
    }
    if (ts.isShorthandPropertyAssignment(node) && node.name.text === "shell") {
      add(node, "shell dispatch option is forbidden");
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) &&
        node.initializer && ts.isIdentifier(node.initializer) && processFunctions.has(node.initializer.text)) {
      processFunctions.set(node.name.text, processFunctions.get(node.initializer.text));
    }

    if (!isLauncher && filename === "src/services/process-exec.ts" &&
        ts.isVariableDeclaration(node) && nameOf(node.name) === "POSIX_GROUP_LAUNCHER") {
      launcherCount += 1;
      const value = node.initializer;
      if (!value || !ts.isTaggedTemplateExpression(value) ||
          value.tag.getText(file) !== "String.raw" ||
          !ts.isNoSubstitutionTemplateLiteral(value.template)) {
        add(node, "embedded POSIX launcher must be a static String.raw template");
      } else {
        findings.push(...inspectJavaScript(filename + "#POSIX_GROUP_LAUNCHER",
          value.template.rawText ?? value.template.text, true));
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  if (!isLauncher && filename === "src/services/process-exec.ts" && launcherCount !== 1) {
    findings.push(filename + ": expected exactly one audited POSIX_GROUP_LAUNCHER declaration");
  }
  return findings;
}

/** Only the supervisor launch boundary is audited, not repository-owned scripts. */
export function inspectSupervisorSource(filename, source) {
  return inspectJavaScript(filename, source);
}

export function inspectSupervisorSources(readSource = (path) =>
  readFileSync(join(ROOT, path), "utf8")) {
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
