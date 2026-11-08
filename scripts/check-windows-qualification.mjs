import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath, URL } from "node:url";
import yaml from "js-yaml";
import ts from "typescript";

const ROOT = resolve(fileURLToPath(new URL("../", import.meta.url)));

const REQUIREMENTS = Object.freeze([
  { step: "Windows package archive inventory regression",
    files: ["tests/package-archive-verification.test.ts"] },
  { step: "Windows exact Node runtime and shell-free npm dispatch",
    files: ["tests/node-runtime-resolver.test.ts", "tests/validation-service.test.ts"] },
  { step: "Windows process supervision",
    files: ["tests/windows-process-host.test.ts", "tests/windows-process-host-protocol.test.ts", "tests/process-exec.test.ts"] },
  { step: "HTTP, MCP, and server boundary behavior",
    files: ["tests/http-request-cancellation.test.ts", "tests/tool-handler-validation.test.ts", "tests/server-network-boundary.test.ts"] },
  { step: "Validation cancellation and receipt gates",
    files: ["tests/validation-service.test.ts"] },
  { step: "Contract tests",
    files: ["tests/tool-contracts.test.ts", "tests/mcp-contract.test.ts"] },
  { step: "Windows helper package hygiene",
    files: ["tests/package-hygiene.test.ts"] }
]);

const FILTERED_CASES = Object.freeze([
  {
    step: "Windows exact Node runtime and shell-free npm dispatch",
    file: "tests/validation-service.test.ts",
    titles: [
      "runs Windows npm through the exact running Node and bundled npm CLI",
      "does not start Windows npm validation when System32/cmd.exe is unavailable",
      "resolves the configured Windows %s profile to its native executable",
      "does not resolve Windows command shim %s",
      "does not select a repository-controlled make.exe from the worktree"
    ]
  },
  {
    step: "Validation cancellation and receipt gates",
    file: "tests/validation-service.test.ts",
    titles: [
      "cancels an npm validation tree without writing a receipt",
      "preserves the latest receipt when Windows cleanup is unconfirmed",
      "does not publish a validation receipt after process supervision fails",
      "cancellation immediately before commit admission preserves latest",
      "allows overlapping validations and preserves each receipt"
    ]
  },
  {
    step: "Windows helper package hygiene",
    file: "tests/package-hygiene.test.ts",
    titles: [
      "pins the repository package inventory to its runtime files",
      "requires the Windows process host only for Windows package builds",
      "checks the parent route before treating an absent Windows host as optional"
    ]
  }
]);

function tokenize(line) {
  const words = [];
  let part = "";
  let quote;
  let open = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    // PowerShell expands subexpressions and variables outside single quotes.
    // A bare regex end anchor ($) is safe; escaped command syntax is not.
    if (quote !== "'" && char === "`") {
      throw new Error("unaudited PowerShell escaping in Vitest command");
    }
    if (quote !== "'" && char === "$" &&
        /[({A-Za-z_0-9?^$]/.test(line[i + 1] ?? "")) {
      throw new Error("PowerShell expansion in Vitest command is forbidden");
    }
    if (quote) {
      if (char === quote) quote = undefined;
      else part += char;
    } else if (char === '"' || char === "'") {
      quote = char;
      open = true;
    } else if (/\s/.test(char)) {
      if (open) words.push(part);
      part = "";
      open = false;
    } else {
      if (/[|;&<>`]/.test(char)) throw new Error("unquoted shell control character");
      part += char;
      open = true;
    }
  }
  if (quote) throw new Error("unclosed command quote");
  if (open) words.push(part);
  return words;
}

function parseVitest(line) {
  const args = tokenize(line);
  if (args[0] !== "npm" || args[1] !== "test" || args[2] !== "--") {
    throw new Error("expected an npm test -- invocation");
  }
  const files = [];
  let selector;
  for (let i = 3; i < args.length; i++) {
    const arg = args[i];
    if (/^tests\/[\w./-]+\.test\.(?:ts|mjs)$/.test(arg)) {
      files.push(arg);
    } else if (arg === "-t" || arg === "--testNamePattern") {
      if (selector !== undefined || !args[i + 1]) throw new Error("missing or duplicate selector");
      selector = args[++i];
    } else if (/^(?:-t|--testNamePattern)=/.test(arg)) {
      if (selector !== undefined) throw new Error("duplicate selector");
      selector = arg.slice(arg.indexOf("=") + 1);
      if (!selector) throw new Error("empty selector");
    } else if (arg === "--reporter") {
      if (args[++i] !== "verbose") throw new Error("unsupported reporter");
    } else if (arg !== "--reporter=verbose") {
      throw new Error("unsupported or ambiguous Vitest argument: " + arg);
    }
  }
  if (!files.length || new Set(files).size !== files.length) {
    throw new Error("missing or duplicate test-file selection");
  }
  if (selector !== undefined) new RegExp(selector);
  return { files, selector };
}

function testCommands(step, findings) {
  if (!step || typeof step.run !== "string") return [];
  try {
    return step.run.split("\n").map((line) => line.trim()).filter(Boolean).map(parseVitest);
  } catch (error) {
    findings.push(step.name + " has an unaudited Vitest command: " + String(error.message));
    return [];
  }
}

function unwrap(node) {
  while (ts.isAsExpression(node) || ts.isParenthesizedExpression(node) ||
         ts.isSatisfiesExpression(node)) node = node.expression;
  return node;
}

function literal(node) {
  if (!node) return undefined;
  node = unwrap(node);
  return ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) ? node.text : undefined;
}

function eachValues(node) {
  node = node && unwrap(node);
  if (!node || !ts.isArrayLiteralExpression(node)) return [];
  return node.elements.map((entry) => {
    entry = unwrap(entry);
    return literal(ts.isArrayLiteralExpression(entry) ? entry.elements[0] : entry);
  }).filter((value) => value !== undefined);
}

function access(node) {
  if (ts.isPropertyAccessExpression(node)) {
    return { receiver: node.expression, method: node.name.text };
  }
  if (ts.isElementAccessExpression(node)) {
    return { receiver: node.expression, method: literal(node.argumentExpression) };
  }
  return undefined;
}

// Small lexical resolver shared by platform provenance and Vitest registration.
// A binding that cannot be proved immutable is not evidence of eligibility.
function lexicalBinding(reference) {
  const name = reference.text;
  const declares = (pattern) => ts.isIdentifier(pattern) ? pattern.text === name :
    (ts.isArrayBindingPattern(pattern) || ts.isObjectBindingPattern(pattern)) &&
      pattern.elements.some((element) => ts.isBindingElement(element) && declares(element.name));
  const fromStatements = (statements) => {
    const found = [];
    for (const statement of statements) {
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (declares(declaration.name)) found.push({ kind: "variable", node: declaration,
            constant: !!(statement.declarationList.flags & ts.NodeFlags.Const) });
        }
      }
      if ((ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) &&
          statement.name?.text === name) found.push({ kind: "opaque" });
      if (ts.isImportDeclaration(statement) && statement.importClause) {
        const imports = statement.importClause;
        const module = literal(statement.moduleSpecifier);
        if (imports.name?.text === name) {
          found.push({ kind: "import", module, imported: "default", typeOnly: imports.isTypeOnly });
        }
        const named = imports.namedBindings;
        if (named && ts.isNamespaceImport(named) && named.name.text === name) {
          found.push({ kind: "import", module, imported: "*", typeOnly: imports.isTypeOnly });
        }
        if (named && ts.isNamedImports(named)) {
          for (const element of named.elements) {
            if (element.name.text === name) found.push({ kind: "import", module,
              imported: element.propertyName?.text ?? element.name.text,
              typeOnly: imports.isTypeOnly || element.isTypeOnly });
          }
        }
      }
    }
    return found;
  };
  const hasHoistedVar = (fn) => {
    let found = false;
    const visit = (node) => {
      if (found || (node !== fn.body && ts.isFunctionLike(node))) return;
      if (ts.isVariableDeclaration(node) && ts.isVariableDeclarationList(node.parent) &&
          !(node.parent.flags & (ts.NodeFlags.Const | ts.NodeFlags.Let)) &&
          declares(node.name)) { found = true; return; }
      ts.forEachChild(node, visit);
    };
    if (fn.body) visit(fn.body);
    return found;
  };
  for (let scope = reference.parent; scope; scope = scope.parent) {
    if (ts.isBlock(scope) || ts.isSourceFile(scope) ||
        ts.isModuleBlock(scope) || ts.isCaseBlock(scope)) {
      const found = fromStatements(scope.statements);
      if (found.length) return found.length === 1 ? found[0] : { kind: "ambiguous" };
    }
    if (ts.isCatchClause(scope) && scope.variableDeclaration &&
        declares(scope.variableDeclaration.name)) return { kind: "opaque" };
    if (ts.isForStatement(scope) || ts.isForOfStatement(scope) ||
        ts.isForInStatement(scope)) {
      const init = scope.initializer;
      if (init && ts.isVariableDeclarationList(init) &&
          init.declarations.some((declaration) => declares(declaration.name))) {
        return { kind: "opaque" };
      }
    }
    if (ts.isFunctionLike(scope)) {
      if (hasHoistedVar(scope) || scope.parameters.some((p) => declares(p.name)) ||
          (scope.name && ts.isIdentifier(scope.name) && scope.name.text === name)) return { kind: "opaque" };
    }
  }
  return undefined;
}

function verifiedProcess(input, seen = new Set()) {
  const node = input && unwrap(input);
  if (!node) return false;
  if (ts.isIdentifier(node)) {
    const binding = lexicalBinding(node);
    if (!binding) return node.text === "process";
    if (binding.kind === "import") return !binding.typeOnly &&
      ["node:process", "process"].includes(binding.module) &&
      ["default", "*"].includes(binding.imported);
    if (binding.kind !== "variable" || !binding.constant ||
        !binding.node.initializer || seen.has(binding.node)) return false;
    const next = new Set(seen);
    next.add(binding.node);
    const init = unwrap(binding.node.initializer);
    if (ts.isCallExpression(init) && ts.isIdentifier(init.expression) &&
        init.expression.text === "require" && init.arguments.length === 1 &&
        ["node:process", "process"].includes(literal(init.arguments[0]))) return true;
    return verifiedProcess(init, next);
  }
  const member = access(node);
  if (member && member.method === "process" &&
      ts.isIdentifier(member.receiver) && member.receiver.text === "globalThis" &&
      !lexicalBinding(member.receiver)) return true;
  return false;
}

function verifiedPlatform(node) {
  node = node && unwrap(node);
  if (!node) return false;
  const member = access(node);
  if (member?.method === "platform") return verifiedProcess(member.receiver);
  if (ts.isIdentifier(node)) {
    const binding = lexicalBinding(node);
    return binding?.kind === "import" && !binding.typeOnly &&
      ["node:process", "process"].includes(binding.module) &&
      binding.imported === "platform";
  }
  return false;
}

// Only Vitest namespace imports and their immutable identifier aliases carry
// namespace provenance. A foreign, mutable, or shadowed binding is unproven.
function vitestNamespace(input, seen = new Set()) {
  const node = input && unwrap(input);
  if (!node || !ts.isIdentifier(node)) return false;
  const binding = lexicalBinding(node);
  if (binding?.kind === "import") return binding.module === "vitest" &&
    !binding.typeOnly && binding.imported === "*";
  if (binding?.kind !== "variable" || !binding.constant ||
      !ts.isIdentifier(binding.node.name) || !binding.node.initializer ||
      seen.has(binding.node)) return false;
  const next = new Set(seen);
  next.add(binding.node);
  return vitestNamespace(binding.node.initializer, next);
}

const VITEST_REGISTRATIONS = new Set(["test", "it", "describe"]);

function vitestKind(input, seen = new Set()) {
  const node = input && unwrap(input);
  if (!node) return undefined;
  const member = access(node);
  if (member && VITEST_REGISTRATIONS.has(member.method) &&
      vitestNamespace(member.receiver, seen)) return member.method;
  if (!ts.isIdentifier(node)) return undefined;
  const binding = lexicalBinding(node);
  if (!binding) return VITEST_REGISTRATIONS.has(node.text) ? node.text : undefined;
  if (binding.kind === "import") return binding.module === "vitest" &&
    !binding.typeOnly && VITEST_REGISTRATIONS.has(binding.imported)
    ? binding.imported : undefined;
  if (binding.kind !== "variable" || !binding.constant ||
      !binding.node.initializer || seen.has(binding.node)) return undefined;
  const next = new Set(seen);
  next.add(binding.node);
  if (ts.isObjectBindingPattern(binding.node.name) &&
      vitestNamespace(binding.node.initializer, next)) {
    const element = binding.node.name.elements.find((item) =>
      ts.isIdentifier(item.name) && item.name.text === node.text &&
      !item.dotDotDotToken && !item.initializer);
    const name = element?.propertyName ?? element?.name;
    const key = name && (ts.isIdentifier(name) || ts.isStringLiteralLike(name))
      ? name.text : name && ts.isComputedPropertyName(name)
        ? literal(name.expression) : undefined;
    return VITEST_REGISTRATIONS.has(key) ? key : undefined;
  }
  return vitestKind(binding.node.initializer, next);
}

// A computed Vitest namespace member cannot prove which registration API it
// selects. If it is used with an exclusive/dynamic decorator, reject rather
// than let another matching mandatory test hide the exclusive declaration.
function unresolvedVitestMember(input, seen = new Set()) {
  const node = input && unwrap(input);
  if (!node) return false;
  const member = access(node);
  if (member) return member.method === undefined && vitestNamespace(member.receiver, seen);
  if (!ts.isIdentifier(node)) return false;
  const binding = lexicalBinding(node);
  if (binding?.kind !== "variable" || !binding.constant ||
      !binding.node.initializer || seen.has(binding.node)) return false;
  const next = new Set(seen);
  next.add(binding.node);
  if (ts.isObjectBindingPattern(binding.node.name) &&
      vitestNamespace(binding.node.initializer, next)) {
    const element = binding.node.name.elements.find((item) =>
      ts.isIdentifier(item.name) && item.name.text === node.text);
    const name = element?.propertyName;
    return !!name && ts.isComputedPropertyName(name) &&
      literal(name.expression) === undefined;
  }
  return ts.isIdentifier(binding.node.name) &&
    unresolvedVitestMember(binding.node.initializer, next);
}

/** A deliberately small Windows-only predicate evaluator; unknown means unproven. */
function conditionOnWindows(node) {
  if (!node) return undefined;
  node = unwrap(node);
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (ts.isPrefixUnaryExpression(node) &&
      node.operator === ts.SyntaxKind.ExclamationToken) {
    const value = conditionOnWindows(node.operand);
    return value === undefined ? undefined : !value;
  }
  if (ts.isBinaryExpression(node)) {
    const op = node.operatorToken.kind;
    const equal = op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      op === ts.SyntaxKind.EqualsEqualsToken;
    const unequal = op === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
      op === ts.SyntaxKind.ExclamationEqualsToken;
    if (!equal && !unequal) return undefined;
    const value = verifiedPlatform(node.left) ? literal(node.right) :
      verifiedPlatform(node.right) ? literal(node.left) : undefined;
    if (value !== undefined) {
      const matches = value === "win32";
      return equal ? matches : !matches;
    }
  }
  return undefined;
}

function invocationKind(expression, names) {
  if (names.includes(vitestKind(expression))) {
    return { enabled: true };
  }
  const member = access(expression);
  if (member && names.includes(vitestKind(member.receiver)) &&
      ["skip", "todo"].includes(member.method)) {
    return { enabled: false };
  }
  if (!ts.isCallExpression(expression)) return undefined;
  const decorator = access(expression.expression);
  if (!decorator) return undefined;
  const inner = invocationKind(decorator.receiver, names);
  if (!inner) return undefined;
  if (decorator.method === "skipIf") {
    return { ...inner, enabled: inner.enabled &&
      conditionOnWindows(expression.arguments[0]) === false };
  }
  if (decorator.method === "runIf") {
    return { ...inner, enabled: inner.enabled &&
      conditionOnWindows(expression.arguments[0]) === true };
  }
  if (decorator.method === "each") {
    const values = eachValues(expression.arguments[0]);
    return { ...inner, enabled: inner.enabled && values.length > 0, values };
  }
  return undefined;
}

/**
 * Prove Vitest registration only in top-level statements and callbacks of
 * enabled describe suites. Uninvoked functions and deferred callbacks are
 * not registration contexts, even when they contain matching test strings.
 */
export function collectWindowsTestTitles(filename, source) {
  const file = ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  if (file.parseDiagnostics.length) throw new Error("Cannot parse Vitest declarations");
  const titles = [];

  // Exclusive declarations anywhere in the file remain fail-closed, including
  // element access and unknown dynamic member selectors.
  const checkExclusive = (node) => {
    const member = access(node);
    if (member && (vitestKind(member.receiver) ||
        unresolvedVitestMember(member.receiver)) &&
        (member.method === undefined || member.method === "only")) {
      throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
    }
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const kind = vitestKind(node.initializer);
      if (vitestNamespace(node.initializer) &&
          !(node.parent.flags & ts.NodeFlags.Const)) {
        throw new Error("Mutable Vitest namespace aliases are unaudited.");
      }
      if (kind && !(node.parent.flags & ts.NodeFlags.Const)) {
        throw new Error("Mutable Vitest registration aliases are unaudited.");
      }
      if (kind && ts.isObjectBindingPattern(node.name) &&
          node.name.elements.some((item) => {
            const name = item.propertyName ?? item.name;
            return ts.isIdentifier(name) && name.text === "only" ||
              ts.isStringLiteralLike(name) && name.text === "only" ||
              ts.isComputedPropertyName(name);
          })) {
        throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
      }
    }
    ts.forEachChild(node, checkExclusive);
  };
  checkExclusive(file);

  const register = (node, disabled = false) => {
    if (ts.isSourceFile(node) || ts.isBlock(node)) {
      for (const statement of node.statements) register(statement, disabled);
      return;
    }
    if (ts.isIfStatement(node)) {
      const outcome = conditionOnWindows(node.expression);
      register(node.thenStatement, disabled || outcome !== true);
      if (node.elseStatement) register(node.elseStatement, disabled || outcome !== false);
      return;
    }
    if (ts.isExpressionStatement(node)) {
      register(node.expression, disabled);
      return;
    }
    node = unwrap(node);
    if (ts.isConditionalExpression(node)) {
      const outcome = conditionOnWindows(node.condition);
      register(node.whenTrue, disabled || outcome !== true);
      register(node.whenFalse, disabled || outcome !== false);
      return;
    }
    if (!ts.isCallExpression(node)) return;

    const suite = invocationKind(node.expression, ["describe"]);
    if (suite) {
      const callback = unwrap(node.arguments[1]);
      if (callback && (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback))) {
        register(callback.body, disabled || !suite.enabled);
      }
      // Unresolved suite callbacks are not proven to register tests.
      return;
    }
    const title = literal(node.arguments[0]);
    const call = invocationKind(node.expression, ["test", "it"]);
    if (call && title !== undefined) {
      const expanded = call.values ? call.values.map((value, i) =>
        title.replace(/%s|%d|%i/, (p) => p === "%i" ? String(i) : String(value))) : [title];
      for (const name of expanded) titles.push({ title: name, enabled: call.enabled && !disabled });
    }
    // Other calls (setTimeout, .then, IIFEs, fixtures) are not Vitest
    // registration contexts; never descend through their callbacks.
  };
  register(file);
  return titles;
}

function expandMandatory(title) {
  if (title === "resolves the configured Windows %s profile to its native executable") {
    return ["make", "just"].map((value) => title.replace("%s", value));
  }
  if (title === "does not resolve Windows command shim %s") {
    return ["make.cmd", "make.bat", "make.ps1"].map((value) => title.replace("%s", value));
  }
  return [title];
}

function mandatoryStep(steps, name, findings, platform) {
  const matches = steps.filter((step) => step?.name === name);
  if (matches.length !== 1) {
    findings.push(platform + " must have exactly one required step: " + name);
    return undefined;
  }
  const step = matches[0];
  if (Object.hasOwn(step, "if") ||
      (Object.hasOwn(step, "continue-on-error") && step["continue-on-error"] !== false)) {
    findings.push(platform + " has a conditional or optional step: " + name);
  }
  return step;
}

function mandatoryJob(jobs, name, runner, findings) {
  const job = jobs?.[name];
  if (!job || !Array.isArray(job.steps)) {
    findings.push("Required CI job missing: " + name);
    return [];
  }
  if (Object.hasOwn(job, "if") ||
      (Object.hasOwn(job, "continue-on-error") && job["continue-on-error"] !== false) ||
      job["runs-on"] !== runner) {
    findings.push("Required CI job is conditional, optional, or uses an unexpected runner: " + name);
  }
  if (JSON.stringify(job.strategy?.matrix?.["node-version"]) !==
        JSON.stringify(["20.x", "22.x"]) ||
      Object.keys(job.strategy?.matrix ?? {}).some((key) => key !== "node-version")) {
    findings.push("Required CI job must qualify both Node 20.x and Node 22.x: " + name);
  }
  return job.steps;
}

export function inspectQualificationWorkflow(workflow, readTest = (path) =>
  readFileSync(join(ROOT, path), "utf8")) {
  const findings = [];
  const linux = mandatoryJob(workflow?.jobs, "test", "ubuntu-latest", findings);
  const windows = mandatoryJob(workflow?.jobs, "windows-test", "windows-2025", findings);
  for (const [steps, platform] of [[linux, "Linux"], [windows, "Windows"]]) {
    const guard = mandatoryStep(steps, "Validation security and CI coverage guardrails", findings, platform);
    if (guard?.run?.trim() !== "npm run check:validation-guardrails") {
      findings.push(platform + " must run mandatory validation guardrails");
    }
  }
  for (const [steps, platform, required] of [
    [linux, "Linux", [
      ["Typecheck", "npm run typecheck"],
      ["Lint", "npm run lint"],
      ["Public hygiene", "npm run check:public"],
      ["Build", "npm run build"],
      ["Whitespace check", "git diff --check"]
    ]],
    [windows, "Windows", [
      ["Typecheck", "npm run typecheck"],
      ["Build production package and Windows helper", "npm run build"],
      ["Lint", "npm run lint"],
      ["Whitespace check", "git diff --check"]
    ]]
  ]) {
    for (const [name, command] of required) {
      const requiredStep = mandatoryStep(steps, name, findings, platform);
      if (requiredStep?.run?.trim() !== command) {
        findings.push(platform + " must execute required command: " + name);
      }
    }
  }
  const linuxSuite = mandatoryStep(linux, "Test", findings, "Linux");
  if (linuxSuite?.run?.trim() !== "npm test") {
    findings.push("Linux CI must run the unfiltered full suite, including POSIX supervision tests.");
  }
  const archive = mandatoryStep(windows, "Verify actual Windows npm package archive", findings, "Windows");
  if (archive?.run?.trim() !== "npm run verify:package-archive") {
    findings.push("Windows CI must verify the actual npm package archive");
  }

  const selectedByStep = new Map();
  for (const scope of REQUIREMENTS) {
    const step = mandatoryStep(windows, scope.step, findings, "Windows");
    const commands = testCommands(step, findings);
    selectedByStep.set(scope.step, commands);
    for (const file of scope.files) {
      if (!commands.some((command) => command.files.includes(file))) {
        findings.push(scope.step + " must execute " + file);
      }
    }
  }

  const parsedFiles = new Map();
  for (const scope of FILTERED_CASES) {
    const commands = (selectedByStep.get(scope.step) ?? [])
      .filter((command) => command.files.includes(scope.file));
    if (!parsedFiles.has(scope.file)) {
      try {
        parsedFiles.set(scope.file, collectWindowsTestTitles(scope.file, readTest(scope.file)));
      } catch {
        parsedFiles.set(scope.file, []);
        findings.push("Could not parse mandatory Vitest declarations: " + scope.file);
      }
    }
    const declarations = parsedFiles.get(scope.file);
    for (const expected of scope.titles.flatMap(expandMandatory)) {
      const matching = declarations.filter((test) => test.title === expected && test.enabled);
      if (matching.length !== 1) {
        findings.push(scope.file + " is missing or disabling mandatory regression: " + expected);
      }
      if (!commands.some((command) =>
        command.selector === undefined || new RegExp(command.selector).test(expected))) {
        findings.push(scope.step + " does not select mandatory regression: " + expected);
      }
    }
  }
  return findings;
}

export function inspectQualificationFile(path = join(ROOT, ".github", "workflows", "ci.yml")) {
  const workflow = yaml.load(readFileSync(path, "utf8"));
  return inspectQualificationWorkflow(workflow);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const findings = inspectQualificationFile();
    if (findings.length > 0) {
      for (const finding of findings) process.stderr.write(finding + "\n");
      process.exitCode = 1;
    } else {
      process.stdout.write("Windows qualification selector guard passed.\n");
    }
  } catch (error) {
    process.stderr.write("Windows qualification guard failed: " +
      (error instanceof Error ? error.message : String(error)) + "\n");
    process.exitCode = 1;
  }
}
