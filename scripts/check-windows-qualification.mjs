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
const WINDOWS_TEST_DECLARATION_CACHE = new Map();

function collectCachedWindowsTestTitles(filename, source) {
  const cached = WINDOWS_TEST_DECLARATION_CACHE.get(filename);
  if (cached?.source === source) return cached.titles;
  const titles = collectWindowsTestTitles(filename, source);
  WINDOWS_TEST_DECLARATION_CACHE.set(filename, { source, titles });
  return titles;
}

function tokenize(line) {
  const words = [];
  let part = "";
  let quote;
  let open = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (quote) {
      if (quote === '"' && char === "`") {
        const escaped = line[index + 1];
        if (!["$", "`", '"'].includes(escaped)) {
          throw new Error("unsupported PowerShell escape in a double-quoted argument");
        }
        part += escaped;
        index += 1;
        continue;
      }
    if (quote === "'" && char === "'" && line[index + 1] === "'") {
      part += "'";
      index += 1;
      continue;
    }
    // PowerShell expands these forms inside double-quoted arguments.
      if (quote === '"' && char === "$" && /[\p{L}\p{Nd}_?^$:({]/u.test(line[index + 1] ?? "")) {
        throw new Error("PowerShell interpolation in a double-quoted argument is unaudited");
      }
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
      if (char === "$" && /[\p{L}\p{Nd}_?^$:({]/u.test(line[index + 1] ?? "")) {
        throw new Error("PowerShell interpolation in an unquoted argument is unaudited");
      }
        // PowerShell starts an expression at unquoted parentheses.
        if (/[|;&<>`()]/.test(char)) throw new Error("unquoted shell control character");
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
  if (!node) return node;
  while (ts.isAsExpression(node) || ts.isParenthesizedExpression(node) ||
         ts.isSatisfiesExpression(node) || ts.isTypeAssertionExpression(node) ||
         ts.isNonNullExpression(node)) node = node.expression;
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

/** A deliberately small Windows-only predicate evaluator; unknown means unproven. */
function conditionOnWindows(node, isProcessPlatform = () => false) {
  if (!node) return undefined;
  node = unwrap(node);
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (ts.isPrefixUnaryExpression(node) &&
      node.operator === ts.SyntaxKind.ExclamationToken) {
    const value = conditionOnWindows(node.operand, isProcessPlatform);
    return value === undefined ? undefined : !value;
  }
  if (ts.isBinaryExpression(node)) {
    const op = node.operatorToken.kind;
    const equal = op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      op === ts.SyntaxKind.EqualsEqualsToken;
    const unequal = op === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
      op === ts.SyntaxKind.ExclamationEqualsToken;
    if (!equal && !unequal) return undefined;
    const value = isProcessPlatform(node.left) ? literal(node.right) :
      isProcessPlatform(node.right) ? literal(node.left) : undefined;
    if (value !== undefined) {
      const matches = value === "win32";
      return equal ? matches : !matches;
    }
  }
  return undefined;
}

function invocationKind(expression, names, isProcessPlatform, testRunnerOf) {
  if (testRunnerOf(expression, names)) {
    return { enabled: true };
  }
  const member = access(expression);
  if (member && testRunnerOf(member.receiver, names) &&
      ["concurrent", "fails", "sequential"].includes(member.method)) {
    return { enabled: true };
  }
  if (member && testRunnerOf(member.receiver, names) &&
      ["skip", "todo"].includes(member.method)) {
    return { enabled: false };
  }
  if (!ts.isCallExpression(expression)) return undefined;
  const decorator = access(expression.expression);
  if (!decorator) return undefined;
  const inner = invocationKind(decorator.receiver, names, isProcessPlatform, testRunnerOf);
  if (!inner) return undefined;
  if (decorator.method === "concurrent" || decorator.method === "sequential") return inner;
  if (decorator.method === "skipIf") {
    return { ...inner, enabled: inner.enabled &&
      conditionOnWindows(expression.arguments[0], isProcessPlatform) === false };
  }
  if (decorator.method === "runIf") {
    return { ...inner, enabled: inner.enabled &&
      conditionOnWindows(expression.arguments[0], isProcessPlatform) === true };
  }
  if (decorator.method === "each") {
    const values = eachValues(expression.arguments[0]);
    return { ...inner, enabled: inner.enabled && values.length > 0, values };
  }
  return undefined;
}

// Vitest may disable an otherwise registered suite or test through its second
// argument. Unknown option shapes cannot prove that a mandatory case runs.
function registrationOptionValueOf(input, resolveBinding, seen = new Set()) {
  const node = unwrap(input);
  if (!node) return undefined;
  if (ts.isArrowFunction(node) || ts.isFunctionExpression(node) ||
      ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) {
    return { kind: "callable" };
  }
  if (ts.isObjectLiteralExpression(node)) return { kind: "options", node };
  if (!ts.isIdentifier(node)) return undefined;
  const binding = resolveBinding(node);
  if (!binding || seen.has(binding.node)) return undefined;
  if (binding.kind === "opaque" &&
      (ts.isFunctionDeclaration(binding.node) || ts.isClassDeclaration(binding.node))) {
    return { kind: "callable" };
  }
  const declaration = ts.isVariableDeclaration(binding.node) ||
    ts.isParameter(binding.node) ? binding.node : undefined;
  if (!declaration?.initializer ||
      (ts.isVariableDeclaration(declaration) && !binding.constant)) return undefined;
  const next = new Set(seen);
  next.add(binding.node);
  return registrationOptionValueOf(declaration.initializer, resolveBinding, next);
}

function registrationOptionsEnabled(argumentsList, resolveBinding) {
  if (argumentsList.length < 2) return true;
  const candidate = unwrap(argumentsList[1]);
  const option = registrationOptionValueOf(candidate, resolveBinding);
  if (option?.kind === "callable") return true;
  if (option?.kind !== "options") return false;
  const supportedOptions = new Set([
    "concurrent", "fails", "meta", "only", "repeats", "retry", "sequential",
    "skip", "tags", "timeout", "todo"
  ]);
  for (const property of option.node.properties) {
    if (ts.isSpreadAssignment(property)) return false;
    const name = ts.isComputedPropertyName(property.name)
      ? literal(property.name.expression)
      : ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) ||
          ts.isNumericLiteral(property.name) ? property.name.text : undefined;
    if (name === undefined) return false;
    if (!supportedOptions.has(name)) return false;
    if (!["only", "skip", "todo"].includes(name)) continue;
    const value = ts.isPropertyAssignment(property)
      ? unwrap(property.initializer)
      : ts.isShorthandPropertyAssignment(property) ? property.name : undefined;
    if (!value || (value.kind !== ts.SyntaxKind.TrueKeyword &&
        value.kind !== ts.SyntaxKind.FalseKeyword)) return false;
    const enabled = value.kind === ts.SyntaxKind.TrueKeyword;
    if (name === "only" && enabled) {
      throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
    }
    if ((name === "skip" || name === "todo") && enabled) return false;
  }
  return true;
}

function hasRegistrationCallback(argumentsList, resolveBinding) {
  return argumentsList.slice(1).some((argument) =>
    registrationOptionValueOf(argument, resolveBinding)?.kind === "callable");
}

// Resolve only the names used by Windows predicates and Vitest registration.
function createWindowsTestBindingResolver(file) {
  const isAmbientDeclaration = (statement) => Boolean(statement.modifiers?.some(
    (modifier) => modifier.kind === ts.SyntaxKind.DeclareKeyword));
  const declaresName = (name, expected) => {
    if (ts.isIdentifier(name)) return name.text === expected;
    if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      return name.elements.some((element) =>
        ts.isBindingElement(element) && declaresName(element.name, expected));
    }
    return false;
  };
  const bindingsIn = (statements = [], name) => {
    const found = [];
    for (const statement of statements) {
      if (!isAmbientDeclaration(statement) && ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (declaresName(declaration.name, name)) {
            found.push({
              kind: ts.isIdentifier(declaration.name) ? "variable" : "opaque",
              node: declaration,
              constant: !!(statement.declarationList.flags & ts.NodeFlags.Const)
            });
          }
        }
      }
      if (!isAmbientDeclaration(statement) &&
          (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement) ||
           ts.isEnumDeclaration(statement) || ts.isModuleDeclaration(statement)) &&
          statement.name?.text === name) found.push({ kind: "opaque", node: statement });
      if (ts.isImportEqualsDeclaration(statement) && statement.name.text === name) {
        found.push({ kind: "opaque", node: statement });
      }
      if (ts.isImportDeclaration(statement) && statement.importClause) {
        const clause = statement.importClause;
        const named = clause.namedBindings;
        if (clause.name?.text === name) {
          found.push({ kind: "import", node: statement, module: literal(statement.moduleSpecifier),
            imported: "default", typeOnly: clause.isTypeOnly });
        }
        if (named && ts.isNamespaceImport(named) && named.name.text === name) {
          found.push({ kind: "import", node: statement, module: literal(statement.moduleSpecifier),
            imported: "*", typeOnly: clause.isTypeOnly });
        }
        if (named && ts.isNamedImports(named)) {
          for (const element of named.elements) {
            if (element.name.text === name) {
              found.push({ kind: "import", node: statement,
                module: literal(statement.moduleSpecifier),
                imported: element.propertyName?.text ?? element.name.text,
                typeOnly: clause.isTypeOnly || element.isTypeOnly });
            }
          }
        }
      }
    }
    return found;
  };
  const hasHoistedVar = (owner, name) => {
    let found = false;
    const visit = (node) => {
      if (found || (node !== owner && ts.isFunctionLike(node))) return;
      if (ts.isVariableDeclaration(node) && ts.isVariableDeclarationList(node.parent) &&
          !(node.parent.flags & (ts.NodeFlags.Const | ts.NodeFlags.Let)) &&
          !isAmbientDeclaration(node.parent.parent) &&
          declaresName(node.name, name)) {
        found = true;
        return;
      }
      ts.forEachChild(node, visit);
    };
    visit(owner);
    return found;
  };
  const resolveBinding = (reference) => {
    const name = reference.text;
    for (let scope = reference.parent; scope; scope = scope.parent) {
    if (ts.isBlock(scope) || ts.isSourceFile(scope) ||
        ts.isModuleBlock(scope) || ts.isCaseBlock(scope)) {
      const scopeStatements = ts.isCaseBlock(scope)
        ? scope.clauses.flatMap((clause) => clause.statements)
        : scope.statements;
      const matches = bindingsIn(scopeStatements, name);
        if (matches.length) return matches.length === 1 ? matches[0] : { kind: "ambiguous" };
        if (ts.isSourceFile(scope) && hasHoistedVar(scope, name)) {
          return { kind: "opaque", node: scope };
        }
      }
      if (ts.isCatchClause(scope) && scope.variableDeclaration &&
          declaresName(scope.variableDeclaration.name, name)) {
        return { kind: "opaque", node: scope.variableDeclaration };
      }
      if ((ts.isForStatement(scope) || ts.isForOfStatement(scope) || ts.isForInStatement(scope)) &&
          scope.initializer && ts.isVariableDeclarationList(scope.initializer) &&
          scope.initializer.declarations.some((declaration) => declaresName(declaration.name, name))) {
        return { kind: "opaque", node: scope.initializer };
      }
      if (ts.isFunctionLike(scope)) {
        if (hasHoistedVar(scope, name)) return { kind: "opaque", node: scope };
        const parameters = scope.parameters.filter((parameter) => declaresName(parameter.name, name));
        if (parameters.length) return parameters.length === 1
          ? { kind: "opaque", node: parameters[0] } : { kind: "ambiguous" };
        if (scope.name && ts.isIdentifier(scope.name) && scope.name.text === name) {
          return { kind: "opaque", node: scope };
        }
      }
    }
    return undefined;
  };
  const staticStringOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return undefined;
    if (ts.isStringLiteralLike(node)) return node.text;
    if (ts.isNumericLiteral(node)) {
      const value = Number(node.text);
      return Number.isFinite(value) ? String(value) : undefined;
    }
    if (ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
      return staticStringOf(node.right, seen);
    }
    if (ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const numericLeft = staticNumericStringOf(node.left, seen);
      const numericRight = staticNumericStringOf(node.right, seen);
      if (numericLeft !== undefined && numericRight !== undefined) {
        return String(numericLeft + numericRight);
      }
      const left = staticStringOf(node.left, seen);
      const right = staticStringOf(node.right, seen);
      return left !== undefined && right !== undefined ? left + right : undefined;
    }
    if (ts.isConditionalExpression(node)) {
      const left = staticStringOf(node.whenTrue, seen);
      const right = staticStringOf(node.whenFalse, seen);
      return left !== undefined && left === right ? left : undefined;
    }
    if (!ts.isIdentifier(node)) return undefined;
    const binding = resolveBinding(node);
    if (binding?.kind !== "variable" || !binding.constant ||
        !binding.node.initializer || seen.has(binding.node) ||
        !ts.isVariableDeclaration(binding.node) ||
        !ts.isIdentifier(binding.node.name)) return undefined;
    const next = new Set(seen);
    next.add(binding.node);
    return staticStringOf(binding.node.initializer, next);
  };
  const staticNumericStringOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return undefined;
    if (ts.isNumericLiteral(node)) {
      const value = Number(node.text);
      return Number.isFinite(value) ? value : undefined;
    }
    if (ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = staticNumericStringOf(node.left, seen);
      const right = staticNumericStringOf(node.right, seen);
      return left !== undefined && right !== undefined ? left + right : undefined;
    }
    if (!ts.isIdentifier(node)) return undefined;
    const binding = resolveBinding(node);
    if (binding?.kind !== "variable" || !binding.constant ||
        !binding.node.initializer || seen.has(binding.node)) return undefined;
    const next = new Set(seen);
    next.add(binding.node);
    return staticNumericStringOf(binding.node.initializer, next);
  };
  const resolvedAccess = (input) => {
    const node = unwrap(input);
    if (!node) return undefined;
    if (ts.isPropertyAccessExpression(node)) {
      return { receiver: node.expression, method: node.name.text };
    }
    if (ts.isElementAccessExpression(node)) {
      return { receiver: node.expression, method: staticStringOf(node.argumentExpression) };
    }
    return undefined;
  };
  const aliasAssignmentKinds = new Set([
    ts.SyntaxKind.EqualsToken,
    ts.SyntaxKind.QuestionQuestionEqualsToken,
    ts.SyntaxKind.BarBarEqualsToken,
    ts.SyntaxKind.AmpersandAmpersandEqualsToken
  ]);
  const assignmentsByBinding = new Map();
  const runnerAssignmentsByBinding = new Map();
  const destructuredAssignmentsByBinding = new Map();
  const destructuredPropertyAssignmentsByBinding = new Map();
  const arrayMutationValuesByBinding = new Map();
const assignmentsByMemberPath = new Map();
  const parameterRunnerArguments = new Map();
  const parameterRestArguments = new Map();
  const parameterFunctionArguments = new Map();
  const functionArgumentsPlans = new Map();
  const getterReceiverOf = (getter) =>
    ts.isObjectLiteralExpression(getter.parent) ? getter.parent : undefined;
const assignmentMemberAccess = (node) => {
  node = unwrap(node);
  if (ts.isPropertyAccessExpression(node)) {
    return { receiver: node.expression, property: node.name.text };
  }
  if (ts.isElementAccessExpression(node)) {
    const property = staticStringOf(node.argumentExpression);
    if (property !== undefined) return { receiver: node.expression, property };
  }
  return undefined;
};
const assignmentReferenceKey = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return undefined;
  const member = assignmentMemberAccess(node);
  if (member) {
    const receiver = assignmentReferenceKey(member.receiver, seen);
    return receiver === undefined ? undefined : JSON.stringify([receiver, member.property]);
  }
  if (ts.isElementAccessExpression(node)) return `dynamic:${node.getText(file)}`;
  if (!ts.isIdentifier(node)) return `expression:${node.pos}:${node.end}`;
  const binding = resolveBinding(node);
  if (!binding) return `global:${node.text}`;
  if (!binding.node) return `unbound:${node.text}`;
  if (seen.has(binding.node)) return `binding:${binding.node.pos}`;
  const next = new Set(seen);
  next.add(binding.node);
  if (binding.kind === "variable" && ts.isVariableDeclaration(binding.node) &&
      ts.isIdentifier(binding.node.name) && binding.node.initializer &&
      (ts.isIdentifier(unwrap(binding.node.initializer)) ||
       assignmentMemberAccess(binding.node.initializer))) {
    const aliased = assignmentReferenceKey(binding.node.initializer, next);
    if (aliased !== undefined) return aliased;
  }
  return `binding:${binding.node.pos}`;
};
  const recordAssignment = (target, value) => {
  const member = assignmentMemberAccess(target);
  if (member) {
    const key = assignmentReferenceKey(target);
    if (key !== undefined) {
      const assignments = assignmentsByMemberPath.get(key) ?? [];
      assignments.push(value);
      assignmentsByMemberPath.set(key, assignments);
    }
    return;
  }
  if (ts.isElementAccessExpression(target)) {
    const key = assignmentReferenceKey(target);
    if (key !== undefined) {
      const assignments = assignmentsByMemberPath.get(key) ?? [];
      assignments.push(value);
      assignmentsByMemberPath.set(key, assignments);
    }
    return;
  }
    const binding = resolveBinding(target);
    if (!binding?.node) return;
    const directBinding =
      (binding.kind === "variable" && ts.isVariableDeclaration(binding.node) &&
       ts.isIdentifier(binding.node.name)) ||
      (binding.kind === "opaque" && (ts.isVariableDeclaration(binding.node) ||
       ts.isParameter(binding.node)) &&
       (ts.isIdentifier(binding.node.name) ||
        ts.isObjectBindingPattern(binding.node.name) ||
        ts.isArrayBindingPattern(binding.node.name)));
    if (!directBinding) return;
    const map = ts.isVariableDeclaration(binding.node) &&
      ts.isIdentifier(binding.node.name) || ts.isParameter(binding.node) &&
      ts.isIdentifier(binding.node.name)
      ? assignmentsByBinding
      : destructuredAssignmentsByBinding;
    const key = map === assignmentsByBinding ? binding.node : `${binding.node.pos}:${target.text}`;
    const assignments = map.get(key) ?? [];
    assignments.push(value);
    map.set(key, assignments);
  };
  const assignmentKey = (name) => {
    if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) {
      return name.text;
    }
    if (ts.isComputedPropertyName(name)) {
      return staticStringOf(name.expression);
    }
    return undefined;
  };
const sourcePropertyValue = (source, key) => {
  const property = source.properties.find((item) => assignmentKey(item.name) === key);
  if (property && ts.isPropertyAssignment(property)) return property.initializer;
  if (property && ts.isShorthandPropertyAssignment(property)) return property.name;
  return undefined;
};
  const recordDestructuredAssignments = (target, source) => {
    source = unwrap(source);
    if (ts.isObjectLiteralExpression(target) && vitestNamespaceOf(source)) {
      for (const property of target.properties) {
        const key = ts.isShorthandPropertyAssignment(property)
          ? property.name.text
          : ts.isPropertyAssignment(property) ? assignmentKey(property.name) : undefined;
        const targetName = ts.isShorthandPropertyAssignment(property)
          ? property.name
          : ts.isPropertyAssignment(property) && ts.isIdentifier(property.initializer)
            ? property.initializer
            : undefined;
        if (key && targetName && ["test", "it", "describe"].includes(key)) {
          const binding = resolveBinding(targetName);
          if (binding?.kind === "variable") {
            runnerAssignmentsByBinding.set(binding.node, key);
          }
        }
      }
      return;
    }
    if (ts.isObjectLiteralExpression(target) && ts.isObjectLiteralExpression(source)) {
      for (const property of target.properties) {
        const key = ts.isShorthandPropertyAssignment(property)
          ? property.name.text
          : ts.isPropertyAssignment(property) ? assignmentKey(property.name) : undefined;
      const targetValue = ts.isShorthandPropertyAssignment(property)
        ? property.name
        : ts.isPropertyAssignment(property) ? unwrap(property.initializer) : undefined;
      const value = key === undefined ? undefined : sourcePropertyValue(source, key);
      if (!targetValue || !value) continue;
      if (ts.isIdentifier(targetValue)) {
        if (key && ["test", "it", "describe"].includes(key) && vitestNamespaceOf(value)) {
          const binding = resolveBinding(targetValue);
          if (binding?.kind === "variable") runnerAssignmentsByBinding.set(binding.node, key);
        } else {
          recordAssignment(targetValue, value);
        }
      } else if (ts.isObjectLiteralExpression(targetValue) ||
                 ts.isArrayLiteralExpression(targetValue)) {
        recordDestructuredAssignments(targetValue, value);
      }
      }
      return;
    }
    if (ts.isArrayLiteralExpression(target) && ts.isArrayLiteralExpression(source)) {
      for (let index = 0; index < target.elements.length; index += 1) {
        const element = target.elements[index];
        if (ts.isSpreadElement(element) || ts.isOmittedExpression(element)) continue;
      const targetValue = unwrap(element);
        const value = source.elements[index];
      if (!value) continue;
      if (ts.isIdentifier(targetValue)) {
        recordAssignment(targetValue, value);
      } else if (ts.isObjectLiteralExpression(targetValue) ||
                 ts.isArrayLiteralExpression(targetValue)) {
        recordDestructuredAssignments(targetValue, value);
      }
      }
    }
  };
  const isDynamicVitestNamespace = (input) => {
    let node = unwrap(input);
    if (ts.isAwaitExpression(node)) node = unwrap(node.expression);
    return Boolean(node && ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      node.arguments.length === 1 && staticModuleNameOf(node.arguments[0]) === "vitest");
  };
  const staticModuleNameOf = (input, seen = new Set()) =>
    staticStringOf(input, seen);
  const vitestNamespaceOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (isDynamicVitestNamespace(node)) return true;
    if (!node || !ts.isIdentifier(node)) return false;
    const binding = resolveBinding(node);
    if (binding?.kind === "import") {
      return !binding.typeOnly && binding.module === "vitest" && binding.imported === "*";
    }
    if (binding?.kind !== "variable" || !binding.constant ||
        !binding.node.initializer || seen.has(binding.node)) return false;
    const next = new Set(seen);
    next.add(binding.node);
    return vitestNamespaceOf(binding.node.initializer, next);
  };
const possibleVitestNamespaceOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return false;
  if (isDynamicVitestNamespace(node)) return true;
  const assignArguments = ts.isCallExpression(node)
    ? intrinsicInvocationArgumentsOf(node, ["Object"], ["assign"], seen)
    : undefined;
  if (assignArguments) {
    return assignArguments.slice(1).flatMap((source) =>
      ts.isSpreadElement(source)
        ? expandedArgumentValuesOf(source.expression, seen)
        : [source]).some((source) => possibleVitestNamespaceOf(source, seen));
  }
  if (ts.isConditionalExpression(node)) {
    return possibleVitestNamespaceOf(node.whenTrue, seen) ||
      possibleVitestNamespaceOf(node.whenFalse, seen);
  }
  if (ts.isBinaryExpression(node)) {
    const operator = node.operatorToken.kind;
    if (operator === ts.SyntaxKind.CommaToken) {
      return possibleVitestNamespaceOf(node.right, seen);
    }
    if (operator === ts.SyntaxKind.AmpersandAmpersandToken ||
        operator === ts.SyntaxKind.BarBarToken ||
        operator === ts.SyntaxKind.QuestionQuestionToken) {
      return possibleVitestNamespaceOf(node.left, seen) ||
        possibleVitestNamespaceOf(node.right, seen);
    }
  }
  if (ts.isObjectLiteralExpression(node)) {
    return node.properties.some((property) =>
      ts.isSpreadAssignment(property) && possibleVitestNamespaceOf(property.expression, seen));
  }
  if (!ts.isIdentifier(node)) {
if (seen.has(node)) return false;
const next = new Set(seen);
next.add(node);
    const member = resolvedAccess(node);
    return Boolean(member && member.method !== undefined &&
objectPropertyValuesOf(member.receiver, member.method, next).some((value) =>
possibleVitestNamespaceOf(value, next)));
  }
  const binding = resolveBinding(node);
  if (binding?.kind === "import") {
    return !binding.typeOnly && binding.module === "vitest" && binding.imported === "*";
  }
  if ((binding?.kind !== "variable" &&
       !(binding?.kind === "opaque" && ts.isVariableDeclaration(binding.node))) ||
      seen.has(binding.node)) return false;
  const next = new Set(seen);
  next.add(binding.node);
  const values = [
    binding.node.initializer,
    ...(assignmentsByBinding.get(binding.node) ?? []),
    ...(destructuredAssignmentsByBinding.get(`${binding.node.pos}:${node.text}`) ?? []),
    ...destructuredValuesOf(binding.node, node.text)
  ];
  return values.some((value) => value && possibleVitestNamespaceOf(value, next));
};
const expressionValuesOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return [];
  if (ts.isConditionalExpression(node)) {
    return [
      ...expressionValuesOf(node.whenTrue, seen),
      ...expressionValuesOf(node.whenFalse, seen)
    ];
  }
  if (ts.isBinaryExpression(node)) {
    const operator = node.operatorToken.kind;
    if (operator === ts.SyntaxKind.CommaToken) {
      return expressionValuesOf(node.right, seen);
    }
    if (operator === ts.SyntaxKind.AmpersandAmpersandToken ||
        operator === ts.SyntaxKind.BarBarToken ||
        operator === ts.SyntaxKind.QuestionQuestionToken) {
      return [
        ...expressionValuesOf(node.left, seen),
        ...expressionValuesOf(node.right, seen)
      ];
    }
  }
  if (!ts.isIdentifier(node)) return [node];
  const binding = resolveBinding(node);
  if (!binding || binding.kind === "import" || seen.has(binding.node)) return [node];
  const next = new Set(seen);
  next.add(binding.node);
  if (binding.kind === "variable" &&
      ts.isVariableDeclaration(binding.node) &&
      ts.isIdentifier(binding.node.name)) {
    return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
      .filter(Boolean)
      .flatMap((value) => expressionValuesOf(value, next));
  }
    if (binding.kind === "parameter" &&
        ts.isParameter(binding.node) &&
        ts.isIdentifier(binding.node.name) &&
        binding.node.initializer) {
      return expressionValuesOf(binding.node.initializer, next);
    }
  return [node];
};
const fixedSpreadValuesOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return undefined;
  const next = new Set(seen);
  next.add(node);
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (binding?.node && seen.has(binding.node)) return undefined;
    const restPlans = binding?.node && ts.isParameter(binding.node) &&
      binding.node.dotDotDotToken
      ? parameterRestArguments.get(binding.node) ?? [] : [];
    if (restPlans.length > 0) {
      const merged = restPlans.reduce((left, right) =>
        mergeCallArgumentPlans(left, right));
      if (merged.unknownAll || merged.unknownIndex !== undefined) {
        return undefined;
      }
      return merged.before;
    }
    if (binding?.kind === "variable" &&
        ts.isVariableDeclaration(binding.node) &&
        ts.isIdentifier(binding.node.name) && binding.node.initializer &&
        ts.isArrayLiteralExpression(unwrap(binding.node.initializer))) {
      const usageStart = node.getStart(file);
      const mutations = (arrayMutationValuesByBinding.get(binding.node) ?? [])
        .filter((mutation) => mutation.start <= usageStart);
      if (mutations.length > 0) {
        const mutationSeen = new Set(next);
        mutationSeen.add(binding.node);
        const values = fixedSpreadValuesOf(
          binding.node.initializer, mutationSeen
        );
        if (!values) return undefined;
        for (const mutation of mutations) {
          const additions = mutation.values.flatMap((value) =>
            ts.isSpreadElement(value)
              ? fixedSpreadValuesOf(
                value.expression, mutationSeen
              ) ?? [value.expression]
              : [unwrap(value)]);
          if (mutation.kind === "push") values.push(...additions);
          else if (mutation.kind === "unshift") values.unshift(...additions);
          else if (mutation.kind === "set") {
            const index = mutation.index === undefined
              ? values.length : Number(mutation.index);
            values[index] = additions[0];
          } else {
            const index = mutation.index === undefined
              ? 0 : Number(mutation.index);
        const deleteCount = mutation.deleteCount === "rest"
          ? values.length - index
          : mutation.deleteCount === undefined
          ? 0 : Number(mutation.deleteCount);
        values.splice(index, deleteCount, ...additions);
          }
        }
        return values;
      }
    }
  }
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    const left = unwrap(node.left);
    const inertPrefix = ts.isNumericLiteral(left) ||
      ts.isBigIntLiteral(left) ||
      ts.isStringLiteral(left) ||
      ts.isNoSubstitutionTemplateLiteral(left) ||
      [ts.SyntaxKind.TrueKeyword, ts.SyntaxKind.FalseKeyword,
        ts.SyntaxKind.NullKeyword].includes(left.kind);
    if (!inertPrefix) return undefined;
    const next = new Set(seen);
    next.add(node);
    return fixedSpreadValuesOf(node.right, next);
  }
  if (ts.isConditionalExpression(node)) {
    const whenTrue = fixedSpreadValuesOf(node.whenTrue, next);
    const whenFalse = fixedSpreadValuesOf(node.whenFalse, next);
    return whenTrue && whenFalse ? [...whenTrue, ...whenFalse] : undefined;
  }
  if (ts.isCallExpression(node)) {
    const returned = functionReturnExpressionsOf(node.expression, next);
    if (returned.length === 0) return undefined;
    const expanded = returned.map((value) => fixedSpreadValuesOf(value, next));
    if (expanded.some((value) => value === undefined)) return undefined;
    return expanded.flat();
  }
  const values = [];
  for (const value of expressionValuesOf(node, next)) {
    if (!ts.isArrayLiteralExpression(value)) return undefined;
    for (const element of value.elements) {
      if (ts.isOmittedExpression(element)) {
        values.push(undefined);
        continue;
      }
      if (ts.isSpreadElement(element)) {
        const expanded = fixedSpreadValuesOf(element.expression, next);
        if (!expanded) return undefined;
        values.push(...expanded);
      } else {
        values.push(unwrap(element));
      }
    }
  }
  return values;
};
const arrayBindingOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || !ts.isIdentifier(node)) return undefined;
  const binding = resolveBinding(node);
  if (!binding?.node || seen.has(binding.node)) return undefined;
  const next = new Set(seen);
  next.add(binding.node);
  if (binding.kind === "variable" &&
    ts.isVariableDeclaration(binding.node) &&
    ts.isIdentifier(binding.node.name)) {
    const values = [
      binding.node.initializer,
      ...(assignmentsByBinding.get(binding.node) ?? [])
    ].filter(Boolean);
    for (const value of values) {
      const initializer = unwrap(value);
      if (ts.isArrayLiteralExpression(initializer)) return binding.node;
      if (ts.isIdentifier(initializer)) {
        const resolved = arrayBindingOf(initializer, next);
        if (resolved) return resolved;
      }
    }
  }
  return undefined;
};
const arrayMutationValueCarriesRunner = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  const next = new Set(seen);
  next.add(node);
  if (ts.isSpreadElement(node)) {
    return arrayMutationValueCarriesRunner(node.expression, next);
  }
  if (testRunnerOf(node, ["test", "it", "describe"]) ||
      containsRunnerValueOf(node, next)) return true;
  if (ts.isConditionalExpression(node)) {
    return arrayMutationValueCarriesRunner(node.whenTrue, next) ||
      arrayMutationValueCarriesRunner(node.whenFalse, next);
  }
  if (ts.isArrayLiteralExpression(node)) {
    return node.elements.some((element) =>
      !ts.isOmittedExpression(element) &&
      arrayMutationValueCarriesRunner(element, next));
  }
  if (!ts.isIdentifier(node)) return false;
  const binding = resolveBinding(node);
  return Boolean(binding?.kind === "variable" &&
    ts.isVariableDeclaration(binding.node) && binding.node.initializer &&
    arrayMutationValueCarriesRunner(binding.node.initializer, next));
};
const arrayMutationIsConditional = (input) => {
  for (let node = input.parent; node; node = node.parent) {
    if (ts.isFunctionLike(node)) return false;
    if (ts.isConditionalExpression(node) || ts.isIfStatement(node) ||
        ts.isSwitchStatement(node) || ts.isCaseClause(node) ||
        ts.isForStatement(node) || ts.isForInStatement(node) ||
        ts.isForOfStatement(node) || ts.isWhileStatement(node) ||
        ts.isDoStatement(node) ||
        (ts.isBinaryExpression(node) && [
          ts.SyntaxKind.AmpersandAmpersandToken,
          ts.SyntaxKind.BarBarToken,
          ts.SyntaxKind.QuestionQuestionToken
        ].includes(node.operatorToken.kind))) return true;
  }
  return false;
};
const collectArrayMutations = (node) => {
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isElementAccessExpression(unwrap(node.left))) {
    const target = unwrap(node.left);
    const binding = arrayBindingOf(target.expression);
    if (binding) {
      const mutations = arrayMutationValuesByBinding.get(binding) ?? [];
      const previousValues = [
        binding.initializer,
        ...mutations.flatMap((mutation) => mutation.values)
      ].filter(Boolean);
      if (arrayMutationValueCarriesRunner(node.right) ||
          (arrayMutationIsConditional(node) && previousValues.some(
            (value) => arrayMutationValueCarriesRunner(value)
          ))) {
        throw new Error(
          "Exclusive or dynamically selected Vitest tests are unaudited."
        );
      }
      mutations.push({
        kind: "set",
        start: node.getStart(file),
        index: staticStringOf(target.argumentExpression),
        values: [unwrap(node.right)]
      });
      arrayMutationValuesByBinding.set(binding, mutations);
    }
  }
  if (ts.isCallExpression(node)) {
    const member = resolvedAccess(unwrap(node.expression));
    const binding = member && [
      "push", "unshift", "splice", "fill", "copyWithin",
      "reverse", "sort", "pop", "shift"
    ].includes(member.method)
      ? arrayBindingOf(member.receiver) : undefined;
    if (binding) {
      const kind = member.method;
      const mutations = arrayMutationValuesByBinding.get(binding) ?? [];
      const previousValues = [
        binding.initializer,
        ...mutations.flatMap((mutation) => mutation.values)
      ].filter(Boolean);
      if (!["push", "unshift", "splice"].includes(kind)) {
        if (node.arguments.some((value) =>
          arrayMutationValueCarriesRunner(value)) ||
            previousValues.some((value) =>
              arrayMutationValueCarriesRunner(value))) {
          throw new Error(
            "Exclusive or dynamically selected Vitest tests are unaudited."
          );
        }
      } else {
      const values = kind === "splice" ? node.arguments.slice(2) : node.arguments;
      const deleteCount = kind === "splice" && node.arguments.length > 1
        ? staticStringOf(node.arguments[1])
        : kind === "splice" ? "rest" : undefined;
      if (values.some((value) => arrayMutationValueCarriesRunner(value))) {
        throw new Error(
          "Exclusive or dynamically selected Vitest tests are unaudited."
        );
      }
      if (arrayMutationIsConditional(node) && previousValues.some(
        (value) => arrayMutationValueCarriesRunner(value)
      )) {
        throw new Error(
          "Exclusive or dynamically selected Vitest tests are unaudited."
        );
      }
      const deletesValues = deleteCount === "rest" ||
        deleteCount === undefined || Number(deleteCount) > 0;
      if (deletesValues && previousValues.some(
        (value) => arrayMutationValueCarriesRunner(value)
      )) {
        throw new Error(
          "Exclusive or dynamically selected Vitest tests are unaudited."
        );
      }
      mutations.push({
        kind,
        start: node.getStart(file),
        index: kind === "splice"
          ? staticStringOf(node.arguments[0]) : undefined,
        deleteCount,
        values
      });
      arrayMutationValuesByBinding.set(binding, mutations);
      }
    }
  }
  ts.forEachChild(node, collectArrayMutations);
};
const staticLogicalValueOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return undefined;
  if (node.kind === ts.SyntaxKind.TrueKeyword) return { truthy: true, nullish: false };
  if (node.kind === ts.SyntaxKind.FalseKeyword) return { truthy: false, nullish: false };
  if (node.kind === ts.SyntaxKind.NullKeyword) return { truthy: false, nullish: true };
  if (ts.isNumericLiteral(node)) {
    return { truthy: Number(node.text) !== 0, nullish: false };
  }
  if (ts.isBigIntLiteral(node)) {
    return { truthy: BigInt(node.text.slice(0, -1)) !== 0n, nullish: false };
  }
  if (ts.isStringLiteralLike(node)) {
    return { truthy: node.text.length > 0, nullish: false };
  }
  if (ts.isArrayLiteralExpression(node) || ts.isObjectLiteralExpression(node) ||
      ts.isFunctionLike(node)) return { truthy: true, nullish: false };
  if (ts.isPrefixUnaryExpression(node) &&
      node.operator === ts.SyntaxKind.ExclamationToken && !seen.has(node)) {
    const value = staticLogicalValueOf(node.operand, new Set([...seen, node]));
    return value ? { truthy: !value.truthy, nullish: false } : undefined;
  }
  if (!ts.isIdentifier(node)) return undefined;
  const binding = resolveBinding(node);
  if (binding?.kind !== "variable" || !binding.constant ||
      !binding.node.initializer || seen.has(binding.node)) return undefined;
  return staticLogicalValueOf(binding.node.initializer,
    new Set([...seen, binding.node]));
};
const fixedSpreadPlansOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return [];
  const next = new Set(seen);
  next.add(node);
  if (ts.isSpreadElement(node)) return fixedSpreadPlansOf(node.expression, next);
  if (ts.isConditionalExpression(node)) {
    return [
      ...fixedSpreadPlansOf(node.whenTrue, next),
      ...fixedSpreadPlansOf(node.whenFalse, next)
    ];
  }
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    return fixedSpreadPlansOf(node.right, next);
  }
  if (ts.isBinaryExpression(node) && [
    ts.SyntaxKind.AmpersandAmpersandToken,
    ts.SyntaxKind.BarBarToken,
    ts.SyntaxKind.QuestionQuestionToken
  ].includes(node.operatorToken.kind)) {
    const leftValue = staticLogicalValueOf(node.left, next);
    if (leftValue) {
      const selectRight = node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
        ? leftValue.truthy
        : node.operatorToken.kind === ts.SyntaxKind.BarBarToken
        ? !leftValue.truthy
        : leftValue.nullish;
      return fixedSpreadPlansOf(selectRight ? node.right : node.left, next);
    }
    return [
      ...fixedSpreadPlansOf(node.left, next),
      ...fixedSpreadPlansOf(node.right, next)
    ];
  }
  if (ts.isArrayLiteralExpression(node)) {
    let plans = [{ before: [], after: [], unknownIndex: undefined }];
    const append = (plan, value) => mergeCallArgumentPlans(
      plan, { before: [value], after: [], unknownIndex: undefined }
    );
    for (const element of node.elements) {
      if (ts.isOmittedExpression(element)) {
        plans = plans.map((plan) => append(plan, undefined));
      } else if (ts.isSpreadElement(element)) {
        const nested = fixedSpreadPlansOf(element.expression, next);
        const alternatives = nested.length > 0
          ? nested
          : [{ before: [], after: [], unknownIndex: 0 }];
        plans = plans.flatMap((plan) => alternatives.map((alternative) =>
          mergeCallArgumentPlans(plan, alternative))).slice(0, 32);
      } else {
        plans = plans.map((plan) => append(plan, unwrap(element)));
      }
    }
    return plans;
  }
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (binding?.kind === "variable" &&
        ts.isVariableDeclaration(binding.node) &&
        ts.isIdentifier(binding.node.name) && binding.node.initializer &&
    ts.isArrayLiteralExpression(unwrap(binding.node.initializer))) {
      const usageStart = node.getStart(file);
      const mutations = (arrayMutationValuesByBinding.get(binding.node) ?? [])
        .filter((mutation) => mutation.start <= usageStart);
    if (mutations.length > 0) {
      const mutationSeen = new Set(next);
      mutationSeen.add(binding.node);
      const values = fixedSpreadValuesOf(
        binding.node.initializer, mutationSeen
      );
      if (!values) return [];
      for (const mutation of mutations) {
        const additions = mutation.values.flatMap((value) =>
          ts.isSpreadElement(value)
            ? fixedSpreadValuesOf(
              value.expression, mutationSeen
            ) ?? [value.expression]
            : [unwrap(value)]);
        if (mutation.kind === "push") values.push(...additions);
        else if (mutation.kind === "unshift") values.unshift(...additions);
        else if (mutation.kind === "set") {
          const index = mutation.index === undefined
            ? values.length : Number(mutation.index);
          values[index] = additions[0];
        } else {
          const index = mutation.index === undefined ? 0 : Number(mutation.index);
        const deleteCount = mutation.deleteCount === "rest"
          ? values.length - index
          : mutation.deleteCount === undefined
          ? 0 : Number(mutation.deleteCount);
        values.splice(index, deleteCount, ...additions);
        }
        }
      return [{ before: values, after: [], unknownIndex: undefined }];
      }
    }
    const values = expressionValuesOf(node, next).filter((value) => value !== node);
    return values.flatMap((value) => fixedSpreadPlansOf(value, next)).slice(0, 32);
  }
  if (ts.isCallExpression(node)) {
    return functionReturnExpressionsOf(node.expression, next)
      .flatMap((value) => fixedSpreadPlansOf(value, next)).slice(0, 32);
  }
  return [];
};
const fixedIndexedValuesOf = (input, index, seen = new Set()) => {
  const plans = fixedSpreadPlansOf(input, seen);
  return plans.flatMap((plan) => callArgumentCandidatesAt(plan, index)).filter(Boolean);
};
const fixedSpreadPlanOf = (input, seen = new Set()) => {
  const plans = fixedSpreadPlansOf(input, seen);
  if (plans.length === 0) return undefined;
  if (plans.length === 1) return plans[0];
  return {
    before: [],
    after: plans.flatMap((plan) => [...plan.before, ...plan.after]),
    unknownIndex: 0,
    unknownAll: true
  };
};
const restSpreadPlanOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || !ts.isIdentifier(node) || seen.has(node)) return undefined;
  const binding = resolveBinding(node);
  if (!binding?.node || !ts.isParameter(binding.node) ||
      !binding.node.dotDotDotToken) return undefined;
  const plans = parameterRestArguments.get(binding.node) ?? [];
  if (plans.length === 0) return undefined;
  const next = new Set(seen);
  next.add(node);
  return plans.map((plan) => {
    const offset = plan.offset ?? 0;
    return {
      before: plan.unknownAll ? [] : plan.before.slice(offset),
      after: [...plan.after],
      unknownIndex: plan.unknownAll || plan.unknownIndex === undefined
        ? plan.unknownAll ? 0 : undefined
        : Math.max(0, plan.unknownIndex - offset),
      ...(plan.unknownAll ? { unknownAll: true } : {})
    };
  }).reduce((left, right) => mergeCallArgumentPlans(left, right));
};
const fixedCallArgumentPlanOf = (argumentsList) => {
  let plan = { before: [], after: [], unknownIndex: undefined };
  for (const argument of argumentsList) {
    const restPlan = ts.isSpreadElement(argument)
      ? restSpreadPlanOf(argument.expression) : undefined;
    if (restPlan) {
      plan = mergeCallArgumentPlans(plan, restPlan);
      continue;
    }
    const expandedPlan = ts.isSpreadElement(argument)
      ? fixedSpreadPlanOf(argument.expression) : undefined;
    const argumentPlan = ts.isSpreadElement(argument)
      ? expandedPlan
        ? expandedPlan
        : { before: [], after: [], unknownIndex: 0 }
      : { before: [unwrap(argument)], after: [], unknownIndex: undefined };
    plan = mergeCallArgumentPlans(plan, argumentPlan);
  }
  return plan;
};
const callArgumentCandidatesAt = (plan, index) => {
  if (plan.unknownAll) return plan.after;
  const targetIndex = (plan.offset ?? 0) + index;
  if (targetIndex < plan.before.length) return [plan.before[targetIndex]];
  if (plan.unknownIndex === undefined) return [];
  return plan.after.slice(0, targetIndex - plan.before.length + 1);
};
const mergeCallArgumentPlans = (first, second) => {
  if (first.unknownAll || second.unknownAll) {
    return {
      before: [],
      after: [
        ...first.before,
        ...first.after,
        ...second.before,
        ...second.after
      ],
      unknownIndex: 0,
      unknownAll: true
    };
  }
  if (first.unknownIndex === undefined) {
    const before = [...first.before, ...second.before];
    const unknownIndex = second.unknownIndex === undefined
      ? undefined : before.length - second.before.length + second.unknownIndex;
    return { before, after: [...second.after], unknownIndex };
  }
  return {
    before: [...first.before],
    after: [...first.after, ...second.before, ...second.after],
    unknownIndex: first.unknownIndex
  };
};
const dropLeadingCallArgument = (plan) =>
  (plan.offset ?? 0) > 0
    ? { ...plan, offset: plan.offset - 1 }
    : plan.before.length > 0
      ? { ...plan, before: plan.before.slice(1) }
      : plan;
const callArgumentPlansEqual = (left, right) =>
  (left.offset ?? 0) === (right.offset ?? 0) &&
  Boolean(left.unknownAll) === Boolean(right.unknownAll) &&
  left.unknownIndex === right.unknownIndex &&
  left.before.length === right.before.length &&
  left.after.length === right.after.length &&
  left.before.every((value, index) => value === right.before[index]) &&
  left.after.every((value, index) => value === right.after[index]);
const argumentArrayPlanOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return { before: [], after: [], unknownIndex: 0 };
  if (ts.isArrayLiteralExpression(node)) return fixedCallArgumentPlanOf(node.elements);
  if (ts.isCallExpression(node)) {
  const next = new Set(seen);
  next.add(node);
    const createArguments = intrinsicInvocationArgumentsOf(
      node, ["Object"], ["create"], next
    );
    if (createArguments?.[0]) {
      return argumentArrayPlanOf(createArguments[0], next);
  }
    const returned = functionReturnExpressionsOf(node.expression, seen);
    if (returned.length > 0) {
      return returned.map((value) => argumentArrayPlanOf(value, next))
        .reduce((left, right) => mergeCallArgumentPlans(left, right));
    }
  }
  if (ts.isObjectLiteralExpression(node)) {
    const entries = new Map();
    const uncertainValues = [];
    let length;
    let lengthIsStatic = true;
    let shapeIsStatic = true;
    const recordUncertainValuesOf = (input, unknownSeen = new Set()) => {
      const candidate = unwrap(input);
      if (!candidate || unknownSeen.has(candidate)) return;
      const next = new Set(unknownSeen);
      next.add(candidate);
      const objects = containerValuesOf(candidate, next)
        .filter((value) => ts.isObjectLiteralExpression(value));
      if (objects.length === 0) {
        uncertainValues.push(candidate);
        return;
      }
      for (const object of objects) {
        for (const property of object.properties) {
          if (ts.isSpreadAssignment(property)) {
            recordUncertainValuesOf(property.expression, next);
            continue;
          }
          if (!("name" in property)) continue;
          const key = assignmentKey(property.name);
          const propertyValue = ts.isPropertyAssignment(property)
            ? property.initializer
            : ts.isShorthandPropertyAssignment(property)
              ? property.name : undefined;
          const index = Number(key);
          if (propertyValue && (key === undefined ||
              (Number.isSafeInteger(index) && index >= 0 &&
               String(index) === key))) {
            uncertainValues.push(unwrap(propertyValue));
          }
        }
      }
    };
    const applyObjectLiteral = (object, objectSeen) => {
      for (const property of object.properties) {
        if (ts.isSpreadAssignment(property)) {
          applyContainer(property.expression, objectSeen);
          continue;
        }
        if (!("name" in property)) {
          shapeIsStatic = false;
          continue;
        }
        const key = assignmentKey(property.name);
        const value = ts.isPropertyAssignment(property)
          ? property.initializer
          : ts.isShorthandPropertyAssignment(property) ? property.name : undefined;
        if (ts.isGetAccessorDeclaration(property)) {
          const returned = functionReturnExpressionsOf(property, objectSeen);
          if (key === undefined || returned.length !== 1) {
            shapeIsStatic = false;
            uncertainValues.push(...returned.map(unwrap));
            continue;
          }
          if (key === "length") {
            const candidate = staticNumericStringOf(unwrap(returned[0]));
            if (candidate === undefined || !Number.isSafeInteger(candidate) ||
                candidate < 0 || candidate > 1024) lengthIsStatic = false;
            else {
              length = candidate;
              lengthIsStatic = true;
            }
            continue;
          }
          const index = Number(key);
          if (Number.isSafeInteger(index) && index >= 0 &&
              String(index) === key) entries.set(index, unwrap(returned[0]));
          continue;
        }
        if (key === undefined || (!value &&
            (ts.isMethodDeclaration(property) ||
             ts.isGetAccessorDeclaration(property)))) {
          shapeIsStatic = false;
          if (value) uncertainValues.push(unwrap(value));
          continue;
        }
        if (key === "length") {
          const candidate = value && staticNumericStringOf(unwrap(value));
          if (candidate === undefined || !Number.isSafeInteger(candidate) ||
              candidate < 0 || candidate > 1024) lengthIsStatic = false;
          else {
            length = candidate;
            lengthIsStatic = true;
          }
          continue;
        }
        const index = Number(key);
        if (value && Number.isSafeInteger(index) && index >= 0 &&
            String(index) === key) entries.set(index, unwrap(value));
      }
    };
    const applyContainer = (input, containerSeen = new Set()) => {
      const candidate = unwrap(input);
      if (!candidate || containerSeen.has(candidate)) {
        shapeIsStatic = false;
        if (candidate) uncertainValues.push(candidate);
        return;
      }
      const next = new Set(containerSeen);
      next.add(candidate);
      const values = expressionValuesOf(candidate, next);
      if (values.length !== 1) {
        shapeIsStatic = false;
        recordUncertainValuesOf(candidate, next);
        return;
      }
      const value = unwrap(values[0]);
      if (ts.isObjectLiteralExpression(value)) {
        applyObjectLiteral(value, next);
        return;
      }
      if (ts.isArrayLiteralExpression(value)) {
        for (let index = 0; index < value.elements.length; index += 1) {
          const element = value.elements[index];
          if (ts.isOmittedExpression(element)) continue;
          if (ts.isSpreadElement(element)) {
            shapeIsStatic = false;
            recordUncertainValuesOf(element.expression, next);
          } else {
            entries.set(index, unwrap(element));
          }
        }
        return;
      }
      shapeIsStatic = false;
      recordUncertainValuesOf(candidate, next);
    };
    applyObjectLiteral(node, new Set([node]));
    if (!shapeIsStatic || !lengthIsStatic || uncertainValues.length > 0) {
        return {
          before: [],
          after: [
            ...[...entries.entries()].sort(([left], [right]) => left - right)
              .map(([, value]) => value),
            ...uncertainValues
          ],
          unknownIndex: 0,
          unknownAll: true
        };
    }
    const before = Array.from({ length: length ?? 0 }, () => undefined);
    for (const [index, value] of entries) {
      if (index < before.length) before[index] = value;
    }
    return { before, after: [], unknownIndex: undefined };
  }
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    const restPlans = binding?.node && ts.isParameter(binding.node) &&
      binding.node.dotDotDotToken
      ? parameterRestArguments.get(binding.node) ?? [] : [];
    if (restPlans.length > 0) {
      return restPlans.reduce((left, right) =>
        mergeCallArgumentPlans(left, right));
    }
    const argumentPlans = functionArgumentsPlanOf(node) ?? [];
    if (argumentPlans.length > 0) {
      return argumentPlans.map((plan) => ({
        ...plan,
        offset: (plan.offset ?? 0) + 1
      })).reduce((left, right) => mergeCallArgumentPlans(left, right));
    }
    if (binding?.kind === "variable" &&
        ts.isVariableDeclaration(binding.node) &&
        ts.isIdentifier(binding.node.name) && binding.node.initializer) {
      const next = new Set(seen);
      next.add(node);
      return argumentArrayPlanOf(binding.node.initializer, next);
    }
  }
  const expanded = fixedSpreadValuesOf(node, seen);
  return expanded
    ? { before: expanded, after: [], unknownIndex: undefined }
    : { before: [], after: [], unknownIndex: 0 };
};
const expandedArgumentValuesOf = (input, seen = new Set()) => {
  const values = [];
  for (const value of expressionValuesOf(input, seen)) {
    if (!ts.isArrayLiteralExpression(value)) {
      values.push(value);
      continue;
    }
    for (const element of value.elements) {
      if (ts.isOmittedExpression(element)) continue;
      if (ts.isSpreadElement(element)) {
        values.push(...expandedArgumentValuesOf(element.expression, seen));
      } else {
        values.push(element);
      }
    }
  }
  return values;
};
const containerValuesOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node || seen.has(node)) return [];
    const next = new Set(seen);
    next.add(node);
  const values = [];
if (node.kind === ts.SyntaxKind.ThisKeyword) {
  let current = node.parent;
  while (current) {
    if (ts.isGetAccessorDeclaration(current)) {
      const receiver = getterReceiverOf(current);
      if (receiver) values.push(...containerValuesOf(receiver, next));
      return values;
    }
    if (ts.isFunctionLike(current) && !ts.isArrowFunction(current)) return [];
    current = current.parent;
  }
  return values;
}
    for (const value of expressionValuesOf(node, next)) {
if (ts.isIdentifier(value)) {
const binding = resolveBinding(value);
if (binding?.kind === "opaque" && ts.isParameter(binding.node) &&
!next.has(binding.node)) {
const parameterNext = new Set(next);
parameterNext.add(binding.node);
for (const argument of parameterRunnerArguments.get(binding.node) ?? []) {
values.push(...containerValuesOf(argument, parameterNext));
}
}
}
      if (value.kind === ts.SyntaxKind.ThisKeyword) {
        values.push(...containerValuesOf(value, next));
        continue;
      }
    if (ts.isObjectLiteralExpression(value) || ts.isArrayLiteralExpression(value)) {
      values.push(value);
      continue;
    }
      const assignArguments = objectAssignArgumentsOf(value);
      if (assignArguments) {
        for (const argument of assignArguments) {
          const expanded = ts.isSpreadElement(argument)
            ? expandedArgumentValuesOf(argument.expression, next)
            : [argument];
          for (const source of expanded) {
            values.push(...containerValuesOf(source, next));
          }
        }
        continue;
      }
      let createPrototypeCandidates;
    if (ts.isCallExpression(value)) {
      const createWrapper = resolvedAccess(unwrap(value.expression));
      if (createWrapper?.method === "apply" &&
        globalIntrinsicMethodOf(
          createWrapper.receiver, ["Object"], ["create"], next
        )) {
        createPrototypeCandidates = callArgumentCandidatesAt(
          argumentArrayPlanOf(value.arguments[1], next), 0
        );
      } else if (reflectApplyReferenceOf(value.expression, next) &&
        globalIntrinsicMethodOf(
          value.arguments[0], ["Object"], ["create"], next
        )) {
        createPrototypeCandidates = callArgumentCandidatesAt(
          argumentArrayPlanOf(value.arguments[2], next), 0
        );
      }
      }
      if (createPrototypeCandidates?.length) {
        for (const prototype of createPrototypeCandidates) {
          values.push(...containerValuesOf(prototype, next));
        }
        continue;
      }
      const createArguments = intrinsicInvocationArgumentsOf(
        value, ["Object"], ["create"], next
      );
      if (createArguments?.[0]) {
        values.push(...containerValuesOf(createArguments[0], next));
        continue;
      }
    if (ts.isCallExpression(value)) {
      const returned = functionReturnExpressionsOf(value.expression, next);
      if (returned.length > 0) {
        for (const item of returned) {
          values.push(...containerValuesOf(item, next));
        }
        continue;
      }
    }
    const member = resolvedAccess(value);
    if (!member || member.method === undefined) continue;
      for (const candidate of objectPropertyValuesOf(member.receiver, member.method, next)) {
        values.push(...containerValuesOf(candidate, next));
    }
  }
  return values;
};
const enclosingFunctionOf = (node) => {
  let current = node?.parent;
  while (current &&
         !(ts.isFunctionLike(current) && !ts.isArrowFunction(current))) {
    current = current.parent;
  }
  return current;
};
const functionArgumentsPlanOf = (identifier, seen = new Set()) => {
  if (!ts.isIdentifier(identifier) || seen.has(identifier)) return undefined;
  const binding = resolveBinding(identifier);
  if (identifier.text === "arguments" && !binding) {
    return functionArgumentsPlans.get(enclosingFunctionOf(identifier));
  }
  if (binding?.kind === "variable" && ts.isVariableDeclaration(binding.node) &&
      ts.isIdentifier(binding.node.name) && binding.node.initializer) {
    const next = new Set(seen);
    next.add(identifier);
    return functionArgumentsPlanOf(binding.node.initializer, next);
  }
  return undefined;
};
const objectPropertyValuesOf = (input, key, seen = new Set()) => {
    const values = restPropertyValuesOf(input, key, seen);
  const reference = unwrap(input);
  if (reference && ts.isIdentifier(reference) && /^\d+$/.test(key)) {
    for (const plan of functionArgumentsPlanOf(reference) ?? []) {
      values.push(...callArgumentCandidatesAt(plan, Number(key)));
    }
  }
  if (reference && ts.isCallExpression(reference) && /^\d+$/.test(key)) {
    for (const returned of functionReturnExpressionsOf(reference.expression, seen)) {
      for (const plan of functionArgumentsPlanOf(returned, seen) ?? []) {
        values.push(...callArgumentCandidatesAt(plan, Number(key)));
      }
      if (ts.isArrayLiteralExpression(unwrap(returned))) {
        const indexed = unwrap(returned).elements[Number(key)];
        if (indexed && !ts.isOmittedExpression(indexed) &&
            !ts.isSpreadElement(indexed)) values.push(indexed);
      }
    }
  }
  if (reference && ts.isIdentifier(reference)) {
    const binding = resolveBinding(reference);
    if (binding?.kind === "opaque" && ts.isParameter(binding.node) &&
        !seen.has(binding.node)) {
      const next = new Set(seen);
      next.add(binding.node);
      if (ts.isIdentifier(binding.node.name) && binding.node.dotDotDotToken &&
          /^\d+$/.test(key)) {
        for (const plan of parameterRestArguments.get(binding.node) ?? []) {
          values.push(...callArgumentCandidatesAt(plan, Number(key)).filter(Boolean));
        }
      } else if (!ts.isIdentifier(binding.node.name)) {
        const sources = [
          ...(parameterRunnerArguments.get(binding.node) ?? [])
        ];
        for (const source of sources) {
          for (const container of destructuredSourceValuesOf(
            binding.node.name, source, reference.text
          )) {
            values.push(...objectPropertyValuesOf(container, key, next));
          }
        }
      }
    }
  }
  for (const container of containerValuesOf(input, seen)) {
    if (ts.isObjectLiteralExpression(container)) {
      for (const property of container.properties) {
        if (ts.isSpreadAssignment(property)) {
          values.push(...objectPropertyValuesOf(property.expression, key, seen));
        } else if (assignmentKey(property.name) === key) {
          if (ts.isPropertyAssignment(property)) values.push(property.initializer);
          else if (ts.isShorthandPropertyAssignment(property)) values.push(property.name);
            else if (ts.isMethodDeclaration(property)) values.push(property);
        else if (ts.isGetAccessorDeclaration(property)) {
          values.push(property, ...functionReturnExpressionsOf(property, seen));
        }
        }
      }
    } else if (ts.isArrayLiteralExpression(container) && /^\d+$/.test(key)) {
      values.push(...fixedIndexedValuesOf(container, Number(key)));
    }
  }
  const receiverKey = assignmentReferenceKey(input);
  const memberKey = receiverKey === undefined
    ? undefined
    : JSON.stringify([receiverKey, key]);
  if (memberKey !== undefined) {
    values.push(...(assignmentsByMemberPath.get(memberKey) ?? []));
  }
  return values;
};
// Resolve the source value selected for one identifier in an assignment pattern.
  const destructuredSourceValuesOf = (pattern, source, targetName) => {
  const values = [];
  const visitPattern = (pattern, source) => {
    if (ts.isObjectBindingPattern(pattern)) {
      for (const element of pattern.elements) {
        if (!ts.isBindingElement(element)) continue;
        if (element.dotDotDotToken) {
          if (ts.isIdentifier(element.name) && element.name.text === targetName) {
            values.push(source);
          }
          continue;
        }
        const key = element.propertyName
          ? assignmentKey(element.propertyName)
          : ts.isIdentifier(element.name) ? element.name.text : undefined;
        const selected = key === undefined ? [] : objectPropertyValuesOf(source, key);
        const candidates = selected.length > 0
          ? selected
          : element.initializer ? [element.initializer] : [];
        if (ts.isIdentifier(element.name) && element.name.text === targetName) {
          values.push(...candidates);
        } else if (ts.isObjectBindingPattern(element.name) ||
                   ts.isArrayBindingPattern(element.name)) {
          for (const candidate of candidates) visitPattern(element.name, candidate);
        }
      }
    } else if (ts.isArrayBindingPattern(pattern)) {
      for (let index = 0; index < pattern.elements.length; index += 1) {
        const element = pattern.elements[index];
        if (!ts.isBindingElement(element) || element.dotDotDotToken) continue;
        const selected = objectPropertyValuesOf(source, String(index));
        const candidates = selected.length > 0
          ? selected
          : element.initializer ? [element.initializer] : [];
        if (ts.isIdentifier(element.name) && element.name.text === targetName) {
          values.push(...candidates);
        } else if (ts.isObjectBindingPattern(element.name) ||
                   ts.isArrayBindingPattern(element.name)) {
          for (const candidate of candidates) visitPattern(element.name, candidate);
        }
      }
    }
  };
    visitPattern(pattern, source);
  return values;
};
  const destructuredValuesOf = (declaration, targetName) => {
    if ((!ts.isVariableDeclaration(declaration) && !ts.isParameter(declaration)) ||
        !declaration.initializer) return [];
    return destructuredSourceValuesOf(
      declaration.name, declaration.initializer, targetName
    );
  };
  const bindingNameInfoOf = (pattern, values = []) => {
    if (!ts.isObjectBindingPattern(pattern) && !ts.isArrayBindingPattern(pattern)) {
      return values;
    }
    for (const element of pattern.elements) {
      if (!ts.isBindingElement(element)) continue;
      if (ts.isIdentifier(element.name)) {
        values.push({
          name: element.name.text,
          rest: Boolean(element.dotDotDotToken)
        });
      } else {
        bindingNameInfoOf(element.name, values);
      }
    }
    return values;
  };
  const restBindingInfoOf = (pattern, targetName) => {
    if (!ts.isObjectBindingPattern(pattern) && !ts.isArrayBindingPattern(pattern)) {
      return undefined;
    }
    if (ts.isObjectBindingPattern(pattern)) {
      const excluded = [];
      for (const element of pattern.elements) {
        if (!ts.isBindingElement(element)) continue;
        if (element.dotDotDotToken && ts.isIdentifier(element.name) &&
            element.name.text === targetName) {
          return { kind: "object", excluded };
        }
        const key = element.propertyName
          ? assignmentKey(element.propertyName)
          : ts.isIdentifier(element.name) ? element.name.text : undefined;
        if (key !== undefined) excluded.push(key);
      }
      return undefined;
    }
    const index = pattern.elements.findIndex((element) =>
      ts.isBindingElement(element) && element.dotDotDotToken &&
      ts.isIdentifier(element.name) && element.name.text === targetName);
    return index === -1 ? undefined : { kind: "array", index };
  };
  const restPropertyValuesOf = (input, key, seen = new Set()) => {
    const node = unwrap(input);
    if (!node || !ts.isIdentifier(node)) return [];
    const binding = resolveBinding(node);
    if (!binding?.node || !ts.isParameter(binding.node) || seen.has(binding.node)) {
      return [];
    }
    const info = restBindingInfoOf(binding.node.name, node.text);
    if (!info) return [];
    const next = new Set(seen);
    next.add(binding.node);
    const sources = [...(parameterRunnerArguments.get(binding.node) ?? [])];
    if (binding.node.initializer) sources.push(binding.node.initializer);
    const values = [];
    for (const source of sources) {
      for (const container of containerValuesOf(source, next)) {
        if (info.kind === "object" && ts.isObjectLiteralExpression(container)) {
          if (info.excluded.includes(key)) continue;
          for (const property of container.properties) {
            if (ts.isSpreadAssignment(property)) {
              values.push(...objectPropertyValuesOf(
                property.expression, key, next
              ));
            } else if (assignmentKey(property.name) === key) {
              if (ts.isPropertyAssignment(property)) values.push(property.initializer);
              if (ts.isShorthandPropertyAssignment(property)) values.push(property.name);
            }
          }
        }
        if (info.kind === "array" && ts.isArrayLiteralExpression(container) &&
            /^\d+$/.test(key)) {
          const element = container.elements[info.index + Number(key)];
          if (element && !ts.isOmittedExpression(element) &&
              !ts.isSpreadElement(element)) values.push(element);
        }
      }
    }
    return values;
  };
const recordResolvedAssignments = (target, source) => {
  target = unwrap(target);
  if (assignmentMemberAccess(target) ||
      (ts.isElementAccessExpression(target) && !assignmentMemberAccess(target))) {
    recordAssignment(target, source);
    return;
  }
  if (ts.isIdentifier(target)) {
    recordAssignment(target, source);
    return;
  }
  if (ts.isObjectLiteralExpression(target)) {
    for (const property of target.properties) {
      if (ts.isSpreadAssignment(property)) {
        const spreadTarget = unwrap(property.expression);
        if (ts.isIdentifier(spreadTarget)) recordAssignment(spreadTarget, source);
        continue;
      }
      const key = assignmentKey(property.name);
      if (key === undefined) continue;
      let targetValue = ts.isShorthandPropertyAssignment(property)
        ? property.name
        : ts.isPropertyAssignment(property) ? unwrap(property.initializer) : undefined;
      if (!targetValue) continue;
      const patternDefault = ts.isBinaryExpression(targetValue) &&
        targetValue.operatorToken.kind === ts.SyntaxKind.EqualsToken
        ? targetValue.right : undefined;
      if (patternDefault) targetValue = unwrap(targetValue.left);
      const defaultValue = ts.isShorthandPropertyAssignment(property)
        ? property.objectAssignmentInitializer
        : patternDefault;
      if (ts.isIdentifier(targetValue)) {
      const binding = resolveBinding(targetValue);
      if (binding?.node) {
        const assignments = destructuredPropertyAssignmentsByBinding
          .get(binding.node) ?? [];
        if (!assignments.some((assignment) => assignment.source === source &&
            assignment.property === key)) {
          assignments.push({ source, property: key });
          destructuredPropertyAssignmentsByBinding.set(binding.node, assignments);
        }
      }
        if (["test", "it", "describe"].includes(key) &&
            possibleVitestNamespaceOf(source)) {
          if (binding?.kind === "variable") {
            runnerAssignmentsByBinding.set(binding.node, key);
            continue;
          }
        }
        if (["concurrent", "fails", "sequential"].includes(key)) {
          const runner = testRunnerOf(source, ["test", "it", "describe"]);
          if (runner && binding?.kind === "variable") {
            runnerAssignmentsByBinding.set(binding.node, runner);
            continue;
          }
        }
      }
      const selected = objectPropertyValuesOf(source, key);
      const resolvedValues = selected.length > 0
        ? selected
        : defaultValue ? [defaultValue] : [];
      for (const value of resolvedValues) {
        recordResolvedAssignments(targetValue, value);
      }
    }
    return;
  }
  if (ts.isArrayLiteralExpression(target)) {
    for (let index = 0; index < target.elements.length; index += 1) {
      const element = target.elements[index];
      if (ts.isOmittedExpression(element)) continue;
      if (ts.isSpreadElement(element)) {
        const spreadTarget = unwrap(element.expression);
        if (ts.isIdentifier(spreadTarget)) recordAssignment(spreadTarget, source);
        continue;
      }
      for (const value of objectPropertyValuesOf(source, String(index))) {
        recordResolvedAssignments(element, value);
      }
    }
  }
};
const collectResolvedAssignments = (node) => {
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
    const target = unwrap(node.left);
    if (ts.isObjectLiteralExpression(target) || ts.isArrayLiteralExpression(target)) {
      recordResolvedAssignments(target, node.right);
    }
  }
  ts.forEachChild(node, collectResolvedAssignments);
};
  function globalObjectOf(input, seen = new Set()) {
    const node = unwrap(input);
    if (!node) return false;
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (!binding) {
        return ["Object", "global", "globalThis"].includes(node.text);
      }
      if (binding.kind !== "variable" || !binding.constant ||
          !binding.node.initializer || seen.has(binding.node)) return false;
      const next = new Set(seen);
      next.add(binding.node);
      return globalObjectOf(binding.node.initializer, next);
    }
  const member = resolvedAccess(node);
    return Boolean(member?.method === "Object" && globalObjectOf(member.receiver, seen));
  }
  function globalIntrinsicOf(input, names, seen = new Set()) {
    const node = unwrap(input);
    if (!node) return false;
    if (ts.isFunctionLike(node)) {
      const returnedValues = functionReturnExpressionsOf(node, seen);
      const next = new Set(seen);
      next.add(node);
      return returnedValues.some((value) =>
        globalIntrinsicOf(value, names, next));
    }
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (!binding) return names.includes(node.text);
      if (binding.kind !== "variable" || !binding.constant ||
          !binding.node.initializer || seen.has(binding.node)) return false;
      const next = new Set(seen);
      next.add(binding.node);
      return globalIntrinsicOf(binding.node.initializer, names, next);
    }
    const member = resolvedAccess(node);
    if (!member) return false;
    if (!seen.has(node)) {
      const next = new Set(seen);
      next.add(node);
      if (objectPropertyValuesOf(member.receiver, member.method, next)
        .some((value) => globalIntrinsicOf(value, names, next))) return true;
    }
    return names.includes(member.method) && globalObjectOf(member.receiver, seen);
  }
  function reflectApplyReferenceOf(input, seen = new Set()) {
    const node = unwrap(input);
    if (!node) return false;
    const member = resolvedAccess(node);
    if (member?.method === "apply" &&
        globalIntrinsicOf(member.receiver, ["Reflect"], seen)) return true;
    if (member && member.method !== undefined && !seen.has(node)) {
      const next = new Set(seen);
      next.add(node);
      const receiver = unwrap(member.receiver);
      const binding = ts.isIdentifier(receiver)
        ? resolveBinding(receiver) : undefined;
      const container = binding?.kind === "variable" && binding.constant &&
        ts.isVariableDeclaration(binding.node) && binding.node.initializer
        ? unwrap(binding.node.initializer) : receiver;
      if (ts.isObjectLiteralExpression(container)) {
        for (const property of container.properties) {
          if (!("name" in property) ||
              assignmentKey(property.name) !== member.method) continue;
          const value = ts.isPropertyAssignment(property)
            ? property.initializer
            : ts.isShorthandPropertyAssignment(property) ? property.name : undefined;
          if (value && reflectApplyReferenceOf(value, next)) return true;
          if (ts.isGetAccessorDeclaration(property) &&
              functionReturnExpressionsOf(property, next)
                .some((returned) => reflectApplyReferenceOf(returned, next))) {
            return true;
          }
        }
      }
    }
    if (!ts.isIdentifier(node)) return false;
    const binding = resolveBinding(node);
    if (!binding?.node || seen.has(binding.node)) return false;
    const declaration = ts.isVariableDeclaration(binding.node) ||
      ts.isParameter(binding.node) ? binding.node : undefined;
    if (!declaration) return false;
    const next = new Set(seen);
    next.add(binding.node);
    if (!ts.isIdentifier(declaration.name)) {
      return Boolean(declaration.initializer &&
        ((globalIntrinsicOf(declaration.initializer, ["Reflect"], next) &&
          patternSelectsProperty(declaration.name, node.text, "apply")) ||
         destructuredValuesOf(declaration, node.text)
           .some((value) => reflectApplyReferenceOf(value, next))));
    }
    return [declaration.initializer, ...(assignmentsByBinding.get(declaration) ?? [])]
      .filter(Boolean)
      .some((value) => reflectApplyReferenceOf(value, next));
  }
  const intrinsicMethodAliasNames = new Set();
  const intrinsicMethodContainerNames = new Set();
  function intrinsicBindMethodOf(
    input, receiverNames, methods, seen = new Set()
  ) {
    const node = unwrap(input);
    if (!node || seen.has(node)) return false;
    const next = new Set(seen);
    next.add(node);
    const member = resolvedAccess(node);
    if (member?.method === "bind" &&
        globalIntrinsicMethodOf(
          member.receiver, receiverNames, methods, next
        )) return true;
    if (!ts.isIdentifier(node)) return false;
    const binding = resolveBinding(node);
    const declaration = binding?.node &&
      (ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node))
      ? binding.node : undefined;
    if (!declaration || seen.has(declaration)) return false;
    const bindingNext = new Set(next);
    bindingNext.add(declaration);
    return [declaration.initializer,
      ...(assignmentsByBinding.get(declaration) ?? [])]
      .filter(Boolean)
      .some((value) => intrinsicBindMethodOf(
        value, receiverNames, methods, bindingNext
      ));
  }
  const globalIntrinsicMethodOf = (input, receiverNames, methods, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
    if (!ts.isIdentifier(node)) {
      if (seen.has(node)) return false;
      const next = new Set(seen);
      next.add(node);
    const member = resolvedAccess(node);
      if (!member) return false;
      if (methods.includes(member.method) &&
          globalIntrinsicOf(member.receiver, receiverNames, next)) return true;
      if (objectPropertyValuesOf(member.receiver, member.method, next)
        .some((value) => globalIntrinsicMethodOf(
          value, receiverNames, methods, next
        ))) return true;
      let container = unwrap(member.receiver);
      const namedContainer = ts.isIdentifier(container) &&
        intrinsicMethodContainerNames.has(container.text);
      if (ts.isIdentifier(container)) {
        const receiverBinding = resolveBinding(container);
        const initializer = receiverBinding?.node &&
          (ts.isVariableDeclaration(receiverBinding.node) ||
           ts.isParameter(receiverBinding.node))
          ? receiverBinding.node.initializer : undefined;
        container = initializer ? unwrap(initializer) : container;
      }
      if (!ts.isArrayLiteralExpression(container) &&
          !ts.isObjectLiteralExpression(container) && !namedContainer &&
          !objectAssignCall(container)) return false;
      return objectPropertyValuesOf(container, member.method, next)
        .some((value) => globalIntrinsicMethodOf(
          value, receiverNames, methods, next));
    }
    const binding = resolveBinding(node);
    if (!binding?.node || seen.has(binding.node)) return false;
    const next = new Set(seen);
    next.add(binding.node);
    if ((destructuredPropertyAssignmentsByBinding.get(binding.node) ?? [])
      .some((assignment) => methods.includes(assignment.property) &&
        globalIntrinsicOf(assignment.source, receiverNames, next))) return true;
    if (binding.kind !== "variable" &&
        !(binding.kind === "opaque" && ts.isVariableDeclaration(binding.node))) {
      return false;
    }
    const declaration = binding.node;
    const values = [declaration.initializer,
      ...(assignmentsByBinding.get(declaration) ?? [])];
    if (values.some((value) => value && ts.isCallExpression(value) &&
        value.arguments.length >= 1 &&
        intrinsicBindMethodOf(value.expression, receiverNames, methods, next) &&
        globalIntrinsicOf(value.arguments[0], receiverNames, next))) return true;
    if (values.some((value) => value && globalIntrinsicMethodOf(
      value, receiverNames, methods, next))) return true;
    if (ts.isIdentifier(declaration.name)) return false;
    const source = declaration.initializer ? unwrap(declaration.initializer) : undefined;
    if (source && (ts.isArrayLiteralExpression(source) ||
        ts.isObjectLiteralExpression(source)) &&
        destructuredValuesOf(declaration, node.text).some((value) =>
          globalIntrinsicMethodOf(value, receiverNames, methods, next))) return true;
    return Boolean(declaration.initializer &&
      globalIntrinsicOf(declaration.initializer, receiverNames, next) &&
      methods.some((method) => patternSelectsProperty(
        declaration.name, node.text, method)));
  };
const globalCapabilitySourceOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  const next = new Set(seen);
  next.add(node);
  if (globalIntrinsicOf(node, ["Object"], next) ||
      globalIntrinsicMethodOf(node, ["Object"], ["create", "assign"], next)) {
    return true;
  }
  const member = resolvedAccess(node);
  if (member && ["create", "assign"].includes(member.method) &&
      ts.isIdentifier(member.receiver) && member.receiver.text === "Object") {
    return true;
  }
  if (ts.isConditionalExpression(node)) {
    return globalCapabilitySourceOf(node.whenTrue, next) ||
      globalCapabilitySourceOf(node.whenFalse, next);
  }
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    return globalCapabilitySourceOf(node.right, next);
  }
  if (ts.isObjectLiteralExpression(node)) {
    return node.properties.some((property) => {
      if (ts.isSpreadAssignment(property)) {
        return globalCapabilitySourceOf(property.expression, next);
      }
      if (ts.isPropertyAssignment(property)) {
        return globalCapabilitySourceOf(property.initializer, next);
      }
      return ts.isShorthandPropertyAssignment(property) &&
        globalCapabilitySourceOf(property.name, next);
    });
  }
  if (ts.isArrayLiteralExpression(node)) {
    return node.elements.some((element) =>
      !ts.isOmittedExpression(element) &&
      globalCapabilitySourceOf(
        ts.isSpreadElement(element) ? element.expression : element, next
      ));
  }
  if (!ts.isIdentifier(node)) return false;
  const binding = resolveBinding(node);
  return Boolean(binding?.node && (ts.isVariableDeclaration(binding.node) ||
    ts.isParameter(binding.node)) && !seen.has(binding.node) &&
    [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
      .filter(Boolean)
      .some((value) => globalCapabilitySourceOf(value, next)));
};
  function intrinsicArgumentValuesOf(argumentsList, seen) {
    return argumentsList.flatMap((argument) =>
      ts.isSpreadElement(argument)
        ? expandedArgumentValuesOf(argument.expression, seen)
        : [argument]);
  }
function intrinsicArgumentPlanValuesOf(plan) {
  const values = [...plan.before];
  if (plan.unknownAll || plan.unknownIndex !== undefined) {
    values.push(...plan.after);
  }
  return values;
}
function reflectApplyTargetArgumentsOf(input, seen = new Set()) {
  const node = unwrap(input);
  if (!node || !ts.isCallExpression(node)) return undefined;
  let target;
  let applicationArguments;
  if (reflectApplyReferenceOf(node.expression, seen)) {
    target = node.arguments[0];
    applicationArguments = node.arguments[2];
  } else {
    const wrapper = resolvedAccess(unwrap(node.expression));
    if (!wrapper || !["apply", "call"].includes(wrapper.method) ||
        !reflectApplyReferenceOf(wrapper.receiver, seen)) return undefined;
    const reflectedArguments = wrapper.method === "call"
      ? node.arguments.slice(1)
      : fixedSpreadValuesOf(node.arguments[1], seen);
    if (!reflectedArguments) return undefined;
    target = reflectedArguments[0];
    applicationArguments = reflectedArguments[2];
  }
  if (!target) return undefined;
  return {
    target,
    arguments: applicationArguments
      ? intrinsicArgumentPlanValuesOf(
        argumentArrayPlanOf(applicationArguments, seen)
      )
      : []
  };
}
  function boundIntrinsicArgumentsOf(
    input, receiverNames, methods, seen = new Set()
  ) {
    const node = unwrap(input);
    if (!node || seen.has(node)) return undefined;
    const next = new Set(seen);
    next.add(node);
    if (ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
      return boundIntrinsicArgumentsOf(
        node.right, receiverNames, methods, next
      );
    }
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      const declaration = binding?.kind === "variable" &&
        ts.isVariableDeclaration(binding.node) &&
        ts.isIdentifier(binding.node.name) ? binding.node : undefined;
      return declaration?.initializer
        ? boundIntrinsicArgumentsOf(
          declaration.initializer, receiverNames, methods, next
        )
        : undefined;
    }
    if (!ts.isCallExpression(node)) return undefined;
    const wrapper = resolvedAccess(node.expression);
  if (wrapper?.method === "bind" &&
      globalIntrinsicMethodOf(
        wrapper.receiver, receiverNames, methods, next
      )) {
    return intrinsicArgumentValuesOf(node.arguments.slice(1), next);
  }
    if (intrinsicBindMethodOf(
      node.expression, receiverNames, methods, next
    ) && globalIntrinsicOf(
      node.arguments[0], receiverNames, next
    )) {
      return intrinsicArgumentValuesOf(node.arguments.slice(1), next);
    }
  if (wrapper && ["apply", "call"].includes(wrapper.method) &&
      intrinsicBindMethodOf(
        wrapper.receiver, receiverNames, methods, next
      ) && globalIntrinsicMethodOf(
        node.arguments[0], receiverNames, methods, next
      )) {
    const plan = wrapper.method === "call"
      ? fixedCallArgumentPlanOf(node.arguments.slice(1))
      : argumentArrayPlanOf(node.arguments[1], next);
    return intrinsicArgumentPlanValuesOf(dropLeadingCallArgument(plan));
  }
  if (wrapper && ["apply", "call"].includes(wrapper.method) &&
      genericBindMethodOf(wrapper.receiver, next) &&
      globalIntrinsicMethodOf(
        node.arguments[0], receiverNames, methods, next
      )) {
    const plan = wrapper.method === "call"
      ? fixedCallArgumentPlanOf(node.arguments.slice(1))
      : argumentArrayPlanOf(node.arguments[1], next);
    return intrinsicArgumentPlanValuesOf(dropLeadingCallArgument(plan));
  }
  if (reflectApplyReferenceOf(node.expression, next) &&
      intrinsicBindMethodOf(
        node.arguments[0], receiverNames, methods, next
      ) && globalIntrinsicMethodOf(
        node.arguments[1], receiverNames, methods, next
      )) {
    const plan = argumentArrayPlanOf(node.arguments[2], next);
    return intrinsicArgumentPlanValuesOf(dropLeadingCallArgument(plan));
  }
  if (reflectApplyReferenceOf(node.expression, next) &&
      genericBindMethodOf(node.arguments[0], next) &&
      globalIntrinsicMethodOf(
        node.arguments[1], receiverNames, methods, next
      )) {
    const plan = argumentArrayPlanOf(node.arguments[2], next);
    return intrinsicArgumentPlanValuesOf(dropLeadingCallArgument(plan));
  }
  return undefined;
  }
  function intrinsicInvocationArgumentsOf(
    input, receiverNames, methods, seen = new Set()
  ) {
    const node = unwrap(input);
    if (!node || !ts.isCallExpression(node)) return undefined;
  const reflected = reflectApplyTargetArgumentsOf(node, seen);
  if (reflected) {
    const boundArguments = boundIntrinsicArgumentsOf(
      reflected.target, receiverNames, methods, seen
    );
    if (globalIntrinsicMethodOf(
      reflected.target, receiverNames, methods, seen
    ) || boundArguments) {
      return [...(boundArguments ?? []), ...reflected.arguments];
    }
  }
    const boundArguments = boundIntrinsicArgumentsOf(
      node.expression, receiverNames, methods, seen
    );
    if (globalIntrinsicMethodOf(
      node.expression, receiverNames, methods, seen
    ) || boundArguments) {
      return [
        ...(boundArguments ?? []),
        ...intrinsicArgumentValuesOf(node.arguments, seen)
      ];
    }
    const wrapper = resolvedAccess(unwrap(node.expression));
    if (!wrapper || !["apply", "call"].includes(wrapper.method) ||
        !globalIntrinsicMethodOf(wrapper.receiver, receiverNames, methods, seen)) {
      return undefined;
    }
    if (wrapper.method === "call") {
      return intrinsicArgumentValuesOf(node.arguments.slice(1), seen);
    }
    if (!node.arguments[1]) return [];
    return expandedArgumentValuesOf(node.arguments[1], seen);
  }
  function patternSelectsProperty(pattern, targetName, property) {
    if (ts.isObjectBindingPattern(pattern)) {
      return pattern.elements.some((element) => {
        if (!ts.isBindingElement(element)) return false;
        const key = element.propertyName
          ? assignmentKey(element.propertyName)
          : ts.isIdentifier(element.name) ? element.name.text : undefined;
        if (ts.isIdentifier(element.name) && element.name.text === targetName) {
          return key === property;
        }
        return (ts.isObjectBindingPattern(element.name) ||
          ts.isArrayBindingPattern(element.name)) &&
          patternSelectsProperty(element.name, targetName, property);
      });
    }
    if (ts.isArrayBindingPattern(pattern)) {
      return pattern.elements.some((element) => ts.isBindingElement(element) &&
        (ts.isObjectBindingPattern(element.name) ||
         ts.isArrayBindingPattern(element.name)) &&
        patternSelectsProperty(element.name, targetName, property));
    }
    return false;
  }
  function objectAssignReference(input, seen = new Set()) {
    const node = unwrap(input);
    if (!node) return false;
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      const declaration = binding?.node &&
        (ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node))
        ? binding.node : undefined;
      if (declaration?.initializer &&
          (ts.isObjectBindingPattern(declaration.name) ||
           ts.isArrayBindingPattern(declaration.name)) && !seen.has(binding.node)) {
        const next = new Set(seen);
        next.add(binding.node);
        if (globalObjectOf(declaration.initializer, next) &&
            patternSelectsProperty(declaration.name, node.text, "assign")) return true;
        for (const value of destructuredValuesOf(declaration, node.text)) {
          if (objectAssignReference(value, next)) return true;
        }
      }
      if (binding?.kind !== "variable" || !binding.constant ||
          !binding.node?.initializer || seen.has(binding.node)) return false;
      const next = new Set(seen);
      next.add(binding.node);
      return objectAssignReference(binding.node.initializer, next);
    }
  const member = resolvedAccess(node);
    const receiver = member && unwrap(member.receiver);
    return member?.method === "assign" && globalObjectOf(receiver, seen);
  }
  function objectAssignCall(node) {
    return objectAssignArgumentsOf(node) !== undefined;
  }
  function objectAssignArgumentsOf(node) {
    if (!ts.isCallExpression(node)) return undefined;
    return intrinsicInvocationArgumentsOf(
      node, ["Object"], ["assign"]
    ) ?? (objectAssignReference(node.expression) ? node.arguments : undefined);
  }
  const collectDestructuredPropertyAssignments = (target, source) => {
    target = unwrap(target);
    source = unwrap(source);
    if (ts.isObjectLiteralExpression(target)) {
      for (const property of target.properties) {
        const key = assignmentKey(property.name);
        if (key === undefined) {
          if (globalCapabilitySourceOf(source)) {
            throw new Error(
              "Exclusive or dynamically selected Vitest tests are unaudited."
            );
          }
          continue;
        }
        let targetValue = ts.isShorthandPropertyAssignment(property)
          ? property.name
          : ts.isPropertyAssignment(property) ? unwrap(property.initializer) : undefined;
        if (!targetValue) continue;
        const patternDefault = ts.isBinaryExpression(targetValue) &&
          targetValue.operatorToken.kind === ts.SyntaxKind.EqualsToken
          ? targetValue.right : undefined;
        if (patternDefault) targetValue = unwrap(targetValue.left);
        if (ts.isIdentifier(targetValue)) {
          const binding = resolveBinding(targetValue);
          if (binding?.node) {
            const assignments = destructuredPropertyAssignmentsByBinding
              .get(binding.node) ?? [];
            if (!assignments.some((assignment) => assignment.source === source &&
                assignment.property === key)) {
              assignments.push({ source, property: key });
              destructuredPropertyAssignmentsByBinding.set(
                binding.node, assignments
              );
            }
          }
        }
        const selected = objectPropertyValuesOf(source, key);
        const values = selected.length > 0
          ? selected : patternDefault ? [patternDefault] : [];
        for (const value of values) {
          collectDestructuredPropertyAssignments(targetValue, value);
        }
      }
    }
  };
  const collectAssignments = (node) => {
    if (ts.isBinaryExpression(node) &&
        aliasAssignmentKinds.has(node.operatorToken.kind)) {
      collectDestructuredPropertyAssignments(node.left, node.right);
    }
    const assignArguments = objectAssignArgumentsOf(node);
    if (assignArguments) {
      const [target, ...sources] = assignArguments;
      if (target && !ts.isSpreadElement(target)) {
        for (const source of sources) {
          const values = ts.isSpreadElement(source)
            ? expandedArgumentValuesOf(source.expression)
            : [source];
          for (const value of values) recordAssignment(target, value);
        }
      }
    }
    if (ts.isBinaryExpression(node) && aliasAssignmentKinds.has(node.operatorToken.kind)) {
      const target = unwrap(node.left);
    if (ts.isIdentifier(target) || assignmentMemberAccess(target)) {
      recordAssignment(target, node.right);
    }
      else if (ts.isObjectLiteralExpression(target) || ts.isArrayLiteralExpression(target)) {
        recordDestructuredAssignments(target, node.right);
      }
    }
    ts.forEachChild(node, collectAssignments);
  };
  const processObjectOf = (input, seen = new Set()) => {
    input = unwrap(input);
    if (!input || !ts.isIdentifier(input)) return false;
    const binding = resolveBinding(input);
    if (!binding) return input.text === "process";
    if (binding.kind === "import" && !binding.typeOnly &&
        ["node:process", "process"].includes(binding.module)) {
      return binding.imported === "default" || binding.imported === "*";
    }
    if (binding.kind !== "variable" || !binding.constant || !binding.node.initializer ||
        seen.has(binding.node)) return false;
    const next = new Set(seen);
    next.add(binding.node);
    return processObjectOf(binding.node.initializer, next);
  };
  const isProcessPlatform = (node) => {
    const member = resolvedAccess(unwrap(node));
    return member?.method === "platform" && processObjectOf(member.receiver);
  };
  const testRunnerOf = (input, names, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return undefined;
    if (!ts.isIdentifier(node)) {
      const member = resolvedAccess(node);
      if (member && ["concurrent", "fails", "sequential"].includes(member.method)) {
        return testRunnerOf(member.receiver, names, seen);
      }
      return member && names.includes(member.method) && vitestNamespaceOf(member.receiver)
        ? member.method : undefined;
    }
    const binding = resolveBinding(node);
    if (!binding) {
      return ["test", "it", "describe"].includes(node.text) && names.includes(node.text)
        ? node.text : undefined;
    }
    if (binding.kind === "import" && !binding.typeOnly && binding.module === "vitest" &&
        ["test", "it", "describe"].includes(binding.imported) && names.includes(binding.imported)) {
      return binding.imported;
    }
    if (binding.kind !== "variable" || !binding.constant || !binding.node.initializer ||
        seen.has(binding.node)) return undefined;
    const next = new Set(seen);
    next.add(binding.node);
    return testRunnerOf(binding.node.initializer, names, next);
  };
  // Mutable aliases can carry .only, but they cannot prove test registration.
  const destructuredBindingCandidate = (declaration, targetName, names) => {
    if (!ts.isVariableDeclaration(declaration) && !ts.isParameter(declaration)) return undefined;
  if (!declaration.initializer) return undefined;
  const source = declaration.initializer;
  const patternSource = (pattern, value) => {
    if (ts.isObjectBindingPattern(pattern)) {
      for (const element of pattern.elements) {
        if (!ts.isBindingElement(element) || element.dotDotDotToken) continue;
        const key = element.propertyName
          ? assignmentKey(element.propertyName)
          : ts.isIdentifier(element.name) ? element.name.text : undefined;
        const selected = key === undefined ? [] : objectPropertyValuesOf(value, key);
        const candidates = selected.length > 0
          ? selected
          : element.initializer ? [element.initializer] : [];
        if (ts.isIdentifier(element.name) && element.name.text === targetName) {
          if (key && names.includes(key) &&
              (vitestNamespaceOf(value) || possibleVitestNamespaceOf(value))) {
            return { runner: key };
          }
          if (key && ["concurrent", "fails", "sequential"].includes(key)) {
            const runner = possibleTestRunnerOf(value, names);
            if (runner) return { runner };
          }
          if (candidates.length > 0) return { value: candidates[0] };
        }
        if (ts.isObjectBindingPattern(element.name) ||
            ts.isArrayBindingPattern(element.name)) {
          for (const candidate of candidates) {
            const nested = patternSource(element.name, candidate);
            if (nested) return nested;
          }
        }
      }
    }
    if (ts.isArrayBindingPattern(pattern)) {
      for (let index = 0; index < pattern.elements.length; index += 1) {
        const element = pattern.elements[index];
        if (!ts.isBindingElement(element) || element.dotDotDotToken) continue;
        const selected = objectPropertyValuesOf(value, String(index));
        const candidates = selected.length > 0
          ? selected
          : element.initializer ? [element.initializer] : [];
        if (ts.isIdentifier(element.name) && element.name.text === targetName) {
          if (candidates.length > 0) return { value: candidates[0] };
        }
        if (ts.isObjectBindingPattern(element.name) || ts.isArrayBindingPattern(element.name)) {
          for (const candidate of candidates) {
            const nested = patternSource(element.name, candidate);
            if (nested) return nested;
          }
        }
      }
    }
    return undefined;
  };
  return patternSource(declaration.name, source);
  };
  const localFunctionValuesOf = (input, seen = new Set()) => {
  const node = unwrap(input);
    if (!node || seen.has(node)) return [];
    if (ts.isFunctionLike(node)) return [node];
    const next = new Set(seen);
    next.add(node);
    if (ts.isConditionalExpression(node)) {
      return [
        ...localFunctionValuesOf(node.whenTrue, next),
        ...localFunctionValuesOf(node.whenFalse, next)
      ];
  }
    if (ts.isBinaryExpression(node) && [
      ts.SyntaxKind.CommaToken,
      ts.SyntaxKind.AmpersandAmpersandToken,
      ts.SyntaxKind.BarBarToken,
      ts.SyntaxKind.QuestionQuestionToken
    ].includes(node.operatorToken.kind)) {
      return [
        ...localFunctionValuesOf(node.left, next),
        ...localFunctionValuesOf(node.right, next)
      ];
    }
if (ts.isCallExpression(node)) {
return functionReturnExpressionsOf(node.expression, next)
.flatMap((value) => localFunctionValuesOf(value, next));
}
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (!binding?.node || seen.has(binding.node)) return [];
      const bindingNext = new Set(next);
      bindingNext.add(binding.node);
      if (ts.isFunctionLike(binding.node)) return [binding.node];
      if (ts.isParameter(binding.node)) {
        const functions = parameterFunctionArguments.get(binding.node) ?? [];
        if (functions.length > 0) {
          return functions.flatMap((value) => localFunctionValuesOf(value, bindingNext));
        }
      }
      if (binding.kind === "variable" && ts.isVariableDeclaration(binding.node) &&
          ts.isIdentifier(binding.node.name) && binding.node.initializer) {
        return localFunctionValuesOf(binding.node.initializer, bindingNext);
      }
      return [];
    }
    const member = resolvedAccess(node);
    if (!member || member.method === undefined) return [];
    return objectPropertyValuesOf(member.receiver, member.method, next)
      .flatMap((value) => localFunctionValuesOf(value, next));
  };
  function functionReturnExpressionsOf(input, seen = new Set()) {
    const node = unwrap(input);
    if (!node || seen.has(node)) return [];
    const next = new Set(seen);
    next.add(node);
    if (ts.isFunctionLike(node)) {
      if (ts.isArrowFunction(node) && !ts.isBlock(node.body)) {
        return [node.body];
      }
    const values = [];
    const visit = (child) => {
      if (ts.isFunctionLike(child) && child !== node) return;
      if (ts.isReturnStatement(child) && child.expression) values.push(child.expression);
      ts.forEachChild(child, visit);
    };
    if (node.body) visit(node.body);
    return values;
  }
if (ts.isCallExpression(node)) {
return functionReturnExpressionsOf(node.expression, next)
.flatMap((value) => functionReturnExpressionsOf(value, next));
}
    return localFunctionValuesOf(node, seen).flatMap((value) =>
      functionReturnExpressionsOf(value, next));
};
  const possibleTestRunnerOf = (input, names, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return undefined;
  if (ts.isGetAccessorDeclaration(node)) {
    const returnedValues = functionReturnExpressionsOf(node, seen);
    const next = new Set(seen);
    next.add(node);
    for (const value of returnedValues) {
      const candidate = possibleTestRunnerOf(value, names, next);
      if (candidate) return candidate;
    }
    return undefined;
  }
  if (ts.isFunctionLike(node)) {
    const returnedValues = functionReturnExpressionsOf(node, seen);
    const next = new Set(seen);
    next.add(node);
    for (const value of returnedValues) {
      const candidate = possibleTestRunnerOf(value, names, next);
      if (candidate) return candidate;
    }
    return undefined;
  }
  if (ts.isConditionalExpression(node)) {
    return possibleTestRunnerOf(node.whenTrue, names, seen) ??
      possibleTestRunnerOf(node.whenFalse, names, seen);
  }
  if (ts.isBinaryExpression(node)) {
    const operator = node.operatorToken.kind;
    if (operator === ts.SyntaxKind.CommaToken) {
      return possibleTestRunnerOf(node.right, names, seen);
    }
    if (operator === ts.SyntaxKind.AmpersandAmpersandToken ||
        operator === ts.SyntaxKind.BarBarToken ||
        operator === ts.SyntaxKind.QuestionQuestionToken) {
      return possibleTestRunnerOf(node.left, names, seen) ??
        possibleTestRunnerOf(node.right, names, seen);
    }
  }
  if (ts.isCallExpression(node)) {
    const createArguments = intrinsicInvocationArgumentsOf(
      node, ["Object"], ["create"], seen
    );
    if (createArguments?.[0]) {
      const candidate = possibleTestRunnerOf(createArguments[0], names, seen);
      if (candidate) return candidate;
    }
    const decorator = resolvedAccess(node.expression);
    if (decorator && ["each", "skipIf", "runIf"].includes(decorator.method)) {
      return possibleTestRunnerOf(decorator.receiver, names, seen);
    }
const callee = unwrap(node.expression);
const binding = ts.isIdentifier(callee) ? resolveBinding(callee) : undefined;
if (binding && seen.has(binding.node)) return undefined;
const next = new Set(seen);
if (binding) next.add(binding.node);
for (const value of functionReturnExpressionsOf(node.expression)) {
const candidate = possibleTestRunnerOf(value, names, next);
if (candidate) return candidate;
}
return undefined;
  }
  if (!ts.isIdentifier(node)) {
if (seen.has(node)) return undefined;
const next = new Set(seen);
next.add(node);
    const member = resolvedAccess(node);
    if (member && ["concurrent", "fails", "sequential"].includes(member.method)) {
return possibleTestRunnerOf(member.receiver, names, next);
    }
    if (member && names.includes(member.method) &&
        (vitestNamespaceOf(member.receiver) || possibleVitestNamespaceOf(member.receiver))) {
      return member.method;
    }
    if (member) {
for (const property of objectPropertyValuesOf(member.receiver, member.method, next)) {
const candidate = possibleTestRunnerOf(property, names, next);
        if (candidate) return candidate;
      }
    }
const stored = assignmentsByMemberPath.get(assignmentReferenceKey(node)) ?? [];
for (const value of stored) {
const candidate = possibleTestRunnerOf(value, names, next);
if (candidate) return candidate;
}
    return testRunnerOf(node, names);
  }
    const binding = resolveBinding(node);
    const declaredCandidate = binding?.kind !== "import" && binding?.node
      ? destructuredBindingCandidate(binding.node, node.text, names)
      : undefined;
    if (declaredCandidate?.runner) return declaredCandidate.runner;
    if (declaredCandidate?.value && !seen.has(binding.node)) {
      const next = new Set(seen);
      next.add(binding.node);
      const candidate = possibleTestRunnerOf(declaredCandidate.value, names, next);
      if (candidate) return candidate;
    }
  if (binding?.node && !seen.has(binding.node)) {
    const next = new Set(seen);
    next.add(binding.node);
    const reassigned = destructuredAssignmentsByBinding.get(
      `${binding.node.pos}:${node.text}`) ?? [];
    for (const value of reassigned) {
      const candidate = possibleTestRunnerOf(value, names, next);
      if (candidate) return candidate;
    }
  }
    if (binding?.kind === "variable" && runnerAssignmentsByBinding.has(binding.node)) {
      return runnerAssignmentsByBinding.get(binding.node);
    }
    if (binding?.kind === "opaque" && ts.isParameter(binding.node) &&
        !seen.has(binding.node)) {
    const next = new Set(seen);
    next.add(binding.node);
      const values = [
        ts.isIdentifier(binding.node.name) ? binding.node.initializer : undefined,
        ...destructuredValuesOf(binding.node, node.text),
        ...(parameterRunnerArguments.get(binding.node) ?? []).flatMap((value) =>
          ts.isIdentifier(binding.node.name)
            ? [value]
            : destructuredSourceValuesOf(binding.node.name, value, node.text)),
        ...(assignmentsByBinding.get(binding.node) ?? [])
      ];
      for (const value of values) {
      const candidate = possibleTestRunnerOf(value, names, next);
      if (candidate) return candidate;
    }
  }
  if (binding?.kind === "opaque" && ts.isVariableDeclaration(binding.node) &&
        ts.isObjectBindingPattern(binding.node.name) && binding.node.initializer &&
      (vitestNamespaceOf(binding.node.initializer) ||
       possibleVitestNamespaceOf(binding.node.initializer))) {
      for (const element of binding.node.name.elements) {
        if (ts.isIdentifier(element.name) && element.name.text === node.text) {
          const imported = element.propertyName?.text ?? element.name.text;
          if (names.includes(imported)) return imported;
        }
      }
    }
  if ((binding?.kind === "variable" || binding?.kind === "opaque") &&
      binding.node && !seen.has(binding.node) &&
      ts.isVariableDeclaration(binding.node) &&
      ts.isIdentifier(binding.node.name)) {
      const next = new Set(seen);
      next.add(binding.node);
      const values = [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])];
      for (const value of values) {
        const candidate = value && possibleTestRunnerOf(value, names, next);
        if (candidate) return candidate;
      }
    }
    return testRunnerOf(node, names);
  }
  const selectedBindingNameOf = (pattern, targetName) => {
   if (ts.isObjectBindingPattern(pattern)) {
     for (const element of pattern.elements) {
       const name = element.propertyName ?? element.name;
       if (ts.isIdentifier(element.name) && element.name.text === targetName) {
         return assignmentKey(name);
       }
       if (ts.isObjectBindingPattern(element.name) ||
           ts.isArrayBindingPattern(element.name)) {
         const nested = selectedBindingNameOf(element.name, targetName);
         if (nested !== undefined) return nested;
       }
     }
   }
   if (ts.isArrayBindingPattern(pattern)) {
     for (let index = 0; index < pattern.elements.length; index += 1) {
       const element = pattern.elements[index];
      if (ts.isOmittedExpression(element)) continue;
       if (ts.isIdentifier(element.name) && element.name.text === targetName) {
         return String(index);
       }
       if (ts.isObjectBindingPattern(element.name) ||
           ts.isArrayBindingPattern(element.name)) {
         const nested = selectedBindingNameOf(element.name, targetName);
         if (nested !== undefined) return nested;
       }
     }
   }
   return undefined;
 };
  const selectedExtractionContainerOf = (
    input, selectedName, names, seen = new Set()
  ) => {
    const node = unwrap(input);
    if (!node || seen.has(node)) return false;
    const next = new Set(seen);
    next.add(node);
    if (ts.isConditionalExpression(node)) {
      return selectedExtractionContainerOf(node.whenTrue, selectedName, names, next) ||
        selectedExtractionContainerOf(node.whenFalse, selectedName, names, next);
    }
    if (ts.isBinaryExpression(node) && [
      ts.SyntaxKind.AmpersandAmpersandToken,
      ts.SyntaxKind.BarBarToken,
      ts.SyntaxKind.CommaToken,
      ts.SyntaxKind.QuestionQuestionToken
    ].includes(node.operatorToken.kind)) {
      return selectedExtractionContainerOf(node.left, selectedName, names, next) ||
        selectedExtractionContainerOf(node.right, selectedName, names, next);
    }
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      const declaration = binding?.node &&
        (ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node))
        ? binding.node : undefined;
      if (!declaration || seen.has(binding.node)) return false;
      const bindingNext = new Set(seen);
      bindingNext.add(binding.node);
      const values = ts.isIdentifier(declaration.name)
        ? [declaration.initializer, ...(assignmentsByBinding.get(declaration) ?? [])]
        : declaration.initializer
          ? destructuredValuesOf(declaration, node.text) : [];
      return values.some((value) => value &&
        selectedExtractionContainerOf(value, selectedName, names, bindingNext));
    }
    const member = resolvedAccess(node);
    if (member?.method === "value" && selectedName === "value") {
      return testRunnerContainerOf(member.receiver, names, seen);
    }
    if (member && member.method === selectedName && names.includes(selectedName)) {
      return testRunnerContainerOf(member.receiver, names, seen);
    }
    const descriptorArguments = intrinsicInvocationArgumentsOf(
      node, ["Object"], ["getOwnPropertyDescriptor"], seen
    );
    if (descriptorArguments && selectedName === "value") {
      const property = staticStringOf(descriptorArguments[1], seen);
      return Boolean(descriptorArguments[0]) &&
        (property === undefined || names.includes(property)) &&
        testRunnerContainerOf(descriptorArguments[0], names, seen);
    }
    const bagArguments = intrinsicInvocationArgumentsOf(
      node, ["Object"], ["fromEntries", "getOwnPropertyDescriptors"], seen
    );
    if (names.includes(selectedName) && bagArguments?.some((argument) =>
      testRunnerContainerOf(argument, names, seen))) return true;
    const valuesArguments = intrinsicInvocationArgumentsOf(
      node, ["Object"], ["values"], seen
    );
    if (/^\d+$/.test(selectedName) && valuesArguments?.some((argument) =>
      testRunnerContainerOf(argument, names, seen))) return true;
    const entriesArguments = intrinsicInvocationArgumentsOf(
      node, ["Object"], ["entries"], seen
    );
    if (/^\d+$/.test(selectedName) && entriesArguments?.some((argument) =>
      testRunnerContainerOf(argument, names, seen))) return true;
    if (member && /^\d+$/.test(member.method ?? "") &&
        /^\d+$/.test(selectedName)) {
      const entryArguments = intrinsicInvocationArgumentsOf(
        member.receiver, ["Object"], ["entries"], seen
      );
      if (entryArguments?.some((argument) =>
        testRunnerContainerOf(argument, names, seen))) return true;
    }
    return false;
  };
  const testRunnerContainerOf = (input, names, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
    if (possibleTestRunnerOf(node, names, seen)) return true;
    if (globalIntrinsicOf(node, ["Proxy"])) return true;
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (binding?.node && !seen.has(binding.node)) {
        const declaration = ts.isVariableDeclaration(binding.node) ||
          ts.isParameter(binding.node) ? binding.node : undefined;
        if (declaration) {
          const next = new Set(seen);
          next.add(binding.node);
          if (declaration.initializer &&
              !ts.isIdentifier(declaration.name)) {
            const selectedName = selectedBindingNameOf(declaration.name, node.text);
            if (selectedName !== undefined &&
                selectedExtractionContainerOf(
                  declaration.initializer, selectedName, names, next
                )) return true;
          }
          const values = ts.isIdentifier(declaration.name)
            ? [declaration.initializer, ...(assignmentsByBinding.get(declaration) ?? [])]
            : declaration.initializer
              ? destructuredValuesOf(declaration, node.text) : [];
          if (values.some((value) => value &&
              testRunnerContainerOf(value, names, next))) return true;
        }
      }
    }
    if (names.some((name) => objectPropertyValuesOf(node, name, seen)
      .some((value) => possibleTestRunnerOf(value, names, seen)))) return true;
    const member = resolvedAccess(node);
    if (member && (member.method === "value" || names.includes(member.method) ||
        /^\d+$/.test(member.method ?? "")) &&
        testRunnerContainerOf(member.receiver, names, seen)) return true;
    if (!ts.isCallExpression(node)) return false;
    if (globalIntrinsicOf(node.expression, ["Proxy"])) {
      return Boolean(node.arguments[0]) &&
        testRunnerContainerOf(node.arguments[0], names, seen);
    }
    const factory = resolvedAccess(unwrap(node.expression));
    if (globalIntrinsicMethodOf(node.expression, ["Reflect"], ["get"], seen)) {
      const property = staticStringOf(node.arguments[1], seen);
      if (property === undefined) {
        return possibleTestRunnerOf(node.arguments[0], names, seen) ||
          possibleVitestNamespaceOf(node.arguments[0]);
      }
      if (property === "only") {
        return possibleTestRunnerOf(node.arguments[0], names, seen);
      }
      return names.includes(property) &&
        (possibleVitestNamespaceOf(node.arguments[0]) ||
         testRunnerContainerOf(node.arguments[0], names, seen));
    }
const assignArguments = intrinsicInvocationArgumentsOf(
  node, ["Object"], ["assign"], seen
);
if (assignArguments) {
  return assignArguments.slice(1).some((argument) =>
    testRunnerContainerOf(argument, names, seen));
    }
    if (factory?.method === "create" &&
        globalIntrinsicOf(factory.receiver, ["Object"])) {
      return Boolean(node.arguments[0]) &&
        testRunnerContainerOf(node.arguments[0], names, seen);
    }
    const descriptorArguments = intrinsicInvocationArgumentsOf(node, ["Object"], [
      "getOwnPropertyDescriptor"
    ], seen);
    if (descriptorArguments) {
      const property = staticStringOf(descriptorArguments[1], seen);
      return Boolean(descriptorArguments[0]) &&
        (property === undefined || names.includes(property)) &&
        testRunnerContainerOf(descriptorArguments[0], names, seen);
    }
    const extractionArguments = intrinsicInvocationArgumentsOf(node, ["Object"], [
      "entries", "fromEntries", "getOwnPropertyDescriptors", "values"
    ], seen);
    if (extractionArguments) {
      return extractionArguments.some((argument) =>
        testRunnerContainerOf(argument, names, seen));
    }
    return false;
  };
  const collectBoundNames = (pattern, names = []) => {
    names.push(...bindingNameInfoOf(pattern).map((binding) => binding.name));
    return names;
  };
  const visitIntrinsicAliases = (node) => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      if (ts.isIdentifier(node.name)) {
        if (globalIntrinsicMethodOf(node.initializer, ["Reflect"], ["get"]) ||
            globalIntrinsicMethodOf(node.initializer, ["Object"], [
          "assign", "create", "entries", "fromEntries", "getOwnPropertyDescriptor",
              "getOwnPropertyDescriptors", "values"
            ])) intrinsicMethodAliasNames.add(node.name.text);
        if (ts.isObjectLiteralExpression(unwrap(node.initializer)) &&
            unwrap(node.initializer).properties.some((property) => {
              if (ts.isSpreadAssignment(property)) return false;
              const value = ts.isPropertyAssignment(property) ? property.initializer
                : ts.isShorthandPropertyAssignment(property) ? property.name : undefined;
              return Boolean(value &&
                (globalIntrinsicMethodOf(value, ["Reflect"], ["get"]) ||
                 globalIntrinsicMethodOf(value, ["Object"], [
            "assign", "create", "entries", "fromEntries", "getOwnPropertyDescriptor",
                   "getOwnPropertyDescriptors", "values"
                 ])));
            })) intrinsicMethodContainerNames.add(node.name.text);
      } else if (ts.isObjectBindingPattern(node.name) ||
          ts.isArrayBindingPattern(node.name)) {
        for (const name of collectBoundNames(node.name)) {
          const selected = destructuredValuesOf(node, name);
          if (selected.some((value) =>
            globalIntrinsicMethodOf(value, ["Reflect"], ["get"]) ||
            globalIntrinsicMethodOf(value, ["Object"], [
              "assign", "create", "entries", "fromEntries", "getOwnPropertyDescriptor",
              "getOwnPropertyDescriptors", "values"
            ]))) {
            intrinsicMethodAliasNames.add(name);
          } else if (globalIntrinsicOf(node.initializer, ["Reflect"]) &&
              patternSelectsProperty(node.name, name, "get")) {
            intrinsicMethodAliasNames.add(name);
          } else if (globalIntrinsicOf(node.initializer, ["Object"]) &&
            ["assign", "create", "entries", "fromEntries", "getOwnPropertyDescriptor",
                "getOwnPropertyDescriptors", "values"].some((method) =>
                patternSelectsProperty(node.name, name, method))) {
            intrinsicMethodAliasNames.add(name);
          }
        }
      }
    }
    if (ts.isBinaryExpression(node) && aliasAssignmentKinds.has(node.operatorToken.kind) &&
        ts.isIdentifier(unwrap(node.left)) &&
        (globalIntrinsicMethodOf(node.right, ["Reflect"], ["get"]) ||
         globalIntrinsicMethodOf(node.right, ["Object"], [
           "assign", "create", "entries", "fromEntries", "getOwnPropertyDescriptor",
           "getOwnPropertyDescriptors", "values"
         ]))) intrinsicMethodAliasNames.add(unwrap(node.left).text);
    ts.forEachChild(node, visitIntrinsicAliases);
  };
  visitIntrinsicAliases(file);
  let expandedAlias = true;
  while (expandedAlias) {
    expandedAlias = false;
    const visitAliasChains = (node) => {
      let target;
      let value;
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) &&
          node.initializer) {
        target = node.name;
        value = node.initializer;
      } else if (ts.isBinaryExpression(node) &&
          aliasAssignmentKinds.has(node.operatorToken.kind) &&
          ts.isIdentifier(unwrap(node.left))) {
        target = unwrap(node.left);
        value = node.right;
      }
      value = unwrap(value);
      if (target && ts.isIdentifier(value) &&
          intrinsicMethodAliasNames.has(value.text) &&
          !intrinsicMethodAliasNames.has(target.text)) {
        intrinsicMethodAliasNames.add(target.text);
        expandedAlias = true;
      }
      ts.forEachChild(node, visitAliasChains);
    };
    visitAliasChains(file);
  }
  // Follow direct calls to local helpers so runner identity reaches their
  // parameters. Repeating finite parameter/argument pairs handles short
  // helper chains without creating a repository-wide call graph.
  const containsRunnerValueOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node || seen.has(node)) return false;
    if (possibleTestRunnerOf(node, ["test", "it", "describe"])) return true;
    const next = new Set(seen);
    next.add(node);
    if (ts.isObjectLiteralExpression(node)) {
      return node.properties.some((property) => {
        if (ts.isSpreadAssignment(property)) {
          return containsRunnerValueOf(property.expression, next);
        }
        if (ts.isPropertyAssignment(property)) {
          return containsRunnerValueOf(property.initializer, next);
        }
        if (ts.isShorthandPropertyAssignment(property)) {
          return containsRunnerValueOf(property.name, next);
        }
        return false;
      });
    }
    if (ts.isArrayLiteralExpression(node)) {
      return node.elements.some((element) =>
        !ts.isOmittedExpression(element) &&
        containsRunnerValueOf(
          ts.isSpreadElement(element) ? element.expression : element, next
        ));
    }
    return false;
  };
const reflectApplyInvocationOf = (argumentsList, seen = new Set()) => {
  const functions = localFunctionValuesOf(argumentsList[0], seen);
  if (functions.length === 0) return undefined;
  return { functions, plan: argumentArrayPlanOf(argumentsList[2], seen) };
};
const bindMethodReferenceOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return undefined;
  if (ts.isGetAccessorDeclaration(node)) {
    const returnedValues = functionReturnExpressionsOf(node, seen);
    const next = new Set(seen);
    next.add(node);
    for (const value of returnedValues) {
      const resolved = bindMethodReferenceOf(value, next);
      if (resolved) return resolved;
    }
    return undefined;
  }
  const member = resolvedAccess(node);
  if (member) {
    const next = new Set(seen);
    next.add(node);
    for (const value of objectPropertyValuesOf(
      member.receiver, member.method, next
    )) {
      const resolved = bindMethodReferenceOf(value, next);
      if (resolved) return resolved;
    }
    if (member.method === "bind") return member;
  }
  if (ts.isCallExpression(node)) {
    const next = new Set(seen);
    next.add(node);
    for (const value of functionReturnExpressionsOf(node.expression, next)) {
      const resolved = bindMethodReferenceOf(value, next);
      if (resolved) return resolved;
    }
    return undefined;
  }
  if (!ts.isIdentifier(node)) return undefined;
  const binding = resolveBinding(node);
  if (binding?.kind !== "variable" ||
      !ts.isVariableDeclaration(binding.node) ||
      !ts.isIdentifier(binding.node.name) || !binding.node.initializer) {
    return undefined;
  }
  const next = new Set(seen);
  next.add(node);
  next.add(binding.node);
  return bindMethodReferenceOf(binding.node.initializer, next);
};
function genericBindMethodOf(input, seen = new Set()) {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  if (ts.isFunctionLike(node)) {
    const returnedValues = functionReturnExpressionsOf(node, seen);
    const next = new Set(seen);
    next.add(node);
    return returnedValues
      .some((value) => genericBindMethodOf(value, next));
  }
  const bind = resolvedAccess(node);
  const prototype = bind?.method === "bind"
    ? resolvedAccess(unwrap(bind.receiver)) : undefined;
  if (prototype?.method === "prototype" &&
      globalIntrinsicOf(prototype.receiver, ["Function"], seen)) return true;
  const next = new Set(seen);
  next.add(node);
  if (bind && objectPropertyValuesOf(bind.receiver, bind.method, next)
    .some((value) => genericBindMethodOf(value, next))) return true;
  if (ts.isCallExpression(node)) {
    return functionReturnExpressionsOf(node.expression, next)
      .some((value) => genericBindMethodOf(value, next));
  }
  if (!ts.isIdentifier(node)) return false;
  const binding = resolveBinding(node);
  return Boolean(binding?.kind === "variable" &&
    ts.isVariableDeclaration(binding.node) && binding.node.initializer &&
    genericBindMethodOf(binding.node.initializer, next));
}
const storedBindInvocationOf = (input, invocationPlan, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return undefined;
  const next = new Set(seen);
  next.add(node);
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (binding?.kind === "variable" &&
        ts.isVariableDeclaration(binding.node) &&
        ts.isIdentifier(binding.node.name)) {
      const declarationNext = new Set(next);
      declarationNext.add(binding.node);
      const values = [
        binding.node.initializer,
        ...(assignmentsByBinding.get(binding.node) ?? [])
      ].filter(Boolean);
      const candidates = [];
      for (const value of values) {
        const candidate = storedBindInvocationOf(
          value, invocationPlan, declarationNext
        );
        if (candidate) candidates.push(candidate);
      }
      if (candidates.length > 0) {
      return {
        alternatives: candidates.flatMap((candidate) =>
          candidate.alternatives ?? [candidate])
      };
      }
    }
    return undefined;
  }
  if (ts.isConditionalExpression(node)) {
    const alternatives = [node.whenTrue, node.whenFalse].flatMap((value) => {
      const candidate = storedBindInvocationOf(
        value, invocationPlan, next
      );
      return candidate ? candidate.alternatives ?? [candidate] : [];
    });
    if (alternatives.length > 0) return { alternatives };
  }
  if (!ts.isCallExpression(node)) return undefined;
  const bind = bindMethodReferenceOf(node.expression, next);
  if (bind?.method === "bind") {
    const plan = mergeCallArgumentPlans(
      fixedCallArgumentPlanOf(node.arguments.slice(1)),
      invocationPlan
    );
    if (reflectApplyReferenceOf(bind.receiver, next)) {
      const functions = callArgumentCandidatesAt(plan, 0)
        .flatMap((value) => localFunctionValuesOf(value, next));
      if (functions.length > 0) {
        const applicationPlans = callArgumentCandidatesAt(plan, 2)
          .map((value) => argumentArrayPlanOf(value, next));
        return {
          functions,
          plan: applicationPlans.length > 0
            ? applicationPlans.reduce((left, right) =>
              mergeCallArgumentPlans(left, right))
            : { before: [], after: [], unknownIndex: 0 }
        };
      }
    }
    const functions = localFunctionValuesOf(bind.receiver, next);
    if (functions.length > 0) {
      return { functions, plan };
    }
  }
  const bindWrapper = resolvedAccess(unwrap(node.expression));
  if (bindWrapper && ["apply", "call"].includes(bindWrapper.method)) {
    const aliasedBind = bindMethodReferenceOf(bindWrapper.receiver, next);
    const genericBind = genericBindMethodOf(bindWrapper.receiver, next);
    const functions = genericBind
      ? localFunctionValuesOf(node.arguments[0], next)
      : aliasedBind?.method === "bind"
        ? localFunctionValuesOf(aliasedBind.receiver, next) : [];
    if (functions.length > 0) {
      const bindArguments = bindWrapper.method === "call"
        ? fixedCallArgumentPlanOf(node.arguments.slice(1))
        : argumentArrayPlanOf(node.arguments[1], next);
      return {
        functions,
        plan: mergeCallArgumentPlans(
          dropLeadingCallArgument(bindArguments), invocationPlan
        )
      };
    }
  }
  if (reflectApplyReferenceOf(unwrap(node.expression), next)) {
    const reflectedBind = bindMethodReferenceOf(node.arguments[0], next);
    const genericBind = genericBindMethodOf(node.arguments[0], next);
    const functions = genericBind
      ? localFunctionValuesOf(node.arguments[1], next)
      : reflectedBind?.method === "bind"
        ? localFunctionValuesOf(reflectedBind.receiver, next) : [];
    if (functions.length > 0) {
      return {
        functions,
        plan: mergeCallArgumentPlans(
dropLeadingCallArgument(argumentArrayPlanOf(node.arguments[2], next)),
          invocationPlan
        )
      };
    }
  }
  return undefined;
};
const localInvocationOf = (call) => {
  const callee = unwrap(call.expression);
  if (reflectApplyReferenceOf(callee)) {
    const reflected = reflectApplyInvocationOf(call.arguments);
    if (reflected) return reflected;
  }
  const storedBound = storedBindInvocationOf(
    callee, fixedCallArgumentPlanOf(call.arguments)
  );
  if (storedBound) return storedBound;
  if (ts.isCallExpression(callee)) {
    const bind = resolvedAccess(unwrap(callee.expression));
    if (bind?.method === "bind") {
      const functions = localFunctionValuesOf(bind.receiver);
      if (functions.length > 0) {
        return {
          functions,
          plan: mergeCallArgumentPlans(
            fixedCallArgumentPlanOf(callee.arguments.slice(1)),
            fixedCallArgumentPlanOf(call.arguments)
          )
        };
      }
    }
  }
  const directFunctions = localFunctionValuesOf(callee);
  if (directFunctions.length > 0) {
    return { functions: directFunctions, plan: fixedCallArgumentPlanOf(call.arguments) };
  }
  const wrapper = resolvedAccess(callee);
  if (wrapper?.method === "bind") {
    const functions = localFunctionValuesOf(wrapper.receiver);
    if (functions.length > 0) {
      return { functions, plan: fixedCallArgumentPlanOf(call.arguments.slice(1)) };
    }
  }
  if (wrapper && ["apply", "call"].includes(wrapper.method)) {
    const functions = localFunctionValuesOf(wrapper.receiver);
    if (functions.length > 0) {
      return {
        functions,
        plan: wrapper.method === "call"
          ? fixedCallArgumentPlanOf(call.arguments.slice(1))
          : argumentArrayPlanOf(call.arguments[1])
      };
    }
    const boundInvocation = storedBindInvocationOf(
      wrapper.receiver,
      wrapper.method === "call"
        ? fixedCallArgumentPlanOf(call.arguments.slice(1))
        : argumentArrayPlanOf(call.arguments[1])
    );
    if (boundInvocation) return boundInvocation;
    if (reflectApplyReferenceOf(wrapper.receiver)) {
      const reflectedArguments = wrapper.method === "call"
        ? call.arguments.slice(1)
        : fixedSpreadValuesOf(call.arguments[1]);
      const reflected = reflectedArguments &&
        reflectApplyInvocationOf(reflectedArguments);
      if (reflected) return reflected;
    }
  }
  return undefined;
};
const recordRestArgumentsOf = (parameter, plan, offset = 0) => {
  const positionedPlan = offset === 0 ? plan : { ...plan, offset };
  if (ts.isIdentifier(parameter.name)) {
    const plans = parameterRestArguments.get(parameter) ?? [];
    if (plans.some((stored) => callArgumentPlansEqual(stored, positionedPlan))) return false;
    plans.push(positionedPlan);
    parameterRestArguments.set(parameter, plans);
    return true;
  }
  if (!ts.isArrayBindingPattern(parameter.name)) return false;
  let changed = false;
  for (let index = 0; index < parameter.name.elements.length; index += 1) {
    const element = parameter.name.elements[index];
    if (!ts.isBindingElement(element)) continue;
    const candidates = callArgumentCandidatesAt(positionedPlan, index)
      .filter((candidate) => candidate && containsRunnerValueOf(candidate));
    const names = ts.isIdentifier(element.name)
      ? [element.name.text] : collectBoundNames(element.name);
    for (const name of names) {
      const key = `${parameter.pos}:${name}`;
      const values = destructuredAssignmentsByBinding.get(key) ?? [];
      for (const candidate of candidates) {
        if (values.includes(candidate)) continue;
        values.push(candidate);
        changed = true;
      }
      destructuredAssignmentsByBinding.set(key, values);
    }
  }
  return changed;
};
const recordPlan = (store, key, plan) => {
  const plans = store.get(key) ?? [];
  if (plans.some((stored) => callArgumentPlansEqual(stored, plan))) return false;
  plans.push(plan);
  store.set(key, plans);
  return true;
};
const recordParameterFunctions = (parameter, functions) => {
  const stored = parameterFunctionArguments.get(parameter) ?? [];
  let changed = false;
  for (const fn of functions) {
    if (stored.includes(fn)) continue;
    stored.push(fn);
    changed = true;
  }
  parameterFunctionArguments.set(parameter, stored);
  return changed;
};
collectResolvedAssignments(file);
collectAssignments(file);
  collectArrayMutations(file);
  let parameterRunnerArgumentsChanged = true;
  while (parameterRunnerArgumentsChanged) {
    parameterRunnerArgumentsChanged = false;
    const collectParameterRunnerArguments = (node) => {
      if (ts.isCallExpression(node)) {
      const invocation = localInvocationOf(node);
      const alternatives = invocation?.alternatives ?? [invocation].filter(Boolean);
      for (const alternative of alternatives) {
      const { functions, plan } = alternative;
      for (const fn of functions) {
        parameterRunnerArgumentsChanged = recordPlan(
          functionArgumentsPlans, fn, plan
        ) || parameterRunnerArgumentsChanged;
        for (let index = 0; index < fn.parameters.length; index += 1) {
            const parameter = fn.parameters[index];
          if (parameter.dotDotDotToken) {
            parameterRunnerArgumentsChanged = recordRestArgumentsOf(
              parameter, plan, index
            ) || parameterRunnerArgumentsChanged;
            break;
          }
          for (const argument of callArgumentCandidatesAt(plan, index)) {
            if (!argument) continue;
            parameterRunnerArgumentsChanged = recordParameterFunctions(
              parameter, localFunctionValuesOf(argument)
            ) || parameterRunnerArgumentsChanged;
            const boundNames = ts.isIdentifier(parameter.name)
              ? []
              : collectBoundNames(parameter.name);
            const hasRestBinding = bindingNameInfoOf(parameter.name)
              .some((binding) => binding.rest);
            const carriesRunner = ts.isIdentifier(parameter.name)
? containsRunnerValueOf(argument) || Boolean(possibleTestRunnerOf(
argument, ["test", "it", "describe"]
))
              : (hasRestBinding && containsRunnerValueOf(argument)) ||
              boundNames.some((name) =>
                destructuredSourceValuesOf(
                  parameter.name, argument, name
                ).some((value) => containsRunnerValueOf(value)));
            if (!carriesRunner) continue;
            const values = parameterRunnerArguments.get(parameter) ?? [];
            if (values.includes(argument)) continue;
            values.push(argument);
            parameterRunnerArguments.set(parameter, values);
            parameterRunnerArgumentsChanged = true;
          }
          }
        }
      }
      }
      ts.forEachChild(node, collectParameterRunnerArguments);
    };
    collectParameterRunnerArguments(file);
  }
return { isProcessPlatform, testRunnerOf, possibleTestRunnerOf,
possibleVitestNamespaceOf, testRunnerContainerOf, globalIntrinsicOf,
    intrinsicInvocationArgumentsOf, resolveBinding, resolvedAccess, staticStringOf };
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
const { isProcessPlatform, testRunnerOf, possibleTestRunnerOf,
possibleVitestNamespaceOf, testRunnerContainerOf,
    intrinsicInvocationArgumentsOf, resolveBinding, resolvedAccess, staticStringOf } =
    createWindowsTestBindingResolver(file);

  // Exclusive declarations anywhere in the file remain fail-closed, including
  // element access and unknown dynamic member selectors.
  const inspectExclusivePattern = (pattern) => {
    if (ts.isObjectBindingPattern(pattern)) {
      for (const element of pattern.elements) {
        const propertyNode = element.propertyName;
        const property = propertyNode
          ? ts.isComputedPropertyName(propertyNode)
            ? literal(propertyNode.expression)
            : ts.isIdentifier(propertyNode) ? propertyNode.text : literal(propertyNode)
          : ts.isIdentifier(element.name) ? element.name.text : undefined;
        if (element.dotDotDotToken ||
            (propertyNode && property === undefined) || property === "only") {
          throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
        }
        if (["test", "it", "describe", "concurrent", "sequential"].includes(property) &&
            (ts.isObjectBindingPattern(element.name) ||
             ts.isArrayBindingPattern(element.name))) {
          inspectExclusivePattern(element.name);
        }
      }
      return;
    }
    if (ts.isObjectLiteralExpression(pattern)) {
      for (const property of pattern.properties) {
        if (ts.isSpreadAssignment(property)) {
          throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
        }
        if (!ts.isPropertyAssignment(property) &&
            !ts.isShorthandPropertyAssignment(property)) continue;
        const name = ts.isShorthandPropertyAssignment(property)
          ? property.name.text
          : ts.isComputedPropertyName(property.name)
          ? literal(property.name.expression)
          : ts.isIdentifier(property.name) ? property.name.text : literal(property.name);
        if (name === "only" ||
            (ts.isComputedPropertyName(property.name) && name === undefined)) {
          throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
        }
        const nested = ts.isPropertyAssignment(property) ? unwrap(property.initializer) : undefined;
        if (["test", "it", "describe", "concurrent", "sequential"].includes(name) &&
            nested && (ts.isObjectLiteralExpression(nested) ||
                       ts.isArrayLiteralExpression(nested))) {
          inspectExclusivePattern(nested);
        }
      }
      }
  };
  const checkExclusive = (node) => {
    if (ts.isParameter(node) && node.initializer &&
        possibleTestRunnerOf(node.initializer, ["test", "it", "describe"])) {
      throw new Error("Exclusive or dynamically selected Vitest tests unaudited.");
    }
const member = resolvedAccess(node);
    if (member && (member.method === undefined || member.method === "only") &&
        testRunnerContainerOf(member.receiver, ["test", "it", "describe"])) {
      throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
    }
    if (ts.isCallExpression(node)) {
    const reflectiveArguments = intrinsicInvocationArgumentsOf(
      node, ["Reflect"], ["get"]
    );
    if (reflectiveArguments) {
      const property = staticStringOf(reflectiveArguments[1]);
        const runner = possibleTestRunnerOf(
        reflectiveArguments[0], ["test", "it", "describe"]);
        if (runner && (property === undefined || property === "only")) {
          throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
        }
      }
    }
    if (ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isObjectLiteralExpression(unwrap(node.left)) &&
        (possibleTestRunnerOf(node.right, ["test", "it", "describe"]) ||
         possibleVitestNamespaceOf(node.right))) {
      for (const property of unwrap(node.left).properties) {
        if (ts.isSpreadAssignment(property)) {
          throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
        }
        if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) continue;
        const name = ts.isShorthandPropertyAssignment(property)
          ? property.name.text
          : ts.isComputedPropertyName(property.name)
            ? literal(property.name.expression)
            : ts.isIdentifier(property.name) ? property.name.text : literal(property.name);
        if (name === "only" || (ts.isComputedPropertyName(property.name) && name === undefined)) {
          throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
        }
        if (["test", "it", "describe", "concurrent", "sequential"].includes(name) &&
            ts.isPropertyAssignment(property)) {
          const nested = unwrap(property.initializer);
          if (ts.isObjectLiteralExpression(nested) ||
              ts.isArrayLiteralExpression(nested)) {
            inspectExclusivePattern(nested);
          }
        }
      }
    }
    if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name) &&
        node.initializer &&
        (possibleTestRunnerOf(node.initializer, ["test", "it", "describe"]) ||
         possibleVitestNamespaceOf(node.initializer))) {
      for (const element of node.name.elements) {
        const propertyNode = element.propertyName;
        const property = propertyNode
          ? ts.isComputedPropertyName(propertyNode)
            ? literal(propertyNode.expression)
            : ts.isIdentifier(propertyNode) ? propertyNode.text : literal(propertyNode)
          : ts.isIdentifier(element.name) ? element.name.text : undefined;
        if (element.dotDotDotToken || (propertyNode && property === undefined) || property === "only") {
          throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
        }
        if (["test", "it", "describe", "concurrent", "sequential"].includes(property) &&
            (ts.isObjectBindingPattern(element.name) ||
             ts.isArrayBindingPattern(element.name))) {
          inspectExclusivePattern(element.name);
        }
      }
    }
    ts.forEachChild(node, checkExclusive);
  };
  checkExclusive(file);

  const register = (node, disabled = false) => {
    if (ts.isSourceFile(node) || ts.isBlock(node)) {
      let continuing = true;
      for (const statement of node.statements) {
        const branchContinues = register(statement, disabled || !continuing);
        if (continuing) continuing = branchContinues;
      }
      return continuing;
    }
    if (ts.isIfStatement(node)) {
      const outcome = conditionOnWindows(node.expression, isProcessPlatform);
      const thenContinues = register(node.thenStatement, disabled || outcome !== true);
      const elseContinues = node.elseStatement
        ? register(node.elseStatement, disabled || outcome !== false)
        : true;
      if (outcome === true) return thenContinues;
      if (outcome === false) return elseContinues;
      return thenContinues && elseContinues;
    }
    if (ts.isExpressionStatement(node)) {
      register(node.expression, disabled);
      return true;
    }
    node = unwrap(node);
    if (ts.isConditionalExpression(node)) {
      const outcome = conditionOnWindows(node.condition, isProcessPlatform);
      register(node.whenTrue, disabled || outcome !== true);
      register(node.whenFalse, disabled || outcome !== false);
      return true;
    }
    if (ts.isReturnStatement(node) || ts.isThrowStatement(node)) return false;
    if (!ts.isCallExpression(node)) return true;

    const suite = invocationKind(node.expression, ["describe"], isProcessPlatform, testRunnerOf);
    if (suite) {
      const callback = node.arguments.slice(1).map(unwrap).find((argument) =>
        ts.isArrowFunction(argument) || ts.isFunctionExpression(argument));
      if (callback && (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback))) {
        register(callback.body,
          disabled || !suite.enabled ||
          !registrationOptionsEnabled(node.arguments, resolveBinding));
      }
      // Unresolved suite callbacks are not proven to register tests.
      return true;
    }
    const title = literal(node.arguments[0]);
    const call = invocationKind(node.expression, ["test", "it"], isProcessPlatform, testRunnerOf);
    if (call && title !== undefined) {
      const expanded = call.values ? call.values.map((value, i) =>
        title.replace(/%s|%d|%i/, (p) => p === "%i" ? String(i) : String(value))) : [title];
      const enabled = call.enabled &&
        registrationOptionsEnabled(node.arguments, resolveBinding) &&
        hasRegistrationCallback(node.arguments, resolveBinding);
      for (const name of expanded) titles.push({ title: name, enabled: enabled && !disabled });
    }
    // Other calls (setTimeout, .then, IIFEs, fixtures) are not Vitest
    // registration contexts; never descend through their callbacks.
    return true;
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
  if (Object.hasOwn(job, "needs") && job.needs !== undefined) {
    findings.push("Required CI job must not depend on another job: " + name);
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
  const pullRequest = workflow?.on?.pull_request;
  if (!workflow?.on || !Object.hasOwn(workflow.on, "pull_request") ||
      (pullRequest !== null &&
       (typeof pullRequest !== "object" || Object.keys(pullRequest).length > 0))) {
    findings.push("CI must run for every pull request without event filters");
  }
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
    const scopedFilters = FILTERED_CASES.filter((filter) => filter.step === scope.step);
    selectedByStep.set(scope.step, commands);
    for (const command of commands) {
      if (command.selector === undefined) continue;
      for (const file of command.files) {
        if (!scopedFilters.some((filter) => filter.file === file)) {
          findings.push(scope.step + " cannot be filtered without mandatory case coverage: " + file);
        }
      }
    }
    for (const file of scope.files) {
      if (!commands.some((command) => command.files.includes(file))) {
        findings.push(scope.step + " must execute " + file);
      }
    }
  }

  const parsedFiles = new Map();
  for (const file of new Set(REQUIREMENTS.flatMap((scope) => scope.files))) {
    try {
      parsedFiles.set(file, collectCachedWindowsTestTitles(file, readTest(file)));
    } catch {
      parsedFiles.set(file, []);
      findings.push("Could not parse mandatory Vitest declarations: " + file);
    }
  }
  for (const scope of FILTERED_CASES) {
    const commands = (selectedByStep.get(scope.step) ?? [])
      .filter((command) => command.files.includes(scope.file));
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
