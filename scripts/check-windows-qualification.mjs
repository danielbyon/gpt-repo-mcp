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
      ["concurrent", "sequential"].includes(member.method)) {
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
  const aliasAssignmentKinds = new Set([
    ts.SyntaxKind.EqualsToken,
    ts.SyntaxKind.QuestionQuestionEqualsToken,
    ts.SyntaxKind.BarBarEqualsToken,
    ts.SyntaxKind.AmpersandAmpersandEqualsToken
  ]);
  const assignmentsByBinding = new Map();
  const runnerAssignmentsByBinding = new Map();
  const destructuredAssignmentsByBinding = new Map();
const assignmentsByMemberPath = new Map();
const assignmentMemberAccess = (node) => {
  node = unwrap(node);
  if (ts.isPropertyAccessExpression(node)) {
    return { receiver: node.expression, property: node.name.text };
  }
  if (ts.isElementAccessExpression(node)) {
    const argument = unwrap(node.argumentExpression);
    if (ts.isStringLiteralLike(argument) || ts.isNoSubstitutionTemplateLiteral(argument)) {
      return { receiver: node.expression, property: argument.text };
    }
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
    if (ts.isComputedPropertyName(name) && ts.isStringLiteralLike(name.expression)) {
      return name.expression.text;
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
  const staticModuleNameOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return undefined;
    if (ts.isStringLiteralLike(node)) return node.text;
    if (ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = staticModuleNameOf(node.left, seen);
      const right = staticModuleNameOf(node.right, seen);
      return left !== undefined && right !== undefined ? left + right : undefined;
    }
    if (!ts.isIdentifier(node)) return undefined;
    const binding = resolveBinding(node);
    if (binding?.kind !== "variable" || !binding.constant ||
        !binding.node.initializer || seen.has(binding.node)) return undefined;
    const next = new Set(seen);
    next.add(binding.node);
    return staticModuleNameOf(binding.node.initializer, next);
  };
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
  if (objectAssignCall(node)) {
    return node.arguments.slice(1).flatMap((source) =>
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
    const member = access(node);
    return Boolean(member && member.method !== undefined &&
      objectPropertyValuesOf(member.receiver, member.method, seen).some((value) =>
        possibleVitestNamespaceOf(value, seen)));
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
  const values = [];
  for (const value of expressionValuesOf(input, seen)) {
    if (ts.isObjectLiteralExpression(value) || ts.isArrayLiteralExpression(value)) {
      values.push(value);
      continue;
    }
    const member = access(value);
    if (!member || member.method === undefined) continue;
    for (const candidate of objectPropertyValuesOf(member.receiver, member.method, seen)) {
      values.push(...containerValuesOf(candidate, seen));
    }
  }
  return values;
};
const objectPropertyValuesOf = (input, key, seen = new Set()) => {
  const values = [];
  for (const container of containerValuesOf(input, seen)) {
    if (ts.isObjectLiteralExpression(container)) {
      for (const property of container.properties) {
        if (ts.isSpreadAssignment(property)) {
          values.push(...objectPropertyValuesOf(property.expression, key, seen));
        } else if (assignmentKey(property.name) === key) {
          if (ts.isPropertyAssignment(property)) values.push(property.initializer);
          else if (ts.isShorthandPropertyAssignment(property)) values.push(property.name);
        }
      }
    } else if (ts.isArrayLiteralExpression(container) && /^\d+$/.test(key)) {
      const element = container.elements[Number(key)];
      if (element && !ts.isOmittedExpression(element) && !ts.isSpreadElement(element)) {
        values.push(element);
      }
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
const destructuredValuesOf = (declaration, targetName) => {
  if ((!ts.isVariableDeclaration(declaration) && !ts.isParameter(declaration)) ||
      !declaration.initializer) return [];
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
  visitPattern(declaration.name, declaration.initializer);
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
        if (["test", "it", "describe"].includes(key) &&
            possibleVitestNamespaceOf(source)) {
          const binding = resolveBinding(targetValue);
          if (binding?.kind === "variable") {
            runnerAssignmentsByBinding.set(binding.node, key);
            continue;
          }
        }
        if (["concurrent", "sequential"].includes(key)) {
          const runner = testRunnerOf(source, ["test", "it", "describe"]);
          const binding = resolveBinding(targetValue);
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
collectResolvedAssignments(file);
  function globalObjectOf(input, seen = new Set()) {
    const node = unwrap(input);
    if (!node) return false;
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (!binding) return node.text === "Object";
      if (binding.kind !== "variable" || !binding.constant ||
          !binding.node.initializer || seen.has(binding.node)) return false;
      const next = new Set(seen);
      next.add(binding.node);
      return globalObjectOf(binding.node.initializer, next);
    }
    const member = access(node);
    return Boolean(member?.method === "Object" && globalObjectOf(member.receiver, seen));
  }
  function globalIntrinsicOf(input, names, seen = new Set()) {
    const node = unwrap(input);
    if (!node) return false;
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (!binding) return names.includes(node.text);
      if (binding.kind !== "variable" || !binding.constant ||
          !binding.node.initializer || seen.has(binding.node)) return false;
      const next = new Set(seen);
      next.add(binding.node);
      return globalIntrinsicOf(binding.node.initializer, names, next);
    }
    const member = access(node);
    return Boolean(member && names.includes(member.method) &&
      globalObjectOf(member.receiver, seen));
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
      const declaration = binding &&
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
          !binding.node.initializer || seen.has(binding.node)) return false;
      const next = new Set(seen);
      next.add(binding.node);
      return objectAssignReference(binding.node.initializer, next);
    }
    const member = access(node);
    const receiver = member && unwrap(member.receiver);
    return member?.method === "assign" && globalObjectOf(receiver, seen);
  }
  function objectAssignCall(node) {
    return ts.isCallExpression(node) && objectAssignReference(node.expression);
  }
  const collectAssignments = (node) => {
    if (objectAssignCall(node)) {
      const [target, ...sources] = node.arguments;
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
  collectAssignments(file);
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
    const member = access(unwrap(node));
    return member?.method === "platform" && processObjectOf(member.receiver);
  };
  const testRunnerOf = (input, names, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return undefined;
    if (!ts.isIdentifier(node)) {
      const member = access(node);
      if (member && ["concurrent", "sequential"].includes(member.method)) {
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
          if (key && ["concurrent", "sequential"].includes(key)) {
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
const functionReturnExpressionsOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return [];
  if (ts.isArrowFunction(node)) {
    if (!ts.isBlock(node.body)) return [node.body];
  }
  if (ts.isFunctionExpression(node) || ts.isFunctionDeclaration(node) ||
      ts.isArrowFunction(node)) {
    const values = [];
    const visit = (child) => {
      if (ts.isFunctionLike(child) && child !== node) return;
      if (ts.isReturnStatement(child) && child.expression) values.push(child.expression);
      ts.forEachChild(child, visit);
    };
    if (node.body) visit(node.body);
    return values;
  }
  if (!ts.isIdentifier(node)) return [];
  const binding = resolveBinding(node);
  if (!binding || seen.has(binding.node)) return [];
  const next = new Set(seen);
  next.add(binding.node);
  if (ts.isFunctionDeclaration(binding.node) || ts.isFunctionExpression(binding.node) ||
      ts.isArrowFunction(binding.node)) {
    return functionReturnExpressionsOf(binding.node, next);
  }
  if (binding.kind === "variable" && ts.isVariableDeclaration(binding.node) &&
      ts.isIdentifier(binding.node.name) && binding.node.initializer) {
    return functionReturnExpressionsOf(binding.node.initializer, next);
  }
  return [];
};
  const possibleTestRunnerOf = (input, names, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return undefined;
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
    const decorator = access(node.expression);
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
    const member = access(node);
    if (member && ["concurrent", "sequential"].includes(member.method)) {
      return possibleTestRunnerOf(member.receiver, names, seen);
    }
    if (member && names.includes(member.method) &&
        (vitestNamespaceOf(member.receiver) || possibleVitestNamespaceOf(member.receiver))) {
      return member.method;
    }
    if (member) {
      for (const property of objectPropertyValuesOf(member.receiver, member.method)) {
        const candidate = possibleTestRunnerOf(property, names, seen);
        if (candidate) return candidate;
      }
    }
const stored = assignmentsByMemberPath.get(assignmentReferenceKey(node)) ?? [];
for (const value of stored) {
const candidate = possibleTestRunnerOf(value, names, seen);
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
      ts.isIdentifier(binding.node.name) && !seen.has(binding.node)) {
    const next = new Set(seen);
    next.add(binding.node);
    for (const value of assignmentsByBinding.get(binding.node) ?? []) {
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
  };
  const testRunnerContainerOf = (input, names, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
    if (possibleTestRunnerOf(node, names, seen)) return true;
    if (globalIntrinsicOf(node, ["Proxy"])) return true;
    if (!ts.isCallExpression(node)) return false;
    if (globalIntrinsicOf(node.expression, ["Proxy"])) {
      return Boolean(node.arguments[0]) &&
        testRunnerContainerOf(node.arguments[0], names, seen);
    }
    const factory = access(unwrap(node.expression));
    if (!factory) return false;
    if (factory.method === "get" &&
        globalIntrinsicOf(factory.receiver, ["Reflect"])) {
      const property = literal(node.arguments[1]);
      if (property === undefined) {
        return possibleTestRunnerOf(node.arguments[0], names, seen) ||
          possibleVitestNamespaceOf(node.arguments[0]);
      }
      if (property === "only") {
        return possibleTestRunnerOf(node.arguments[0], names, seen);
      }
      return names.includes(property) &&
        possibleVitestNamespaceOf(node.arguments[0]);
    }
    if (factory.method === "assign" &&
        globalIntrinsicOf(factory.receiver, ["Object"])) {
      return node.arguments.some((argument) =>
        testRunnerContainerOf(argument, names, seen));
    }
    if (factory.method === "create" &&
        globalIntrinsicOf(factory.receiver, ["Object"])) {
      return Boolean(node.arguments[0]) &&
        testRunnerContainerOf(node.arguments[0], names, seen);
    }
    return false;
  };
  return { isProcessPlatform, testRunnerOf, possibleTestRunnerOf,
    possibleVitestNamespaceOf, testRunnerContainerOf, globalIntrinsicOf,
    resolveBinding };
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
    possibleVitestNamespaceOf, testRunnerContainerOf, globalIntrinsicOf,
    resolveBinding } =
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
    const member = access(node);
    if (member && testRunnerContainerOf(member.receiver, ["test", "it", "describe"]) &&
        (member.method === undefined || member.method === "only")) {
      throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
    }
    if (ts.isCallExpression(node)) {
      const reflective = access(unwrap(node.expression));
      if (reflective?.method === "get" &&
          globalIntrinsicOf(reflective.receiver, ["Reflect"])) {
        const property = literal(node.arguments[1]);
        const runner = possibleTestRunnerOf(
          node.arguments[0], ["test", "it", "describe"]);
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
