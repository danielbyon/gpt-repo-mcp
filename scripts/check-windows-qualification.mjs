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
  if (ts.isIdentifier(expression) && testRunnerOf(expression, names)) {
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

// Resolve only the names used by Windows predicates and Vitest registration.
function createWindowsTestBindingResolver(file) {
  const declaresName = (name, expected) => {
    if (ts.isIdentifier(name)) return name.text === expected;
    if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      return name.elements.some((element) =>
        ts.isBindingElement(element) && declaresName(element.name, expected));
    }
    return false;
  };
  const bindingsIn = (statements, name) => {
    const found = [];
    for (const statement of statements) {
      if (ts.isVariableStatement(statement)) {
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
      if ((ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement) ||
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
        const matches = bindingsIn(scope.statements, name);
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
  const recordAssignment = (target, value) => {
    const binding = resolveBinding(target);
    if (binding?.kind !== "variable") return;
    const assignments = assignmentsByBinding.get(binding.node) ?? [];
    assignments.push(value);
    assignmentsByBinding.set(binding.node, assignments);
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
  const vitestNamespaceOf = (input, seen = new Set()) => {
    const node = unwrap(input);
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
  if (!node || !ts.isIdentifier(node)) return false;
  const binding = resolveBinding(node);
  if (binding?.kind === "import") {
    return !binding.typeOnly && binding.module === "vitest" && binding.imported === "*";
  }
  if (binding?.kind !== "variable" || seen.has(binding.node)) return false;
  const next = new Set(seen);
  next.add(binding.node);
  const values = [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])];
  return values.some((value) => value && possibleVitestNamespaceOf(value, next));
};
const objectPropertyValueOf = (input, key, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return undefined;
  if (ts.isObjectLiteralExpression(node)) return sourcePropertyValue(node, key);
  if (!ts.isIdentifier(node)) return undefined;
  const binding = resolveBinding(node);
  if (binding?.kind !== "variable" || seen.has(binding.node)) return undefined;
  const next = new Set(seen);
  next.add(binding.node);
  const values = [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])];
  for (const value of values) {
    const property = value && objectPropertyValueOf(value, key, next);
    if (property) return property;
  }
  return undefined;
};
  const collectAssignments = (node) => {
    if (ts.isBinaryExpression(node) && aliasAssignmentKinds.has(node.operatorToken.kind)) {
      const target = unwrap(node.left);
      if (ts.isIdentifier(target)) recordAssignment(target, node.right);
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
    const source = unwrap(declaration.initializer);
    if (!source) return undefined;
  const patternSource = (pattern, value) => {
    value = unwrap(value);
    if (ts.isObjectBindingPattern(pattern)) {
      for (const element of pattern.elements) {
        if (!ts.isBindingElement(element) || element.dotDotDotToken) continue;
        const key = element.propertyName
          ? assignmentKey(element.propertyName)
          : ts.isIdentifier(element.name) ? element.name.text : undefined;
        if (ts.isIdentifier(element.name) && element.name.text === targetName) {
          if (key && names.includes(key) && vitestNamespaceOf(value)) return { runner: key };
          if (!key || !ts.isObjectLiteralExpression(value)) continue;
          const item = sourcePropertyValue(value, key);
          if (item) return { value: item };
        }
        if ((ts.isObjectBindingPattern(element.name) || ts.isArrayBindingPattern(element.name)) &&
            ts.isObjectLiteralExpression(value) && key !== undefined) {
          const item = sourcePropertyValue(value, key);
          const nested = item && patternSource(element.name, item);
          if (nested) return nested;
        }
      }
    }
    if (ts.isArrayBindingPattern(pattern) && ts.isArrayLiteralExpression(value)) {
      for (let index = 0; index < pattern.elements.length; index += 1) {
        const element = pattern.elements[index];
        if (!ts.isBindingElement(element) || element.dotDotDotToken || !value.elements[index]) continue;
        if (ts.isIdentifier(element.name) && element.name.text === targetName) {
          return { value: value.elements[index] };
        }
        if (ts.isObjectBindingPattern(element.name) || ts.isArrayBindingPattern(element.name)) {
          const nested = patternSource(element.name, value.elements[index]);
          if (nested) return nested;
        }
      }
    }
    return undefined;
  };
  return patternSource(declaration.name, source);
  };
  const possibleTestRunnerOf = (input, names, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return undefined;
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
  if (!ts.isIdentifier(node)) {
    const member = access(node);
    if (member && ["concurrent", "sequential"].includes(member.method)) {
      return possibleTestRunnerOf(member.receiver, names, seen);
    }
    if (member && names.includes(member.method) &&
        (vitestNamespaceOf(member.receiver) || possibleVitestNamespaceOf(member.receiver))) {
      return member.method;
    }
    const property = member && objectPropertyValueOf(member.receiver, member.method);
    if (property) return possibleTestRunnerOf(property, names, seen);
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
    if (binding?.kind === "variable" && runnerAssignmentsByBinding.has(binding.node)) {
      return runnerAssignmentsByBinding.get(binding.node);
    }
    if (binding?.kind === "opaque" && ts.isVariableDeclaration(binding.node) &&
        ts.isObjectBindingPattern(binding.node.name) && binding.node.initializer &&
        vitestNamespaceOf(binding.node.initializer)) {
      for (const element of binding.node.name.elements) {
        if (ts.isIdentifier(element.name) && element.name.text === node.text) {
          const imported = element.propertyName?.text ?? element.name.text;
          if (names.includes(imported)) return imported;
        }
      }
    }
    if (binding?.kind === "variable" && !seen.has(binding.node)) {
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
  return { isProcessPlatform, testRunnerOf, possibleTestRunnerOf };
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
  const { isProcessPlatform, testRunnerOf, possibleTestRunnerOf } =
    createWindowsTestBindingResolver(file);

  // Exclusive declarations anywhere in the file remain fail-closed, including
  // element access and unknown dynamic member selectors.
  const checkExclusive = (node) => {
    if (ts.isParameter(node) && node.initializer &&
        possibleTestRunnerOf(node.initializer, ["test", "it", "describe"])) {
      throw new Error("Exclusive or dynamically selected Vitest tests unaudited.");
    }
    const member = access(node);
    if (member && possibleTestRunnerOf(member.receiver, ["test", "it", "describe"]) &&
        (member.method === undefined || member.method === "only")) {
      throw new Error("Exclusive or dynamically selected Vitest tests are unaudited.");
    }
    if (ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isObjectLiteralExpression(unwrap(node.left)) &&
        possibleTestRunnerOf(node.right, ["test", "it", "describe"])) {
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
      }
    }
    if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name) &&
        node.initializer && possibleTestRunnerOf(node.initializer, ["test", "it", "describe"])) {
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
      const outcome = conditionOnWindows(node.expression, isProcessPlatform);
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
      const outcome = conditionOnWindows(node.condition, isProcessPlatform);
      register(node.whenTrue, disabled || outcome !== true);
      register(node.whenFalse, disabled || outcome !== false);
      return;
    }
    if (!ts.isCallExpression(node)) return;

    const suite = invocationKind(node.expression, ["describe"], isProcessPlatform, testRunnerOf);
    if (suite) {
      const callback = unwrap(node.arguments[1]);
      if (callback && (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback))) {
        register(callback.body, disabled || !suite.enabled);
      }
      // Unresolved suite callbacks are not proven to register tests.
      return;
    }
    const title = literal(node.arguments[0]);
    const call = invocationKind(node.expression, ["test", "it"], isProcessPlatform, testRunnerOf);
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
