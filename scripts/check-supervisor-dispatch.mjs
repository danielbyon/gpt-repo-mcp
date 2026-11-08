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
const MODULE_LOADING_MODULES = new Set(["node:module", "module"]);
const SHELL_MODULES = new Set(["cross-spawn", "shelljs", "execa"]);
const SAFE_PROCESS_EXPORTS = new Set(["spawn", "spawnSync", "execFile", "execFileSync"]);
const DISALLOWED_PROGRAMS = /(?:^|[\\/])(?:cmd|command|powershell|pwsh|bash|sh|zsh)(?:\.exe)?$/i;
const DISALLOWED_SHIMS = /\.(?:cmd|bat|ps1|psm1|sh)$/i;

const moduleLiteral = (node) => node && ts.isStringLiteralLike(node) ? node.text : undefined;
const nameOf = (node) => ts.isIdentifier(node) ? node.text : undefined;
const callName = (node) => nameOf(node) ||
  (ts.isPropertyAccessExpression(node) ? node.name.text : undefined);
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
  let launcherCount = 0;

  const add = (node, message) => {
    const pos = file.getLineAndCharacterOfPosition(node.getStart(file));
    findings.push(filename + ":" + (pos.line + 1) + ": " + message);
  };
  if (file.parseDiagnostics.length > 0) {
    return [filename + ": source cannot be parsed for process-execution inspection"];
  }

  const processBinding = (exported, node) => {
    if (!SAFE_PROCESS_EXPORTS.has(exported)) {
      add(node, "unaudited child_process export: " + exported);
    }
  };

  const inspectRequire = (node) => {
    if (!ts.isCallExpression(node) || !requireReferenceOf(node.expression)) return;
    if (node.arguments.length !== 1 || !moduleLiteral(node.arguments[0])) {
      add(node, "dynamic require is forbidden in supervisor source");
      return;
    }
    const module = moduleLiteral(node.arguments[0]);
    if (SHELL_MODULES.has(module)) {
      add(node, "shell-capable runner imports are forbidden");
    } else if (MODULE_LOADING_MODULES.has(module)) {
      add(node, "node:module loading is forbidden in supervisor source");
    } else if (PROCESS_MODULES.has(module)) {
      const declaration = node.parent;
      if (!ts.isVariableDeclaration(declaration) || declaration.initializer !== node ||
          !ts.isObjectBindingPattern(declaration.name)) {
        add(node, "child_process require must destructure audited named exports");
        return;
      }
      if (!(declaration.parent.flags & ts.NodeFlags.Const)) {
        add(declaration, "child_process require bindings must be immutable");
      }
      const statement = declaration.parent.parent;
      if (ts.isVariableStatement(statement) && (statement.modifiers ?? []).some(
        (modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) {
        add(declaration, "exported child_process require bindings are forbidden");
      }
      for (const element of declaration.name.elements) {
        if (element.initializer || element.dotDotDotToken ||
            !ts.isIdentifier(element.name)) {
          add(element, "unsupported child_process destructuring binding");
        }
        const exported = element.propertyName?.getText(file) ?? element.name.getText(file);
        processBinding(exported, element);
      }
    }
  };

  const unwrap = (node) => {
    while (node && (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) ||
           ts.isTypeAssertionExpression(node) || ts.isSatisfiesExpression(node) ||
           ts.isNonNullExpression(node))) node = node.expression;
    return node;
  };
  const requireReferenceOf = (input) => {
    const node = unwrap(input);
    if (!node) return false;
    if (ts.isIdentifier(node)) return node.text === "require" && !resolveBinding(node);
    if (!ts.isBinaryExpression(node)) return false;
    const operator = node.operatorToken.kind;
    if (operator === ts.SyntaxKind.CommaToken) {
      return requireReferenceOf(node.right);
    }
    if (operator === ts.SyntaxKind.AmpersandAmpersandToken ||
        operator === ts.SyntaxKind.BarBarToken ||
        operator === ts.SyntaxKind.QuestionQuestionToken) {
      return requireReferenceOf(node.left) || requireReferenceOf(node.right);
    }
    return false;
  };
  const hasRuntimeImport = (node) => {
    const clause = node.importClause;
    if (!clause) return true;
    if (clause.isTypeOnly) return false;
    if (clause.name) return true;
    const bindings = clause.namedBindings;
    if (ts.isNamespaceImport(bindings)) return true;
    return !bindings || bindings.elements.length === 0 ||
      bindings.elements.some((element) => !element.isTypeOnly);
  };
  const isCallback = (node) => ts.isFunctionExpression(node) || ts.isArrowFunction(node);

  // A second argument must be provably an argv array: Node treats a non-array
  // object there as its options, even when a third argument is supplied.
  const declaresName = (name, text) => {
    if (ts.isIdentifier(name)) return name.text === text;
    if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      return name.elements.some((part) =>
        ts.isBindingElement(part) && declaresName(part.name, text));
    }
    return false;
  };

  // Resolve a reference through enclosing lexical scopes, not through a file-
  // wide name table. An unknown or ambiguous binding is never argv evidence.
  const resolveBinding = (reference) => {
    const text = reference.text;
const declarations = (statements = []) => {
      const found = [];
      for (const statement of statements) {
        if (ts.isVariableStatement(statement)) {
          for (const declaration of statement.declarationList.declarations) {
            if (declaresName(declaration.name, text)) {
              found.push({
                kind: ts.isIdentifier(declaration.name) ? "variable" : "opaque",
                node: declaration,
                constant: !!(statement.declarationList.flags & ts.NodeFlags.Const)
              });
            }
          }
        }
        if ((ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) &&
            statement.name?.text === text) {
          found.push({ kind: "opaque", node: statement });
        }
        if (ts.isImportDeclaration(statement) && statement.importClause) {
          const imports = statement.importClause;
          if (imports.name?.text === text ||
              (imports.namedBindings && ts.isNamespaceImport(imports.namedBindings) &&
               imports.namedBindings.name.text === text) ||
              (imports.namedBindings && ts.isNamedImports(imports.namedBindings) &&
               imports.namedBindings.elements.some((element) => element.name.text === text))) {
            found.push({ kind: "import", node: statement, module: moduleLiteral(statement.moduleSpecifier) });
          }
        }
      }
      return found;
    };

    // Nested var declarations belong to their nearest function, module, or file scope.
    // Keep those names opaque so they cannot fall through to ambient runner names.
    const hasHoistedVar = (scope, name) => {
      let found = false;
      const visit = (node) => {
        if (found || (node !== scope && (
          ts.isFunctionLike(node) || ts.isModuleDeclaration(node) ||
          ts.isClassStaticBlockDeclaration(node)
        ))) return;
        if (ts.isVariableDeclaration(node) &&
            ts.isVariableDeclarationList(node.parent) &&
            !(node.parent.flags & (ts.NodeFlags.Const | ts.NodeFlags.Let)) &&
            declaresName(node.name, name)) {
          found = true;
          return;
        }
        ts.forEachChild(node, visit);
      };
      const root = ts.isFunctionLike(scope) ? scope.body : scope;
      if (root) visit(root);
      return found;
    };

    for (let scope = reference.parent; scope; scope = scope.parent) {
      if (ts.isBlock(scope) || ts.isSourceFile(scope) ||
          ts.isModuleBlock(scope) || ts.isCaseBlock(scope)) {
const scopeStatements = ts.isCaseBlock(scope)
? scope.clauses.flatMap((clause) => clause.statements)
: scope.statements;
const matches = declarations(scopeStatements);
        if (matches.length) {
          return matches.length === 1 ? matches[0] : { kind: "ambiguous" };
        }
      }
      if (ts.isCatchClause(scope) &&
          scope.variableDeclaration && declaresName(scope.variableDeclaration.name, text)) {
        return { kind: "opaque", node: scope.variableDeclaration };
      }
      if (ts.isForStatement(scope) || ts.isForOfStatement(scope) ||
          ts.isForInStatement(scope)) {
        const initializer = scope.initializer;
        if (initializer && ts.isVariableDeclarationList(initializer) &&
            initializer.declarations.some((declaration) => declaresName(declaration.name, text))) {
          return { kind: "opaque", node: initializer };
        }
      }
      if (ts.isFunctionLike(scope)) {
        if (hasHoistedVar(scope, text)) return { kind: "opaque", node: scope };
        const matches = scope.parameters.filter((parameter) =>
          declaresName(parameter.name, text));
        if (matches.length) return matches.length === 1
          ? { kind: "parameter", node: matches[0] }
          : { kind: "ambiguous" };
        if (scope.name && ts.isIdentifier(scope.name) && scope.name.text === text) {
          return { kind: "opaque", node: scope };
        }
      }
      if ((ts.isSourceFile(scope) || ts.isModuleBlock(scope)) &&
          hasHoistedVar(scope, text)) {
        return { kind: "opaque", node: scope };
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
  const assignmentPropertyName = (name) => {
    if (!name) return undefined;
    if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) {
      return name.text;
    }
    if (ts.isComputedPropertyName(name) && ts.isStringLiteralLike(name.expression)) {
      return name.expression.text;
    }
    return undefined;
  };
  const recordAssignment = (target, value) => {
    if (!ts.isIdentifier(target)) return;
    const binding = resolveBinding(target);
    if (binding?.kind !== "variable") return;
    const assignments = assignmentsByBinding.get(binding.node) ?? [];
    assignments.push(value);
    assignmentsByBinding.set(binding.node, assignments);
  };
  const collectAssignments = (node) => {
    if (ts.isBinaryExpression(node) &&
        aliasAssignmentKinds.has(node.operatorToken.kind)) {
      const target = unwrap(node.left);
      if (ts.isIdentifier(target)) {
        recordAssignment(target, node.right);
      } else if (ts.isObjectLiteralExpression(target) &&
                 ts.isObjectLiteralExpression(unwrap(node.right))) {
        const source = unwrap(node.right);
        for (const property of target.properties) {
          const key = ts.isShorthandPropertyAssignment(property)
            ? property.name.text
            : ts.isPropertyAssignment(property)
              ? assignmentPropertyName(property.name)
              : undefined;
          const targetName = ts.isShorthandPropertyAssignment(property)
            ? property.name
            : ts.isPropertyAssignment(property) && ts.isIdentifier(property.initializer)
              ? property.initializer
              : undefined;
          const sourceProperty = key === undefined ? undefined : source.properties.find((item) =>
            assignmentPropertyName(item.name) === key);
          const value = sourceProperty && ts.isPropertyAssignment(sourceProperty)
            ? sourceProperty.initializer
            : sourceProperty && ts.isShorthandPropertyAssignment(sourceProperty)
              ? sourceProperty.name
              : undefined;
          if (targetName && value) recordAssignment(targetName, value);
        }
      }
    }
    ts.forEachChild(node, collectAssignments);
  };
  collectAssignments(file);

  const enclosingFunction = (node, expected) => {
    for (let parent = node.parent; parent; parent = parent.parent) {
      if (ts.isFunctionDeclaration(parent)) {
        return parent.name?.text === expected ? parent : undefined;
      }
    }
    return undefined;
  };
  const stringArrayMember = (type, field) => {
    if (!type) return false;
    if (ts.isIntersectionTypeNode(type)) {
      return type.types.some((member) => stringArrayMember(member, field));
    }
    return ts.isTypeLiteralNode(type) && type.members.some((member) =>
      ts.isPropertySignature(member) && member.name?.getText(file) === field &&
      member.type && ts.isArrayTypeNode(member.type) &&
      member.type.elementType.kind === ts.SyntaxKind.StringKeyword);
  };
  const sourceContractArray = (node) => {
    const field = node.getText(file).replace(/\s+/g, "");
    if (filename === "src/services/process-exec.ts" && field === "input.args") {
      const owner = enclosingFunction(node, "runProcessWithTail");
      const parameter = owner?.parameters.find((item) => nameOf(item.name) === "input");
      return !!parameter && ts.isIdentifier(node.expression) &&
        resolveBinding(node.expression)?.node === parameter &&
        stringArrayMember(parameter.type, "args");
    }
    if (filename === "src/services/windows-process-host.ts" && field === "launch?.args") {
      const owner = enclosingFunction(node, "runWindowsProcessWithTail");
      const parameter = owner?.parameters.find((item) => nameOf(item.name) === "launch");
      const alias = file.statements.find((item) => ts.isTypeAliasDeclaration(item) &&
        item.name.text === "WindowsProcessHostLaunch");
      return !!parameter?.type && ts.isIdentifier(node.expression) &&
        resolveBinding(node.expression)?.node === parameter &&
        ts.isTypeReferenceNode(parameter.type) &&
        parameter.type.typeName.getText(file) === "WindowsProcessHostLaunch" &&
        !!alias && stringArrayMember(alias.type, "args");
    }
    return false;
  };
  const provenArrayProducer = (node) => {
    const target = node.expression.getText(file).replace(/\s+/g, "");
    if (target === "process.argv.slice") {
      const argvAccess = node.expression.expression;
      const processIdentifier = ts.isPropertyAccessExpression(argvAccess)
        ? argvAccess.expression : undefined;
      if (!processIdentifier || !ts.isIdentifier(processIdentifier)) return false;
      const binding = resolveBinding(processIdentifier);
      return !binding || (binding.kind === "import" && binding.module === "node:process");
    }
    if (filename !== "src/services/windows-process-host.ts" ||
        target !== "windowsHostArgs" ||
        !enclosingFunction(node, "runWindowsProcessWithTail")) return false;
    const producer = file.statements.find((item) => ts.isFunctionDeclaration(item) &&
      item.name?.text === "windowsHostArgs");
    if (!producer?.body || !producer.type || !ts.isArrayTypeNode(producer.type) ||
        producer.type.elementType.kind !== ts.SyntaxKind.StringKeyword ||
        !ts.isIdentifier(node.expression) ||
        resolveBinding(node.expression)?.node !== producer) return false;
    const returns = [];
    const inspectReturns = (child) => {
      if (child !== producer.body && ts.isFunctionLike(child)) return;
      if (ts.isReturnStatement(child)) returns.push(unwrap(child.expression));
      ts.forEachChild(child, inspectReturns);
    };
    inspectReturns(producer.body);
    return returns.length > 0 && returns.every((result) =>
      result && ts.isArrayLiteralExpression(result));
  };

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
    if (ts.isPropertyAccessExpression(node)) return sourceContractArray(node);
    if (ts.isCallExpression(node)) return provenArrayProducer(node);
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (binding?.kind === "variable" && binding.constant &&
          binding.node.initializer && !seen.has(binding.node)) {
        const next = new Set(seen);
        next.add(binding.node);
        return isArrayArguments(binding.node.initializer, next);
      }
    }
    return false;
  };

  // Keep literal executable checks effective across immutable local aliases.
  const staticStringOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return undefined;
    if (ts.isStringLiteralLike(node)) return node.text;
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = staticStringOf(node.left, seen);
      const right = staticStringOf(node.right, seen);
      return left !== undefined && right !== undefined ? left + right : undefined;
    }
    if (!ts.isIdentifier(node)) return undefined;
    const binding = resolveBinding(node);
    if (binding?.kind !== "variable" || !binding.constant ||
        !binding.node.initializer || seen.has(binding.node)) return undefined;
    const next = new Set(seen);
    next.add(binding.node);
    return staticStringOf(binding.node.initializer, next);
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

  // Bounded runner provenance: immutable imports/aliases and one proven
  // node:util promisify(execFile) adapter. All other references fail closed.
  const importedExport = (binding, localName) => {
    if (binding?.kind !== "import") return undefined;
    const named = binding.node.importClause?.namedBindings;
    if (!named || !ts.isNamedImports(named)) return undefined;
    const item = named.elements.find((element) =>
      element.name.text === localName && !element.isTypeOnly);
    return item?.propertyName?.text ?? item?.name.text;
  };
  const immutableAlias = (declaration) => {
    if (!declaration || !ts.isVariableDeclaration(declaration) ||
        !ts.isIdentifier(declaration.name) ||
        !ts.isVariableDeclarationList(declaration.parent) ||
        !(declaration.parent.flags & ts.NodeFlags.Const)) return false;
    const statement = declaration.parent.parent;
    return !ts.isVariableStatement(statement) ||
      !(statement.modifiers ?? []).some((modifier) =>
        modifier.kind === ts.SyntaxKind.ExportKeyword);
  };
  const memberAccess = (node) => {
    if (ts.isPropertyAccessExpression(node)) {
      return { receiver: node.expression, property: node.name.text };
    }
    if (ts.isElementAccessExpression(node)) {
      const property = staticStringOf(unwrap(node.argumentExpression));
      if (property !== undefined) return { receiver: node.expression, property };
    }
    return undefined;
  };
  const processModuleRequire = (node) => {
    if (!node || !ts.isCallExpression(node) ||
        !ts.isIdentifier(unwrap(node.expression)) ||
        unwrap(node.expression).text !== "require" || resolveBinding(unwrap(node.expression)) ||
        node.arguments.length !== 1) return false;
    return ["node:process", "process"].includes(moduleLiteral(node.arguments[0]));
  };
  const resolvedValuesOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return [];
    if (ts.isConditionalExpression(node)) {
      return [
        ...resolvedValuesOf(node.whenTrue, seen),
        ...resolvedValuesOf(node.whenFalse, seen)
      ];
    }
    if (ts.isBinaryExpression(node)) {
      const operator = node.operatorToken.kind;
      if (operator === ts.SyntaxKind.CommaToken) {
        return resolvedValuesOf(node.right, seen);
      }
      if (operator === ts.SyntaxKind.AmpersandAmpersandToken ||
          operator === ts.SyntaxKind.BarBarToken ||
          operator === ts.SyntaxKind.QuestionQuestionToken) {
        return [
          ...resolvedValuesOf(node.left, seen),
          ...resolvedValuesOf(node.right, seen)
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
        .flatMap((value) => resolvedValuesOf(value, next));
    }
    if (binding.kind === "parameter" &&
        ts.isParameter(binding.node) &&
        ts.isIdentifier(binding.node.name) &&
        binding.node.initializer) {
      return resolvedValuesOf(binding.node.initializer, next);
    }
    return [node];
  };
  const objectValueCandidatesOf = (input, seen = new Set()) => {
    const objects = [];
    for (const value of resolvedValuesOf(input, seen)) {
      if (ts.isObjectLiteralExpression(value)) {
        objects.push(value);
        continue;
      }
      const member = memberAccess(value);
      if (!member) continue;
      for (const candidate of memberValueCandidatesOf(
        member.receiver,
        member.property,
        seen
      )) {
        objects.push(...objectValueCandidatesOf(candidate, seen));
      }
    }
    return objects;
  };
  const memberValueCandidatesOf = (input, property, seen = new Set()) => {
    const values = [];
    for (const object of objectValueCandidatesOf(input, seen)) {
      for (const candidate of object.properties) {
        if (ts.isSpreadAssignment(candidate)) {
          values.push(...memberValueCandidatesOf(candidate.expression, property, seen));
          continue;
        }
        if (!("name" in candidate)) continue;
        const name = launchOptionName(candidate.name);
        if (name !== property) continue;
        if (ts.isPropertyAssignment(candidate)) values.push(candidate.initializer);
        if (ts.isShorthandPropertyAssignment(candidate)) values.push(candidate.name);
      }
    }
    for (const value of resolvedValuesOf(input, seen)) {
      if (!ts.isArrayLiteralExpression(value) || !/^\d+$/.test(property)) continue;
      const indexed = value.elements[Number(property)];
      if (indexed && !ts.isOmittedExpression(indexed) && !ts.isSpreadElement(indexed)) {
        values.push(indexed);
      }
    }
    return values;
  };
  const bindingPatternValuesOf = (pattern, source, targetName, seen = new Set()) => {
    const values = [];
    if (ts.isObjectBindingPattern(pattern)) {
      for (const element of pattern.elements) {
        const key = element.propertyName
          ? launchOptionName(element.propertyName)
          : ts.isIdentifier(element.name) ? element.name.text : undefined;
        if (element.dotDotDotToken) {
          if (ts.isIdentifier(element.name) && element.name.text === targetName) {
            values.push(source);
          }
          continue;
        }
        const selected = key === undefined ? [] : memberValueCandidatesOf(source, key, seen);
        const candidates = selected.length > 0
          ? selected
          : element.initializer ? [element.initializer] : [];
        if (ts.isIdentifier(element.name) && element.name.text === targetName) {
          values.push(...candidates);
        } else if (ts.isObjectBindingPattern(element.name) ||
                   ts.isArrayBindingPattern(element.name)) {
          for (const candidate of candidates) {
            values.push(...bindingPatternValuesOf(element.name, candidate, targetName, seen));
          }
        }
      }
      return values;
    }
    if (ts.isArrayBindingPattern(pattern)) {
      for (let index = 0; index < pattern.elements.length; index += 1) {
        const element = pattern.elements[index];
        if (ts.isOmittedExpression(element)) continue;
        if (element.dotDotDotToken) {
          if (ts.isIdentifier(element.name) && element.name.text === targetName) {
            values.push(source);
          }
          continue;
        }
        const selected = memberValueCandidatesOf(source, String(index), seen);
        const candidates = selected.length > 0
          ? selected
          : element.initializer ? [element.initializer] : [];
        if (ts.isIdentifier(element.name) && element.name.text === targetName) {
          values.push(...candidates);
        } else if (ts.isObjectBindingPattern(element.name) ||
                   ts.isArrayBindingPattern(element.name)) {
          for (const candidate of candidates) {
            values.push(...bindingPatternValuesOf(element.name, candidate, targetName, seen));
          }
        }
      }
    }
    return values;
  };
  const bindingDefaultMatches = (pattern, predicate) => {
    if (!ts.isObjectBindingPattern(pattern) && !ts.isArrayBindingPattern(pattern)) {
      return false;
    }
    return pattern.elements.some((element) => {
      if (!ts.isBindingElement(element)) return false;
      if (element.initializer && predicate(element.initializer)) return true;
      return bindingDefaultMatches(element.name, predicate);
    });
  };
  // Follow local aliases and object spreads that preserve process capabilities.
  const processObjectOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
  if (ts.isConditionalExpression(node)) {
    return processObjectOf(node.whenTrue, seen) || processObjectOf(node.whenFalse, seen);
  }
    if (ts.isBinaryExpression(node) && [
    ts.SyntaxKind.CommaToken,
      ts.SyntaxKind.AmpersandAmpersandToken,
      ts.SyntaxKind.BarBarToken,
      ts.SyntaxKind.QuestionQuestionToken
    ].includes(node.operatorToken.kind)) {
      return processObjectOf(node.left, seen) || processObjectOf(node.right, seen);
    }
    if (ts.isCallExpression(node)) return processModuleRequire(node);
    if (ts.isObjectLiteralExpression(node)) {
    return node.properties.some((property) => {
      if (ts.isSpreadAssignment(property)) return processObjectOf(property.expression, seen);
      if (ts.isPropertyAssignment(property)) return processObjectOf(property.initializer, seen);
      if (ts.isShorthandPropertyAssignment(property)) return processObjectOf(property.name, seen);
      return false;
    });
    }
    if (!ts.isIdentifier(node)) {
      const member = memberAccess(node);
      if (member?.property === "process") return globalObjectOf(member.receiver);
    if (member && memberValueCandidatesOf(member.receiver, member.property, seen)
      .some((value) => processObjectOf(value, seen))) return true;
      return member?.property === "default" && processObjectOf(member.receiver, seen);
    }
    const binding = resolveBinding(node);
    if (!binding) return node.text === "process";
    if (binding.kind === "import" && ["node:process", "process"].includes(binding.module)) {
      const clause = binding.node.importClause;
      const named = clause?.namedBindings;
      return clause?.name?.text === node.text ||
        (named && ts.isNamespaceImport(named) && named.name.text === node.text) ||
        (named && ts.isNamedImports(named) && named.elements.some((element) =>
          element.name.text === node.text && !element.isTypeOnly &&
          (element.propertyName?.text ?? element.name.text) === "default"));
    }
  if (seen.has(binding.node)) return false;
  const next = new Set(seen);
  next.add(binding.node);
  if ((binding.kind === "variable" || binding.kind === "opaque") &&
      ts.isVariableDeclaration(binding.node)) {
    if (ts.isIdentifier(binding.node.name)) {
      const candidates = [binding.node.initializer,
        ...(assignmentsByBinding.get(binding.node) ?? [])];
      return candidates.some((candidate) => candidate && processObjectOf(candidate, next));
    }
    if (binding.node.initializer &&
        (ts.isObjectBindingPattern(binding.node.name) ||
         ts.isArrayBindingPattern(binding.node.name))) {
      return bindingPatternValuesOf(
        binding.node.name,
        binding.node.initializer,
        node.text,
        next
      ).some((value) => processObjectOf(value, next));
    }
  }
  if (binding.kind === "parameter" && ts.isParameter(binding.node)) {
    if (ts.isIdentifier(binding.node.name)) {
      return Boolean(binding.node.initializer &&
        processObjectOf(binding.node.initializer, next));
    }
    if (binding.node.initializer &&
        (ts.isObjectBindingPattern(binding.node.name) ||
         ts.isArrayBindingPattern(binding.node.name))) {
      return bindingPatternValuesOf(
        binding.node.name,
        binding.node.initializer,
        node.text,
        next
      ).some((value) => processObjectOf(value, next));
    }
  }
  return false;
  };
  const globalObjectOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
  if (ts.isConditionalExpression(node)) {
    return globalObjectOf(node.whenTrue, seen) || globalObjectOf(node.whenFalse, seen);
  }
    if (ts.isBinaryExpression(node) && [
    ts.SyntaxKind.CommaToken,
      ts.SyntaxKind.AmpersandAmpersandToken,
      ts.SyntaxKind.BarBarToken,
      ts.SyntaxKind.QuestionQuestionToken
    ].includes(node.operatorToken.kind)) {
      return globalObjectOf(node.left, seen) || globalObjectOf(node.right, seen);
    }
    const member = memberAccess(node);
    if (member?.property === "globalThis" || member?.property === "global") {
      return globalObjectOf(member.receiver, seen);
    }
  if (member && memberValueCandidatesOf(member.receiver, member.property, seen)
    .some((value) => globalObjectOf(value, seen))) return true;
  if (ts.isObjectLiteralExpression(node)) {
    return node.properties.some((property) => {
      if (ts.isSpreadAssignment(property)) return globalObjectOf(property.expression, seen);
      if (ts.isPropertyAssignment(property)) return globalObjectOf(property.initializer, seen);
      if (ts.isShorthandPropertyAssignment(property)) return globalObjectOf(property.name, seen);
      return false;
    });
  }
    if (!ts.isIdentifier(node)) return false;
    const binding = resolveBinding(node);
    if (!binding) return node.text === "globalThis" || node.text === "global";
  if (seen.has(binding.node)) return false;
    const next = new Set(seen);
    next.add(binding.node);
  if ((binding.kind === "variable" || binding.kind === "opaque") &&
      ts.isVariableDeclaration(binding.node)) {
    if (ts.isIdentifier(binding.node.name)) {
      const candidates = [binding.node.initializer,
        ...(assignmentsByBinding.get(binding.node) ?? [])];
      return candidates.some((candidate) => candidate && globalObjectOf(candidate, next));
    }
    if (binding.node.initializer &&
        (ts.isObjectBindingPattern(binding.node.name) ||
         ts.isArrayBindingPattern(binding.node.name))) {
      return bindingPatternValuesOf(
        binding.node.name,
        binding.node.initializer,
        node.text,
        next
      ).some((value) => globalObjectOf(value, next));
    }
  }
  if (binding.kind === "parameter" && ts.isParameter(binding.node)) {
    if (ts.isIdentifier(binding.node.name)) {
      return Boolean(binding.node.initializer &&
        globalObjectOf(binding.node.initializer, next));
    }
    if (binding.node.initializer &&
        (ts.isObjectBindingPattern(binding.node.name) ||
         ts.isArrayBindingPattern(binding.node.name))) {
      return bindingPatternValuesOf(
        binding.node.name,
        binding.node.initializer,
        node.text,
        next
      ).some((value) => globalObjectOf(value, next));
    }
  }
  return false;
  };
  const destructuringEntries = (target) => {
    if (ts.isObjectBindingPattern(target)) {
      return target.elements.map((element) => ({
        name: element.propertyName ?? element.name,
        node: element,
        rest: Boolean(element.dotDotDotToken)
      }));
    }
    return target.properties.map((property) => {
      if (ts.isPropertyAssignment(property)) {
        return { name: property.name, node: property, rest: false };
      }
      if (ts.isShorthandPropertyAssignment(property)) {
        return { name: property.name, node: property, rest: false };
      }
      return { name: undefined, node: property, rest: true };
    });
  };
  const destructuringSourceValues = (target, source) => {
    const result = [];
  for (const values of resolvedValuesOf(source)) {
  if ((ts.isObjectBindingPattern(target) || ts.isObjectLiteralExpression(target)) &&
      ts.isObjectLiteralExpression(values)) {
      for (const entry of destructuringEntries(target)) {
        if (entry.rest) {
          for (const property of values.properties) {
            if (ts.isPropertyAssignment(property)) result.push(property.initializer);
            else if (ts.isShorthandPropertyAssignment(property)) result.push(property.name);
          }
          continue;
        }
        const key = entry.name ? launchOptionName(entry.name) : undefined;
        if (key === undefined) continue;
        const property = values.properties.find((item) =>
          assignmentPropertyName(item.name) === key);
        if (property && ts.isPropertyAssignment(property)) result.push(property.initializer);
        else if (property && ts.isShorthandPropertyAssignment(property)) result.push(property.name);
      }
    continue;
    }
  if (!ts.isArrayLiteralExpression(values)) continue;
    const { elements: targets } = target;
    for (let index = 0; index < targets.length; index += 1) {
      const element = targets[index];
      const rest = ts.isBindingElement(element)
        ? Boolean(element.dotDotDotToken)
        : ts.isSpreadElement(element);
      if (!rest && ts.isOmittedExpression(element)) continue;
      const end = rest ? values.elements.length : Math.min(index + 1, values.elements.length);
      for (let valueIndex = index; valueIndex < end; valueIndex += 1) {
        result.push(values.elements[valueIndex]);
      }
      if (rest) break;
    }
  }
    return result;
  };
  const inspectRequireDestructuring = (target, source) => {
    for (const value of destructuringSourceValues(target, source)) {
      if (requireReferenceOf(value)) {
        add(value, "aliasing require to bypass import inspection is forbidden");
      }
    }
  };
  const recordResolvedAssignments = (target, source) => {
    target = unwrap(target);
    if (ts.isIdentifier(target)) {
      recordAssignment(target, source);
      return;
    }
    if (ts.isObjectLiteralExpression(target)) {
      for (const property of target.properties) {
        const targetValue = ts.isShorthandPropertyAssignment(property)
          ? property.name
          : ts.isPropertyAssignment(property) ? unwrap(property.initializer) : undefined;
        if (ts.isSpreadAssignment(property)) {
          if (ts.isIdentifier(unwrap(property.expression))) {
            recordAssignment(unwrap(property.expression), source);
          }
          continue;
        }
        if (!targetValue || !ts.isPropertyAssignment(property) &&
            !ts.isShorthandPropertyAssignment(property)) continue;
        const key = assignmentPropertyName(property.name);
        if (key === undefined) continue;
        for (const value of memberValueCandidatesOf(source, key)) {
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
        for (const value of memberValueCandidatesOf(source, String(index))) {
          recordResolvedAssignments(element, value);
        }
      }
    }
  };
  const inspectProcessDestructuring = (target) => {
    for (const entry of destructuringEntries(target)) {
      const property = entry.name ? launchOptionName(entry.name) : undefined;
      if (entry.rest || (entry.name && property === undefined)) {
        add(entry.node,
          "dynamic process capability destructuring is unproven in supervisor source");
      } else if (property === "getBuiltinModule") {
        add(entry.node, "process.getBuiltinModule is forbidden in supervisor source");
      } else if (property === "default") {
        add(entry.node, "process object alias destructuring is unproven in supervisor source");
      }
    const nested = ts.isBindingElement(entry.node)
      ? entry.node.name
      : ts.isPropertyAssignment(entry.node) ? entry.node.initializer : undefined;
    if (nested && (ts.isObjectBindingPattern(nested) ||
                   ts.isArrayBindingPattern(nested) ||
                   ts.isObjectLiteralExpression(nested) ||
                   ts.isArrayLiteralExpression(nested))) {
      inspectProcessDestructuring(nested);
    }
    }
  };
  const inspectGlobalDestructuring = (target) => {
    for (const entry of destructuringEntries(target)) {
      const property = entry.name ? launchOptionName(entry.name) : undefined;
      if (entry.rest || (entry.name && property === undefined)) {
        add(entry.node,
          "dynamic global capability destructuring is unproven in supervisor source");
      } else if (property === "eval") {
        add(entry.node, "global dynamic evaluation is forbidden in supervisor source");
    } else if (property === "Function" || property === "constructor") {
        add(entry.node, "dynamic function construction is unaudited");
      } else if (property === "process") {
        add(entry.node,
          "global process capability destructuring is unproven in supervisor source");
      } else if (property === "global" || property === "globalThis") {
        add(entry.node,
          "global object alias destructuring is unproven in supervisor source");
      }
    const nested = ts.isBindingElement(entry.node)
      ? entry.node.name
      : ts.isPropertyAssignment(entry.node) ? entry.node.initializer : undefined;
    if (nested && (ts.isObjectBindingPattern(nested) ||
                   ts.isArrayBindingPattern(nested) ||
                   ts.isObjectLiteralExpression(nested) ||
                   ts.isArrayLiteralExpression(nested))) {
      inspectGlobalDestructuring(nested);
    }
    }
  };
  const inspectCapabilityArrayDestructuring = (target, source) => {
    const targets = ts.isArrayBindingPattern(target)
      ? target.elements
      : ts.isArrayLiteralExpression(target) ? target.elements : [];
  for (const values of resolvedValuesOf(source)) {
  if (!ts.isArrayLiteralExpression(values)) continue;
    for (let index = 0; index < targets.length; index += 1) {
      const element = targets[index];
      const rest = ts.isBindingElement(element)
        ? Boolean(element.dotDotDotToken)
        : ts.isSpreadElement(element);
      if (!rest && ts.isOmittedExpression(element)) continue;
      const end = rest ? values.elements.length : Math.min(index + 1, values.elements.length);
      for (let valueIndex = index; valueIndex < end; valueIndex += 1) {
        const value = values.elements[valueIndex];
        if (processObjectOf(value)) {
          add(value,
            "array destructuring of process capability is unproven in supervisor source");
        } else if (globalObjectOf(value)) {
          add(value,
            "array destructuring of global capability is unproven in supervisor source");
        }
      }
      if (rest) break;
    }
  }
  };
  // A global eval reference is unsafe even when it is stored or passed elsewhere.
  const globalEvalOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (!binding) return node.text === "eval";
      if (binding.kind !== "variable" || !binding.constant ||
          !immutableAlias(binding.node) || !binding.node.initializer || seen.has(binding.node)) {
        return false;
      }
      const next = new Set(seen);
      next.add(binding.node);
      return globalEvalOf(binding.node.initializer, next);
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
      return globalEvalOf(node.right, seen);
    }
    const member = memberAccess(node);
    return member?.property === "eval" && globalObjectOf(member.receiver);
  };
  const functionValueOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
    if (ts.isFunctionExpression(node) || ts.isArrowFunction(node) ||
        ts.isClassExpression(node) || ts.isFunctionDeclaration(node) ||
        ts.isClassDeclaration(node)) return true;
    if (ts.isConditionalExpression(node)) {
      return functionValueOf(node.whenTrue, seen) || functionValueOf(node.whenFalse, seen);
    }
    if (ts.isBinaryExpression(node) &&
        [ts.SyntaxKind.CommaToken, ts.SyntaxKind.AmpersandAmpersandToken,
         ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken]
          .includes(node.operatorToken.kind)) {
      return functionValueOf(node.left, seen) || functionValueOf(node.right, seen);
    }
    if (!ts.isIdentifier(node)) return false;
    const binding = resolveBinding(node);
    if (!binding || seen.has(binding.node)) return false;
    if (binding.kind === "opaque" &&
        (ts.isFunctionDeclaration(binding.node) || ts.isClassDeclaration(binding.node))) {
      return true;
    }
    if (binding.kind !== "variable" || !binding.constant ||
        !immutableAlias(binding.node) || !binding.node.initializer) return false;
    const next = new Set(seen);
    next.add(binding.node);
    return functionValueOf(binding.node.initializer, next);
  };
  const constructorFunctionOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
    if (functionValueOf(node, seen)) return true;
    if (ts.isConditionalExpression(node)) {
      return constructorFunctionOf(node.whenTrue, seen) ||
        constructorFunctionOf(node.whenFalse, seen);
    }
    if (ts.isBinaryExpression(node) &&
        [ts.SyntaxKind.CommaToken, ts.SyntaxKind.AmpersandAmpersandToken,
         ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken]
          .includes(node.operatorToken.kind)) {
      return constructorFunctionOf(node.left, seen) ||
        constructorFunctionOf(node.right, seen);
    }
    const member = memberAccess(node);
    if (member?.property === "constructor") return true;
    if (!ts.isIdentifier(node)) return false;
    const binding = resolveBinding(node);
    if (!binding || seen.has(binding.node) ||
        binding.kind !== "variable" || !binding.constant ||
        !immutableAlias(binding.node) || !binding.node.initializer) return false;
    const next = new Set(seen);
    next.add(binding.node);
    return constructorFunctionOf(binding.node.initializer, next);
  };
  const dynamicFunctionOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
  if (ts.isConditionalExpression(node)) {
    return dynamicFunctionOf(node.whenTrue, seen) || dynamicFunctionOf(node.whenFalse, seen);
  }
  if (ts.isBinaryExpression(node) &&
      [ts.SyntaxKind.CommaToken, ts.SyntaxKind.AmpersandAmpersandToken,
       ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken]
        .includes(node.operatorToken.kind)) {
    return dynamicFunctionOf(node.left, seen) || dynamicFunctionOf(node.right, seen);
  }
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (!binding) return node.text === "Function";
      if (binding.kind !== "variable" || !binding.constant ||
          !immutableAlias(binding.node) || !binding.node.initializer || seen.has(binding.node)) {
        return false;
      }
      const next = new Set(seen);
      next.add(binding.node);
      return dynamicFunctionOf(binding.node.initializer, next);
    }
    const member = memberAccess(node);
    if (member?.property === "Function" && globalObjectOf(member.receiver)) return true;
    if (member?.property !== "constructor") return false;
    if (functionValueOf(member.receiver, seen) ||
        constructorFunctionOf(member.receiver, seen)) return true;
    const owner = memberAccess(member.receiver);
    if (owner?.property === "constructor") return true;
    if (owner?.property === "Function" && globalObjectOf(owner.receiver)) return true;
  const constructorObjectOf = (value, constructorSeen = new Set()) => {
    const candidate = unwrap(value);
    if (!candidate) return false;
    if (ts.isConditionalExpression(candidate)) {
      return constructorObjectOf(candidate.whenTrue, constructorSeen) ||
        constructorObjectOf(candidate.whenFalse, constructorSeen);
    }
    if (ts.isBinaryExpression(candidate) &&
        [ts.SyntaxKind.CommaToken, ts.SyntaxKind.AmpersandAmpersandToken,
         ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken]
          .includes(candidate.operatorToken.kind)) {
      return constructorObjectOf(candidate.left, constructorSeen) ||
        constructorObjectOf(candidate.right, constructorSeen);
    }
    if (ts.isIdentifier(candidate)) {
      const binding = resolveBinding(candidate);
      if (!binding) return false;
      if (!binding.node || constructorSeen.has(binding.node)) return false;
      const next = new Set(constructorSeen);
      next.add(binding.node);
      if ((binding.kind === "variable" || binding.kind === "opaque") &&
          ts.isVariableDeclaration(binding.node) &&
          binding.node.initializer &&
          (ts.isObjectBindingPattern(binding.node.name) ||
           ts.isArrayBindingPattern(binding.node.name))) {
        return bindingPatternValuesOf(
          binding.node.name,
          binding.node.initializer,
          candidate.text,
          next
        ).some((value) => constructorObjectOf(value, next));
      }
      if (binding.kind === "parameter" && ts.isParameter(binding.node)) {
        if (ts.isIdentifier(binding.node.name)) {
          return Boolean(binding.node.initializer &&
            constructorObjectOf(binding.node.initializer, next));
        }
        return Boolean(binding.node.initializer &&
          bindingPatternValuesOf(
            binding.node.name,
            binding.node.initializer,
            candidate.text,
            next
          ).some((value) => constructorObjectOf(value, next)));
      }
      if (binding.kind !== "variable" || !binding.constant ||
          !immutableAlias(binding.node) || !binding.node.initializer) return false;
      return constructorObjectOf(binding.node.initializer, next);
    }
    const inner = memberAccess(candidate);
    return Boolean(inner && inner.property === "constructor" &&
      (globalObjectOf(inner.receiver) || constructorObjectOf(inner.receiver, constructorSeen)));
  };
  return globalObjectOf(member.receiver) || constructorObjectOf(member.receiver, seen);
  };
  const isReferenceIdentifier = (node) => {
    const parent = node.parent;
    return !((ts.isPropertyAccessExpression(parent) && parent.name === node) ||
      (ts.isPropertyAssignment(parent) && parent.name === node) ||
      ts.isImportSpecifier(parent) ||
      (ts.isBindingElement(parent) && (parent.name === node || parent.propertyName === node)) ||
      (ts.isVariableDeclaration(parent) && parent.name === node) ||
      (ts.isFunctionDeclaration(parent) && parent.name === node) ||
      (ts.isParameter(parent) && parent.name === node) ||
      (ts.isMethodDeclaration(parent) && parent.name === node) ||
      (ts.isPropertySignature(parent) && parent.name === node) ||
      ts.isTypeQueryNode(parent) || ts.isTypeReferenceNode(parent));
  };
  const transparent = (parent, child) => parent?.expression === child &&
    (ts.isParenthesizedExpression(parent) || ts.isAsExpression(parent) ||
     ts.isTypeAssertionExpression(parent) || ts.isSatisfiesExpression(parent) ||
     ts.isNonNullExpression(parent));
  const outer = (node) => {
    let current = node;
    while (transparent(current.parent, current)) current = current.parent;
    return current;
  };
  const runnerOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node || !ts.isIdentifier(node)) return undefined;
    const binding = resolveBinding(node);
    if (!binding) return SAFE_PROCESS_EXPORTS.has(node.text) ? node.text : undefined;
    if (binding.kind === "import" && PROCESS_MODULES.has(binding.module)) {
      const exported = importedExport(binding, node.text);
      return SAFE_PROCESS_EXPORTS.has(exported) ? exported : undefined;
    }
    if (binding.kind === "opaque" && ts.isVariableDeclaration(binding.node) &&
        ts.isObjectBindingPattern(binding.node.name) &&
        ts.isVariableDeclarationList(binding.node.parent) &&
        (binding.node.parent.flags & ts.NodeFlags.Const)) {
      const init = unwrap(binding.node.initializer);
      if (!init || !ts.isCallExpression(init) ||
          !ts.isIdentifier(unwrap(init.expression)) ||
          unwrap(init.expression).text !== "require" ||
          init.arguments.length !== 1 ||
          !PROCESS_MODULES.has(moduleLiteral(init.arguments[0]))) return undefined;
      const element = binding.node.name.elements.find((item) =>
        ts.isIdentifier(item.name) && item.name.text === node.text &&
        !item.initializer && !item.dotDotDotToken);
      const exported = element?.propertyName?.text ?? element?.name.text;
      return SAFE_PROCESS_EXPORTS.has(exported) ? exported : undefined;
    }
    if (binding.kind !== "variable" || !binding.constant ||
        !immutableAlias(binding.node) || !binding.node.initializer ||
        seen.has(binding.node)) return undefined;
    const next = new Set(seen);
    next.add(binding.node);
    const init = unwrap(binding.node.initializer);
    if (ts.isIdentifier(init)) return runnerOf(init, next);
    return provenPromisify(init, next) ? "execFile" : undefined;
  };
  const provenPromisify = (expression, seen = new Set()) => {
    const call = unwrap(expression);
    if (!call || !ts.isCallExpression(call) || call.questionDotToken ||
        call.arguments.length !== 1) return false;
    const callee = unwrap(call.expression);
    if (!ts.isIdentifier(callee)) return false;
    const binding = resolveBinding(callee);
    return binding?.kind === "import" && binding.module === "node:util" &&
      importedExport(binding, callee.text) === "promisify" &&
      runnerOf(call.arguments[0], seen) === "execFile";
  };
  const inspectRunnerReference = (node) => {
    const parent = node.parent;
    // Declaration names, property keys and erased types are not references.
    if ((ts.isPropertyAccessExpression(parent) && parent.name === node) ||
        (ts.isPropertyAssignment(parent) && parent.name === node) ||
        ts.isImportSpecifier(parent) ||
        (ts.isBindingElement(parent) &&
         (parent.name === node || parent.propertyName === node)) ||
        (ts.isVariableDeclaration(parent) && parent.name === node) ||
        (ts.isFunctionDeclaration(parent) && parent.name === node) ||
        (ts.isParameter(parent) && parent.name === node) ||
        (ts.isMethodDeclaration(parent) && parent.name === node) ||
        (ts.isPropertySignature(parent) && parent.name === node) ||
        ts.isTypeQueryNode(parent) || ts.isTypeReferenceNode(parent)) return;
    if (!runnerOf(node)) return;
    const expression = outer(node);
    const context = expression.parent;
    if (ts.isCallExpression(context) && context.expression === expression &&
        !context.questionDotToken) return;
    if (immutableAlias(context) && context.initializer === expression) return;
    if (ts.isCallExpression(context) && context.arguments.length === 1 &&
        context.arguments[0] === expression && provenPromisify(context)) {
      const initializer = outer(context);
      if (immutableAlias(initializer.parent) &&
          initializer.parent.initializer === initializer) return;
    }
    add(node, "indirect or escaping child_process runner reference is forbidden");
  };

  const visit = (node) => {
    if (ts.isExportDeclaration(node)) {
      if (node.isTypeOnly) return;
      if (node.moduleSpecifier) {
        const module = moduleLiteral(node.moduleSpecifier);
        const clause = node.exportClause;
        const typeOnly = clause && ts.isNamedExports(clause) &&
          clause.elements.length > 0 && clause.elements.every((item) => item.isTypeOnly);
        if (!typeOnly && (PROCESS_MODULES.has(module) || SHELL_MODULES.has(module))) {
          add(node, "runtime process-runner re-export is forbidden");
        }
        if (!typeOnly && ["node:process", "process"].includes(module)) {
          add(node, "runtime process capability re-export is forbidden");
        }
        // Source-module names are not references to this module's local bindings.
        return;
      }
    }
    if (ts.isExportSpecifier(node)) {
      // Only a local value name can escape; type-only and public alias names cannot.
    if (!node.isTypeOnly) {
      inspectRunnerReference(node.propertyName ?? node.name);
      if (processObjectOf(node.propertyName ?? node.name)) {
        add(node, "runtime process capability re-export is forbidden");
      }
    }
      return;
    }
    if (ts.isImportDeclaration(node)) {
      const module = moduleLiteral(node.moduleSpecifier);
      if (SHELL_MODULES.has(module)) add(node, "shell-capable runner imports are forbidden");
      if (MODULE_LOADING_MODULES.has(module) && hasRuntimeImport(node)) {
        add(node, "node:module loading is forbidden in supervisor source");
      }
      if (["node:process", "process"].includes(module) &&
          node.importClause?.namedBindings && ts.isNamedImports(node.importClause.namedBindings)) {
        for (const element of node.importClause.namedBindings.elements) {
          if (!element.isTypeOnly &&
              (element.propertyName?.text ?? element.name.text) === "getBuiltinModule") {
            add(element, "process.getBuiltinModule is forbidden in supervisor source");
          }
        }
      }
      if (PROCESS_MODULES.has(module) && !node.importClause?.isTypeOnly) {
        const bindings = node.importClause?.namedBindings;
        if (node.importClause?.name || !bindings || !ts.isNamedImports(bindings)) {
          add(node, "child_process imports must use audited named exports");
        } else {
          for (const element of bindings.elements) {
            if (!element.isTypeOnly) {
              processBinding(element.propertyName?.text ?? element.name.text, element);
            }
          }
        }
      }
    }

    if (ts.isImportEqualsDeclaration(node)) {
      add(node, "import-equals loading is unaudited in supervisor source");
    }
    if (ts.isCallExpression(node)) {
      const called = callName(unwrap(node.expression));
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        add(node, "dynamic import is forbidden in supervisor source");
      }
      if (requireReferenceOf(node.expression)) inspectRequire(node);
      if (called === "createRequire" || called === "_parse") {
        add(node, "indirect process loading, eval, or private shim parsing is forbidden");
      }
      const callee = unwrap(node.expression);
      const runner = ts.isIdentifier(callee) ? runnerOf(callee) : undefined;
      if (runner) {
        if (node.arguments.some((argument) => ts.isSpreadElement(argument))) {
          add(node, "spread process-runner call arguments cannot prove native dispatch");
        }
        inspectLaunchOptions(node, runner);
        const program = staticStringOf(node.arguments[0]);
        if (program && (DISALLOWED_PROGRAMS.test(program) ||
                        DISALLOWED_SHIMS.test(program))) {
          add(node, "direct interpreter or command-shim dispatch is forbidden");
        }
      }
    }
    if (ts.isVariableDeclaration(node) && node.initializer &&
        requireReferenceOf(node.initializer)) {
      add(node, "aliasing require to bypass import inspection is forbidden");
    }
    if (ts.isBinaryExpression(node) && aliasAssignmentKinds.has(node.operatorToken.kind) &&
        ts.isIdentifier(unwrap(node.left)) && requireReferenceOf(node.right)) {
      add(node, "aliasing require to bypass import inspection is forbidden");
    }
    if (ts.isCallExpression(node) && dynamicFunctionOf(node.expression)) {
      add(node, "dynamic function construction is unaudited");
    }
    if (ts.isNewExpression(node) && dynamicFunctionOf(node.expression)) {
      add(node, "dynamic function construction is unaudited");
    }
    const member = memberAccess(node);
    if (member?.property === "getBuiltinModule" && processObjectOf(member.receiver)) {
      add(node, "process.getBuiltinModule is forbidden in supervisor source");
    }
    if (ts.isElementAccessExpression(node) && processObjectOf(node.expression) && !member) {
      add(node, "dynamic process capability access is unproven in supervisor source");
    }
    if (member?.property === "eval" && globalObjectOf(member.receiver)) {
      add(node, "global dynamic evaluation is forbidden in supervisor source");
    }
    if (ts.isElementAccessExpression(node) && globalObjectOf(node.expression) && !member) {
      add(node, "dynamic global capability access is unproven in supervisor source");
    }
    if (ts.isParameter(node) && node.initializer) {
      if (processObjectOf(node.initializer)) {
        add(node, "process capability parameter default is unproven in supervisor source");
      }
      if (globalObjectOf(node.initializer)) {
        add(node, "global capability parameter default is unproven in supervisor source");
      }
    }
    if ((ts.isParameter(node) || ts.isVariableDeclaration(node)) &&
        (ts.isObjectBindingPattern(node.name) || ts.isArrayBindingPattern(node.name))) {
      if (bindingDefaultMatches(node.name, (value) => processObjectOf(value))) {
        add(node, "process capability destructuring default is unproven in supervisor source");
      }
      if (bindingDefaultMatches(node.name, (value) => globalObjectOf(value))) {
        add(node, "global capability destructuring default is unproven in supervisor source");
      }
    }
    if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name) &&
        node.initializer) {
      if (processObjectOf(node.initializer)) inspectProcessDestructuring(node.name);
      if (globalObjectOf(node.initializer)) inspectGlobalDestructuring(node.name);
    }
    if (ts.isVariableDeclaration(node) && ts.isArrayBindingPattern(node.name) &&
        node.initializer) {
      inspectCapabilityArrayDestructuring(node.name, node.initializer);
    }
    if (ts.isVariableDeclaration(node) && node.initializer &&
        (ts.isObjectBindingPattern(node.name) || ts.isArrayBindingPattern(node.name))) {
      inspectRequireDestructuring(node.name, node.initializer);
    }
    if (ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const target = unwrap(node.left);
      if (ts.isObjectLiteralExpression(target)) {
        recordResolvedAssignments(target, node.right);
        inspectRequireDestructuring(target, node.right);
        if (processObjectOf(node.right)) inspectProcessDestructuring(target);
        if (globalObjectOf(node.right)) inspectGlobalDestructuring(target);
      } else if (ts.isArrayLiteralExpression(target)) {
        recordResolvedAssignments(target, node.right);
        inspectRequireDestructuring(target, node.right);
        inspectCapabilityArrayDestructuring(target, node.right);
      }
    }
    const functionReference = ts.isIdentifier(node)
      ? isReferenceIdentifier(node)
      : ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node);
    if (functionReference && dynamicFunctionOf(node)) {
      const expression = outer(node);
      const context = expression.parent;
      const called = ts.isCallExpression(context) && context.expression === expression &&
        !context.questionDotToken;
      const constructed = ts.isNewExpression(context) && context.expression === expression;
      if (!called && !constructed &&
          !(immutableAlias(context) && context.initializer === expression)) {
        add(node, "dynamic function reference escapes its audited call");
      }
    }
    if (ts.isIdentifier(node)) {
      inspectRunnerReference(node);
      if (isReferenceIdentifier(node) && globalEvalOf(node)) {
        add(node, "global dynamic evaluation is forbidden in supervisor source");
      }
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
