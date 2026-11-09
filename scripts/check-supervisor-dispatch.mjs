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
const DYNAMIC_EVALUATION_MODULES = new Set(["node:vm", "vm"]);
const SHELL_MODULES = new Set(["cross-spawn", "shelljs", "execa"]);
const SAFE_PROCESS_EXPORTS = new Set(["spawn", "spawnSync", "execFile", "execFileSync"]);
const DISALLOWED_PROGRAMS = /(?:^|[\\/])(?:cmd|command|powershell|pwsh|bash|dash|sh|zsh|ksh|ash|fish|csh|tcsh|busybox|env)(?:\.exe)?$/i;
const DISALLOWED_SHIMS = /\.(?:cmd|bat|ps1|psm1|sh)$/i;

const moduleLiteral = (node) => node && ts.isStringLiteralLike(node) ? node.text : undefined;
const nameOf = (node) => ts.isIdentifier(node) ? node.text : undefined;
const callName = (node) => nameOf(node) ||
  (ts.isPropertyAccessExpression(node) ? node.name.text : undefined);

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
    } else if (DYNAMIC_EVALUATION_MODULES.has(module)) {
      add(node, "dynamic evaluation module loading is forbidden in supervisor source");
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
  const parameterProcessArguments = new Map();
  const parameterGlobalArguments = new Map();
  const parameterRequireArguments = new Map();
  const parameterRestArguments = new Map();
const parameterFunctionArguments = new Map();
const functionArgumentsPlans = new Map();
const getterReceiverOf = (getter) =>
  ts.isObjectLiteralExpression(getter.parent) ? getter.parent : undefined;
  const requireReferenceOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (binding?.kind === "parameter" && ts.isParameter(binding.node)) {
        if (seen.has(binding.node)) return false;
        const next = new Set(seen);
        next.add(binding.node);
        return (parameterRequireArguments.get(binding.node) ?? []).some((value) => {
          const candidates = ts.isIdentifier(binding.node.name)
            ? [value]
            : bindingPatternValuesOf(
              binding.node.name, value, node.text, next
            );
          return candidates.some((candidate) =>
            requireReferenceOf(candidate, next));
        });
      }
      return node.text === "require" && !binding;
    }
  if (ts.isPropertyAccessExpression(node)) {
    const property = node.name.text;
    if (property === "require") return globalObjectOf(node.expression);
    return ["call", "apply", "bind"].includes(property) &&
      requireReferenceOf(node.expression, seen);
  }
  if (ts.isElementAccessExpression(node)) {
    const property = moduleLiteral(node.argumentExpression);
    if (property === "require") return globalObjectOf(node.expression);
    return ["call", "apply", "bind"].includes(property) &&
      requireReferenceOf(node.expression, seen);
  }
  if (ts.isConditionalExpression(node)) {
    return requireReferenceOf(node.whenTrue, seen) ||
      requireReferenceOf(node.whenFalse, seen);
  }
    if (!ts.isBinaryExpression(node)) return false;
    const operator = node.operatorToken.kind;
    if (operator === ts.SyntaxKind.CommaToken) {
      return requireReferenceOf(node.right, seen);
    }
    if (operator === ts.SyntaxKind.AmpersandAmpersandToken ||
        operator === ts.SyntaxKind.BarBarToken ||
        operator === ts.SyntaxKind.QuestionQuestionToken) {
      return requireReferenceOf(node.left, seen) ||
        requireReferenceOf(node.right, seen);
    }
    return false;
  };
  const requireReferenceInContainerOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
    if (requireReferenceOf(node)) return true;
    if (ts.isObjectLiteralExpression(node)) {
      return node.properties.some((property) => {
        if (ts.isPropertyAssignment(property)) {
          return requireReferenceInContainerOf(property.initializer, seen);
        }
        if (ts.isShorthandPropertyAssignment(property)) {
          return requireReferenceOf(property.name);
        }
        return ts.isSpreadAssignment(property) &&
          requireReferenceInContainerOf(property.expression, seen);
      });
    }
    if (ts.isArrayLiteralExpression(node)) {
      return node.elements.some((element) =>
        requireReferenceInContainerOf(element, seen));
    }
    if (ts.isConditionalExpression(node)) {
      return requireReferenceInContainerOf(node.whenTrue, seen) ||
        requireReferenceInContainerOf(node.whenFalse, seen);
    }
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node) ||
        ts.isFunctionDeclaration(node)) {
      return functionReturnExpressionsOf(node)
        .some((value) => requireReferenceInContainerOf(value, seen));
    }
    if (ts.isBinaryExpression(node) && [
      ts.SyntaxKind.AmpersandAmpersandToken,
      ts.SyntaxKind.BarBarToken,
      ts.SyntaxKind.CommaToken,
      ts.SyntaxKind.QuestionQuestionToken
    ].includes(node.operatorToken.kind)) {
      return requireReferenceInContainerOf(node.left, seen) ||
        requireReferenceInContainerOf(node.right, seen);
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
  const isAmbientDeclaration = (statement) => Boolean(statement.modifiers?.some(
    (modifier) => modifier.kind === ts.SyntaxKind.DeclareKeyword));
const declarations = (statements = []) => {
      const found = [];
      for (const statement of statements) {
      if (!isAmbientDeclaration(statement) && ts.isVariableStatement(statement)) {
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
      if (!isAmbientDeclaration(statement) &&
          (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) &&
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
            !isAmbientDeclaration(node.parent.parent) &&
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
const staticNumericNameOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return undefined;
  if (ts.isNumericLiteral(node)) {
    const value = Number(node.text);
    return Number.isFinite(value) ? value : undefined;
  }
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = staticNumericNameOf(node.left, seen);
    const right = staticNumericNameOf(node.right, seen);
    return left !== undefined && right !== undefined ? left + right : undefined;
  }
  if (!ts.isIdentifier(node)) return undefined;
  const binding = resolveBinding(node);
  if (binding?.kind !== "variable" || !binding.constant ||
      !binding.node.initializer || seen.has(binding.node)) return undefined;
  const next = new Set(seen);
  next.add(binding.node);
  return staticNumericNameOf(binding.node.initializer, next);
};
const staticAssignmentNameOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return undefined;
  if (ts.isStringLiteralLike(node)) return node.text;
  if (ts.isNumericLiteral(node)) {
    const value = Number(node.text);
    return Number.isFinite(value) ? String(value) : undefined;
  }
  if (ts.isConditionalExpression(node)) {
    const left = staticAssignmentNameOf(node.whenTrue, seen);
    const right = staticAssignmentNameOf(node.whenFalse, seen);
    return left !== undefined && left === right ? left : undefined;
  }
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    return staticAssignmentNameOf(node.right, seen);
  }
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const numericLeft = staticNumericNameOf(node.left, seen);
    const numericRight = staticNumericNameOf(node.right, seen);
    if (numericLeft !== undefined && numericRight !== undefined) {
      return String(numericLeft + numericRight);
    }
    const left = staticAssignmentNameOf(node.left, seen);
    const right = staticAssignmentNameOf(node.right, seen);
    return left !== undefined && right !== undefined ? left + right : undefined;
  }
  if (!ts.isIdentifier(node)) return undefined;
  const binding = resolveBinding(node);
  if (binding?.kind !== "variable" || !binding.constant ||
      !binding.node.initializer || seen.has(binding.node)) return undefined;
  const next = new Set(seen);
  next.add(binding.node);
  return staticAssignmentNameOf(binding.node.initializer, next);
};
  const assignmentsByBinding = new Map();
  const destructuredAssignmentsByBinding = new Map();
const destructuredPropertyAssignmentsByBinding = new Map();
const arrayMutationValuesByBinding = new Map();
  const assignmentPropertyName = (name) => {
    if (!name) return undefined;
    if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) {
      return name.text;
    }
  if (ts.isComputedPropertyName(name)) {
    return staticAssignmentNameOf(name.expression);
    }
    return undefined;
  };
const assignmentsByMemberPath = new Map();
const constructorDestructuredBindings = new Set();
const constructorDestructuredMembers = new Set();
const assignmentMemberAccess = (node) => {
  node = unwrap(node);
  if (ts.isPropertyAccessExpression(node)) {
    return { receiver: node.expression, property: node.name.text };
  }
  if (ts.isElementAccessExpression(node)) {
    const property = staticAssignmentNameOf(node.argumentExpression);
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
const assignmentMemberPathKey = (receiver, property) => {
  const key = assignmentReferenceKey(receiver);
  return key === undefined ? undefined : JSON.stringify([key, property]);
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
    if (!ts.isIdentifier(target)) return;
    const binding = resolveBinding(target);
    if (!binding?.node) return;
    const directBinding =
      (binding.kind === "variable" && ts.isVariableDeclaration(binding.node)) ||
      (binding.kind === "parameter" && ts.isParameter(binding.node)) ||
      (binding.kind === "opaque" && (ts.isVariableDeclaration(binding.node) ||
       ts.isParameter(binding.node)));
    if (!directBinding) return;
    const name = ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node)
      ? binding.node.name : undefined;
    if (!name) return;
    const usesDirectBinding = ts.isIdentifier(name);
    const key = usesDirectBinding
      ? binding.node : `${binding.node.pos}:${target.text}`;
    const assignments = usesDirectBinding
      ? assignmentsByBinding.get(key) ?? []
      : destructuredAssignmentsByBinding.get(key) ?? [];
    assignments.push(value);
    (usesDirectBinding ? assignmentsByBinding : destructuredAssignmentsByBinding)
      .set(key, assignments);
  };
const recordDestructuredPropertyAssignment = (target, source, property) => {
  if (!ts.isIdentifier(target) || property === undefined) return;
  const binding = resolveBinding(target);
  if (!binding?.node) return;
  const assignments = destructuredPropertyAssignmentsByBinding.get(binding.node) ?? [];
  if (!assignments.some((assignment) => assignment.source === source &&
      assignment.property === property)) {
    assignments.push({ source, property });
    destructuredPropertyAssignmentsByBinding.set(binding.node, assignments);
  }
};
const destructuredObjectPropertyValuesOf = (
  source, property, seen = new Set()
) => {
  const node = unwrap(source);
  if (!node || seen.has(node)) return [];
  const next = new Set(seen);
  next.add(node);
  if (ts.isObjectLiteralExpression(node)) {
    const values = [];
    for (const item of node.properties) {
      if (ts.isSpreadAssignment(item)) {
        values.push(...destructuredObjectPropertyValuesOf(
          item.expression, property, next
        ));
      } else if (assignmentPropertyName(item.name) === property) {
        if (ts.isPropertyAssignment(item)) values.push(item.initializer);
        else if (ts.isShorthandPropertyAssignment(item)) values.push(item.name);
      }
    }
    return values;
  }
  if (!ts.isIdentifier(node)) return [];
  const binding = resolveBinding(node);
  return binding?.kind === "variable" &&
    ts.isVariableDeclaration(binding.node) && binding.node.initializer
    ? destructuredObjectPropertyValuesOf(
      binding.node.initializer, property, next
    )
    : [];
};
const recordNestedDestructuredProperties = (target, source) => {
  target = unwrap(target);
  source = unwrap(source);
  if (ts.isObjectLiteralExpression(target)) {
    for (const property of target.properties) {
      const key = assignmentPropertyName(property.name);
      let targetValue = ts.isShorthandPropertyAssignment(property)
        ? property.name
        : ts.isPropertyAssignment(property) ? unwrap(property.initializer) : undefined;
      if (!targetValue) continue;
      const patternDefault = ts.isBinaryExpression(targetValue) &&
        targetValue.operatorToken.kind === ts.SyntaxKind.EqualsToken
        ? targetValue.right : undefined;
      if (patternDefault) targetValue = unwrap(targetValue.left);
      if (key !== undefined) {
        recordDestructuredPropertyAssignment(targetValue, source, key);
        const values = destructuredObjectPropertyValuesOf(source, key);
        const resolved = values.length > 0
          ? values : patternDefault ? [patternDefault] : [];
        for (const value of resolved) {
          if (ts.isIdentifier(targetValue)) {
            recordAssignment(targetValue, value);
          }
          recordNestedDestructuredProperties(targetValue, value);
        }
      }
    }
  }
};
  const collectAssignments = (node) => {
    if (ts.isBinaryExpression(node) &&
        aliasAssignmentKinds.has(node.operatorToken.kind)) {
      const target = unwrap(node.left);
    recordNestedDestructuredProperties(target, node.right);
      if (ts.isIdentifier(target) || assignmentMemberAccess(target)) {
        recordAssignment(target, node.right);
    } else if (ts.isObjectLiteralExpression(target)) {
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
        if (targetName && key !== undefined) {
          recordDestructuredPropertyAssignment(targetName, source, key);
        }
        if (!ts.isObjectLiteralExpression(source)) continue;
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
  if (ts.isNumericLiteral(node)) {
    const value = Number(node.text);
    return Number.isFinite(value) ? String(value) : undefined;
  }
  if (ts.isConditionalExpression(node)) {
    const left = staticStringOf(node.whenTrue, seen);
    const right = staticStringOf(node.whenFalse, seen);
    return left !== undefined && left === right ? left : undefined;
  }
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    return staticStringOf(node.right, seen);
  }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const numericLeft = staticNumericNameOf(node.left, seen);
    const numericRight = staticNumericNameOf(node.right, seen);
    if (numericLeft !== undefined && numericRight !== undefined) {
      return String(numericLeft + numericRight);
    }
      const left = staticStringOf(node.left, seen);
      const right = staticStringOf(node.right, seen);
      return left !== undefined && right !== undefined ? left + right : undefined;
    }
  if (ts.isElementAccessExpression(node)) {
    const index = unwrap(node.argumentExpression);
    if (!index || (!ts.isNumericLiteral(index) && !ts.isStringLiteralLike(index))) {
      return undefined;
    }
    const values = memberValueCandidatesOf(node.expression, index.text, seen)
      .map((value) => staticStringOf(value, seen))
      .filter((value) => value !== undefined);
    const unique = [...new Set(values)];
    return unique.length === 1 ? unique[0] : undefined;
  }
    if (!ts.isIdentifier(node)) return undefined;
    const binding = resolveBinding(node);
    if (binding?.kind !== "variable" || !binding.constant ||
        !binding.node.initializer || seen.has(binding.node)) return undefined;
    const next = new Set(seen);
    next.add(binding.node);
    return staticStringOf(binding.node.initializer, next);
  };
  const staticPropertyNameOf = (name) => {
    if (!name) return undefined;
    if (ts.isComputedPropertyName(name)) return staticStringOf(name.expression);
    return assignmentPropertyName(name);
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
      const name = staticPropertyNameOf(property.name);
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
    const node = unwrap(input);
    if (!node || seen.has(node)) return [];
    const next = new Set(seen);
    next.add(node);
    const objects = [];
  if (node.kind === ts.SyntaxKind.ThisKeyword) {
    let current = node.parent;
    while (current) {
      if (ts.isGetAccessorDeclaration(current)) {
        const receiver = getterReceiverOf(current);
        if (receiver) {
          objects.push(...objectValueCandidatesOf(receiver, next));
        }
        return objects;
      }
      if (ts.isFunctionLike(current) && !ts.isArrowFunction(current)) return [];
      current = current.parent;
    }
    return objects;
  }
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (binding?.kind === "parameter" && ts.isParameter(binding.node) &&
        !next.has(binding.node)) {
      const parameterNext = new Set(next);
      parameterNext.add(binding.node);
      for (const argument of [
        ...(parameterProcessArguments.get(binding.node) ?? []),
        ...(parameterGlobalArguments.get(binding.node) ?? [])
      ]) {
        objects.push(...objectValueCandidatesOf(argument, parameterNext));
      }
    }
  }
    for (const value of resolvedValuesOf(node, next)) {
    if (ts.isIdentifier(value)) {
      const binding = resolveBinding(value);
      if (binding?.kind === "parameter" && ts.isParameter(binding.node) &&
          !next.has(binding.node)) {
        const parameterNext = new Set(next);
        parameterNext.add(binding.node);
        for (const argument of [
          ...(parameterProcessArguments.get(binding.node) ?? []),
          ...(parameterGlobalArguments.get(binding.node) ?? [])
        ]) {
          objects.push(...objectValueCandidatesOf(argument, parameterNext));
        }
      }
    }
      if (value.kind === ts.SyntaxKind.ThisKeyword) {
        objects.push(...objectValueCandidatesOf(value, next));
        continue;
      }
      if (ts.isObjectLiteralExpression(value)) {
        objects.push(value);
        continue;
      }
      if (ts.isCallExpression(value)) {
      const copiedArguments = objectAssignInvocationArgumentsOf(value, next);
      if (copiedArguments) {
        for (const argument of copiedArguments) {
          objects.push(...objectValueCandidatesOf(argument, next));
          }
        continue;
      }
        const prototypes = objectCreatePrototypeValuesOf(value, next);
        if (prototypes.length > 0) {
          for (const prototype of prototypes) {
            objects.push(...objectValueCandidatesOf(prototype, next));
          }
          continue;
        }
      for (const returned of functionReturnExpressionsOf(value.expression, next)) {
        objects.push(...objectValueCandidatesOf(returned, next));
        }
        continue;
      }
      const member = memberAccess(value);
      if (!member) continue;
      for (const candidate of memberValueCandidatesOf(
        member.receiver,
        member.property,
        next
      )) {
        objects.push(...objectValueCandidatesOf(candidate, next));
      }
    }
    return objects;
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
  const memberValueCandidatesOf = (input, property, seen = new Set()) => {
    const node = unwrap(input);
    if (!node || seen.has(node)) return [];
    const next = new Set(seen);
    next.add(node);
    const values = [];
    for (const object of objectValueCandidatesOf(node, seen)) {
      for (const candidate of object.properties) {
        if (ts.isSpreadAssignment(candidate)) {
          values.push(...memberValueCandidatesOf(candidate.expression, property, next));
          continue;
        }
        if (!("name" in candidate)) continue;
        const name = staticPropertyNameOf(candidate.name);
        if (name !== property) continue;
        if (ts.isPropertyAssignment(candidate)) values.push(candidate.initializer);
        if (ts.isShorthandPropertyAssignment(candidate)) values.push(candidate.name);
      if (ts.isMethodDeclaration(candidate)) values.push(candidate);
if (ts.isGetAccessorDeclaration(candidate)) {
        values.push(candidate, ...functionReturnExpressionsOf(candidate, next));
}
      }
    }
    for (const value of resolvedValuesOf(node, next)) {
      if (!ts.isArrayLiteralExpression(value) || !/^\d+$/.test(property)) continue;
      values.push(...fixedIndexedValuesOf(value, Number(property)));
    }
    if (ts.isIdentifier(node)) {
    if (/^\d+$/.test(property)) {
      for (const plan of functionArgumentsPlanOf(node) ?? []) {
        values.push(...callArgumentCandidatesAt(plan, Number(property)));
      }
    }
      values.push(...destructuredParameterValueCandidatesOf(
        node, property, next
      ));
    }
    if (ts.isCallExpression(node) && /^\d+$/.test(property)) {
      for (const returned of functionReturnExpressionsOf(node.expression, next)) {
        for (const plan of functionArgumentsPlanOf(returned, next) ?? []) {
          values.push(...callArgumentCandidatesAt(plan, Number(property)));
        }
        if (ts.isArrayLiteralExpression(unwrap(returned))) {
          const indexed = unwrap(returned).elements[Number(property)];
          if (indexed && !ts.isOmittedExpression(indexed) &&
              !ts.isSpreadElement(indexed)) values.push(indexed);
        }
      }
    }
    const key = assignmentMemberPathKey(node, property);
  if (key !== undefined) {
    values.push(...(assignmentsByMemberPath.get(key) ?? []));
  }
    return values;
  };
  const bindingPatternValuesOf = (pattern, source, targetName, seen = new Set()) => {
    const values = [];
    if (ts.isObjectBindingPattern(pattern)) {
      for (const element of pattern.elements) {
        const key = element.propertyName
          ? staticPropertyNameOf(element.propertyName)
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
const bindingPatternSelectsPropertyOf = (pattern, targetName, property) => {
  if (!ts.isObjectBindingPattern(pattern) && !ts.isArrayBindingPattern(pattern)) {
    return false;
  }
  return pattern.elements.some((element) => {
    if (!ts.isBindingElement(element)) return false;
    if (ts.isIdentifier(element.name)) {
      if (element.name.text !== targetName) return false;
      const key = element.propertyName
        ? staticPropertyNameOf(element.propertyName)
        : element.name.text;
      return key === property;
    }
    return bindingPatternSelectsPropertyOf(element.name, targetName, property);
  });
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
    if (binding.kind === "parameter" && ts.isParameter(binding.node)) {
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
    const member = memberAccess(node);
    if (!member) return [];
    return memberValueCandidatesOf(member.receiver, member.property, next)
      .flatMap((value) => localFunctionValuesOf(value, next));
  };
  const functionReturnExpressionsOf = (input, seen = new Set()) => {
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
  // Follow local aliases and object spreads that preserve process capabilities.
  const processObjectOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
  if (ts.isGetAccessorDeclaration(node)) {
    const returnedValues = functionReturnExpressionsOf(node, seen);
    const next = new Set(seen);
    next.add(node);
    return returnedValues
      .some((value) => processObjectOf(value, next));
  }
  if (ts.isFunctionLike(node)) {
    const returnedValues = functionReturnExpressionsOf(node, seen);
    const next = new Set(seen);
    next.add(node);
    return returnedValues.some((value) => processObjectOf(value, next));
  }
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
    if (ts.isCallExpression(node)) {
      if (processModuleRequire(node)) return true;
  const copiedArguments = objectAssignInvocationArgumentsOf(node, seen);
  if (copiedArguments?.some((value) => processObjectOf(value, seen))) return true;
      const prototypes = objectCreatePrototypeValuesOf(node, seen);
      if (prototypes.some((value) => processObjectOf(value, seen))) return true;
      const callee = unwrap(node.expression);
      const binding = ts.isIdentifier(callee) ? resolveBinding(callee) : undefined;
      if (binding && seen.has(binding.node)) return false;
      const next = new Set(seen);
      if (binding) next.add(binding.node);
  return functionReturnExpressionsOf(node.expression)
    .some((value) => processObjectOf(value, next));
    }
    if (ts.isObjectLiteralExpression(node)) {
    return node.properties.some((property) => {
      if (ts.isSpreadAssignment(property)) return processObjectOf(property.expression, seen);
      if (ts.isPropertyAssignment(property)) return processObjectOf(property.initializer, seen);
      if (ts.isShorthandPropertyAssignment(property)) return processObjectOf(property.name, seen);
      return false;
    });
    }
    if (!ts.isIdentifier(node)) {
      if (seen.has(node)) return false;
      const next = new Set(seen);
      next.add(node);
      const member = memberAccess(node);
      if (member?.property === "process") return globalObjectOf(member.receiver, next);
      if (member && memberValueCandidatesOf(member.receiver, member.property, next)
        .some((value) => processObjectOf(value, next))) return true;
      if (ts.isElementAccessExpression(node)) {
        const key = assignmentReferenceKey(node);
        if (key !== undefined && (assignmentsByMemberPath.get(key) ?? [])
          .some((value) => processObjectOf(value, next))) return true;
      }
      return member?.property === "default" && processObjectOf(member.receiver, next);
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
      return [
        ...bindingPatternValuesOf(
          binding.node.name,
          binding.node.initializer,
          node.text,
          next
        ),
        ...(destructuredAssignmentsByBinding.get(
          `${binding.node.pos}:${node.text}`) ?? [])
      ].some((value) => processObjectOf(value, next));
    }
  }
  if (binding.kind === "parameter" && ts.isParameter(binding.node)) {
    if (ts.isIdentifier(binding.node.name)) {
        return [
          ...(parameterProcessArguments.get(binding.node) ?? []),
          binding.node.initializer,
        ...(assignmentsByBinding.get(binding.node) ?? [])]
        .filter(Boolean)
        .some((value) => processObjectOf(value, next));
    }
    if (
        (ts.isObjectBindingPattern(binding.node.name) ||
         ts.isArrayBindingPattern(binding.node.name))) {
      return [
        ...(binding.node.initializer ? bindingPatternValuesOf(
          binding.node.name,
          binding.node.initializer,
          node.text,
          next
        ) : []),
      ...(parameterProcessArguments.get(binding.node) ?? []).flatMap((value) =>
        bindingPatternValuesOf(binding.node.name, value, node.text, next)),
        ...(destructuredAssignmentsByBinding.get(
          `${binding.node.pos}:${node.text}`) ?? [])
      ].some((value) => processObjectOf(value, next));
    }
  }
  return false;
  };
  const globalObjectOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
  if (ts.isGetAccessorDeclaration(node)) {
    const returnedValues = functionReturnExpressionsOf(node, seen);
    const next = new Set(seen);
    next.add(node);
    return returnedValues
      .some((value) => globalObjectOf(value, next));
  }
  if (ts.isFunctionLike(node)) {
    const returnedValues = functionReturnExpressionsOf(node, seen);
    const next = new Set(seen);
    next.add(node);
    return returnedValues.some((value) => globalObjectOf(value, next));
  }
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
    if (ts.isCallExpression(node)) {
      const callee = unwrap(node.expression);
    const createFactory = memberAccess(callee);
    if (createFactory?.property === "create" &&
        globalPrototypeObjectOf(createFactory.receiver, seen) &&
        node.arguments[0] && globalObjectOf(node.arguments[0], seen)) return true;
      const binding = ts.isIdentifier(callee) ? resolveBinding(callee) : undefined;
      if (binding && seen.has(binding.node)) return false;
      const next = new Set(seen);
      if (binding) next.add(binding.node);
  return functionReturnExpressionsOf(node.expression)
    .some((value) => globalObjectOf(value, next));
    }
if (seen.has(node)) return false;
const memberSeen = new Set(seen);
memberSeen.add(node);
const member = memberAccess(node);
    if (member?.property === "globalThis" || member?.property === "global") {
return globalObjectOf(member.receiver, memberSeen);
    }
if (member && memberValueCandidatesOf(member.receiver, member.property, memberSeen)
  .some((value) => globalObjectOf(value, memberSeen))) return true;
  if (ts.isObjectLiteralExpression(node)) {
    return node.properties.some((property) => {
      if (ts.isSpreadAssignment(property)) return globalObjectOf(property.expression, seen);
      if (ts.isPropertyAssignment(property)) return globalObjectOf(property.initializer, seen);
      if (ts.isShorthandPropertyAssignment(property)) return globalObjectOf(property.name, seen);
      return false;
    });
  }
    if (ts.isElementAccessExpression(node)) {
      const key = assignmentReferenceKey(node);
      if (key !== undefined && (assignmentsByMemberPath.get(key) ?? [])
  .some((value) => globalObjectOf(value, memberSeen))) return true;
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
      return [
        ...bindingPatternValuesOf(
          binding.node.name,
          binding.node.initializer,
          node.text,
          next
        ),
        ...(destructuredAssignmentsByBinding.get(
          `${binding.node.pos}:${node.text}`) ?? [])
      ].some((value) => globalObjectOf(value, next));
    }
  }
  if (binding.kind === "parameter" && ts.isParameter(binding.node)) {
    if (ts.isIdentifier(binding.node.name)) {
        return [
          ...(parameterGlobalArguments.get(binding.node) ?? []),
          binding.node.initializer,
        ...(assignmentsByBinding.get(binding.node) ?? [])]
        .filter(Boolean)
        .some((value) => globalObjectOf(value, next));
    }
    if (
        (ts.isObjectBindingPattern(binding.node.name) ||
         ts.isArrayBindingPattern(binding.node.name))) {
      return [
        ...(binding.node.initializer ? bindingPatternValuesOf(
          binding.node.name,
          binding.node.initializer,
          node.text,
          next
        ) : []),
      ...(parameterGlobalArguments.get(binding.node) ?? []).flatMap((value) =>
        bindingPatternValuesOf(binding.node.name, value, node.text, next)),
        ...(destructuredAssignmentsByBinding.get(
          `${binding.node.pos}:${node.text}`) ?? [])
      ].some((value) => globalObjectOf(value, next));
    }
  }
  return false;
  };
const globalReflectOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return false;
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (!binding) return node.text === "Reflect";
    if (!binding.node || seen.has(binding.node) ||
        !(ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node)) ||
        !ts.isIdentifier(binding.node.name)) return false;
    const next = new Set(seen);
    next.add(binding.node);
    return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
      .filter(Boolean)
      .some((value) => globalReflectOf(value, next));
  }
  const member = memberAccess(node);
  return member?.property === "Reflect" && globalObjectOf(member.receiver, seen);
};
const reflectApplyReferenceOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return false;
  const member = memberAccess(node);
  if (member?.property === "apply" && globalReflectOf(member.receiver, seen)) return true;
  if (member && !seen.has(node)) {
    const next = new Set(seen);
    next.add(node);
    const receiver = unwrap(member.receiver);
    const binding = ts.isIdentifier(receiver) ? resolveBinding(receiver) : undefined;
    const container = binding?.kind === "variable" && binding.constant &&
      ts.isVariableDeclaration(binding.node) && binding.node.initializer
      ? unwrap(binding.node.initializer) : receiver;
    if (ts.isObjectLiteralExpression(container)) {
      for (const property of container.properties) {
        if (!("name" in property) ||
            staticPropertyNameOf(property.name) !== member.property) continue;
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
  if (!binding?.node || seen.has(binding.node) ||
      !(ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node))) {
    return false;
  }
  const next = new Set(seen);
  next.add(binding.node);
  if (!ts.isIdentifier(binding.node.name)) {
    return Boolean(binding.node.initializer &&
      ((globalReflectOf(binding.node.initializer, next) &&
        bindingPatternSelectsPropertyOf(
          binding.node.name, node.text, "apply"
        )) ||
       bindingPatternValuesOf(
         binding.node.name, binding.node.initializer, node.text, next
       ).some((value) => reflectApplyReferenceOf(value, next))));
  }
  return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
    .filter(Boolean)
    .some((value) => reflectApplyReferenceOf(value, next));
};
const globalStringOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return false;
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (!binding) return node.text === "String";
    if (!binding.node || seen.has(binding.node) ||
        !(ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node)) ||
        !ts.isIdentifier(binding.node.name)) return false;
    const next = new Set(seen);
    next.add(binding.node);
    return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
      .filter(Boolean)
      .some((value) => globalStringOf(value, next));
  }
  const member = memberAccess(node);
  return member?.property === "String" && globalObjectOf(member.receiver, seen);
};
const staticStringRawTagOf = (input) => {
  const member = memberAccess(unwrap(input));
  return Boolean(member && member.property === "raw" && globalStringOf(member.receiver));
};
const untrustedProcessExecPathOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return false;
  if (ts.isConditionalExpression(node)) {
    return untrustedProcessExecPathOf(node.whenTrue, seen) ||
      untrustedProcessExecPathOf(node.whenFalse, seen);
  }
  if (ts.isBinaryExpression(node)) {
    return untrustedProcessExecPathOf(node.left, seen) ||
      untrustedProcessExecPathOf(node.right, seen);
  }
  const member = memberAccess(node);
  if (member?.property === "execPath") return !processObjectOf(member.receiver, seen);
  if (!ts.isIdentifier(node)) return false;
  const binding = resolveBinding(node);
  if (!binding?.node || seen.has(binding.node) ||
      !(ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node)) ||
      !ts.isIdentifier(binding.node.name)) return false;
  const next = new Set(seen);
  next.add(binding.node);
  return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
    .filter(Boolean)
    .some((value) => untrustedProcessExecPathOf(value, next));
};
const reflectiveReadOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return false;
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (!binding?.node || seen.has(binding.node)) return false;
    const next = new Set(seen);
    next.add(binding.node);
    if (ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node)) {
      if (ts.isIdentifier(binding.node.name)) {
        return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
          .filter(Boolean).some((value) => reflectiveReadOf(value, next));
      }
      const values = [
        ...(binding.node.initializer ? bindingPatternValuesOf(
          binding.node.name,
          binding.node.initializer,
          node.text,
          next
        ) : []),
        ...(destructuredAssignmentsByBinding.get(
          `${binding.node.pos}:${node.text}`) ?? [])
      ];
      if (values.some((value) => reflectiveReadOf(value, next))) return true;
      return Boolean(binding.node.initializer &&
        globalPrototypeObjectOf(binding.node.initializer, next) &&
        ["entries", "get", "getOwnPropertyDescriptor", "getOwnPropertyDescriptors"]
          .some((property) => destructuresConstructor(binding.node.name, node.text, property)));
    }
    return false;
  }
  if (ts.isCallExpression(node)) {
    if (seen.has(node)) return false;
    const next = new Set(seen);
    next.add(node);
    return functionReturnExpressionsOf(node.expression, next)
      .some((value) => reflectiveReadOf(value, next));
  }
  const member = memberAccess(node);
  if (!member) return false;
  if ((member.property === "get" && globalReflectOf(member.receiver, seen)) ||
      (["entries", "getOwnPropertyDescriptor", "getOwnPropertyDescriptors"].includes(
        member.property) && globalPrototypeObjectOf(member.receiver, seen))) return true;
  if (seen.has(node)) return false;
  const next = new Set(seen);
  next.add(node);
  return memberValueCandidatesOf(member.receiver, member.property, next)
    .some((value) => reflectiveReadOf(value, next));
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
        const key = entry.name ? staticPropertyNameOf(entry.name) : undefined;
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
  const recordConstructorDestructuring = (target) => {
    target = unwrap(target);
    const member = assignmentMemberAccess(target);
    if (member) {
      const key = assignmentReferenceKey(target);
      if (key !== undefined) constructorDestructuredMembers.add(key);
      return;
    }
    if (ts.isElementAccessExpression(target)) {
      const key = assignmentReferenceKey(target);
      if (key !== undefined) constructorDestructuredMembers.add(key);
      return;
    }
    if (!ts.isIdentifier(target)) return;
    const binding = resolveBinding(target);
    if (binding?.kind === "variable" || binding?.kind === "opaque") {
      constructorDestructuredBindings.add(binding.node);
    }
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
        let targetValue = ts.isShorthandPropertyAssignment(property)
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
        const selected = memberValueCandidatesOf(source, key);
        const patternDefault = targetValue && ts.isBinaryExpression(targetValue) &&
          targetValue.operatorToken.kind === ts.SyntaxKind.EqualsToken
          ? targetValue.right : undefined;
        if (patternDefault) targetValue = unwrap(targetValue.left);
        const defaultValue = ts.isShorthandPropertyAssignment(property)
          ? property.objectAssignmentInitializer
          : patternDefault;
    recordDestructuredPropertyAssignment(targetValue, source, key);
        const resolvedValues = selected.length > 0
          ? selected
          : defaultValue ? [defaultValue] : [];
        if (key === "constructor" && resolvedValues.length === 0) {
          recordConstructorDestructuring(targetValue);
        }
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
        for (const value of memberValueCandidatesOf(source, String(index))) {
          recordResolvedAssignments(element, value);
        }
      }
    }
  };
  const inspectProcessDestructuring = (target) => {
    for (const entry of destructuringEntries(target)) {
      const property = entry.name ? staticPropertyNameOf(entry.name) : undefined;
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
      const property = entry.name ? staticPropertyNameOf(entry.name) : undefined;
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
    } else if (property === "require") {
      add(entry.node, "global require capability is forbidden in supervisor source");
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
  const destructuresConstructor = (pattern, targetName, propertyName = "constructor") => {
    if (ts.isObjectBindingPattern(pattern)) {
      for (const element of pattern.elements) {
        const key = element.propertyName
          ? staticPropertyNameOf(element.propertyName)
          : ts.isIdentifier(element.name) ? element.name.text : undefined;
        if (ts.isIdentifier(element.name) && element.name.text === targetName &&
            key === propertyName) return true;
        if ((ts.isObjectBindingPattern(element.name) ||
             ts.isArrayBindingPattern(element.name)) &&
            destructuresConstructor(element.name, targetName, propertyName)) return true;
      }
    }
    if (ts.isArrayBindingPattern(pattern)) {
      return pattern.elements.some((element) =>
        ts.isBindingElement(element) &&
        (ts.isObjectBindingPattern(element.name) ||
         ts.isArrayBindingPattern(element.name)) &&
        destructuresConstructor(element.name, targetName, propertyName));
    }
    return false;
  };
  const globalFunctionObjects = new Set([
    "Array", "ArrayBuffer", "BigInt", "Boolean", "Date", "Error", "EvalError",
    "Function", "Map", "Number", "Object", "Promise", "Proxy", "RangeError",
    "ReferenceError", "RegExp", "Set", "String", "Symbol", "SyntaxError",
    "TypeError", "URIError", "WeakMap", "WeakSet"
  ]);
  const globalFunctionObjectOf = (input) => {
    const node = unwrap(input);
    if (ts.isIdentifier(node)) return !resolveBinding(node) && globalFunctionObjects.has(node.text);
    const member = memberAccess(node);
    return Boolean(member && globalFunctionObjects.has(member.property) &&
      globalObjectOf(member.receiver));
  };
  const constructorDestructuringOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!ts.isIdentifier(node)) return false;
    const binding = resolveBinding(node);
    if (!binding || seen.has(binding.node)) return false;
    if (constructorDestructuredBindings.has(binding.node)) return true;
    const next = new Set(seen);
    next.add(binding.node);
    const declaration = ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node)
      ? binding.node : undefined;
    const pattern = declaration?.name;
    if (!pattern || (!ts.isObjectBindingPattern(pattern) &&
        !ts.isArrayBindingPattern(pattern))) return false;
    const selected = declaration.initializer
      ? bindingPatternValuesOf(pattern, declaration.initializer, node.text, next)
      : [];
    return selected.length === 0 && destructuresConstructor(pattern, node.text);
  };
  const classMethodCandidatesOf = (input, property, seen = new Set()) => {
    const methods = [];
    for (const value of resolvedValuesOf(input, seen)) {
      if (!ts.isNewExpression(value)) continue;
      const expression = unwrap(value.expression);
      let owner = ts.isClassExpression(expression) ? expression : undefined;
      if (!owner && ts.isIdentifier(expression)) {
        const binding = resolveBinding(expression);
        if (binding && ts.isClassDeclaration(binding.node)) owner = binding.node;
      }
      if (!owner || seen.has(owner)) continue;
      const next = new Set(seen);
      next.add(owner);
      for (const member of owner.members) {
        if (ts.isMethodDeclaration(member) &&
            staticPropertyNameOf(member.name) === property) methods.push(member);
      }
    }
    return methods;
  };
  const functionValueOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
    if (ts.isFunctionExpression(node) || ts.isArrowFunction(node) ||
        ts.isClassExpression(node) || ts.isFunctionDeclaration(node) ||
        ts.isClassDeclaration(node) || ts.isMethodDeclaration(node)) return true;
    if (globalFunctionObjectOf(node)) return true;
    if (ts.isConditionalExpression(node)) {
      return functionValueOf(node.whenTrue, seen) || functionValueOf(node.whenFalse, seen);
    }
    if (ts.isBinaryExpression(node) &&
        [ts.SyntaxKind.CommaToken, ts.SyntaxKind.AmpersandAmpersandToken,
         ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken]
          .includes(node.operatorToken.kind)) {
      return functionValueOf(node.left, seen) || functionValueOf(node.right, seen);
    }
    const member = memberAccess(node);
    if (member) {
      return memberValueCandidatesOf(member.receiver, member.property, seen)
        .some((value) => functionValueOf(value, seen)) ||
        classMethodCandidatesOf(member.receiver, member.property, seen)
          .some((value) => functionValueOf(value, seen));
    }
    if (!ts.isIdentifier(node)) return false;
    const binding = resolveBinding(node);
    if (!binding || seen.has(binding.node)) return false;
    if (binding.kind === "opaque" &&
        (ts.isFunctionDeclaration(binding.node) || ts.isClassDeclaration(binding.node))) {
      return true;
    }
    const next = new Set(seen);
    next.add(binding.node);
    if ((binding.kind === "variable" || binding.kind === "opaque") &&
        ts.isVariableDeclaration(binding.node) &&
        binding.node.initializer &&
        (ts.isObjectBindingPattern(binding.node.name) ||
         ts.isArrayBindingPattern(binding.node.name))) {
      return bindingPatternValuesOf(
        binding.node.name,
        binding.node.initializer,
        node.text,
        next
      ).some((value) => functionValueOf(value, next));
    }
    if (binding.kind === "parameter" && ts.isParameter(binding.node) &&
        binding.node.initializer) {
      if (ts.isIdentifier(binding.node.name)) {
        return functionValueOf(binding.node.initializer, next);
      }
      return bindingPatternValuesOf(
        binding.node.name,
        binding.node.initializer,
        node.text,
        next
      ).some((value) => functionValueOf(value, next));
    }
    if (binding.kind === "variable" && ts.isVariableDeclaration(binding.node) &&
        ts.isIdentifier(binding.node.name)) {
      return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
        .filter(Boolean)
        .some((value) => functionValueOf(value, next));
    }
    return false;
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
    if (constructorDestructuredMembers.has(assignmentReferenceKey(node))) return true;
    if (!ts.isIdentifier(node)) return false;
    const binding = resolveBinding(node);
    if (!binding || seen.has(binding.node)) return false;
    const next = new Set(seen);
    next.add(binding.node);
    if ((binding.kind === "variable" || binding.kind === "opaque" ||
         binding.kind === "parameter")) {
      const source = ts.isVariableDeclaration(binding.node) ||
        ts.isParameter(binding.node) ? binding.node.initializer : undefined;
      const pattern = ts.isVariableDeclaration(binding.node) ||
        ts.isParameter(binding.node) ? binding.node.name : undefined;
      if (pattern && (ts.isObjectBindingPattern(pattern) ||
                      ts.isArrayBindingPattern(pattern))) {
        const values = source ? bindingPatternValuesOf(
          pattern,
          source,
          node.text,
          next
        ) : [];
        if (values.length > 0) {
          return values.some((value) => constructorFunctionOf(value, next));
        }
        if (destructuresConstructor(pattern, node.text)) return true;
      }
    }
    if (constructorDestructuredBindings.has(binding.node)) return true;
    if (binding.kind === "variable" && ts.isVariableDeclaration(binding.node) &&
        ts.isIdentifier(binding.node.name)) {
      return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
        .filter(Boolean)
        .some((value) => constructorFunctionOf(value, next));
    }
    return false;
  };
  const globalPrototypeObjectOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return false;
  if (ts.isFunctionLike(node)) {
    const returnedValues = functionReturnExpressionsOf(node, seen);
    const next = new Set(seen);
    next.add(node);
    return returnedValues
      .some((value) => globalPrototypeObjectOf(value, next));
  }
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (!binding) return ["Object", "Reflect"].includes(node.text);
      if (!binding.node || seen.has(binding.node) ||
          !(ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node)) ||
          !ts.isIdentifier(binding.node.name)) return false;
      const next = new Set(seen);
      next.add(binding.node);
      return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
        .filter(Boolean)
        .some((value) => globalPrototypeObjectOf(value, next));
    }
    const member = memberAccess(node);
  if (member && !seen.has(node)) {
    const next = new Set(seen);
    next.add(node);
    if (memberValueCandidatesOf(member.receiver, member.property, next)
      .some((value) => globalPrototypeObjectOf(value, next))) return true;
  }
    return Boolean(member && ["Object", "Reflect"].includes(member.property) &&
      globalObjectOf(member.receiver, seen));
  };
const staticMethodReferenceOf = (
  input, property, ownerOf, seen = new Set()
) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  const next = new Set(seen);
  next.add(node);
  if (ts.isGetAccessorDeclaration(node) || ts.isFunctionLike(node)) {
    return functionReturnExpressionsOf(node, next)
      .some((value) => staticMethodReferenceOf(value, property, ownerOf, next));
  }
  const member = memberAccess(node);
  if (member) {
    if (member.property === property && ownerOf(member.receiver, next)) return true;
    if (memberValueCandidatesOf(member.receiver, member.property, next)
      .some((value) => staticMethodReferenceOf(value, property, ownerOf, next))) {
      return true;
    }
  }
  if (ts.isCallExpression(node)) {
    return functionReturnExpressionsOf(node.expression, next)
      .some((value) => staticMethodReferenceOf(value, property, ownerOf, next));
  }
  if (!ts.isIdentifier(node)) return false;
  const binding = resolveBinding(node);
  if (!binding?.node || seen.has(binding.node)) return false;
  const bindingNext = new Set(next);
  bindingNext.add(binding.node);
  if ((destructuredPropertyAssignmentsByBinding.get(binding.node) ?? [])
    .some((assignment) => assignment.property === property &&
      ownerOf(assignment.source, bindingNext))) return true;
  if (ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node)) {
    if (!ts.isIdentifier(binding.node.name)) {
      return Boolean(binding.node.initializer &&
        ownerOf(binding.node.initializer, next) &&
        bindingPatternSelectsPropertyOf(binding.node.name, node.text, property)) ||
        bindingPatternValuesOf(
          binding.node.name, binding.node.initializer, node.text, next
        ).some((value) => staticMethodReferenceOf(value, property, ownerOf, next));
    }
    return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
      .filter(Boolean)
      .some((value) => staticMethodReferenceOf(value, property, ownerOf, next));
  }
  return false;
};
const globalCapabilitySourceOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  const next = new Set(seen);
  next.add(node);
  if (ts.isIdentifier(node) && ["Object", "Reflect"].includes(node.text)) {
    return true;
  }
  if (globalObjectOf(node, next) || globalPrototypeObjectOf(node, next) ||
      staticMethodReferenceOf(
        node, "create", globalPrototypeObjectOf, next
      ) || staticMethodReferenceOf(node, "assign", globalObjectOf, next)) {
    return true;
  }
  const member = memberAccess(node);
  if (member && ["create", "assign"].includes(member.property) &&
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
    ts.isParameter(binding.node)) &&
    !seen.has(binding.node) &&
    [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
      .filter(Boolean)
      .some((value) => globalCapabilitySourceOf(value, next)));
};
const boundStaticMethodPrefixPlanOf = (
  input, property, ownerOf, seen = new Set()
) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return undefined;
  const next = new Set(seen);
  next.add(node);
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    return boundStaticMethodPrefixPlanOf(node.right, property, ownerOf, next);
  }
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (binding?.kind === "variable" &&
        ts.isVariableDeclaration(binding.node) &&
        ts.isIdentifier(binding.node.name) && binding.node.initializer) {
      return boundStaticMethodPrefixPlanOf(
        binding.node.initializer, property, ownerOf, next
      );
    }
    return undefined;
  }
  if (!ts.isCallExpression(node)) return undefined;
  const bind = bindMethodReferenceOf(node.expression, next);
  if (bind?.property === "bind" &&
      staticMethodReferenceOf(bind.receiver, property, ownerOf, next)) {
    return dropLeadingCallArgument(fixedCallArgumentPlanOf(node.arguments));
  }
const wrapper = memberAccess(node.expression);
if (wrapper && ["apply", "call"].includes(wrapper.property)) {
  const intrinsicBind = bindMethodReferenceOf(wrapper.receiver, next);
  if (intrinsicBind?.property === "bind" &&
      staticMethodReferenceOf(
        intrinsicBind.receiver, property, ownerOf, next
      )) {
    const plan = wrapper.property === "call"
      ? fixedCallArgumentPlanOf(node.arguments.slice(1))
      : argumentArrayPlanOf(node.arguments[1], next);
    return dropLeadingCallArgument(plan);
  }
}
if (reflectApplyReferenceOf(node.expression, next)) {
  const intrinsicBind = bindMethodReferenceOf(node.arguments[0], next);
  if (intrinsicBind?.property === "bind" &&
      staticMethodReferenceOf(
        intrinsicBind.receiver, property, ownerOf, next
      )) {
    return dropLeadingCallArgument(
      argumentArrayPlanOf(node.arguments[2], next)
    );
  }
}
  if (genericBindMethodOf(node.expression, next) &&
      staticMethodReferenceOf(node.arguments[0], property, ownerOf, next)) {
    return fixedCallArgumentPlanOf(node.arguments.slice(2));
  }
  return undefined;
};
const staticMethodInvocationPlanOf = (
  call, property, ownerOf, seen = new Set()
) => {
  const callee = unwrap(call.expression);
  if (!callee) return undefined;
  const next = new Set(seen);
  next.add(call);
  if (staticMethodReferenceOf(callee, property, ownerOf, next)) {
    return fixedCallArgumentPlanOf(call.arguments);
  }
  if (reflectApplyReferenceOf(callee, next)) {
    const target = call.arguments[0];
    const applicationPlan = argumentArrayPlanOf(call.arguments[2], next);
    if (staticMethodReferenceOf(target, property, ownerOf, next)) {
      return applicationPlan;
    }
    const boundPlan = boundStaticMethodPrefixPlanOf(
      target, property, ownerOf, next
    );
    return boundPlan
      ? mergeCallArgumentPlans(boundPlan, applicationPlan) : undefined;
  }
  const wrapper = memberAccess(callee);
  if (wrapper && ["apply", "call"].includes(wrapper.property) &&
      staticMethodReferenceOf(wrapper.receiver, property, ownerOf, next)) {
    return wrapper.property === "call"
      ? fixedCallArgumentPlanOf(call.arguments.slice(1))
      : argumentArrayPlanOf(call.arguments[1], next);
  }
  const boundPlan = boundStaticMethodPrefixPlanOf(
    callee, property, ownerOf, next
  );
  return boundPlan === undefined
    ? undefined
    : mergeCallArgumentPlans(boundPlan, fixedCallArgumentPlanOf(call.arguments));
};
const objectCreatePrototypeValuesOf = (call, seen = new Set()) => {
  const plan = staticMethodInvocationPlanOf(
    call, "create", globalPrototypeObjectOf, seen
  );
if (plan) return callArgumentCandidatesAt(plan, 0).filter(Boolean);
if (seen.has(call)) return [];
const next = new Set(seen);
next.add(call);
return [...new Set(functionReturnExpressionsOf(call.expression, next)
  .filter((value) => ts.isCallExpression(value))
  .flatMap((value) => objectCreatePrototypeValuesOf(value, next)))];
};
const objectAssignInvocationArgumentsOf = (call, seen = new Set()) => {
  const plan = staticMethodInvocationPlanOf(
    call, "assign", globalPrototypeObjectOf, seen
  );
if (plan) return [...plan.before, ...plan.after].filter(Boolean);
if (seen.has(call)) return undefined;
const next = new Set(seen);
next.add(call);
const returnedArguments = functionReturnExpressionsOf(call.expression, next)
  .filter((value) => ts.isCallExpression(value))
  .flatMap((value) => objectAssignInvocationArgumentsOf(value, next) ?? []);
return returnedArguments.length > 0 ? returnedArguments : undefined;
};
  const getPrototypeOfFunctionOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    const method = memberAccess(node);
    if (method?.property === "getPrototypeOf") {
      return globalPrototypeObjectOf(method.receiver);
    }
    if (!ts.isIdentifier(node)) return false;
    const binding = resolveBinding(node);
    if (!binding || seen.has(binding.node)) return false;
    const next = new Set(seen);
    next.add(binding.node);
    const declaration = ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node)
      ? binding.node : undefined;
    const pattern = declaration?.name;
    if (pattern && (ts.isObjectBindingPattern(pattern) || ts.isArrayBindingPattern(pattern)) &&
        destructuresConstructor(pattern, node.text, "getPrototypeOf")) {
      const values = declaration.initializer
        ? bindingPatternValuesOf(pattern, declaration.initializer, node.text, next)
        : [];
      if (values.some((value) => getPrototypeOfFunctionOf(value, next))) return true;
      if (globalPrototypeObjectOf(declaration.initializer)) return true;
    }
    if (binding.kind !== "variable" || !declaration ||
        !ts.isIdentifier(declaration.name) || !declaration.initializer) return false;
    return [declaration.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
      .filter(Boolean)
      .some((value) => getPrototypeOfFunctionOf(value, next));
  };
  const functionPrototypeObjectOf = (input, seen = new Set()) => {
    const node = unwrap(input);
    if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (binding?.kind !== "variable" || !ts.isVariableDeclaration(binding.node) ||
          !ts.isIdentifier(binding.node.name) || seen.has(binding.node)) return false;
      const next = new Set(seen);
      next.add(binding.node);
      return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
        .filter(Boolean)
        .some((value) => functionPrototypeObjectOf(value, next));
    }
    if (ts.isCallExpression(node) && node.arguments.length > 0 &&
        getPrototypeOfFunctionOf(node.expression, seen)) {
      return functionValueOf(node.arguments[0], seen) ||
        constructorFunctionOf(node.arguments[0], seen);
    }
    const member = memberAccess(node);
    return member?.property === "__proto__" &&
      (functionValueOf(member.receiver, seen) ||
       constructorFunctionOf(member.receiver, seen));
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
      if (seen.has(binding.node)) return false;
      if (constructorDestructuringOf(node, seen)) return true;
      const next = new Set(seen);
      next.add(binding.node);
      if (binding.kind === "variable" && ts.isVariableDeclaration(binding.node) &&
          ts.isIdentifier(binding.node.name)) {
        return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
          .filter(Boolean)
          .some((value) => dynamicFunctionOf(value, next));
      }
      return false;
    }
    if (constructorDestructuredMembers.has(assignmentReferenceKey(node))) return true;
    const member = memberAccess(node);
    if (member?.property === "Function" && globalObjectOf(member.receiver)) return true;
    if (member?.property !== "constructor") return false;
    if (functionPrototypeObjectOf(member.receiver, seen)) return true;
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
        if (!typeOnly && DYNAMIC_EVALUATION_MODULES.has(module)) {
          add(node, "runtime dynamic-evaluation re-export is forbidden");
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
      if (SHELL_MODULES.has(module) && hasRuntimeImport(node)) {
        add(node, "shell-capable runner imports are forbidden");
      }
      if (MODULE_LOADING_MODULES.has(module) && hasRuntimeImport(node)) {
        add(node, "node:module loading is forbidden in supervisor source");
      }
      if (DYNAMIC_EVALUATION_MODULES.has(module) && hasRuntimeImport(node)) {
        add(node, "dynamic evaluation module loading is forbidden in supervisor source");
      }
      if (["node:process", "process"].includes(module) &&
          !node.importClause?.isTypeOnly &&
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
      const invoked = memberAccess(unwrap(node.expression));
      if (invoked?.property === "apply" && globalReflectOf(invoked.receiver) &&
          requireReferenceOf(node.arguments[0])) {
        add(node, "dynamic require forbidden in supervisor source");
      }
      if (called === "createRequire" || called === "_parse") {
        add(node, "indirect process loading, eval, or private shim parsing is forbidden");
      }
      const indirectReflective = invoked && ["apply", "bind", "call"].includes(
        invoked.property) && reflectiveReadOf(invoked.receiver);
      if (indirectReflective) {
        add(node, "reflective access to dynamic execution or process capabilities forbidden");
      } else if (reflectiveReadOf(node.expression)) {
        const receiver = node.arguments[0];
        const property = staticStringOf(node.arguments[1]);
        const globalCapabilityReceiver = globalObjectOf(receiver) ||
          globalFunctionObjectOf(receiver);
        const sensitive = property === undefined
          ? globalCapabilityReceiver || processObjectOf(receiver)
          : (globalCapabilityReceiver &&
            ["Function", "eval", "process", "constructor", "require"].includes(property)) ||
            (processObjectOf(receiver) && property === "getBuiltinModule");
        if (sensitive) {
          add(node, "reflective access to dynamic execution or process capabilities forbidden");
        }
      }
      const callee = unwrap(node.expression);
      const runner = ts.isIdentifier(callee) ? runnerOf(callee) : undefined;
      if (runner) {
        if (node.arguments.some((argument) => ts.isSpreadElement(argument))) {
          add(node, "spread process-runner call arguments cannot prove native dispatch");
        }
        inspectLaunchOptions(node, runner);
        if (untrustedProcessExecPathOf(node.arguments[0])) {
          add(node, "untrusted process.execPath launch source is forbidden");
        }
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
        (ts.isIdentifier(unwrap(node.left)) || assignmentMemberAccess(node.left)) &&
        requireReferenceOf(node.right)) {
      add(node, "aliasing require to bypass import inspection is forbidden");
    }
    if ((ts.isArrayLiteralExpression(node) || ts.isObjectLiteralExpression(node)) &&
        requireReferenceInContainerOf(node)) {
      add(node, "require capability escape through a container is forbidden");
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
        if (globalObjectOf(node.right) || globalPrototypeObjectOf(node.right) ||
            globalCapabilitySourceOf(node.right)) {
          inspectGlobalDestructuring(target);
          for (const property of target.properties) {
            if (property.name && ts.isComputedPropertyName(property.name) &&
                assignmentPropertyName(property.name) === undefined) {
              add(property, "dynamic global capability destructuring is unproven in supervisor source");
            }
          }
        }
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
          !staticStringRawTagOf(value.tag) ||
          !ts.isNoSubstitutionTemplateLiteral(value.template)) {
        add(node, "embedded POSIX launcher must be a static String.raw template");
      } else {
        findings.push(...inspectJavaScript(filename + "#POSIX_GROUP_LAUNCHER",
          value.template.rawText ?? value.template.text, true));
      }
    }
    ts.forEachChild(node, visit);
  };

  // Seed direct local calls with their known capability arguments. Repeating
  // the finite parameter/argument pairs handles short helper chains without
  // creating a repository-wide call graph.
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
    if (ts.isConditionalExpression(node)) {
      const whenTrue = fixedSpreadValuesOf(node.whenTrue, next);
      const whenFalse = fixedSpreadValuesOf(node.whenFalse, next);
      return whenTrue && whenFalse ? [...whenTrue, ...whenFalse] : undefined;
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
      return fixedSpreadValuesOf(node.right, next);
    }
  if (ts.isCallExpression(node)) {
    const returned = functionReturnExpressionsOf(node.expression, next);
    if (returned.length === 0) return undefined;
    const expanded = returned.map((value) => fixedSpreadValuesOf(value, next));
    if (expanded.some((value) => value === undefined)) return undefined;
    return expanded.flat();
  }
    const values = [];
    for (const value of resolvedValuesOf(node, next)) {
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
const arrayMutationValueCarriesCapability = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  const next = new Set(seen);
  next.add(node);
  if (ts.isSpreadElement(node)) {
    return arrayMutationValueCarriesCapability(node.expression, next);
  }
  if (processObjectOf(node, next) || globalObjectOf(node, next) ||
      requireReferenceOf(node, next)) return true;
  if (ts.isConditionalExpression(node)) {
    return arrayMutationValueCarriesCapability(node.whenTrue, next) ||
      arrayMutationValueCarriesCapability(node.whenFalse, next);
  }
  if (ts.isArrayLiteralExpression(node)) {
    return node.elements.some((element) =>
      !ts.isOmittedExpression(element) &&
      arrayMutationValueCarriesCapability(element, next));
  }
  if (!ts.isIdentifier(node)) return false;
  const binding = resolveBinding(node);
  return Boolean(binding?.kind === "variable" &&
    ts.isVariableDeclaration(binding.node) && binding.node.initializer &&
    arrayMutationValueCarriesCapability(binding.node.initializer, next));
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
      if (arrayMutationValueCarriesCapability(node.right) ||
          (arrayMutationIsConditional(node) && previousValues.some(
            (value) => arrayMutationValueCarriesCapability(value)
          ))) {
        add(node, "capability escape through mutable array mutation is unproven in supervisor source");
      }
      mutations.push({
        kind: "set",
        start: node.getStart(file),
        index: staticAssignmentNameOf(target.argumentExpression),
        values: [unwrap(node.right)]
      });
      arrayMutationValuesByBinding.set(binding, mutations);
    }
  }
  if (ts.isCallExpression(node)) {
    const member = memberAccess(node.expression);
    const binding = member && [
      "push", "unshift", "splice", "fill", "copyWithin",
      "reverse", "sort", "pop", "shift"
    ].includes(member.property)
      ? arrayBindingOf(member.receiver) : undefined;
    if (binding) {
      const kind = member.property;
      const mutations = arrayMutationValuesByBinding.get(binding) ?? [];
      const previousValues = [
        binding.initializer,
        ...mutations.flatMap((mutation) => mutation.values)
      ].filter(Boolean);
      if (!["push", "unshift", "splice"].includes(kind)) {
        if (node.arguments.some((value) =>
          arrayMutationValueCarriesCapability(value)) ||
            previousValues.some((value) =>
              arrayMutationValueCarriesCapability(value))) {
          add(node, "capability escape through mutable array method is unproven in supervisor source");
        }
      } else {
      const values = kind === "splice" ? node.arguments.slice(2) : node.arguments;
      const deleteCount = kind === "splice" && node.arguments.length > 1
        ? staticAssignmentNameOf(node.arguments[1])
        : kind === "splice" ? "rest" : undefined;
      if (values.some((value) => arrayMutationValueCarriesCapability(value))) {
        add(node, "capability escape through mutable array mutation is unproven in supervisor source");
      }
      if (arrayMutationIsConditional(node) && previousValues.some(
        (value) => arrayMutationValueCarriesCapability(value)
      )) {
        add(node, "conditional mutable array mutation is unproven in supervisor source");
      }
      const deletesValues = deleteCount === "rest" ||
        deleteCount === undefined || Number(deleteCount) > 0;
      if (deletesValues && previousValues.some(
        (value) => arrayMutationValueCarriesCapability(value)
      )) {
        add(node, "capability escape through mutable array splice is unproven in supervisor source");
      }
      mutations.push({
        kind,
        start: node.getStart(file),
        index: kind === "splice"
          ? staticAssignmentNameOf(node.arguments[0]) : undefined,
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
    const values = resolvedValuesOf(node, next).filter((value) => value !== node);
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
    const prototypes = objectCreatePrototypeValuesOf(node, next);
    if (prototypes.length > 0) {
      return prototypes.map((value) => argumentArrayPlanOf(value, next))
        .reduce((left, right) => mergeCallArgumentPlans(left, right));
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
      const objects = objectValueCandidatesOf(candidate, next);
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
          const key = staticPropertyNameOf(property.name);
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
        const key = staticPropertyNameOf(property.name);
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
            const candidate = staticNumericNameOf(unwrap(returned[0]));
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
          const candidate = value && staticNumericNameOf(unwrap(value));
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
      const values = [...resolvedValuesOf(candidate, next)];
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
  const member = memberAccess(node);
  if (member) {
    const next = new Set(seen);
    next.add(node);
    for (const value of memberValueCandidatesOf(
      member.receiver, member.property, next
    )) {
      const resolved = bindMethodReferenceOf(value, next);
      if (resolved) return resolved;
    }
    if (member.property === "bind") return member;
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
const genericBindMethodOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  if (ts.isFunctionLike(node)) {
    const returnedValues = functionReturnExpressionsOf(node, seen);
    const next = new Set(seen);
    next.add(node);
    return returnedValues
      .some((value) => genericBindMethodOf(value, next));
  }
  const bind = memberAccess(node);
  const prototype = bind?.property === "bind"
    ? memberAccess(unwrap(bind.receiver)) : undefined;
  if (prototype?.property === "prototype" &&
      globalFunctionObjectOf(prototype.receiver)) return true;
  const next = new Set(seen);
  next.add(node);
  if (bind && memberValueCandidatesOf(bind.receiver, bind.property, next)
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
};
const storedBindInvocationOf = (input, invocationPlan, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return undefined;
  const next = new Set(seen);
  next.add(node);
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (binding?.node && seen.has(binding.node)) return undefined;
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
  if (bind?.property === "bind") {
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
  const bindWrapper = memberAccess(unwrap(node.expression));
  if (bindWrapper && ["apply", "call"].includes(bindWrapper.property)) {
    const aliasedBind = bindMethodReferenceOf(bindWrapper.receiver, next);
    const genericBind = genericBindMethodOf(bindWrapper.receiver, next);
    const functions = genericBind
      ? localFunctionValuesOf(node.arguments[0], next)
      : aliasedBind?.property === "bind"
        ? localFunctionValuesOf(aliasedBind.receiver, next) : [];
    if (functions.length > 0) {
      const bindArguments = bindWrapper.property === "call"
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
      : reflectedBind?.property === "bind"
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
    const bind = memberAccess(unwrap(callee.expression));
    if (bind?.property === "bind") {
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
  const wrapper = memberAccess(callee);
  if (wrapper?.property === "bind") {
    const functions = localFunctionValuesOf(wrapper.receiver);
    if (functions.length > 0) {
      return { functions, plan: fixedCallArgumentPlanOf(call.arguments.slice(1)) };
    }
  }
  if (wrapper && ["apply", "call"].includes(wrapper.property)) {
    const functions = localFunctionValuesOf(wrapper.receiver);
    if (functions.length > 0) {
      return {
        functions,
        plan: wrapper.property === "call"
          ? fixedCallArgumentPlanOf(call.arguments.slice(1))
          : argumentArrayPlanOf(call.arguments[1])
      };
    }
    const boundInvocation = storedBindInvocationOf(
      wrapper.receiver,
      wrapper.property === "call"
        ? fixedCallArgumentPlanOf(call.arguments.slice(1))
        : argumentArrayPlanOf(call.arguments[1])
    );
    if (boundInvocation) return boundInvocation;
    if (reflectApplyReferenceOf(wrapper.receiver)) {
      const reflectedArguments = wrapper.property === "call"
        ? call.arguments.slice(1)
        : fixedSpreadValuesOf(call.arguments[1]);
      const reflected = reflectedArguments &&
        reflectApplyInvocationOf(reflectedArguments);
      if (reflected) return reflected;
    }
  }
  return undefined;
};
  const bindingNamesOf = (pattern, names = []) => {
    for (const element of pattern.elements) {
    if (!ts.isBindingElement(element)) continue;
      if (ts.isIdentifier(element.name)) {
        names.push(element.name.text);
      } else {
        bindingNamesOf(element.name, names);
      }
    }
    return names;
  };
const destructuredParameterValueCandidatesOf = (reference, property, seen) => {
  const binding = resolveBinding(reference);
  if (binding?.kind !== "parameter" || !ts.isParameter(binding.node) ||
      seen.has(binding.node)) return [];
  const next = new Set(seen);
  next.add(binding.node);
  if (ts.isIdentifier(binding.node.name) && binding.node.dotDotDotToken) {
    if (!/^\d+$/.test(property)) return [];
    return (parameterRestArguments.get(binding.node) ?? []).flatMap((plan) =>
      callArgumentCandidatesAt(plan, Number(property)));
  }
  if (ts.isIdentifier(binding.node.name)) return [];
  const sources = [
    ...(parameterProcessArguments.get(binding.node) ?? []),
    ...(parameterGlobalArguments.get(binding.node) ?? []),
    ...(parameterRequireArguments.get(binding.node) ?? [])
  ];
  const containers = sources.flatMap((source) =>
    bindingPatternValuesOf(
      binding.node.name, source, reference.text, next
    ));
  return containers.flatMap((container) =>
    memberValueCandidatesOf(container, property, next));
};
const hasRestBindingOf = (pattern) =>
  (ts.isObjectBindingPattern(pattern) || ts.isArrayBindingPattern(pattern)) &&
  pattern.elements.some((element) => ts.isBindingElement(element) &&
    (Boolean(element.dotDotDotToken) || hasRestBindingOf(element.name)));
const containerCarriesCapabilityOf = (input, predicate, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  if (predicate(node)) return true;
  const next = new Set(seen);
  next.add(node);
  if (ts.isArrayLiteralExpression(node)) {
    return node.elements.some((element) => !ts.isOmittedExpression(element) &&
      containerCarriesCapabilityOf(
        ts.isSpreadElement(element) ? element.expression : element, predicate, next
      ));
  }
  if (!ts.isObjectLiteralExpression(node)) return false;
  return node.properties.some((property) =>
    ts.isPropertyAssignment(property)
      ? containerCarriesCapabilityOf(property.initializer, predicate, next)
      : ts.isShorthandPropertyAssignment(property)
        ? containerCarriesCapabilityOf(property.name, predicate, next)
        : ts.isSpreadAssignment(property) &&
          containerCarriesCapabilityOf(property.expression, predicate, next));
};
  const carriesParameterCapabilityOf = (parameter, argument, predicate) => {
    if (ts.isIdentifier(parameter.name)) return predicate(argument);
  if (bindingNamesOf(parameter.name).some((name) =>
    bindingPatternValuesOf(parameter.name, argument, name)
      .some((value) => predicate(value)))) {
    return true;
  }
  return hasRestBindingOf(parameter.name) &&
    containerCarriesCapabilityOf(argument, predicate);
  };
  const recordParameterArgument = (store, parameter, argument) => {
    const values = store.get(parameter) ?? [];
    if (values.includes(argument)) return false;
    values.push(argument);
    store.set(parameter, values);
    return true;
  };
const recordCapabilityArgumentsOf = (parameter, plan, offset = 0) => {
  const positionedPlan = offset === 0 ? plan : { ...plan, offset };
  if (ts.isIdentifier(parameter.name)) {
    const plans = parameterRestArguments.get(parameter) ?? [];
    if (!plans.some((stored) => callArgumentPlansEqual(stored, positionedPlan))) {
      plans.push(positionedPlan);
      parameterRestArguments.set(parameter, plans);
    }
    return;
  }
  if (!ts.isArrayBindingPattern(parameter.name)) return;
  for (let index = 0; index < parameter.name.elements.length; index += 1) {
    const element = parameter.name.elements[index];
    if (!ts.isBindingElement(element)) continue;
    const candidates = callArgumentCandidatesAt(positionedPlan, index);
    for (const name of ts.isIdentifier(element.name)
      ? [element.name.text] : bindingNamesOf(element.name)) {
      const values = candidates.flatMap((candidate) => !candidate ? [] :
        ts.isIdentifier(element.name) ? [candidate]
          : bindingPatternValuesOf(element.name, candidate, name, new Set()));
      if (values.length === 0) continue;
      const key = `${parameter.pos}:${name}`;
      const stored = destructuredAssignmentsByBinding.get(key) ?? [];
      stored.push(...values);
      destructuredAssignmentsByBinding.set(key, stored);
    }
  }
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
  let capabilityArgumentsChanged = true;
  while (capabilityArgumentsChanged) {
    capabilityArgumentsChanged = false;
    const collect = (node) => {
      if (ts.isCallExpression(node)) {
      const invocation = localInvocationOf(node);
      const alternatives = invocation?.alternatives ?? [invocation].filter(Boolean);
      for (const alternative of alternatives) {
      const { functions, plan } = alternative;
      for (const fn of functions) {
        capabilityArgumentsChanged = recordPlan(
          functionArgumentsPlans, fn, plan
        ) || capabilityArgumentsChanged;
        for (let index = 0; index < fn.parameters.length; index += 1) {
            const parameter = fn.parameters[index];
          if (parameter.dotDotDotToken) {
            recordCapabilityArgumentsOf(parameter, plan, index);
            break;
          }
          for (const argument of callArgumentCandidatesAt(plan, index)) {
            if (!argument) continue;
            capabilityArgumentsChanged = recordParameterFunctions(
              parameter, localFunctionValuesOf(argument)
            ) || capabilityArgumentsChanged;
            if (carriesParameterCapabilityOf(
              parameter, argument, processObjectOf
            )) {
              capabilityArgumentsChanged = recordParameterArgument(
                parameterProcessArguments, parameter, argument
              ) || capabilityArgumentsChanged;
            }
            if (carriesParameterCapabilityOf(
              parameter, argument, globalObjectOf
            )) {
              capabilityArgumentsChanged = recordParameterArgument(
                parameterGlobalArguments, parameter, argument
              ) || capabilityArgumentsChanged;
            }
            if (carriesParameterCapabilityOf(
              parameter, argument, requireReferenceOf
            )) {
              capabilityArgumentsChanged = recordParameterArgument(
                parameterRequireArguments, parameter, argument
              ) || capabilityArgumentsChanged;
            }
          }
      }
          }
        }
      }
      ts.forEachChild(node, collect);
    };
    collect(file);
  }
  collectArrayMutations(file);
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
