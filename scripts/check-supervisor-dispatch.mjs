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
const WORKER_MODULES = new Set(["node:worker_threads", "worker_threads"]);
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
  const hasLocalClasses = /\bclass\b/.test(source);
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
const parameterValueArguments = new Map();
const functionThisArguments = new Map();
const classMemberThisArguments = new WeakMap();
const functionArgumentsPlans = new Map();
const isThisParameter = (parameter) => Boolean(
  parameter && ts.isIdentifier(parameter.name) && parameter.name.text === "this"
);
const runtimeParameterIndexOf = (fn, parameter) => {
  const index = fn.parameters.indexOf(parameter);
  return index >= 0 && isThisParameter(fn.parameters[0]) ? index - 1 : index;
};
const getterReceiverOf = (getter) =>
  ts.isObjectLiteralExpression(getter.parent) ? getter.parent : undefined;
const thisArgumentsOf = (owner) => [
  ...(functionThisArguments.get(owner) ?? []),
  ...(classMemberThisArguments.get(owner) ?? [])
];
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
      return {
        kind: "opaque",
        node: initializer,
        iterable: ts.isForOfStatement(scope) ? scope.expression : undefined
      };
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
  const joined = staticJoinedStringOf(node, seen);
  if (joined !== undefined) return joined;
  if (ts.isCallExpression(node) && !node.questionDotToken &&
      node.arguments.length === 1) {
    const callee = unwrap(node.expression);
    if (ts.isIdentifier(callee) && callee.text === "String" &&
        !resolveBinding(callee)) {
      return staticAssignmentNameOf(node.arguments[0], seen);
    }
  }
  if (!ts.isIdentifier(node)) return undefined;
  const binding = resolveBinding(node);
  if (binding?.kind !== "variable" || !binding.constant ||
      !binding.node.initializer || seen.has(binding.node)) return undefined;
  const next = new Set(seen);
  next.add(binding.node);
  return staticAssignmentNameOf(binding.node.initializer, next);
};
// A destructuring default applies when any reachable branch is undefined.
const mayBeUndefinedOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return false;
  if (ts.isVoidExpression(node)) return true;
  if (ts.isBinaryExpression(node)) {
    const operator = node.operatorToken.kind;
    if (operator === ts.SyntaxKind.CommaToken) {
      return mayBeUndefinedOf(node.right, seen);
    }
    if ([ts.SyntaxKind.AmpersandAmpersandToken,
      ts.SyntaxKind.BarBarToken,
      ts.SyntaxKind.QuestionQuestionToken].includes(operator)) {
      const left = staticLogicalValueOf(node.left, seen);
      if (!left) {
        return mayBeUndefinedOf(node.left, seen) ||
          mayBeUndefinedOf(node.right, seen);
      }
      const selectsLeft = operator === ts.SyntaxKind.AmpersandAmpersandToken
        ? !left.truthy
        : operator === ts.SyntaxKind.BarBarToken
        ? left.truthy
        : !left.nullish;
      return mayBeUndefinedOf(selectsLeft ? node.left : node.right, seen);
    }
  }
  if (ts.isConditionalExpression(node)) {
    const condition = staticLogicalValueOf(node.condition, seen);
    if (!condition) {
      return mayBeUndefinedOf(node.whenTrue, seen) ||
        mayBeUndefinedOf(node.whenFalse, seen);
    }
    return mayBeUndefinedOf(
      condition.truthy ? node.whenTrue : node.whenFalse, seen
    );
  }
  if (!ts.isIdentifier(node)) return false;
  const binding = resolveBinding(node);
  if (!binding) return node.text === "undefined";
  if (binding.kind !== "variable" ||
      !ts.isVariableDeclaration(binding.node) ||
      !ts.isIdentifier(binding.node.name) || seen.has(binding.node)) {
    return false;
  }
  const next = new Set(seen);
  next.add(binding.node);
  return activeBindingValuesOf(binding.node, node)
    .some((value) => mayBeUndefinedOf(value, next));
};
  const assignmentsByBinding = new Map();
  const destructuredAssignmentsByBinding = new Map();
const destructuredPropertyAssignmentsByBinding = new Map();
const arrayMutationValuesByBinding = new Map();
  const activeBindingValuesOf = (declaration, reference) => {
    const referenceStart = reference.getStart(file);
    return [declaration.initializer, ...(assignmentsByBinding.get(declaration) ?? [])]
    .filter((value) => value && (value.getStart(file) <= referenceStart ||
      enclosingFunctionOf(value) !== enclosingFunctionOf(reference)));
  };
  const assignmentPropertyName = (name) => {
    if (!name) return undefined;
    if (ts.isPrivateIdentifier(name)) return name.text;
    if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) {
      return name.text;
    }
  if (ts.isComputedPropertyName(name)) {
    return staticAssignmentNameOf(name.expression);
    }
    return undefined;
  };
const assignmentsByMemberPath = new Map();
const memberAssignmentTargets = [];
const dynamicMemberAssignments = [];
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
const assignmentMemberPathKey = (receiver, property) => {
  const key = assignmentReferenceKey(receiver);
  return key === undefined ? undefined : JSON.stringify([key, property]);
};
  const recordAssignment = (target, value) => {
  const member = assignmentMemberAccess(target);
  if (member) {
    memberAssignmentTargets.push({
      node: target,
      receiver: member.receiver,
      property: member.property,
      value
    });
    const key = assignmentReferenceKey(target);
    if (key !== undefined) {
      const assignments = assignmentsByMemberPath.get(key) ?? [];
      assignments.push(value);
      assignmentsByMemberPath.set(key, assignments);
    }
    return;
  }
  if (ts.isElementAccessExpression(target)) {
    dynamicMemberAssignments.push({
      node: target,
      receiver: target.expression,
      value
    });
    return;
  }
    if (!ts.isIdentifier(target)) return;
    const binding = resolveBinding(target);
    if (!binding?.node) return;
    const directBinding =
      (binding.kind === "variable" && ts.isVariableDeclaration(binding.node)) ||
      (binding.kind === "parameter" && ts.isParameter(binding.node)) ||
    (binding.kind === "class" && ts.isClassDeclaration(binding.node)) ||
      (binding.kind === "opaque" && (ts.isVariableDeclaration(binding.node) ||
      ts.isParameter(binding.node) || ts.isClassDeclaration(binding.node)));
    if (!directBinding) return;
  const name = ts.isVariableDeclaration(binding.node) ||
    ts.isParameter(binding.node) || ts.isClassDeclaration(binding.node)
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
  if (!assignments.some((assignment) => assignment.name === target.text &&
      assignment.source === source &&
      assignment.property === property)) {
    assignments.push({ name: target.text, source, property });
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
    if (ts.isCallExpression(node)) {
      const containers = [
        ...(objectAssignInvocationArgumentsOf(node, next) ?? []),
        ...objectCreatePrototypeValuesOf(node, next)
      ];
      if (containers.length > 0) {
        return containers.flatMap((value) => destructuredObjectPropertyValuesOf(
          value, property, next
        ));
      }
    }
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
    if (!binding && globalPrototypeObjectOf(node, next) &&
        ["create", "assign"].includes(property)) return [node];
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
  if (!ts.isObjectLiteralExpression(target) && !ts.isObjectBindingPattern(target)) {
    return;
  }
  for (const entry of destructuringEntries(target)) {
    const key = entry.name ? assignmentPropertyName(entry.name) : undefined;
    let targetValue = ts.isBindingElement(entry.node)
      ? entry.node.name
      : ts.isShorthandPropertyAssignment(entry.node)
      ? entry.node.name
      : ts.isPropertyAssignment(entry.node) ? unwrap(entry.node.initializer) : undefined;
    if (!targetValue) continue;
    const patternDefault = ts.isBindingElement(entry.node)
      ? entry.node.initializer
      : ts.isBinaryExpression(targetValue) &&
        targetValue.operatorToken.kind === ts.SyntaxKind.EqualsToken
      ? targetValue.right : undefined;
    if (!ts.isBindingElement(entry.node) && patternDefault) {
      targetValue = unwrap(targetValue.left);
    }
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
};
  const collectAssignments = (node) => {
    if (ts.isVariableDeclaration(node) && node.initializer &&
        ts.isObjectBindingPattern(node.name)) {
      recordNestedDestructuredProperties(node.name, node.initializer);
    }
    if (ts.isBinaryExpression(node) &&
        aliasAssignmentKinds.has(node.operatorToken.kind)) {
      const target = unwrap(node.left);
    recordNestedDestructuredProperties(target, node.right);
    if (ts.isIdentifier(target) || assignmentMemberAccess(target) ||
        ts.isElementAccessExpression(target)) {
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

function staticStringArrayOf(input, seen = new Set()) {
  const node = unwrap(input);
  if (!node || seen.has(node)) return undefined;
  const next = new Set(seen);
  next.add(node);
  if (ts.isArrayLiteralExpression(node)) {
    const values = [];
    for (const element of node.elements) {
      if (ts.isOmittedExpression(element) || ts.isSpreadElement(element)) {
        return undefined;
      }
      const value = staticStringOf(element, next);
      if (value === undefined) return undefined;
      values.push(value);
    }
    return values;
  }
  return undefined;
}

function staticJoinedStringOf(input, seen = new Set()) {
  const node = unwrap(input);
  if (!node || !ts.isCallExpression(node) || node.questionDotToken ||
      node.arguments.length > 1) return undefined;
  const callee = memberAccess(unwrap(node.expression));
  if (callee?.property !== "join") return undefined;
  const values = staticStringArrayOf(callee.receiver, seen);
  if (!values) return undefined;
  const separator = node.arguments.length === 0
    ? ","
    : staticStringOf(node.arguments[0], seen);
  return separator === undefined ? undefined : values.join(separator);
}

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
  if (ts.isCallExpression(node) && !node.questionDotToken) {
    const callee = unwrap(node.expression);
    if (ts.isIdentifier(callee) && callee.text === "String" &&
        !resolveBinding(callee) && node.arguments.length === 1) {
      return staticStringOf(node.arguments[0], seen);
    }
    const joined = staticJoinedStringOf(node, seen);
    if (joined !== undefined) return joined;
  }
    if (!ts.isIdentifier(node)) return undefined;
    const binding = resolveBinding(node);
    if (binding?.kind !== "variable" || !binding.constant ||
        !binding.node.initializer || seen.has(binding.node)) return undefined;
    const next = new Set(seen);
    next.add(binding.node);
    return staticStringOf(binding.node.initializer, next);
  };
function staticStringArrayAtInspectionOf(input, seen = new Set()) {
  const node = unwrap(input);
  if (!node || seen.has(node)) return undefined;
  const next = new Set(seen);
  next.add(node);
  if (ts.isArrayLiteralExpression(node)) {
    const values = [];
    for (const element of node.elements) {
      if (ts.isOmittedExpression(element) || ts.isSpreadElement(element)) {
        return undefined;
      }
      const value = staticStringAtInspectionOf(element, next);
      if (value === undefined) return undefined;
      values.push(value);
    }
    return values;
  }
  if (!ts.isIdentifier(node)) return undefined;
  const binding = resolveBinding(node);
  if (binding?.kind !== "variable" || !binding.constant ||
      !binding.node.initializer || next.has(binding.node)) return undefined;
  if ((arrayMutationValuesByBinding.get(binding.node) ?? []).length > 0) {
    return undefined;
  }
  return staticStringArrayAtInspectionOf(
    binding.node.initializer, next
  );
}
function staticStringAtInspectionOf(input, seen = new Set()) {
  const node = unwrap(input);
  if (!node || seen.has(node)) return undefined;
  if (ts.isCallExpression(node) && !node.questionDotToken) {
    const callee = unwrap(node.expression);
    if (ts.isIdentifier(callee) && callee.text === "String" &&
        !resolveBinding(callee) && node.arguments.length === 1) {
      return staticStringAtInspectionOf(node.arguments[0], seen);
    }
    const member = memberAccess(callee);
    if (member?.property === "join" && node.arguments.length <= 1) {
      const values = staticStringArrayAtInspectionOf(
        member.receiver, seen
      );
      const separator = node.arguments.length === 0
        ? ","
        : staticStringAtInspectionOf(node.arguments[0], seen);
      if (values && separator !== undefined) return values.join(separator);
    }
  }
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (binding?.kind === "variable" && binding.constant &&
        binding.node.initializer && !seen.has(binding.node)) {
      const next = new Set(seen);
      next.add(binding.node);
      return staticStringAtInspectionOf(binding.node.initializer, next);
    }
  }
  return staticStringOf(node, seen);
}
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
const hasExportModifier = (node) =>
  (node.modifiers ?? []).some((modifier) =>
    modifier.kind === ts.SyntaxKind.ExportKeyword);
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
  let staticLogicalValueOf;
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
        const leftValue = staticLogicalValueOf(node.left, seen);
        if (leftValue) {
          const selectRight = operator === ts.SyntaxKind.AmpersandAmpersandToken
            ? leftValue.truthy
            : operator === ts.SyntaxKind.BarBarToken
            ? !leftValue.truthy
            : leftValue.nullish;
          return resolvedValuesOf(selectRight ? node.right : node.left, seen);
        }
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
const objectValueCandidatesOf = (input, seen = new Set(), unresolved) => {
    const node = unwrap(input);
  if (!node || seen.has(node)) {
    unresolved?.push(input);
    return [];
  }
    const next = new Set(seen);
    next.add(node);
    const objects = [];
  if (node.kind === ts.SyntaxKind.ThisKeyword) {
    let current = node.parent;
    while (current) {
      if (ts.isGetAccessorDeclaration(current)) {
        const receiver = getterReceiverOf(current);
        if (receiver) {
        objects.push(...objectValueCandidatesOf(receiver, next, unresolved));
        }
        return objects;
      }
      if (ts.isFunctionLike(current) && !ts.isArrowFunction(current)) {
      objects.push(...thisArgumentsOf(current)
        .flatMap((receiver) => objectValueCandidatesOf(receiver, next, unresolved)));
        return objects;
      }
      current = current.parent;
    }
    if (objects.length === 0) unresolved?.push(node);
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
      objects.push(...objectValueCandidatesOf(argument, parameterNext, unresolved));
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
        objects.push(...objectValueCandidatesOf(argument, parameterNext, unresolved));
        }
      }
    }
      if (value.kind === ts.SyntaxKind.ThisKeyword) {
      objects.push(...objectValueCandidatesOf(value, next, unresolved));
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
        objects.push(...objectValueCandidatesOf(argument, next, unresolved));
          }
        continue;
      }
        const prototypes = objectCreatePrototypeValuesOf(value, next);
        if (prototypes.length > 0) {
          for (const prototype of prototypes) {
        objects.push(...objectValueCandidatesOf(prototype, next, unresolved));
          }
          continue;
        }
    const returnedValues = functionReturnExpressionsOf(value.expression, next);
    if (returnedValues.length === 0) {
      unresolved?.push(value);
    } else {
      for (const returned of returnedValues) {
        objects.push(...objectValueCandidatesOf(returned, next, unresolved));
      }
        }
        continue;
      }
      const member = memberAccess(value);
  if (!member) {
    unresolved?.push(value);
    continue;
  }
  const candidates = memberValueCandidatesOf(
        member.receiver,
        member.property,
        next
  );
  if (candidates.length === 0) {
    unresolved?.push(value);
    continue;
  }
  for (const candidate of candidates) {
    objects.push(...objectValueCandidatesOf(candidate, next, unresolved));
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
const localClassMemberTargetOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return undefined;
  if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
    return { classNode: node, instance: false };
  }
  if (ts.isNewExpression(node)) {
    const target = localClassMemberTargetOf(node.expression, seen);
    return target ? { classNode: target.classNode, instance: true } : undefined;
  }
  if (!ts.isIdentifier(node)) return undefined;
  const binding = resolveBinding(node);
  if (!binding?.node || seen.has(binding.node)) return undefined;
  if (ts.isClassDeclaration(binding.node) || ts.isClassExpression(binding.node)) {
    return { classNode: binding.node, instance: false };
  }
  if ((binding.kind === "variable" || binding.kind === "opaque") &&
      ts.isVariableDeclaration(binding.node) &&
      ts.isIdentifier(binding.node.name) && binding.node.initializer) {
    const next = new Set(seen);
    next.add(binding.node);
    return localClassMemberTargetOf(binding.node.initializer, next);
  }
  return undefined;
};
const localClassMemberTargetsOf = (input, seen = new Set()) => {
  const targets = [];
  const unresolved = [];
  const addTarget = (target) => {
    if (target && !targets.some((candidate) =>
      candidate.classNode === target.classNode &&
      candidate.instance === target.instance)) {
      targets.push(target);
    }
  };
  const visit = (input, instance, encountered) => {
    const node = unwrap(input);
    if (!node || encountered.has(node)) {
      unresolved.push(node);
      return;
    }
    const next = new Set(encountered);
    next.add(node);
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      addTarget({ classNode: node, instance });
      return;
    }
    if (ts.isNewExpression(node)) {
      visit(node.expression, true, next);
      return;
    }
    if (!ts.isIdentifier(node)) {
      unresolved.push(node);
      return;
    }
    const binding = resolveBinding(node);
    if (!binding?.node) {
      unresolved.push(node);
      return;
    }
    if (ts.isClassDeclaration(binding.node) || ts.isClassExpression(binding.node)) {
      addTarget({ classNode: binding.node, instance });
      const referenceStart = node.getStart(file);
      for (const assigned of assignmentsByBinding.get(binding.node) ?? []) {
        if (assigned.getStart(file) <= referenceStart) visit(assigned, instance, next);
      }
      return;
    }
    if ((binding.kind === "variable" || binding.kind === "opaque") &&
        ts.isVariableDeclaration(binding.node) && binding.node.initializer) {
      const values = resolvedValuesOf(node, next);
      if (values.length === 0 || values.every((value) => unwrap(value) === node)) {
        unresolved.push(node);
      } else {
        for (const value of values) visit(value, instance, next);
      }
      return;
    }
    unresolved.push(node);
  };
  visit(input, false, new Set(seen));
  return {
    targets,
    unresolved: targets.length > 0 && unresolved.length > 0
  };
};
// Heritage stays local: follow class declarations/expressions and immutable
// aliases only. Any other heritage is unresolved for member provenance.
const unresolvedLocalClassHeritage = Symbol("unresolvedLocalClassHeritage");
const localClassHeritageOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return undefined;
  if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) return node;
  if (node.kind === ts.SyntaxKind.NullKeyword) return undefined;
  if (!ts.isIdentifier(node)) return unresolvedLocalClassHeritage;
  const binding = resolveBinding(node);
  if (!binding?.node) return unresolvedLocalClassHeritage;
  if (ts.isClassDeclaration(binding.node) || ts.isClassExpression(binding.node)) {
    const reassignedBeforeUse = (assignmentsByBinding.get(binding.node) ?? [])
      .some((value) => value.getStart(file) <= node.getStart(file));
    if (reassignedBeforeUse) return unresolvedLocalClassHeritage;
    return binding.node;
  }
  if ((binding.kind === "variable" || binding.kind === "opaque") &&
      binding.constant && immutableAlias(binding.node) &&
      ts.isVariableDeclaration(binding.node) &&
      ts.isIdentifier(binding.node.name) && binding.node.initializer &&
      !seen.has(binding.node)) {
    const next = new Set(seen);
    next.add(binding.node);
    return localClassHeritageOf(binding.node.initializer, next);
  }
  return unresolvedLocalClassHeritage;
};
const localClassBaseOf = (classNode, seen = new Set()) => {
  const heritage = (classNode.heritageClauses ?? []).find((clause) =>
    clause.token === ts.SyntaxKind.ExtendsKeyword);
  const baseType = heritage?.types[0];
  if (!baseType) return undefined;
  return localClassHeritageOf(baseType.expression, seen);
};
const classMemberMatchesAccessOf = (member, property, instance) => {
  if (!("name" in member) ||
      staticPropertyNameOf(member.name) !== property) return false;
  const isStatic = (member.modifiers ?? []).some((modifier) =>
    modifier.kind === ts.SyntaxKind.StaticKeyword);
  return isStatic === !instance;
};
// Class fields and methods are inherited through the class chain. Follow the
// same chain for this.member assignments in constructors and static blocks.
const localClassAssignedMemberValuesOf = (classNode, property, instance) => {
  const values = [];
  for (const member of classNode.members) {
    const ownerMatches = instance
      ? ts.isConstructorDeclaration(member)
      : ts.isClassStaticBlockDeclaration(member);
    if (!ownerMatches) continue;
    const visit = (child) => {
      if (ts.isBinaryExpression(child) &&
        aliasAssignmentKinds.has(child.operatorToken.kind)) {
        const assigned = assignmentMemberAccess(child.left);
        if (assigned?.property === property &&
            unwrap(assigned.receiver)?.kind === ts.SyntaxKind.ThisKeyword) {
          values.push(child.right);
        }
      }
      ts.forEachChild(child, visit);
    };
    ts.forEachChild(member, visit);
  }
  return values;
};
// Public members inherit through a bounded local extends chain. Instance
// fields precede prototype methods, while static members share one own
// property namespace. Private identifiers remain scoped to their class.
const localClassMemberResolutionOf = (classNode, property, instance) => {
  const privateAccess = property.startsWith("#");
  if (!instance) {
    let current = classNode;
    const visited = new Set();
    const inheritedAssignments = [];
    while (current && !visited.has(current)) {
      visited.add(current);
      const members = current.members.filter((member) =>
        classMemberMatchesAccessOf(member, property, false));
      const assignedValues = localClassAssignedMemberValuesOf(
        current, property, false
      );
      if (members.length > 0) {
        return {
          classNode: current,
          members,
          assignedValues: [...inheritedAssignments, ...assignedValues]
        };
      }
      inheritedAssignments.push(...assignedValues);
      if (privateAccess) return undefined;
      current = localClassBaseOf(current, visited);
      if (current === unresolvedLocalClassHeritage) return { unresolved: true };
    }
    return inheritedAssignments.length > 0
      ? { classNode, members: [], assignedValues: inheritedAssignments }
      : undefined;
  }

  // Constructor assignments and field initializers create own properties,
  // which precede every prototype method. A derived own source shadows a base
  // own source, but a derived prototype method does not.
  let current = classNode;
  const ownVisited = new Set();
  const inheritedAssignments = [];
  while (current && !ownVisited.has(current)) {
    ownVisited.add(current);
    const members = current.members.filter((member) =>
      ts.isPropertyDeclaration(member) &&
      classMemberMatchesAccessOf(member, property, true));
    const assignedValues = localClassAssignedMemberValuesOf(
      current, property, true
    );
    if (members.length > 0) {
      return {
        classNode: current,
        members,
        assignedValues: [...inheritedAssignments, ...assignedValues]
      };
    }
    inheritedAssignments.push(...assignedValues);
    if (privateAccess) return undefined;
    current = localClassBaseOf(current, ownVisited);
    if (current === unresolvedLocalClassHeritage) return { unresolved: true };
  }

  current = classNode;
  const prototypeVisited = new Set();
  while (current && !prototypeVisited.has(current)) {
    prototypeVisited.add(current);
    const members = current.members.filter((member) =>
      (ts.isMethodDeclaration(member) || ts.isGetAccessorDeclaration(member)) &&
      classMemberMatchesAccessOf(member, property, true));
    if (members.length > 0) {
      return {
        classNode: current,
        members,
        assignedValues: inheritedAssignments
      };
    }
    if (privateAccess) return undefined;
    current = localClassBaseOf(current, prototypeVisited);
    if (current === unresolvedLocalClassHeritage) return { unresolved: true };
  }
  return inheritedAssignments.length > 0
    ? { classNode, members: [], assignedValues: inheritedAssignments }
    : undefined;
};
const classMemberIsStaticOf = (member) =>
  (member.modifiers ?? []).some((modifier) =>
    modifier.kind === ts.SyntaxKind.StaticKeyword);
const localClassMemberValuesForTargetOf = (
  target, property, receiver
) => {
  const resolution = localClassMemberResolutionOf(
    target.classNode, property, target.instance
  );
  if (!resolution?.classNode) return [];
  const values = [...(resolution.assignedValues ?? [])];
  for (const member of resolution.members) {
    if (ts.isPropertyDeclaration(member) && member.initializer) {
      values.push(member.initializer);
    } else if (ts.isMethodDeclaration(member) ||
        ts.isGetAccessorDeclaration(member)) {
      const receivers = classMemberThisArguments.get(member) ?? [];
      if (!receivers.includes(receiver)) {
        receivers.push(receiver);
        classMemberThisArguments.set(member, receivers);
      }
      values.push(member);
    }
  }
  return values;
};
const localClassMemberTargetFromThisOf = (node, property) => {
  const owner = enclosingFunctionOf(node);
  const ownerClass = owner?.parent;
  if (!ownerClass ||
      (!ts.isClassDeclaration(ownerClass) && !ts.isClassExpression(ownerClass))) {
    return undefined;
  }
  return {
    owner,
    target: { classNode: ownerClass, instance: !classMemberIsStaticOf(owner) },
    privateAccess: property.startsWith("#")
  };
};
const localClassMemberValuesOf = (input, property, seen = new Set()) => {
  if (!hasLocalClasses) return [];
  const node = unwrap(input);
  if (!node) return [];
  if (node.kind === ts.SyntaxKind.ThisKeyword) {
    const context = localClassMemberTargetFromThisOf(node, property);
    if (!context) return [];
    const next = new Set(seen);
    next.delete(context.owner);
    next.add(node);
    if (context.privateAccess) {
      return localClassMemberValuesForTargetOf(
        context.target, property, node
      );
    }
    return thisArgumentsOf(context.owner).flatMap((receiver) =>
      localClassMemberValuesOf(receiver, property, next));
  }
  const resolution = localClassMemberTargetsOf(node, seen);
  return resolution.targets.flatMap((target) =>
    localClassMemberValuesForTargetOf(target, property, node));
};
const localClassMemberUnresolvedOf = (input, property, seen = new Set()) => {
  if (!hasLocalClasses) return false;
  const node = unwrap(input);
  if (!node) return false;
  if (node.kind === ts.SyntaxKind.ThisKeyword) {
    const context = localClassMemberTargetFromThisOf(node, property);
    if (!context) return false;
    const next = new Set(seen);
    next.delete(context.owner);
    next.add(node);
    if (context.privateAccess) {
      return Boolean(localClassMemberResolutionOf(
        context.target.classNode, property, context.target.instance
      )?.unresolved);
    }
    return thisArgumentsOf(context.owner).some((receiver) =>
      localClassMemberUnresolvedOf(receiver, property, next));
  }
  const targets = localClassMemberTargetsOf(node, seen);
  return targets.unresolved || targets.targets.some((target) =>
    Boolean(localClassMemberResolutionOf(
      target.classNode, property, target.instance
    )?.unresolved));
};
  const memberValueCandidatesOf = (input, property, seen = new Set()) => {
    const node = unwrap(input);
    if (!node) return [];
    const classSeen = new Set(seen);
    classSeen.delete(node);
    const classValues = localClassMemberValuesOf(node, property, classSeen);
    if (seen.has(node)) return classValues;
    const next = new Set(seen);
    next.add(node);
    const values = [...classValues];
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
      if (!/^\d+$/.test(property)) continue;
      if (ts.isArrayLiteralExpression(value)) {
        values.push(...fixedIndexedValuesOf(value, Number(property)));
        continue;
      }
      if (ts.isCallExpression(value)) {
        const argumentsList = fixedArrayOfInvocationArgumentsOf(value, next);
        const indexed = argumentsList?.[Number(property)];
        if (indexed) values.push(indexed);
      }
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
      const expanded = fixedSpreadValuesOf(node, seen);
      if (expanded) {
      const indexed = expanded[Number(property)];
      if (indexed) values.push(indexed);
      }
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
// Shift the source plan past the destructured prefix. An opaque tail keeps
// the remaining positions so later indexed reads stay conservative.
const arrayRestPlansByNode = new WeakMap();
const arrayRestValuesBySource = new WeakMap();
const arrayRestBindingValueOf = (source, startIndex) => {
  const cached = arrayRestValuesBySource.get(source)?.get(startIndex);
  if (cached) return cached;
  const values = fixedSpreadValuesOf(source);
  let value;
  if (values !== undefined) {
    value = ts.factory.createArrayLiteralExpression(values.slice(startIndex).map((entry) =>
      entry ?? ts.factory.createOmittedExpression()));
  } else {
    const plan = fixedSpreadPlanOf(source);
    if (!plan) return source;
    value = ts.factory.createArrayLiteralExpression([]);
    arrayRestPlansByNode.set(value, {
      before: plan.unknownAll ? [] : plan.before.slice(startIndex),
      after: [...plan.after],
      unknownIndex: plan.unknownAll
        ? 0
        : Math.max(0, (plan.unknownIndex ?? 0) - startIndex),
      ...(plan.unknownAll ? { unknownAll: true } : {})
    });
  }
  const byIndex = arrayRestValuesBySource.get(source) ?? new Map();
  byIndex.set(startIndex, value);
  arrayRestValuesBySource.set(source, byIndex);
  return value;
};
  const bindingPatternValuesOf = (pattern, source, targetName, seen = new Set()) => {
    const values = [];
  const usesDefault = (value) => mayBeUndefinedOf(value);
    const candidatesWithDefault = (selected, initializer) =>
      initializer && (selected.length === 0 || selected.some(usesDefault))
        ? [...selected, initializer]
        : selected;
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
        const candidates = candidatesWithDefault(selected, element.initializer);
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
      const restValue = arrayRestBindingValueOf(source, index);
      if (!restValue) continue;
          if (ts.isIdentifier(element.name) && element.name.text === targetName) {
        values.push(restValue);
          } else if (ts.isObjectBindingPattern(element.name) ||
            ts.isArrayBindingPattern(element.name)) {
        values.push(...bindingPatternValuesOf(
          element.name, restValue, targetName, seen
        ));
          }
          continue;
        }
        const selected = memberValueCandidatesOf(source, String(index), seen);
        for (const candidate of fixedIndexedValuesOf(source, index, seen)) {
          if (!selected.includes(candidate)) selected.push(candidate);
        }
        const candidates = candidatesWithDefault(selected, element.initializer);
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
const bindingPatternSourcePropertyOf = (
  pattern, source, targetName, property, seen = new Set()
) => {
  const sources = [];
  const visitArrayPattern = (arrayPattern, arraySource, startIndex) => {
    for (let offset = 0; offset < arrayPattern.elements.length; offset += 1) {
      const element = arrayPattern.elements[offset];
      if (ts.isOmittedExpression(element)) continue;
      const index = startIndex + offset;
      if (element.dotDotDotToken) {
        if (ts.isObjectBindingPattern(element.name) ||
          ts.isArrayBindingPattern(element.name)) {
          visitArrayPattern(element.name, arraySource, index);
        }
        break;
      }
      const selected = memberValueCandidatesOf(
        arraySource, String(index), seen
      );
      for (const candidate of fixedIndexedValuesOf(
        arraySource, index, seen
      )) {
        if (!selected.includes(candidate)) selected.push(candidate);
      }
      if (ts.isObjectBindingPattern(element.name) ||
        ts.isArrayBindingPattern(element.name)) {
        for (const candidate of selected) {
          visitPattern(element.name, candidate);
        }
      }
    }
  };
  const visitPattern = (candidatePattern, candidateSource) => {
    if (ts.isObjectBindingPattern(candidatePattern)) {
      for (const element of candidatePattern.elements) {
        if (!ts.isBindingElement(element) || element.dotDotDotToken) continue;
        const key = element.propertyName
          ? staticPropertyNameOf(element.propertyName)
          : ts.isIdentifier(element.name) ? element.name.text : undefined;
        if (ts.isIdentifier(element.name) && element.name.text === targetName &&
          key === property) {
          sources.push(candidateSource);
        }
        if (key === undefined || (!ts.isObjectBindingPattern(element.name) &&
          !ts.isArrayBindingPattern(element.name))) continue;
        for (const candidate of memberValueCandidatesOf(
          candidateSource, key, seen
        )) {
          visitPattern(element.name, candidate);
        }
      }
    } else if (ts.isArrayBindingPattern(candidatePattern)) {
      visitArrayPattern(candidatePattern, candidateSource, 0);
    }
  };
  visitPattern(pattern, source);
  return sources;
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
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      const constructor = node.members.find(ts.isConstructorDeclaration);
      return constructor ? [constructor] : [];
    }
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
      if (ts.isClassDeclaration(binding.node) ||
          ts.isClassExpression(binding.node)) {
        const constructor = binding.node.members.find(ts.isConstructorDeclaration);
        return constructor ? [constructor] : [];
      }
      if (binding.kind === "opaque" && binding.iterable &&
          ts.isVariableDeclarationList(binding.node)) {
        const declaration = binding.node.declarations.find((candidate) =>
          declaresName(candidate.name, node.text));
        const iterated = fixedSpreadValuesOf(binding.iterable, bindingNext);
        if (declaration && iterated) {
          const candidates = ts.isIdentifier(declaration.name)
            ? iterated
            : iterated.flatMap((source) => bindingPatternValuesOf(
              declaration.name, source, node.text, bindingNext
            ));
          return candidates.flatMap((value) =>
            localFunctionValuesOf(value, bindingNext));
        }
      }
    if (binding.kind === "parameter" && ts.isParameter(binding.node)) {
      const functions = parameterFunctionArguments.get(binding.node) ?? [];
      if (functions.length > 0) {
        return functions.flatMap((value) => localFunctionValuesOf(value, bindingNext));
      }
    }
      if ((binding.kind === "variable" || binding.kind === "opaque") &&
          ts.isVariableDeclaration(binding.node) && binding.node.initializer) {
        const values = ts.isIdentifier(binding.node.name)
          ? [binding.node.initializer]
          : bindingPatternValuesOf(
            binding.node.name, binding.node.initializer, node.text, bindingNext
          );
        return values.flatMap((value) =>
          localFunctionValuesOf(value, bindingNext));
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
      if (reflectConstructReferenceOf(node.expression, next)) {
        return localFunctionValuesOf(node.arguments[0], next)
          .flatMap((value) => functionReturnExpressionsOf(value, next));
      }
return functionReturnExpressionsOf(node.expression, next)
        .flatMap((value) => functionReturnExpressionsOf(value, next));
}
    if (ts.isTaggedTemplateExpression(node) || ts.isNewExpression(node)) {
      return localFunctionValuesOf(
        ts.isTaggedTemplateExpression(node) ? node.tag : node.expression,
        next
      ).flatMap((value) => functionReturnExpressionsOf(value, next));
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
  if (node.kind === ts.SyntaxKind.ThisKeyword) {
    let owner = node.parent;
    while (owner &&
        !(ts.isFunctionLike(owner) && !ts.isArrowFunction(owner))) {
      owner = owner.parent;
    }
    if (!owner || seen.has(owner)) return false;
    const next = new Set(seen);
    next.add(owner);
    return thisArgumentsOf(owner)
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
      const returned = reflectConstructReferenceOf(node.expression, next)
        ? functionReturnExpressionsOf(node, next)
        : functionReturnExpressionsOf(node.expression);
      return returned
    .some((value) => processObjectOf(value, next));
    }
    if (ts.isTaggedTemplateExpression(node) || ts.isNewExpression(node)) {
      return functionReturnExpressionsOf(node, seen)
        .some((value) => processObjectOf(value, seen));
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
  if (binding.kind === "opaque" && binding.iterable &&
      ts.isVariableDeclarationList(binding.node)) {
    const declaration = binding.node.declarations.find((candidate) =>
      declaresName(candidate.name, node.text));
    const iterated = fixedSpreadValuesOf(binding.iterable, next);
    if (declaration && iterated) {
      const candidates = ts.isIdentifier(declaration.name)
        ? iterated
        : iterated.flatMap((source) => bindingPatternValuesOf(
          declaration.name, source, node.text, next
        ));
      return candidates.some((candidate) => processObjectOf(candidate, next));
    }
  }
  if ((binding.kind === "variable" || binding.kind === "opaque") &&
      ts.isVariableDeclaration(binding.node)) {
    if (ts.isIdentifier(binding.node.name)) {
      const candidates = activeBindingValuesOf(binding.node, node);
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
    return activeBindingValuesOf(binding.node, node)
      .some((value) => globalReflectOf(value, next));
  }
  const member = memberAccess(node);
  return member?.property === "Reflect" && globalObjectOf(member.receiver, seen);
};
const reflectMethodReferenceOf = (input, method, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return false;
  const member = memberAccess(node);
  if (member?.property === method && globalReflectOf(member.receiver, seen)) return true;
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
        if (value && reflectMethodReferenceOf(value, method, next)) return true;
        if (ts.isGetAccessorDeclaration(property) &&
            functionReturnExpressionsOf(property, next)
              .some((returned) => reflectMethodReferenceOf(returned, method, next))) {
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
          binding.node.name, node.text, method
        )) ||
       bindingPatternValuesOf(
         binding.node.name, binding.node.initializer, node.text, next
       ).some((value) => reflectMethodReferenceOf(value, method, next))));
  }
  return [binding.node.initializer, ...(assignmentsByBinding.get(binding.node) ?? [])]
    .filter(Boolean)
    .some((value) => reflectMethodReferenceOf(value, method, next));
};
const reflectApplyReferenceOf = (input, seen = new Set()) =>
  reflectMethodReferenceOf(input, "apply", seen);
const reflectConstructReferenceOf = (input, seen = new Set()) =>
  reflectMethodReferenceOf(input, "construct", seen);
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
    if (ts.isBindingElement(target)) {
      recordResolvedAssignments(target.name, source);
      return;
    }
    if (assignmentMemberAccess(target) ||
        (ts.isElementAccessExpression(target) && !assignmentMemberAccess(target))) {
      recordAssignment(target, source);
      return;
    }
    if (ts.isIdentifier(target)) {
      recordAssignment(target, source);
      return;
    }
    if (ts.isObjectLiteralExpression(target) || ts.isObjectBindingPattern(target)) {
      for (const property of target.properties ?? target.elements) {
        if (ts.isBindingElement(property) && property.dotDotDotToken) continue;
        let targetValue = ts.isBindingElement(property)
          ? unwrap(property.name)
          : ts.isShorthandPropertyAssignment(property)
            ? property.name
            : ts.isPropertyAssignment(property) ? unwrap(property.initializer) : undefined;
        if (ts.isSpreadAssignment(property)) {
          if (ts.isIdentifier(unwrap(property.expression))) {
            recordAssignment(unwrap(property.expression), source);
          }
          continue;
        }
        if (!targetValue || !ts.isBindingElement(property) &&
            !ts.isPropertyAssignment(property) &&
            !ts.isShorthandPropertyAssignment(property)) continue;
        const key = assignmentPropertyName(
          ts.isBindingElement(property) ? property.propertyName ?? property.name : property.name
        );
        if (key === undefined) continue;
        const selected = memberValueCandidatesOf(source, key);
        const patternDefault = targetValue && ts.isBinaryExpression(targetValue) &&
          targetValue.operatorToken.kind === ts.SyntaxKind.EqualsToken
          ? targetValue.right : undefined;
        if (patternDefault) targetValue = unwrap(targetValue.left);
        const defaultValue = ts.isBindingElement(property)
          ? property.initializer
          : ts.isShorthandPropertyAssignment(property)
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
    if (ts.isArrayLiteralExpression(target) || ts.isArrayBindingPattern(target)) {
      const elements = target.elements;
      for (let index = 0; index < elements.length; index += 1) {
        const element = elements[index];
        if (ts.isOmittedExpression(element)) continue;
        if (ts.isSpreadElement(element)) {
          const spreadTarget = unwrap(element.expression);
          if (ts.isIdentifier(spreadTarget)) recordAssignment(spreadTarget, source);
          continue;
        }
        const selected = memberValueCandidatesOf(source, String(index));
        const rest = ts.isBindingElement(element) && element.dotDotDotToken;
        if (rest && ts.isIdentifier(element.name)) {
          const sourceValues = fixedSpreadValuesOf(source);
          if (sourceValues) {
            for (let tailIndex = index; tailIndex < sourceValues.length; tailIndex += 1) {
              const target = ts.factory.createElementAccessExpression(
                element.name,
                ts.factory.createNumericLiteral(String(tailIndex - index))
              );
              recordAssignment(target, sourceValues[tailIndex]);
            }
          }
          continue;
        }
        const defaultValue = ts.isBindingElement(element) ? element.initializer : undefined;
        const candidates = selected.length > 0
          ? selected
          : defaultValue ? [defaultValue] : [];
        const nestedTarget = ts.isBindingElement(element) ? element.name : element;
        for (const value of candidates) {
          recordResolvedAssignments(nestedTarget, value);
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
  const fixedValues = fixedSpreadValuesOf(source);
  const valueLists = fixedValues
    ? [fixedValues]
    : [...resolvedValuesOf(source)]
      .filter((value) => ts.isArrayLiteralExpression(value))
      .map((value) => value.elements.map((element) =>
        ts.isOmittedExpression(element)
          ? undefined
          : ts.isSpreadElement(element)
            ? unwrap(element.expression)
            : unwrap(element)));
  for (const values of valueLists) {
    for (let index = 0; index < targets.length; index += 1) {
      const element = targets[index];
      const rest = ts.isBindingElement(element)
        ? Boolean(element.dotDotDotToken)
        : ts.isSpreadElement(element);
      if (!rest && ts.isOmittedExpression(element)) continue;
      const end = rest
        ? values.length
        : Math.min(index + 1, values.length);
      const selected = [];
      for (const candidate of fixedIndexedValuesOf(source, index)) {
        if (!selected.includes(candidate)) selected.push(candidate);
      }
      for (let valueIndex = index; valueIndex < end; valueIndex += 1) {
        const value = unwrap(values[valueIndex]);
        if (!value) continue;
        selected.push(value);
        if (processObjectOf(value)) {
          add(value,
            "array destructuring process capability unproven in supervisor source");
        } else if (globalObjectOf(value)) {
          add(value,
            "array destructuring global capability unproven in supervisor source");
        }
      }
      const nested = ts.isBindingElement(element) ? element.name : element;
    const restValue = rest ? arrayRestBindingValueOf(source, index) : undefined;
      for (const value of selected) {
      recordResolvedAssignments(
        nested,
        rest && ts.isIdentifier(nested) && restValue ? restValue : value
      );
      if (rest && ts.isIdentifier(nested) && restValue) continue;
        if (ts.isObjectBindingPattern(nested) ||
            ts.isObjectLiteralExpression(nested)) {
          const objectValues = ts.isArrayLiteralExpression(value)
            ? [value, ...(fixedSpreadValuesOf(value) ?? [])]
            : [value];
          if (objectValues.some((candidate) => processObjectOf(candidate))) {
            inspectProcessDestructuring(nested);
          }
          if (objectValues.some((candidate) =>
            globalObjectOf(candidate) || globalCapabilitySourceOf(candidate)
          )) {
            inspectGlobalDestructuring(nested);
          }
        } else if (ts.isArrayBindingPattern(nested) ||
                   ts.isArrayLiteralExpression(nested)) {
          inspectCapabilityArrayDestructuring(nested, value);
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
    if (!binding?.node || seen.has(binding.node)) return false;
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
      return activeBindingValuesOf(binding.node, node)
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
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    return staticMethodReferenceOf(node.right, property, ownerOf, next);
  }
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
    .some((assignment) => assignment.name === node.text &&
      assignment.property === property &&
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
      return activeBindingValuesOf(binding.node, node)
      .some((value) => staticMethodReferenceOf(value, property, ownerOf, next));
  }
  return false;
};
const staticMethodWrapperReferenceOf = (
  input, wrapperProperty, property, ownerOf, seen = new Set()
) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  const next = new Set(seen);
  next.add(node);
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    return staticMethodWrapperReferenceOf(
      node.right, wrapperProperty, property, ownerOf, next
    );
  }
  const member = memberAccess(node);
  if (member) {
    if (member.property === wrapperProperty &&
        staticMethodReferenceOf(member.receiver, property, ownerOf, next)) {
      return true;
    }
    if (memberValueCandidatesOf(member.receiver, member.property, next)
        .some((value) => staticMethodWrapperReferenceOf(
          value, wrapperProperty, property, ownerOf, next
        ))) return true;
  }
  if (ts.isCallExpression(node)) {
    if (staticMethodReferenceOf(
      node.expression, "get", globalReflectOf, next
    ) && staticAssignmentNameOf(node.arguments[1]) === wrapperProperty &&
        staticMethodReferenceOf(node.arguments[0], property, ownerOf, next)) {
      return true;
    }
    return functionReturnExpressionsOf(node.expression, next)
      .some((value) => staticMethodWrapperReferenceOf(
        value, wrapperProperty, property, ownerOf, next
      ));
  }
  if (!ts.isIdentifier(node)) return false;
  const binding = resolveBinding(node);
  if (!binding?.node || seen.has(binding.node)) return false;
  const bindingNext = new Set(next);
  bindingNext.add(binding.node);
  if ((destructuredPropertyAssignmentsByBinding.get(binding.node) ?? [])
    .some((assignment) => assignment.name === node.text &&
      assignment.property === wrapperProperty &&
        staticMethodReferenceOf(
          assignment.source, property, ownerOf, bindingNext
        ))) return true;
  if (ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node)) {
    if (!ts.isIdentifier(binding.node.name)) {
      if (binding.node.initializer && bindingPatternSourcePropertyOf(
        binding.node.name, binding.node.initializer, node.text,
        wrapperProperty, bindingNext
      ).some((source) => staticMethodReferenceOf(
        source, property, ownerOf, bindingNext
      ))) return true;
      return bindingPatternValuesOf(
        binding.node.name, binding.node.initializer, node.text, bindingNext
      ).some((value) => staticMethodWrapperReferenceOf(
        value, wrapperProperty, property, ownerOf, bindingNext
      ));
    }
    return activeBindingValuesOf(binding.node, node)
      .some((value) => staticMethodWrapperReferenceOf(
        value, wrapperProperty, property, ownerOf, bindingNext
      ));
  }
  return false;
};
const globalCapabilitySourceOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  const next = new Set(seen);
  next.add(node);
    if (globalObjectOf(node, seen) || globalPrototypeObjectOf(node, seen) ||
      staticMethodReferenceOf(
          node, "create", globalPrototypeObjectOf, seen
        ) || staticMethodReferenceOf(node, "assign", globalPrototypeObjectOf, seen)) {
    return true;
  }
    if (ts.isCallExpression(node)) {
      const copiedArguments = objectAssignInvocationArgumentsOf(node, seen);
      if (copiedArguments?.some((value) => globalCapabilitySourceOf(value, next))) {
        return true;
      }
      if (objectCreatePrototypeValuesOf(node, seen)
        .some((value) => globalCapabilitySourceOf(value, next))) return true;
      return functionReturnExpressionsOf(node.expression, next)
        .some((value) => globalCapabilitySourceOf(value, next));
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
      activeBindingValuesOf(binding.node, node)
      .some((value) => globalCapabilitySourceOf(value, next)));
};
const globalCapabilityDestructuringOf = (target, source) => {
  if (globalObjectOf(source) || globalPrototypeObjectOf(source)) return true;
  return destructuringSourceValues(target, source).some((value) =>
    globalCapabilitySourceOf(value) || processObjectOf(value) ||
    requireReferenceOf(value) || dynamicFunctionOf(value));
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
const workerModuleRequireOf = (input) => {
  const call = unwrap(input);
  if (!call || !ts.isCallExpression(call) || call.questionDotToken ||
      call.arguments.length !== 1) return false;
  const callee = unwrap(call.expression);
  return ts.isIdentifier(callee) && callee.text === "require" &&
    !resolveBinding(callee) && WORKER_MODULES.has(moduleLiteral(call.arguments[0]));
};
// Resolve Worker provenance through static imports, CommonJS bindings, and
// active local aliases. Other constructor sources remain unaudited.
const workerNamespaceOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  if (workerModuleRequireOf(node)) return true;
  if (ts.isObjectLiteralExpression(node)) {
    let hasWorker = false;
    for (const property of node.properties) {
      if (ts.isSpreadAssignment(property)) {
        if (workerNamespaceOf(property.expression, seen)) hasWorker = true;
        continue;
      }
      if (!("name" in property) ||
          staticPropertyNameOf(property.name) !== "Worker") continue;
      if (ts.isPropertyAssignment(property)) {
        hasWorker = workerConstructorOf(property.initializer, seen);
      } else if (ts.isShorthandPropertyAssignment(property)) {
        hasWorker = workerConstructorOf(property.name, seen);
      } else if (ts.isGetAccessorDeclaration(property)) {
        hasWorker = functionReturnExpressionsOf(property, seen)
          .some((value) => workerConstructorOf(value, seen));
      } else {
        hasWorker = false;
      }
    }
    return hasWorker;
  }
  if (ts.isCallExpression(node)) {
    const copiedArguments = objectAssignInvocationArgumentsOf(node, seen);
    if (copiedArguments?.some((value) => workerNamespaceOf(value, seen))) {
      return true;
    }
    return functionReturnExpressionsOf(node.expression, seen)
      .some((value) => workerNamespaceOf(value, seen));
  }
  const resolved = resolvedValuesOf(node, seen);
  if (resolved.some((value) => value !== node)) {
    const next = new Set(seen);
    next.add(node);
    return resolved.filter((value) => value !== node)
      .some((value) => workerNamespaceOf(value, next));
  }
  if (!ts.isIdentifier(node)) return false;
  const binding = resolveBinding(node);
  if (!binding?.node || seen.has(binding.node)) return false;
  if (binding.kind === "import" && WORKER_MODULES.has(binding.module)) {
    const named = binding.node.importClause?.namedBindings;
    return Boolean(named && ts.isNamespaceImport(named) &&
      named.name.text === node.text);
  }
  if (binding.kind === "parameter" && ts.isParameter(binding.node)) {
    const parameterNext = new Set(seen);
    parameterNext.add(binding.node);
    return (parameterValueArguments.get(binding.node) ?? []).some((value) =>
      (ts.isIdentifier(binding.node.name) ? [value] :
        bindingPatternValuesOf(
          binding.node.name, value, node.text, parameterNext
        )).some((candidate) => workerNamespaceOf(candidate, parameterNext)));
  }
  if ((binding.kind === "variable" || binding.kind === "opaque") &&
      ts.isVariableDeclaration(binding.node) && binding.node.initializer &&
      ts.isObjectBindingPattern(binding.node.name)) {
    const rest = binding.node.name.elements.find((element) =>
      element.dotDotDotToken && ts.isIdentifier(element.name) &&
      element.name.text === node.text);
    if (rest && workerNamespaceOf(binding.node.initializer, seen)) return true;
  }
  return false;
};
const workerAssignedClassMemberValuesOf = (
  input, property, seen = new Set()
) => {
  const classSeen = new Set(seen);
  const normalized = unwrap(input);
  if (normalized) classSeen.delete(normalized);
  return localClassMemberTargetsOf(normalized, classSeen).targets.flatMap((target) =>
    localClassMemberResolutionOf(
      target.classNode, property, target.instance
    )?.assignedValues ?? []);
};
const workerMemberOf = (input, property, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  if (property === "Worker" && workerNamespaceOf(node, seen)) return true;
  const next = new Set(seen);
  next.add(node);
  if (localClassMemberUnresolvedOf(node, property, seen)) return true;
  const candidates = memberValueCandidatesOf(node, property, seen);
  if (candidates.some((value) => workerConstructorOf(value, next) ||
      functionReturnExpressionsOf(value, next)
        .some((returned) => workerConstructorOf(returned, next)))) return true;
  if (workerAssignedClassMemberValuesOf(node, property, next)
      .some((value) => workerConstructorOf(value, next))) return true;
  if (property !== "Worker") return false;
  return objectValueCandidatesOf(node, seen).some((object) =>
    object.properties.some((property) =>
      ts.isSpreadAssignment(property) &&
      workerNamespaceOf(property.expression, next)));
};
const workerBoundConstructorPlanOf = (input, seen = new Set()) => {
 const node = unwrap(input);
 if (!node || seen.has(node)) return undefined;
 const next = new Set(seen);
 next.add(node);
 if (ts.isIdentifier(node)) {
 const binding = resolveBinding(node);
 if (binding?.kind === "variable" &&
 ts.isVariableDeclaration(binding.node) &&
 ts.isIdentifier(binding.node.name) && binding.node.initializer) {
 return workerBoundConstructorPlanOf(binding.node.initializer, next);
 }
 return undefined;
 }
 if (!ts.isCallExpression(node)) return undefined;
 const bind = bindMethodReferenceOf(node.expression, next);
 if (bind?.property === "bind" && workerConstructorOf(bind.receiver, next)) {
 return dropLeadingCallArgument(fixedCallArgumentPlanOf(node.arguments));
 }
 const wrapper = memberAccess(node.expression);
 if (wrapper && ["apply", "call"].includes(wrapper.property)) {
 const wrappedBind = bindMethodReferenceOf(wrapper.receiver, next);
 if (wrappedBind?.property === "bind" &&
 workerConstructorOf(wrappedBind.receiver, next)) {
 const plan = wrapper.property === "call"
        ? dropLeadingCallArgument(fixedCallArgumentPlanOf(node.arguments))
 : argumentArrayPlanOf(node.arguments[1], next);
      return plan;
 }
 }
 if (reflectApplyReferenceOf(node.expression, next)) {
 const reflectedBind = bindMethodReferenceOf(node.arguments[0], next);
 if (reflectedBind?.property === "bind" &&
 workerConstructorOf(reflectedBind.receiver, next)) {
        return argumentArrayPlanOf(node.arguments[2], next);
 }
 }
 return undefined;
};
const workerConstructorOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  if (ts.isIdentifier(node)) {
    if (workerBoundConstructorPlanOf(node, seen) !== undefined) return true;
    const classTarget = localClassMemberTargetOf(node, seen);
    if (classTarget && !classTarget.instance) {
      const classNext = new Set(seen);
      classNext.add(node);
      if (workerConstructorOf(classTarget.classNode, classNext)) return true;
    }
  }
  const earlyMember = memberAccess(node);
  if (earlyMember) {
    const memberNext = new Set(seen);
    memberNext.add(node);
    if (workerMemberOf(
      earlyMember.receiver, earlyMember.property, memberNext
    )) return true;
  }
  const resolved = resolvedValuesOf(node, seen);
  if (resolved.some((value) => value !== node)) {
    const next = new Set(seen);
    next.add(node);
    return resolved.filter((value) => value !== node)
      .some((value) => workerConstructorOf(value, next));
  }
  if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
    return (node.heritageClauses ?? []).some((clause) =>
      clause.token === ts.SyntaxKind.ExtendsKeyword && clause.types.some((type) =>
        workerConstructorOf(type.expression, seen)));
  }
  if (ts.isCallExpression(node)) {
    const next = new Set(seen);
    next.add(node);
 if (workerBoundConstructorPlanOf(node, seen)) return true;
    return functionReturnExpressionsOf(node.expression, next)
      .some((value) => workerConstructorOf(value, next));
  }
  if (!ts.isIdentifier(node)) return false;
  const binding = resolveBinding(node);
  if (!binding?.node || seen.has(binding.node)) return false;
  if (binding.kind === "import" && WORKER_MODULES.has(binding.module)) {
    return importedExport(binding, node.text) === "Worker";
  }
  if (binding.kind === "parameter" && ts.isParameter(binding.node)) {
    const parameterNext = new Set(seen);
    parameterNext.add(binding.node);
    return (parameterValueArguments.get(binding.node) ?? []).some((value) =>
      (ts.isIdentifier(binding.node.name) ? [value] :
        bindingPatternValuesOf(
          binding.node.name, value, node.text, parameterNext
        )).some((candidate) => workerConstructorOf(candidate, parameterNext)));
  }
  if (!(binding.kind === "variable" || binding.kind === "opaque") ||
      !ts.isVariableDeclaration(binding.node)) return false;
  const next = new Set(seen);
  next.add(binding.node);
  if (ts.isIdentifier(binding.node.name)) {
    if (workerBoundConstructorPlanOf(node, next) !== undefined) return true;
    const initializer = binding.node.initializer && unwrap(binding.node.initializer);
    return Boolean(initializer && (ts.isClassDeclaration(initializer) ||
      ts.isClassExpression(initializer)) && workerConstructorOf(initializer, next));
  }
  if (binding.node.initializer && bindingPatternSelectsPropertyOf(
    binding.node.name, node.text, "Worker"
  ) &&
      workerNamespaceOf(binding.node.initializer, next)) return true;
  const values = [
    ...bindingPatternValuesOf(
      binding.node.name, binding.node.initializer, node.text, next
    ),
    ...(destructuredAssignmentsByBinding.get(
      `${binding.node.pos}:${node.text}`) ?? [])
  ];
  return values.some((value) => workerConstructorOf(value, next));
};
const classBodyCapabilityOf = (body, seen) => {
if (!body) return false;
let found = false;
const visit = (child) => {
if (found || seen.has(child)) return;
if (workerConstructorOf(child, seen) || workerNamespaceOf(child, seen)) {
found = true;
return;
}
const next = new Set(seen);
next.add(child);
ts.forEachChild(child, visit);
};
ts.forEachChild(body, visit);
return found;
};
const workerClassCapabilityOf = (classNode, seen = new Set()) => {
const next = new Set(seen);
next.add(classNode);
for (const clause of classNode.heritageClauses ?? []) {
if (clause.token !== ts.SyntaxKind.ExtendsKeyword) continue;
for (const clauseType of clause.types) {
if (workerConstructorOf(clauseType.expression, next)) return true;
}
}
for (const member of classNode.members) {
if (ts.isPropertyDeclaration(member) && member.initializer &&
workerCapabilityOf(member.initializer, next)) return true;
if (ts.isMethodDeclaration(member) || ts.isGetAccessorDeclaration(member)) {
if (workerCapabilityOf(member, next)) return true;
}
if ((ts.isConstructorDeclaration(member) ||
ts.isClassStaticBlockDeclaration(member)) &&
classBodyCapabilityOf(member.body, next)) return true;
}
return false;
};
// Verified Worker capability must not escape the fixed supervisor inventory,
// including through local helpers, arrays, classes, or exported containers.
const workerCapabilityOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  if (ts.isCallExpression(node)) {
    const bound = memberAccess(node.expression);
    if (bound?.property === "bind") {
      const next = new Set(seen);
      next.add(node);
      return workerCapabilityOf(bound.receiver, next) ||
        node.arguments.some((argument) => workerCapabilityOf(argument, next));
    }
  }
  if (workerConstructorOf(node, seen) || workerNamespaceOf(node, seen)) return true;
  const next = new Set(seen);
  next.add(node);
  if (ts.isIdentifier(node) && localClassMemberTargetsOf(node, seen).targets.some(
    (target) => !target.instance && workerClassCapabilityOf(target.classNode, next))) {
    return true;
  }
  const arrayValues = fixedSpreadValuesOf(node, seen);
  if (arrayValues?.some((value) => workerCapabilityOf(value, next))) return true;
  if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
if (workerClassCapabilityOf(node, seen)) return true;
}
if (ts.isNewExpression(node)) {
    if (localClassMemberTargetsOf(node, seen).targets.some((target) =>
      workerClassCapabilityOf(target.classNode, next))) return true;
}
  for (const object of objectValueCandidatesOf(node, seen)) {
    for (const property of object.properties) {
      if (ts.isSpreadAssignment(property)) {
        if (workerCapabilityOf(property.expression, next)) return true;
        continue;
      }
      if (!("name" in property)) continue;
      const value = ts.isPropertyAssignment(property) ? property.initializer
        : ts.isShorthandPropertyAssignment(property) ? property.name
          : ts.isMethodDeclaration(property) || ts.isGetAccessorDeclaration(property)
            ? property : undefined;
      if (value && workerCapabilityOf(value, next)) return true;
    }
  }
  return functionReturnExpressionsOf(node, seen).some((value) =>
    workerCapabilityOf(value, next));
};
// Only a statically false eval option is safe. Retrieved spreads use the same
// provenance rules; computed names and unresolved values fail closed.
const inspectWorkerEvalValue = (value, findingNode, unproven) => {
  const staticValue = staticLogicalValueOf(value);
  if (!staticValue) {
    add(findingNode, unproven);
  } else if (staticValue.truthy) {
    add(findingNode, "worker_threads inline evaluation is forbidden");
  }
};
let workerCallExpressions;
const workerOptionMutationReferenceKeysOf = (options, seen = new Set()) => {
  const keys = new Set();
  const visited = new Set();
  const queue = [unwrap(options)].filter(Boolean);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [parameter, argumentsList] of parameterValueArguments) {
      if (!ts.isIdentifier(parameter.name)) continue;
      const parameterKey = assignmentReferenceKey(parameter.name);
      if (parameterKey === undefined || keys.has(parameterKey)) continue;
      if (argumentsList.some((argument) =>
        keys.has(assignmentReferenceKey(argument)))) {
        keys.add(parameterKey);
        queue.push(parameter.name);
        changed = true;
      }
    }
    while (queue.length > 0) {
      const value = unwrap(queue.shift());
      if (!value || visited.has(value)) continue;
      visited.add(value);
      const key = assignmentReferenceKey(value);
      if (key !== undefined && !keys.has(key)) {
        keys.add(key);
        changed = true;
      }
      const next = new Set(seen);
      next.add(value);
      for (const resolved of resolvedValuesOf(value, next)) {
        if (!ts.isCallExpression(resolved)) continue;
        queue.push(...objectCreatePrototypeValuesOf(resolved, next));
      queue.push(...functionReturnExpressionsOf(resolved.expression, next));
      }
    }
  }
  return keys;
};
const workerReferenceMatchesKeysOf = (
  input, targetKeys, seen = new Set()
) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  if (targetKeys.has(assignmentReferenceKey(node))) return true;
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if ((binding?.kind === "variable" || binding?.kind === "opaque") &&
        ts.isVariableDeclaration(binding.node) && binding.node.initializer &&
        !ts.isIdentifier(binding.node.name)) {
      const next = new Set(seen);
      next.add(node);
      next.add(binding.node);
      return bindingPatternValuesOf(
        binding.node.name, binding.node.initializer, node.text, next
      ).some((value) => workerReferenceMatchesKeysOf(value, targetKeys, next));
    }
  }
  const member = assignmentMemberAccess(node);
  if (!member) return false;
  const next = new Set(seen);
  next.add(node);
  return memberValueCandidatesOf(member.receiver, member.property, next)
    .some((value) => workerReferenceMatchesKeysOf(value, targetKeys, next));
};
const workerOptionFactoryReturnExpressionsOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return [];
  const next = new Set(seen);
  next.add(node);
  if (!ts.isCallExpression(node)) return functionReturnExpressionsOf(node, next);
  return localFunctionValuesOf(node.expression, next)
    .flatMap((value) => functionReturnExpressionsOf(value, next));
};
const firstDirectReturnByBlock = new WeakMap();
const workerMutationIsUnreachableOf = (node) => {
  for (let current = node; current && !ts.isFunctionLike(current);
       current = current.parent) {
    const block = current.parent;
    if (!block || !ts.isBlock(block)) continue;
    let firstReturn = firstDirectReturnByBlock.get(block);
    if (!firstDirectReturnByBlock.has(block)) {
      firstReturn = block.statements.find(ts.isReturnStatement);
      firstDirectReturnByBlock.set(block, firstReturn);
    }
    if (firstReturn && firstReturn !== current &&
        firstReturn.getEnd() <= current.getStart(file)) {
      return true;
    }
  }
  return false;
};
// A mutation can affect Worker options when it is evaluated in the constructor
// argument or in the bounded local factory that produced the options value.
const workerOptionMutationCanAffectOf = (options, reference) => {
  const referenceEnd = reference?.getEnd() ?? Number.POSITIVE_INFINITY;
  const functions = new Set(workerOptionFactoryReturnExpressionsOf(options)
    .map((value) => {
      let owner = value.parent;
      while (owner && !ts.isFunctionLike(owner)) owner = owner.parent;
      return owner;
    })
    .filter(Boolean));
  return (node) => {
    if (workerMutationIsUnreachableOf(node)) return false;
    if (node.getStart(file) <= referenceEnd) return true;
    let owner = node.parent;
    while (owner && !ts.isFunctionLike(owner)) owner = owner.parent;
    return functions.has(owner);
  };
};
const inspectKnownWorkerOptionMutations = (
  options, reference, seen, unproven, targetKeys
) => {
  if (!reference || targetKeys.size === 0) return;
  const canAffectOptions = workerOptionMutationCanAffectOf(options, reference);
  const targetsOptions = (candidate) =>
    workerReferenceMatchesKeysOf(candidate, targetKeys);
  for (const assignment of dynamicMemberAssignments) {
    if (canAffectOptions(assignment.node) &&
        targetsOptions(assignment.receiver)) {
      const property = staticStringAtInspectionOf(
        assignment.node.argumentExpression
      );
      if (property === undefined) {
        add(assignment.node, unproven);
      } else if (property === "eval") {
        inspectWorkerEvalValue(assignment.value, assignment.node, unproven);
      }
    }
  }
  const inspectNamedMutation = (call, name, value) => {
    const property = staticStringOf(name);
    if (property === undefined) {
      add(call, unproven);
    } else if (property === "eval") {
      inspectWorkerEvalValue(value, value, unproven);
    }
  };
  const inspectDescriptorValue = (call, descriptor) => {
    const values = memberValueCandidatesOf(descriptor, "value", seen);
    if (values.length === 0) add(call, unproven);
    for (const value of values) {
      inspectWorkerEvalValue(value, value, unproven);
    }
  };
  const inspectNamedDescriptorMutation = (call, name, descriptor) => {
    const property = staticStringOf(name) ?? staticPropertyNameOf(name);
    if (property === undefined) {
      add(call, unproven);
    } else if (property === "eval") {
      inspectDescriptorValue(call, descriptor);
    }
  };
  const inspectDescriptorMap = (call, descriptors) => {
    const maps = objectValueCandidatesOf(descriptors, seen);
    if (maps.length === 0) add(call, unproven);
    for (const map of maps) {
      for (const property of map.properties) {
        if (ts.isSpreadAssignment(property)) {
          add(call, unproven);
          continue;
        }
        if (!("name" in property)) {
          add(call, unproven);
          continue;
        }
        let descriptors;
        if (ts.isPropertyAssignment(property)) {
          descriptors = [property.initializer];
        } else if (ts.isShorthandPropertyAssignment(property)) {
          descriptors = [property.name];
        } else if (ts.isGetAccessorDeclaration(property)) {
          descriptors = functionReturnExpressionsOf(property, seen);
          if (descriptors.length === 0) add(call, unproven);
        } else {
          continue;
        }
        for (const descriptor of descriptors) {
          inspectNamedDescriptorMutation(call, property.name, descriptor);
        }
      }
    }
  };
  if (!workerCallExpressions) {
    workerCallExpressions = [];
    const collect = (node) => {
      if (ts.isCallExpression(node)) workerCallExpressions.push(node);
      ts.forEachChild(node, collect);
    };
    ts.forEachChild(file, collect);
  }
  for (const node of workerCallExpressions) {
    if (!canAffectOptions(node)) continue;
      const copiedArguments = objectAssignInvocationArgumentsOf(node, seen);
      if (copiedArguments &&
          (targetsOptions(copiedArguments[0]) || targetsOptions(node))) {
        for (const source of copiedArguments.slice(1)) {
          inspectWorkerOptions(source, seen, reference, true);
        }
      }
      const setPlan = staticMethodInvocationPlanOf(
        node, "set", globalReflectOf, seen
      );
      if (setPlan && callArgumentCandidatesAt(setPlan, 0).some(targetsOptions)) {
        const names = callArgumentCandidatesAt(setPlan, 1);
        if (names.length === 0) add(node, unproven);
        for (const name of names) {
          for (const value of callArgumentCandidatesAt(setPlan, 2)) {
            inspectNamedMutation(node, name, value);
          }
        }
      }
      const prototypePlan = staticMethodInvocationPlanOf(
        node, "setPrototypeOf", globalObjectOf, seen
      ) ?? staticMethodInvocationPlanOf(
        node, "setPrototypeOf", globalPrototypeObjectOf, seen
      );
      if (prototypePlan &&
          callArgumentCandidatesAt(prototypePlan, 0).some(targetsOptions)) {
        const prototypes = callArgumentCandidatesAt(prototypePlan, 1);
        if (prototypes.length === 0) add(node, unproven);
        for (const prototype of prototypes) {
          inspectWorkerOptions(prototype, seen, reference, false);
        }
      }
      const definePropertiesPlan = staticMethodInvocationPlanOf(
        node, "defineProperties", globalObjectOf, seen
      ) ?? staticMethodInvocationPlanOf(
        node, "defineProperties", globalPrototypeObjectOf, seen
      );
      if (definePropertiesPlan &&
          callArgumentCandidatesAt(definePropertiesPlan, 0).some(targetsOptions)) {
        const descriptors = callArgumentCandidatesAt(definePropertiesPlan, 1);
        if (descriptors.length === 0) add(node, unproven);
        for (const descriptor of descriptors) {
          inspectDescriptorMap(node, descriptor);
        }
      }
      const definePlan = staticMethodInvocationPlanOf(
        node, "defineProperty", globalObjectOf, seen
      ) ?? staticMethodInvocationPlanOf(
        node, "defineProperty", globalPrototypeObjectOf, seen
      ) ?? staticMethodInvocationPlanOf(
        node, "defineProperty", globalReflectOf, seen
      );
      if (definePlan && callArgumentCandidatesAt(definePlan, 0).some(targetsOptions)) {
        const names = callArgumentCandidatesAt(definePlan, 1);
        if (names.length === 0) add(node, unproven);
        const descriptors = callArgumentCandidatesAt(definePlan, 2);
        if (descriptors.length === 0) add(node, unproven);
        for (const name of names) {
          for (const descriptor of descriptors) {
            inspectNamedDescriptorMutation(node, name, descriptor);
          }
        }
      }
  }
};
const isAbsentOptionsValue = (input) => {
  const node = unwrap(input);
  if (!node || node.kind === ts.SyntaxKind.NullKeyword ||
      ts.isVoidExpression(node)) return true;
  return ts.isIdentifier(node) && node.text === "undefined" &&
    !resolveBinding(node);
};
const inspectWorkerOptions = (
  input, seen = new Set(), reference = unwrap(input), inspectMutations = true
) => {
  const options = unwrap(input);
  // Worker treats a missing options argument as eval: false.
  if (seen.has(options) || isAbsentOptionsValue(options)) return;
  const next = new Set(seen);
  next.add(options);
  const unproven = "worker_threads inline-evaluation options are unproven";
  const mutationKeys = workerOptionMutationReferenceKeysOf(options, seen);
  if (inspectMutations) {
    inspectKnownWorkerOptionMutations(
      options, reference, next, unproven, mutationKeys
    );
  }
  // inline local factory may mutate its result after the outer call starts.
  const canAffectOptions = workerOptionMutationCanAffectOf(options, reference);
  for (const assignment of memberAssignmentTargets) {
    if (assignment.property === "eval" &&
        canAffectOptions(assignment.node) &&
        workerReferenceMatchesKeysOf(assignment.receiver, mutationKeys)) {
      inspectWorkerEvalValue(assignment.value, assignment.node, unproven);
    }
  }
  const objects = [];
  const inspectedParameters = new Set();
  // Conditional and assigned options can contain branches that do not resolve
  // to an object literal. Any such branch can enable inline evaluation.
  for (const candidate of resolvedValuesOf(options, next)) {
    if (isAbsentOptionsValue(candidate)) continue;
    const binding = ts.isIdentifier(candidate) ? resolveBinding(candidate) : undefined;
    if (binding?.kind === "parameter" && ts.isParameter(binding.node) &&
        !inspectedParameters.has(binding.node)) {
      const parameterValues = parameterValueArguments.get(binding.node) ?? [];
      if (parameterValues.length > 0) {
        inspectedParameters.add(binding.node);
        const parameterNext = new Set(next);
        parameterNext.add(binding.node);
        for (const value of parameterValues) {
          const selected = ts.isIdentifier(binding.node.name)
            ? [value]
            : bindingPatternValuesOf(
                binding.node.name, value, candidate.text, parameterNext
              );
          if (selected.length === 0) add(candidate, unproven);
          for (const selectedValue of selected) {
            inspectWorkerOptions(
              selectedValue, parameterNext, reference, inspectMutations
            );
          }
        }
        continue;
      }
    }
    if (binding?.kind === "parameter" && ts.isParameter(binding.node) &&
        inspectedParameters.has(binding.node)) continue;
    const unresolvedCandidates = [];
    const candidateObjects = objectValueCandidatesOf(
      candidate, seen, unresolvedCandidates
    );
    if (candidateObjects.length === 0 || unresolvedCandidates.length > 0) {
      add(candidate, unproven);
    }
    objects.push(...candidateObjects);
  }
  if (objects.length === 0) return;
  for (const object of objects) {
    // An omitted eval property means false; other Worker options do not enable
    // evaluation of source text.
    for (const property of object.properties) {
      if (!("name" in property)) {
        inspectWorkerOptions(property.expression, next, reference, false);
        continue;
      }
      if (ts.isPropertyAssignment(property) &&
          staticPropertyNameOf(property.name) === "__proto__") {
        inspectWorkerOptions(property.initializer, next, reference, false);
        continue;
      }
      const name = staticPropertyNameOf(property.name);
      if (name === undefined) {
        add(property, unproven);
        continue;
      }
      if (name !== "eval") continue;
      const value = ts.isPropertyAssignment(property)
        ? property.initializer
        : ts.isShorthandPropertyAssignment(property) ? property.name : property;
      inspectWorkerEvalValue(value, property, unproven);
    }
  }
};
const inspectWorkerConstruction = (
 call, plan = fixedCallArgumentPlanOf(call.arguments)
) => {
  const options = callArgumentCandidatesAt(plan, 1);
  if (plan.unknownIndex !== undefined && plan.unknownIndex <= 1) {
    add(call, "worker_threads inline-evaluation options are unproven");
  }
  for (const option of options) {
    inspectWorkerOptions(option, new Set(), call);
  }
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
    // Named, namespace, and star exports can all expose Worker.
    const exportsWorker = !clause || !ts.isNamedExports(clause) ||
      clause.elements.some((element) => !element.isTypeOnly &&
        [element.propertyName?.text, element.name.text].includes("Worker"));
    if (!typeOnly && WORKER_MODULES.has(module) && exportsWorker) {
      add(node, "runtime worker_threads capability re-export is forbidden");
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
    if (workerCapabilityOf(node.propertyName ?? node.name)) {
      add(node, "runtime worker_threads capability re-export is forbidden");
    }
    }
      return;
    }
if (ts.isExportAssignment(node) && workerCapabilityOf(node.expression)) {
  add(node, "runtime worker_threads capability re-export is forbidden");
}
if (ts.isFunctionDeclaration(node) && hasExportModifier(node) &&
    workerCapabilityOf(node)) {
  add(node, "runtime worker_threads capability re-export is forbidden");
}
if (ts.isClassDeclaration(node) && hasExportModifier(node) &&
    workerCapabilityOf(node)) {
  add(node, "runtime worker_threads capability re-export is forbidden");
}
if (ts.isVariableDeclaration(node) && node.initializer &&
    ts.isVariableStatement(node.parent.parent) && hasExportModifier(node.parent.parent) &&
    workerCapabilityOf(node.initializer)) {
  add(node, "runtime worker_threads capability re-export is forbidden");
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
    if (ts.isCallExpression(node) &&
        node.expression.kind === ts.SyntaxKind.SuperKeyword) {
      const owner = enclosingFunctionOf(node);
      const ownerClass = owner?.parent;
      if (ownerClass &&
          (ts.isClassDeclaration(ownerClass) || ts.isClassExpression(ownerClass)) &&
          workerConstructorOf(ownerClass, new Set([node]))) {
        inspectWorkerConstruction(node);
      }
    }
if (ts.isNewExpression(node) && workerConstructorOf(node.expression)) {
 const boundPlan = workerBoundConstructorPlanOf(node.expression);
 inspectWorkerConstruction(node, boundPlan
   ? mergeCallArgumentPlans(
     boundPlan, fixedCallArgumentPlanOf(node.arguments ?? []))
   : undefined);
    }
  if (ts.isCallExpression(node) &&
      reflectConstructReferenceOf(node.expression) &&
      node.arguments[0] && workerConstructorOf(node.arguments[0])) {
    const plan = argumentArrayPlanOf(node.arguments[1]);
    const options = callArgumentCandidatesAt(plan, 1);
    if (options.length === 0 && plan.unknownIndex !== undefined &&
        plan.unknownIndex <= 1) {
      add(node, "worker_threads inline-evaluation options are unproven");
    }
    for (const option of options) {
      inspectWorkerOptions(option, new Set(), node);
    }
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
      recordResolvedAssignments(node.name, node.initializer);
      if (processObjectOf(node.initializer)) inspectProcessDestructuring(node.name);
    if (globalCapabilityDestructuringOf(
      node.name, node.initializer
    )) {
        inspectGlobalDestructuring(node.name);
      }
    }
    if (ts.isVariableDeclaration(node) && ts.isArrayBindingPattern(node.name) &&
        node.initializer) {
      recordResolvedAssignments(node.name, node.initializer);
      inspectCapabilityArrayDestructuring(node.name, node.initializer);
    }
    if (ts.isForOfStatement(node)) {
      const targets = ts.isVariableDeclarationList(node.initializer)
        ? node.initializer.declarations.map((declaration) => declaration.name)
        : [unwrap(node.initializer)];
      const iterated = fixedSpreadValuesOf(node.expression);
      for (const target of targets) {
        if (ts.isObjectBindingPattern(target) ||
            ts.isObjectLiteralExpression(target)) {
          if (iterated?.some((value) => processObjectOf(value))) {
            inspectProcessDestructuring(target);
          }
          if (iterated?.some((value) =>
            globalObjectOf(value) || globalCapabilitySourceOf(value))) {
            inspectGlobalDestructuring(target);
          }
        } else if (ts.isArrayBindingPattern(target) ||
                   ts.isArrayLiteralExpression(target)) {
          for (const source of iterated ?? [node.expression]) {
            inspectCapabilityArrayDestructuring(target, source);
          }
        }
      }
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
        if (globalCapabilityDestructuringOf(target, node.right)) {
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
  const expandedStaticArgumentsOf = (argumentsList, seen) => {
    const values = [];
    for (const argument of argumentsList) {
      if (!ts.isSpreadElement(argument)) {
        values.push(unwrap(argument));
        continue;
      }
      const expanded = fixedSpreadValuesOf(argument.expression, seen);
      if (!expanded) return undefined;
      values.push(...expanded);
    }
    return values;
  };
const fixedBoundStaticArgumentsOf = (input, property, ownerOf, seen) => {
  const plan = boundStaticMethodPrefixPlanOf(input, property, ownerOf, seen);
  if (!plan || plan.unknownAll || plan.unknownIndex !== undefined) return undefined;
  return [...plan.before, ...plan.after].filter(Boolean);
};
const staticMethodWrapperMethodOf = (input, seen) => {
  for (const wrapperMethod of ["apply", "call"]) {
    if (staticMethodWrapperReferenceOf(
      input, wrapperMethod, "of", globalArrayObjectOf, seen
    )) return wrapperMethod;
  }
  return undefined;
};
const boundStaticMethodWrapperMethodOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return undefined;
  const next = new Set(seen);
  next.add(node);
  const member = memberAccess(node);
  if (member) {
    for (const value of memberValueCandidatesOf(
      member.receiver, member.property, next
    )) {
      const method = boundStaticMethodWrapperMethodOf(value, next);
      if (method) return method;
    }
  }
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (binding?.node && (ts.isVariableDeclaration(binding.node) ||
      ts.isParameter(binding.node)) && !ts.isIdentifier(binding.node.name) &&
      binding.node.initializer) {
      return bindingPatternValuesOf(
        binding.node.name, binding.node.initializer, node.text, next
      ).some((value) => boundStaticMethodWrapperMethodOf(value, next));
    }
    if (binding?.kind === "variable" &&
        ts.isVariableDeclaration(binding.node) &&
        ts.isIdentifier(binding.node.name) && binding.node.initializer) {
      return boundStaticMethodWrapperMethodOf(binding.node.initializer, next);
    }
    return undefined;
  }
  if (!ts.isCallExpression(node)) return undefined;
  const bind = bindMethodReferenceOf(node.expression, next);
  if (bind?.property !== "bind") return undefined;
  const plan = fixedCallArgumentPlanOf(node.arguments);
  if (plan.unknownAll || plan.unknownIndex !== undefined) return undefined;
  const boundArguments = [...plan.before, ...plan.after].filter(Boolean);
  const thisArgument = boundArguments[0];
  if (!thisArgument || !staticMethodReferenceOf(
    thisArgument, "of", globalArrayObjectOf, next
  )) return undefined;
  return staticMethodWrapperMethodOf(bind.receiver, next);
};
const fixedArrayOfInvocationArgumentsOf = (call, seen) => {
  const argumentsList = expandedStaticArgumentsOf(call.arguments, seen);
  if (!argumentsList) return undefined;

  const wrapperInvocationValuesOf = (wrapperMethod, invocationArguments) => {
    if (!globalArrayObjectOf(invocationArguments[0], seen)) return undefined;
    if (wrapperMethod === "apply") {
      return invocationArguments[1]
        ? fixedSpreadValuesOf(invocationArguments[1], seen) : [];
    }
    return invocationArguments.slice(1);
  };

  const invokedArgumentsOf = (invocationArguments) => {
    if (!invocationArguments) return undefined;
    const target = invocationArguments[0];
    const applicationArguments = invocationArguments[2];
    const applicationValues = applicationArguments
      ? fixedSpreadValuesOf(applicationArguments, seen) : [];
    if (!applicationValues) return undefined;
    const wrapperMethod = staticMethodWrapperMethodOf(target, seen);
    if (wrapperMethod) {
      if (!staticMethodReferenceOf(
        invocationArguments[1], "of", globalArrayObjectOf, seen
      )) return undefined;
      return wrapperInvocationValuesOf(wrapperMethod, applicationValues);
    }
    if (target && staticMethodReferenceOf(
      target, "of", globalArrayObjectOf, seen
    )) return applicationValues;
    if (!target) return undefined;
    const boundArguments = fixedBoundStaticArgumentsOf(
      target, "of", globalArrayObjectOf, seen
    );
    return boundArguments
      ? [...boundArguments, ...applicationValues] : undefined;
  };

  if (reflectApplyReferenceOf(call.expression, seen)) {
    return invokedArgumentsOf(argumentsList);
  }

  const wrapper = memberAccess(unwrap(call.expression));
  if (wrapper && ["apply", "call"].includes(wrapper.property)) {
    const receiverArguments = wrapper.property === "call"
      ? argumentsList.slice(1)
      : argumentsList[1]
        ? fixedSpreadValuesOf(argumentsList[1], seen) : [];
    if (!receiverArguments) return undefined;
    const boundWrapperMethod = boundStaticMethodWrapperMethodOf(
      wrapper.receiver, seen
    );
    if (boundWrapperMethod) {
      const wrapperValues = wrapperInvocationValuesOf(
        boundWrapperMethod, receiverArguments
      );
      if (wrapperValues) return wrapperValues;
    }
    for (const wrapperMethod of ["apply", "call"]) {
      if (!staticMethodWrapperReferenceOf(
        wrapper.receiver, wrapperMethod, "of", globalArrayObjectOf, seen
      )) continue;
      if (!argumentsList[0] || !staticMethodReferenceOf(
        argumentsList[0], "of", globalArrayObjectOf, seen
      )) return undefined;
      return wrapperInvocationValuesOf(wrapperMethod, receiverArguments);
    }
    if (reflectApplyReferenceOf(wrapper.receiver, seen)) {
      return invokedArgumentsOf(receiverArguments);
    }
    if (staticMethodReferenceOf(
      wrapper.receiver, "of", globalArrayObjectOf, seen
    )) return receiverArguments;
    const boundArguments = fixedBoundStaticArgumentsOf(
      wrapper.receiver, "of", globalArrayObjectOf, seen
    );
    if (boundArguments) return [...boundArguments, ...receiverArguments];
  }

  const boundWrapperMethod = boundStaticMethodWrapperMethodOf(call.expression, seen);
  if (boundWrapperMethod) {
    const wrapperValues = wrapperInvocationValuesOf(
      boundWrapperMethod, argumentsList
    );
    if (wrapperValues) return wrapperValues;
  }

  if (staticMethodReferenceOf(
    call.expression, "of", globalArrayObjectOf, seen
  )) return argumentsList;
  const boundArguments = fixedBoundStaticArgumentsOf(
    call.expression, "of", globalArrayObjectOf, seen
  );
  return boundArguments
    ? [...boundArguments, ...argumentsList] : undefined;
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
        (ts.isArrayLiteralExpression(unwrap(binding.node.initializer)) ||
         isNewArrayExpression(unwrap(binding.node.initializer)))) {
    const usageStart = node.getStart(file);
    const mutations = (arrayMutationValuesByBinding.get(binding.node) ?? [])
      .filter((mutation) => mutation.start <= usageStart);
      if (mutations.length === 0) {
        const mutationSeen = new Set(next);
        mutationSeen.add(binding.node);
        return fixedSpreadValuesOf(binding.node.initializer, mutationSeen);
      }
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
  const arrayOfInvocation = fixedArrayOfInvocationArgumentsOf(node, next);
  if (arrayOfInvocation) return arrayOfInvocation;
    if (reflectApplyReferenceOf(node.expression, next) &&
        staticMethodReferenceOf(
          node.arguments[0], "of", globalArrayObjectOf, next
        )) {
      return fixedSpreadValuesOf(node.arguments[2], next);
    }
    const arrayOfWrapper = memberAccess(unwrap(node.expression));
    if (arrayOfWrapper && ["apply", "call"].includes(arrayOfWrapper.property) &&
        staticMethodReferenceOf(
          arrayOfWrapper.receiver, "of", globalArrayObjectOf, next
        )) {
      return arrayOfWrapper.property === "call"
        ? expandedStaticArgumentsOf(node.arguments.slice(1), next)
        : fixedSpreadValuesOf(node.arguments[1], next);
    }
    const boundArrayOf = boundStaticMethodPrefixPlanOf(
      node.expression, "of", globalArrayObjectOf, next
    );
    if (boundArrayOf && !boundArrayOf.unknownAll &&
        boundArrayOf.unknownIndex === undefined) {
      const argumentsList = expandedStaticArgumentsOf(node.arguments, next);
      if (argumentsList) {
        return [...boundArrayOf.before, ...boundArrayOf.after, ...argumentsList];
      }
    }
    if (staticMethodReferenceOf(
      node.expression, "of", globalArrayObjectOf, next
    )) {
      return expandedStaticArgumentsOf(node.arguments, next);
    }
    const returned = functionReturnExpressionsOf(node.expression, next);
    if (returned.length === 0) return undefined;
    const expanded = returned.map((value) => fixedSpreadValuesOf(value, next));
    if (expanded.some((value) => value === undefined)) return undefined;
    return expanded.flat();
  }
  if (isNewArrayExpression(node)) {
    const argumentsList = node.arguments ?? [];
    if (argumentsList.length === 0) return [];
    if (argumentsList.length === 1 &&
        ts.isNumericLiteral(unwrap(argumentsList[0]))) return [];
    const values = [];
    for (const argument of argumentsList) {
      if (!ts.isSpreadElement(argument)) {
        values.push(unwrap(argument));
        continue;
      }
      const expanded = fixedSpreadValuesOf(argument.expression, next);
      if (!expanded) return undefined;
      values.push(...expanded);
    }
    return values;
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
const isNewArrayExpression = (node) => Boolean(
  ts.isNewExpression(node) && ts.isIdentifier(unwrap(node.expression)) &&
  unwrap(node.expression).text === "Array" && !resolveBinding(unwrap(node.expression))
);
const arrayBindingsOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return [];
  if (ts.isArrayLiteralExpression(node) || isNewArrayExpression(node)) return [node];
  if (ts.isCallExpression(node)) {
    const next = new Set(seen);
    next.add(node);
    return functionReturnExpressionsOf(node.expression, next)
      .flatMap((value) => arrayBindingsOf(value, next));
  }
  const member = memberAccess(node);
  if (member && !seen.has(node)) {
    const next = new Set(seen);
    next.add(node);
    return memberValueCandidatesOf(member.receiver, member.property, next)
      .flatMap((value) => arrayBindingsOf(value, next));
  }
  if (!ts.isIdentifier(node)) return [];
  const binding = resolveBinding(node);
  if (!binding?.node || seen.has(binding.node)) return [];
  const next = new Set(seen);
  next.add(binding.node);
  if (binding.kind === "variable" &&
      ts.isVariableDeclaration(binding.node) &&
      ts.isIdentifier(binding.node.name)) {
    const values = activeBindingValuesOf(binding.node, node);
    if (values.some((value) => {
      const initializer = unwrap(value);
      return ts.isArrayLiteralExpression(initializer) || isNewArrayExpression(initializer);
    })) return [binding.node];
    return values.flatMap((value) => arrayBindingsOf(value, next));
  }
  if (binding.kind === "parameter" && ts.isParameter(binding.node) &&
      ts.isIdentifier(binding.node.name)) {
    const fn = binding.node.parent;
  const index = runtimeParameterIndexOf(fn, binding.node);
    const plans = functionArgumentsPlans.get(fn) ?? [];
    return plans.flatMap((plan) => callArgumentCandidatesAt(plan, index)
      .flatMap((value) => arrayBindingsOf(value, next)));
  }
  return [];
};
const arrayInitialValueOf = (binding) => {
  const value = unwrap(binding);
  return ts.isVariableDeclaration(value) ? value.initializer : value;
};
const arrayPreviousValuesOf = (binding, mutations) => [
  arrayInitialValueOf(binding),
  ...mutations.flatMap((mutation) => mutation.values)
].filter(Boolean);
const arrayMutationValueCarriesCapability = (
  input, seen = new Set(), invocation = undefined
) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return false;
  const next = new Set(seen);
  next.add(node);
  if (ts.isSpreadElement(node)) {
    return arrayMutationValueCarriesCapability(
      node.expression, next, invocation
    );
  }
  if (invocation && ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (binding?.kind === "parameter" && ts.isParameter(binding.node) &&
        binding.node.parent === invocation.fn) {
    const index = runtimeParameterIndexOf(invocation.fn, binding.node);
      return callArgumentCandidatesAt(invocation.plan, index).some((value) =>
        arrayMutationValueCarriesCapability(value, next, invocation));
    }
  }
  if (processObjectOf(node, next) || globalObjectOf(node, next) ||
      requireReferenceOf(node, next)) return true;
  if (ts.isConditionalExpression(node)) {
    return arrayMutationValueCarriesCapability(
      node.whenTrue, next, invocation
    ) || arrayMutationValueCarriesCapability(
      node.whenFalse, next, invocation
    );
  }
  if (ts.isArrayLiteralExpression(node)) {
    return node.elements.some((element) =>
      !ts.isOmittedExpression(element) &&
      arrayMutationValueCarriesCapability(element, next, invocation));
  }
  if (isNewArrayExpression(node)) {
    return (node.arguments ?? []).some((argument) =>
      arrayMutationValueCarriesCapability(argument, next, invocation));
  }
  if (ts.isObjectLiteralExpression(node)) {
    return node.properties.some((property) =>
      ts.isPropertyAssignment(property)
      ? arrayMutationValueCarriesCapability(
        property.initializer, next, invocation
      )
        : ts.isShorthandPropertyAssignment(property)
      ? arrayMutationValueCarriesCapability(property.name, next, invocation)
        : ts.isSpreadAssignment(property) &&
      arrayMutationValueCarriesCapability(
        property.expression, next, invocation
      ));
  }
  if (!ts.isIdentifier(node)) return false;
  const binding = resolveBinding(node);
  if (binding?.kind === "parameter" && ts.isParameter(binding.node)) {
    return [
      ...(parameterProcessArguments.get(binding.node) ?? []),
      ...(parameterGlobalArguments.get(binding.node) ?? []),
      ...(parameterRequireArguments.get(binding.node) ?? [])
    ].some((value) => arrayMutationValueCarriesCapability(value, next));
  }
  return Boolean(binding?.kind === "variable" &&
    ts.isVariableDeclaration(binding.node) && binding.node.initializer &&
    arrayMutationValueCarriesCapability(
      binding.node.initializer, next, invocation
    ));
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
const arrayMutationValuesCarryCapabilityForTarget = (target, values) => {
  const node = unwrap(target);
  if (!node || !ts.isIdentifier(node)) return undefined;
  const binding = resolveBinding(node);
  if (binding?.kind !== "parameter" || !ts.isParameter(binding.node)) {
    return undefined;
  }
  const fn = binding.node.parent;
const index = runtimeParameterIndexOf(fn, binding.node);
  if (index < 0) return false;
  return (functionArgumentsPlans.get(fn) ?? []).some((plan) => {
    const targetArguments = callArgumentCandidatesAt(plan, index);
    if (!targetArguments.some((argument) =>
      arrayBindingsOf(argument).length > 0)) return false;
    return values.some((value) => arrayMutationValueCarriesCapability(
      value, new Set(), { fn, plan }
    ));
  });
};
const mutableArrayMethods = new Set([
  "push", "unshift", "splice", "fill", "copyWithin",
  "reverse", "sort", "pop", "shift"
]);
const globalArrayObjectOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node) return false;
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if (!binding) return node.text === "Array";
    if (!binding.node || seen.has(binding.node) ||
        !(ts.isVariableDeclaration(binding.node) || ts.isParameter(binding.node)) ||
        !ts.isIdentifier(binding.node.name)) return false;
    const next = new Set(seen);
    next.add(binding.node);
    return activeBindingValuesOf(binding.node, node)
      .some((value) => globalArrayObjectOf(value, next));
  }
  const member = memberAccess(node);
  return Boolean(member?.property === "Array" && globalObjectOf(member.receiver, seen));
};
const globalArrayPrototypeOf = (input, seen = new Set()) => {
  const member = memberAccess(unwrap(input));
  return Boolean(member?.property === "prototype" &&
    globalArrayObjectOf(member.receiver, seen));
};
const arrayMutationMethodAlternativesOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return [];
  const next = new Set(seen);
  next.add(node);
  const member = memberAccess(node);
  if (member) {
    const members = memberValueCandidatesOf(member.receiver, member.property, next);
    if (members.length > 0) {
      return members.flatMap((value) => arrayMutationMethodAlternativesOf(value, next));
    }
    if (mutableArrayMethods.has(member.property) &&
        (globalArrayPrototypeOf(member.receiver, next) ||
         arrayBindingsOf(member.receiver, next).length > 0)) {
      return [{
        kind: member.property,
        receiver: globalArrayPrototypeOf(member.receiver, next)
          ? undefined : member.receiver,
        bound: false,
        captured: []
      }];
    }
    return [];
  }
  if (ts.isCallExpression(node)) {
    const callee = memberAccess(node.expression);
    if (callee?.property === "bind") {
      return arrayMutationMethodAlternativesOf(callee.receiver, next).map((method) => ({
        ...method,
        receiver: method.bound
          ? method.receiver : node.arguments[0] ?? method.receiver,
        bound: true,
        captured: [...method.captured, ...node.arguments.slice(1)]
      }));
    }
    return functionReturnExpressionsOf(node.expression, next)
      .flatMap((value) => arrayMutationMethodAlternativesOf(value, next));
  }
  if (!ts.isIdentifier(node)) return [];
  const binding = resolveBinding(node);
  if (!binding?.node || seen.has(binding.node) ||
      !ts.isVariableDeclaration(binding.node)) return [];
  const destructuredMethod = (
    destructuredPropertyAssignmentsByBinding.get(binding.node) ?? []
  ).find((assignment) => assignment.name === node.text &&
    mutableArrayMethods.has(assignment.property));
  if (destructuredMethod) {
    return [{
      kind: destructuredMethod.property,
      receiver: destructuredMethod.source,
      bound: false,
      captured: []
    }];
  }
  if (!ts.isIdentifier(binding.node.name)) {
    if (!ts.isObjectBindingPattern(binding.node.name) ||
        !binding.node.initializer) return [];
    const entry = binding.node.name.elements.find((element) =>
      ts.isIdentifier(element.name) && element.name.text === node.text);
    const kind = entry && assignmentPropertyName(entry.propertyName ?? entry.name);
    return kind && mutableArrayMethods.has(kind)
      ? [{
        kind,
        receiver: binding.node.initializer,
        bound: false,
        captured: []
      }]
      : [];
  }
  return [binding.node.initializer,
    ...(assignmentsByBinding.get(binding.node) ?? [])].filter(Boolean)
    .flatMap((value) => arrayMutationMethodAlternativesOf(value, next));
};
const arrayMutationArgumentPlanOf = (input, seen = new Set()) => {
  if (!unwrap(input)) return { values: [], unproven: false };
  const plan = argumentArrayPlanOf(input, seen);
  return {
    values: [...plan.before, ...plan.after].filter(Boolean),
    unproven: Boolean(plan.unknownAll || plan.unknownIndex !== undefined)
  };
};
const arrayMutationArgumentsAreUnproven = (argumentsList) =>
  argumentsList.some((value) => ts.isSpreadElement(value) &&
    fixedSpreadValuesOf(value.expression) === undefined);
const arrayMutationCallSitesOf = (call) => {
  const callee = unwrap(call.expression);
  if (reflectApplyReferenceOf(callee)) {
    const methods = arrayMutationMethodAlternativesOf(call.arguments[0]);
    const plan = arrayMutationArgumentPlanOf(call.arguments[2]);
    return methods.map((method) => ({
      ...method,
      target: method.bound ? method.receiver : call.arguments[1] ?? method.receiver,
      arguments: [...method.captured, ...plan.values],
      unprovenArguments: plan.unproven
    }));
  }
  const wrapper = memberAccess(callee);
  if (wrapper && ["apply", "call"].includes(wrapper.property)) {
    const methods = arrayMutationMethodAlternativesOf(wrapper.receiver);
    const plan = wrapper.property === "call"
      ? {
        values: call.arguments.slice(1),
        unproven: arrayMutationArgumentsAreUnproven(call.arguments.slice(1))
      }
      : arrayMutationArgumentPlanOf(call.arguments[1]);
    return methods.map((method) => ({
      ...method,
      target: method.bound ? method.receiver : call.arguments[0] ?? method.receiver,
      arguments: [...method.captured, ...plan.values],
      unprovenArguments: plan.unproven
    }));
  }
  return arrayMutationMethodAlternativesOf(callee).map((method) => ({
    ...method,
    target: method.receiver,
    arguments: [...method.captured, ...call.arguments],
    unprovenArguments: arrayMutationArgumentsAreUnproven(call.arguments)
  }));
};
const collectArrayMutations = (node) => {
  if (ts.isBinaryExpression(node) &&
      aliasAssignmentKinds.has(node.operatorToken.kind) &&
      ts.isElementAccessExpression(unwrap(node.left))) {
    const target = unwrap(node.left);
    for (const binding of arrayBindingsOf(target.expression)) {
      const mutations = arrayMutationValuesByBinding.get(binding) ?? [];
      const previousValues = arrayPreviousValuesOf(binding, mutations);
      const conditional = node.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
        arrayMutationIsConditional(node);
      const writeCarriesCapability =
        arrayMutationValuesCarryCapabilityForTarget(
          target.expression, [unwrap(node.right)]
        ) ?? arrayMutationValueCarriesCapability(node.right);
      const previousValuesCarryCapability =
        arrayMutationValuesCarryCapabilityForTarget(
          target.expression, previousValues
        ) ?? previousValues.some((value) =>
          arrayMutationValueCarriesCapability(value));
      if (writeCarriesCapability ||
        (conditional && previousValuesCarryCapability)) {
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
    const assignedArguments = objectAssignInvocationArgumentsOf(node);
    if (assignedArguments?.length > 1 &&
        arrayBindingsOf(assignedArguments[0]).length > 0 &&
        assignedArguments.slice(1).some((value) =>
          arrayMutationValueCarriesCapability(value))) {
      add(node, "capability escape through mutable array method is unproven in supervisor source");
    }
    if (staticMethodReferenceOf(node.expression, "set", globalReflectOf) &&
        node.arguments.length >= 3 &&
        arrayBindingsOf(node.arguments[0]).length > 0 &&
        arrayMutationValueCarriesCapability(node.arguments[2])) {
      add(node, "capability escape through mutable array method is unproven in supervisor source");
    }
    for (const site of arrayMutationCallSitesOf(node)) {
      const kind = site.kind;
      if (site.unprovenArguments) {
        add(node, "capability escape through mutable array method is unproven in supervisor source");
      }
      for (const binding of arrayBindingsOf(site.target)) {
      const mutations = arrayMutationValuesByBinding.get(binding) ?? [];
      const previousValues = arrayPreviousValuesOf(binding, mutations);
      const valuesCarryCapability =
        arrayMutationValuesCarryCapabilityForTarget(
          site.target, site.arguments
        ) ?? site.arguments.some((value) =>
          arrayMutationValueCarriesCapability(value));
      const previousValuesCarryCapability =
        arrayMutationValuesCarryCapabilityForTarget(
          site.target, previousValues
        ) ?? previousValues.some((value) =>
          arrayMutationValueCarriesCapability(value));
      if (!["push", "unshift", "splice"].includes(kind)) {
        if (valuesCarryCapability || previousValuesCarryCapability) {
          add(node, "capability escape through mutable array method is unproven in supervisor source");
        }
      } else {
        const values = kind === "splice" ? site.arguments.slice(2) : site.arguments;
        const deleteCount = kind === "splice" && site.arguments.length > 1
          ? staticAssignmentNameOf(site.arguments[1])
        : kind === "splice" ? "rest" : undefined;
      const insertedValuesCarryCapability =
        arrayMutationValuesCarryCapabilityForTarget(
          site.target, values
        ) ?? values.some((value) =>
          arrayMutationValueCarriesCapability(value));
      if (insertedValuesCarryCapability) {
        add(node, "capability escape through mutable array mutation is unproven in supervisor source");
      }
      if (arrayMutationIsConditional(node) &&
          previousValuesCarryCapability) {
        add(node, "conditional mutable array mutation is unproven in supervisor source");
      }
      const deletesValues = deleteCount === "rest" ||
        deleteCount === undefined || Number(deleteCount) > 0;
      if (deletesValues && previousValuesCarryCapability) {
        add(node, "capability escape through mutable array splice is unproven in supervisor source");
      }
      mutations.push({
        kind,
        start: node.getStart(file),
        index: kind === "splice"
            ? staticAssignmentNameOf(site.arguments[0]) : undefined,
        deleteCount,
        values
      });
      arrayMutationValuesByBinding.set(binding, mutations);
      }
    }
  }
  }
  ts.forEachChild(node, collectArrayMutations);
};
staticLogicalValueOf = (input, seen = new Set()) => {
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
  const arrayRestPlan = arrayRestPlansByNode.get(node);
  if (arrayRestPlan) return [arrayRestPlan];
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
  if (isNewArrayExpression(node)) {
    const values = fixedSpreadValuesOf(node, seen);
    return values
      ? [{ before: values, after: [], unknownIndex: undefined }]
      : [{ before: [], after: [], unknownIndex: 0 }];
  }
  if (ts.isIdentifier(node)) {
const binding = resolveBinding(node);
if (binding?.kind === "variable" &&
ts.isVariableDeclaration(binding.node) &&
ts.isIdentifier(binding.node.name) && binding.node.initializer &&
    (ts.isArrayLiteralExpression(unwrap(binding.node.initializer)) ||
     isNewArrayExpression(unwrap(binding.node.initializer)))) {
    const usageStart = node.getStart(file);
    const mutations = (arrayMutationValuesByBinding.get(binding.node) ?? [])
      .filter((mutation) => mutation.start <= usageStart);
    if (mutations.length === 0) {
      const mutationSeen = new Set(next);
      mutationSeen.add(binding.node);
      return fixedSpreadPlansOf(binding.node.initializer, mutationSeen);
    }
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
    const values = fixedSpreadValuesOf(node, seen);
    if (values) {
      return [{ before: values, after: [], unknownIndex: undefined }];
    }
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
  return {
    functions,
    plan: argumentArrayPlanOf(argumentsList[2], seen),
    thisArguments: [argumentsList[1]].filter(Boolean)
  };
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
  if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    return bindMethodReferenceOf(node.right, seen);
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
    if (staticMethodReferenceOf(
      node.expression, "get", globalReflectOf, next
    ) &&
        staticAssignmentNameOf(node.arguments[1]) === "bind") {
      return { property: "bind", receiver: unwrap(node.arguments[0]) };
    }
    for (const value of functionReturnExpressionsOf(node.expression, next)) {
      const resolved = bindMethodReferenceOf(value, next);
      if (resolved) return resolved;
    }
    return undefined;
  }
  if (!ts.isIdentifier(node)) return undefined;
  const binding = resolveBinding(node);
  if (!binding?.node || !ts.isVariableDeclaration(binding.node)) return undefined;
  const next = new Set(seen);
  next.add(node);
  next.add(binding.node);
  const destructuredBind = (destructuredPropertyAssignmentsByBinding.get(binding.node) ?? [])
    .find((assignment) => assignment.name === node.text &&
      assignment.property === "bind");
  if (destructuredBind) {
    const sourceMember = memberAccess(destructuredBind.source);
    return {
      property: "bind",
      receiver: sourceMember?.property === "bind"
        ? sourceMember.receiver : destructuredBind.source
    };
  }
  return ts.isIdentifier(binding.node.name) && binding.node.initializer
    ? bindMethodReferenceOf(binding.node.initializer, next)
    : undefined;
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
  const member = memberAccess(node);
  if (member) {
    const alternatives = memberValueCandidatesOf(
      member.receiver, member.property, next
    ).flatMap((value) => {
      const candidate = storedBindInvocationOf(value, invocationPlan, next);
      return candidate ? candidate.alternatives ?? [candidate] : [];
    });
    if (alternatives.length > 0) return { alternatives };
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
  if (ts.isBinaryExpression(node)) {
    const operator = node.operatorToken.kind;
    if (operator === ts.SyntaxKind.CommaToken) {
      return storedBindInvocationOf(node.right, invocationPlan, next);
    }
    if ([
      ts.SyntaxKind.AmpersandAmpersandToken,
      ts.SyntaxKind.BarBarToken,
      ts.SyntaxKind.QuestionQuestionToken
    ].includes(operator)) {
      const leftValue = staticLogicalValueOf(node.left, next);
        const selectRight = operator === ts.SyntaxKind.AmpersandAmpersandToken
          ? leftValue?.truthy
          : operator === ts.SyntaxKind.BarBarToken
          ? leftValue ? !leftValue.truthy : undefined
          : leftValue?.nullish;
      const selected = leftValue
          ? [selectRight ? node.right : node.left]
        : [node.left, node.right];
      const alternatives = selected.flatMap((value) => {
        const candidate = storedBindInvocationOf(value, invocationPlan, next);
        return candidate ? candidate.alternatives ?? [candidate] : [];
      });
      if (alternatives.length > 0) return { alternatives };
    }
  }
  if (!ts.isCallExpression(node)) return undefined;
  const bind = bindMethodReferenceOf(node.expression, next);
  if (bind?.property === "bind") {
    const bindPlan = fixedCallArgumentPlanOf(node.arguments);
    const plan = mergeCallArgumentPlans(
      dropLeadingCallArgument(bindPlan),
      invocationPlan
    );
    const bindThisArguments = callArgumentCandidatesAt(
      bindPlan, 0
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
            : { before: [], after: [], unknownIndex: 0 },
          thisArguments: callArgumentCandidatesAt(plan, 1)
        };
      }
    }
    const functions = localFunctionValuesOf(bind.receiver, next);
    if (functions.length > 0) {
      return { functions, plan, thisArguments: bindThisArguments };
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
        ),
        thisArguments: callArgumentCandidatesAt(bindArguments, 0)
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
      const bindArguments = argumentArrayPlanOf(node.arguments[2], next);
      return {
        functions,
        plan: mergeCallArgumentPlans(
          dropLeadingCallArgument(bindArguments),
          invocationPlan
        ),
        thisArguments: callArgumentCandidatesAt(bindArguments, 0)
      };
    }
  }
  return undefined;
};
const localFunctionTermOf = (input, seen = new Set()) => {
  const node = unwrap(input);
  if (!node || seen.has(node)) return undefined;
  const next = new Set(seen);
  next.add(node);
  const member = memberAccess(node);
  if (member && ["call", "apply"].includes(member.property)) {
    const prototype = memberAccess(unwrap(member.receiver));
    if (prototype?.property === "prototype" &&
        globalFunctionObjectOf(prototype.receiver)) {
      return { kind: "method", method: member.property, value: node };
    }
    const receiverTerm = localFunctionTermOf(member.receiver, next);
    if (receiverTerm && receiverTerm.kind !== "value") {
      return {
        kind: "method",
        base: receiverTerm,
        method: member.property,
        value: node
      };
    }
    const functions = localFunctionValuesOf(member.receiver, next);
    if (functions.length > 0) {
      return {
        kind: "method",
        base: { kind: "local", functions, value: member.receiver },
        method: member.property,
        value: node
      };
    }
  }
  if (member) {
    for (const value of memberValueCandidatesOf(
      member.receiver, member.property, next
    )) {
      const valueTerm = localFunctionTermOf(value, next);
      if (valueTerm && valueTerm.kind !== "value") return valueTerm;
    }
  }
  if (ts.isIdentifier(node)) {
    const binding = resolveBinding(node);
    if ((binding?.kind === "variable" || binding?.kind === "opaque") &&
        ts.isVariableDeclaration(binding.node) &&
        binding.node.initializer && !next.has(binding.node)) {
      const bindingNext = new Set(next);
      bindingNext.add(binding.node);
      if (!ts.isIdentifier(binding.node.name)) {
        const prototype = memberAccess(unwrap(binding.node.initializer));
        if (prototype?.property === "prototype" &&
            globalFunctionObjectOf(prototype.receiver)) {
          for (const method of ["call", "apply"]) {
            if (bindingPatternSelectsPropertyOf(
              binding.node.name, node.text, method
            )) {
              return { kind: "method", method, value: node };
            }
          }
        }
      }
      const initializers = ts.isIdentifier(binding.node.name)
        ? [binding.node.initializer]
        : bindingPatternValuesOf(
          binding.node.name, binding.node.initializer, node.text, bindingNext
        );
      for (const initializer of initializers) {
        const initializerTerm = localFunctionTermOf(initializer, bindingNext);
        if (initializerTerm && initializerTerm.kind !== "value") {
          return initializerTerm;
        }
      }
    }
  }
  const functions = localFunctionValuesOf(node, new Set(seen));
  return functions.length > 0
    ? { kind: "local", functions, value: node }
    : { kind: "value", value: node };
};
const localFunctionTermArgumentsPlanOf = (plan, index, seen) => {
  const plans = callArgumentCandidatesAt(plan, index)
    .map((candidate) => argumentArrayPlanOf(candidate, seen))
    .filter(Boolean);
  return plans.length > 0
    ? plans.reduce((left, right) => mergeCallArgumentPlans(left, right))
    : { before: [], after: [], unknownIndex: 0 };
};
const localFunctionTermInvocationOf = (
  term, thisTerm, plan, depth = 0
) => {
  if (!term || depth > 32) return undefined;
  if (term.kind === "local") {
    return {
      functions: term.functions,
      plan,
      thisArguments: thisTerm ? [thisTerm.value] : []
    };
  }
  if (term.kind !== "method" || !thisTerm) return undefined;
  const thisCandidates = callArgumentCandidatesAt(plan, 0);
  const nextPlan = term.method === "call"
    ? dropLeadingCallArgument(plan)
    : localFunctionTermArgumentsPlanOf(plan, 1, new Set());
  const alternatives = [];
  for (const candidate of thisCandidates.length > 0 ? thisCandidates : [undefined]) {
    const targetThisTerm = candidate
      ? localFunctionTermOf(candidate, new Set())
      : undefined;
    const invocation = localFunctionTermInvocationOf(
      thisTerm, targetThisTerm, nextPlan, depth + 1
    );
    if (invocation) {
      alternatives.push(...(invocation.alternatives ?? [invocation]));
    }
  }
  return alternatives.length > 0 ? { alternatives } : undefined;
};
const localInvocationResultOf = (callExpression, argumentExpressions) => {
  const callee = unwrap(callExpression);
  if (reflectApplyReferenceOf(callee)) {
    const reflected = reflectApplyInvocationOf(argumentExpressions);
    if (reflected) return reflected;
  }
  if (reflectConstructReferenceOf(callee)) {
    const functions = localFunctionValuesOf(argumentExpressions[0]);
    if (functions.length > 0) {
      return {
        functions,
        plan: argumentArrayPlanOf(argumentExpressions[1]),
        thisArguments: []
      };
    }
  }
  const storedBound = storedBindInvocationOf(
    callee, fixedCallArgumentPlanOf(argumentExpressions)
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
            fixedCallArgumentPlanOf(argumentExpressions)
          ),
        thisArguments: [callee.arguments[0]].filter(Boolean)
        };
      }
    }
  }
  const directFunctions = localFunctionValuesOf(callee);
  if (directFunctions.length > 0) {
  return {
    functions: directFunctions,
    plan: fixedCallArgumentPlanOf(argumentExpressions),
    thisArguments: [memberAccess(callee)?.receiver].filter(Boolean)
  };
  }
  const callableTerm = localFunctionTermOf(callee);
  if (callableTerm?.kind === "method") {
    const invocation = localFunctionTermInvocationOf(
      callableTerm, callableTerm.base, fixedCallArgumentPlanOf(argumentExpressions)
    );
    if (invocation) return invocation;
  }
  const wrapper = memberAccess(callee);
  if (wrapper?.property === "bind") {
    const functions = localFunctionValuesOf(wrapper.receiver);
    if (functions.length > 0) {
      return {
        functions,
        plan: fixedCallArgumentPlanOf(argumentExpressions.slice(1)),
        thisArguments: [argumentExpressions[0]].filter(Boolean)
      };
    }
  }
  if (wrapper && ["apply", "call"].includes(wrapper.property)) {
    const functions = localFunctionValuesOf(wrapper.receiver);
    if (functions.length > 0) {
      return {
        functions,
        plan: wrapper.property === "call"
          ? fixedCallArgumentPlanOf(argumentExpressions.slice(1))
        : argumentArrayPlanOf(argumentExpressions[1]),
      thisArguments: [argumentExpressions[0]].filter(Boolean)
      };
    }
    const boundInvocation = storedBindInvocationOf(
      wrapper.receiver,
      wrapper.property === "call"
        ? fixedCallArgumentPlanOf(argumentExpressions.slice(1))
        : argumentArrayPlanOf(argumentExpressions[1])
    );
    if (boundInvocation) return boundInvocation;
    if (reflectApplyReferenceOf(wrapper.receiver)) {
      const reflectedArguments = wrapper.property === "call"
        ? argumentExpressions.slice(1)
        : fixedSpreadValuesOf(argumentExpressions[1]);
      const reflected = reflectedArguments &&
        reflectApplyInvocationOf(reflectedArguments);
      if (reflected) return reflected;
    }
  }
  return undefined;
};
const localInvocationOf = (expression, argumentExpressions, kind = "call") => {
  const invocation = localInvocationResultOf(expression, argumentExpressions);
  if (kind !== "construct" || !invocation) return invocation;
  const withoutConstructedThis = (alternative) => ({
    ...alternative,
    thisArguments: []
  });
  return invocation.alternatives
    ? { alternatives: invocation.alternatives.map(withoutConstructedThis) }
    : withoutConstructedThis(invocation);
};
// Reuse the synthetic argument plan so repeated fixpoint scans compare equal.
const taggedTemplateArgumentsByNode = new WeakMap();
const taggedTemplateArgumentsOf = (node) => {
  const cached = taggedTemplateArgumentsByNode.get(node);
  if (cached) return cached;
  const templateStrings = ts.factory.createArrayLiteralExpression(
    ts.isTemplateExpression(node.template)
      ? [node.template.head, ...node.template.templateSpans.map((span) => span.literal)]
      : [node.template]
  );
  const values = [
    templateStrings,
    ...(ts.isTemplateExpression(node.template)
      ? node.template.templateSpans.map((span) => span.expression)
      : [])
  ];
  taggedTemplateArgumentsByNode.set(node, values);
  return values;
};
const localTaggedTemplateInvocationOf = (node) => localInvocationOf(
  node.tag, taggedTemplateArgumentsOf(node)
);
const localNewExpressionInvocationOf = (node) => {
  return localInvocationOf(
    node.expression, node.arguments ?? [], "construct"
  );
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
  collectAssignments(file);
  let capabilityArgumentsChanged = true;
  while (capabilityArgumentsChanged) {
    capabilityArgumentsChanged = false;
    const collect = (node) => {
      const invocation = ts.isCallExpression(node)
        ? localInvocationOf(node.expression, node.arguments)
        : ts.isTaggedTemplateExpression(node)
        ? localTaggedTemplateInvocationOf(node)
        : ts.isNewExpression(node)
        ? localNewExpressionInvocationOf(node)
        : undefined;
      if (invocation) {
      const alternatives = invocation?.alternatives ?? [invocation].filter(Boolean);
      for (const alternative of alternatives) {
      const { functions, plan, thisArguments = [] } = alternative;
      for (const fn of functions) {
        capabilityArgumentsChanged = recordPlan(
          functionArgumentsPlans, fn, plan
        ) || capabilityArgumentsChanged;
        for (const receiver of thisArguments) {
          capabilityArgumentsChanged = recordParameterArgument(
            functionThisArguments, fn, receiver
          ) || capabilityArgumentsChanged;
        }
        for (let index = 0; index < fn.parameters.length; index += 1) {
            const parameter = fn.parameters[index];
          if (isThisParameter(parameter)) continue;
          const runtimeIndex = runtimeParameterIndexOf(fn, parameter);
          if (parameter.dotDotDotToken) {
            recordCapabilityArgumentsOf(parameter, plan, runtimeIndex);
            break;
          }
          for (const argument of callArgumentCandidatesAt(plan, runtimeIndex)) {
            if (!argument) continue;
          capabilityArgumentsChanged = recordParameterArgument(
            parameterValueArguments, parameter, argument
          ) || capabilityArgumentsChanged;
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
