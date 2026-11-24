import js from "@eslint/js";
import tseslint from "typescript-eslint";

const processBoundaryFiles = {
  "src/services/process-exec.ts": ["spawn", "ChildProcess"],
  "src/services/windows-process-host.ts": ["spawn", "ChildProcess"],
  "src/services/node-runtime-resolver.ts": ["execFile"],
  "src/services/validation-service.ts": []
};

const directLaunch = "CallExpression[callee.name=/^(spawn|execFile|execFileAsync)$/]";
const shellExecutable = String.raw`/(^|[\x2f\\])(sh|bash|dash|zsh|fish|ksh|ash|csh|tcsh|cmd|powershell|pwsh)(\.exe)?$/i`;

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    ignores: ["dist/**", "**/dist/**", "coverage/**", "node_modules/**", ".scratch/**"]
  },
  {
    files: ["**/*.ts"],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname
      }
    },
    rules: {
      "@typescript-eslint/no-explicit-any": "error"
    }
  },
  {
    files: Object.keys(processBoundaryFiles),
    rules: {
      "@typescript-eslint/no-require-imports": "error",
      "no-eval": "error",
      "no-new-func": "error",
      "no-restricted-syntax": [
        "error",
        {
          selector: "ImportExpression, TSImportEqualsDeclaration, CallExpression[callee.property.name=/^(require|getBuiltinModule)$/]",
          message: "Use static imports in the process dispatch boundary."
        },
        {
          selector: "ImportDeclaration[source.value='node:child_process'][specifiers.length=0], ExportNamedDeclaration[source.value='node:child_process'], ExportAllDeclaration[source.value='node:child_process']",
          message: "Use only the allowed named child_process imports."
        },
        {
          selector: "ImportDeclaration[source.value='node:child_process'][importKind!='type'] ImportSpecifier[imported.name='ChildProcess'][importKind!='type']",
          message: "Import ChildProcess as a type."
        },
        {
          selector: [
            "Property[key.name='shell'][value.value!=false]",
            "Property[key.value='shell'][value.value!=false]",
            "AssignmentExpression[left.property.name='shell'][right.value!=false]",
            "AssignmentExpression[left.property.value='shell'][right.value!=false]"
          ].join(", "),
          message: "Process dispatch must leave shell unset or set it to false."
        },
        {
          selector: [
            `${directLaunch} > Literal.arguments:first-child[value=${shellExecutable}]`,
            `${directLaunch} > TemplateLiteral.arguments:first-child[expressions.length=0] > TemplateElement[value.cooked=${shellExecutable}]`
          ].join(", "),
          message: "Dispatch the native executable directly."
        }
      ]
    }
  },
  ...Object.entries(processBoundaryFiles).map(([file, allowed]) => ({
    files: [file],
    rules: {
      "@typescript-eslint/no-restricted-imports": ["error", {
        paths: [
          "child_process", "vm", "module", "worker_threads",
          { name: "node:vm", allowTypeImports: true },
          { name: "node:module", allowTypeImports: true },
          { name: "node:worker_threads", allowTypeImports: true },
          {
            name: "node:child_process",
            ...(allowed.length ? { allowImportNames: allowed } : {})
          }
        ],
        patterns: [
          { group: ["shelljs", "execa", "cross-spawn", "cross-spawn-promise", "zx", "npm-run-all", "npm-run-all2"], message: "Use the approved process dispatch path." }
        ]
      }]
    }
  }))
);
