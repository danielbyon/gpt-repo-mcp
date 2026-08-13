# Direct `just` Validation Runner Design

## Summary

Add first-class `just` support to repository-owned validation profiles. The existing `make` behavior remains unchanged. A profile may declare either `make` or `just`, and GPT Repo MCP executes the selected runner directly with one validated target argument and no shell.

Example:

```json
{
  "operations": {
    "enabled": true,
    "validation_enabled": true,
    "validation_profiles": {
      "test": { "runner": "just", "target": "test" },
      "all": { "runner": "just", "target": "verify" }
    }
  }
}
```

## Goal

Repositories that use `just` as their canonical task runner should be able to expose validation profiles directly without adding an npm or Make adapter solely for GPT Repo MCP.

## Scope

The change covers the existing repository-owned validation profile surface only:

- profile names remain `test`, `build`, `lint`, `typecheck`, `smoke`, and `all`;
- each configured profile still contains only `runner` and `target`;
- supported runner values become `make` and `just`;
- target validation remains the existing restricted target regex;
- `make` behavior and fallback behavior remain compatible;
- focused `test_paths` remain unsupported for repository-owned profiles, regardless of whether the runner is `make` or `just`.

## Architecture

### Configuration schema

Replace the make-only profile schema with a runner-aware schema that accepts exactly two allowlisted runner values:

```text
runner = "make" | "just"
target = existing validated target string
```

The profile object remains strict, so arbitrary executable names, arguments, shell snippets, or extra fields remain rejected.

### Operations policy types

Update the operations-policy input and normalized types so each validation profile carries an allowlisted runner union instead of the current `"make"` literal.

No change is required to the profile map keys or default empty profile map.

### Validation command resolution

When a repository-owned profile exists, command resolution will derive the executable from `profile.runner`:

```text
make -> executable "make", args [target]
just -> executable "just", args [target]
```

The command shown in validation results will match the direct invocation, for example `make test` or `just test`. The script identifier should remain deterministic and runner-qualified, for example `make:test` or `just:test`.

The process continues to execute through the existing direct process runner with no shell.

### Focused test paths

Repository-owned profiles currently reject `test_paths` because GPT Repo MCP cannot safely infer how a repository-specific task should accept file paths. That behavior remains unchanged for both runners.

The error message should be runner-neutral rather than referring specifically to a declared make profile.

## Resolution precedence

Existing precedence remains unchanged:

1. repository-owned `operations.validation_profiles[profile]`;
2. matching npm scripts;
3. pytest fallback for applicable test validation.

A configured `just` profile therefore has the same precedence as a configured `make` profile.

## Security invariants

The change must preserve all current validation execution boundaries:

- no shell execution;
- no arbitrary executable from config;
- no arbitrary argument arrays from config;
- only `make` and `just` are accepted runners;
- target remains restricted by the existing target regex;
- command execution remains `executable + argv`, not string interpolation;
- validation remains gated by repository operations policy;
- output redaction, bounded tails, timeout handling, and validation artifacts remain unchanged.

These invariants are the primary reason not to introduce a generic executable runner in this change.

## Error handling

- Unknown runner values fail strict config validation.
- Invalid targets continue to fail config validation.
- Missing `make` or `just` executables fail through the existing process-execution result path; this change does not add runner discovery or installation logic.
- Focused test paths with any repository-owned profile continue to fail with `VALIDATION_TEST_PATHS_DISABLED`, using runner-neutral wording.

## Tests

Add or update focused tests to prove:

1. config accepts a `just` validation profile;
2. config still accepts existing `make` profiles unchanged;
3. config rejects unsupported runner values;
4. a configured `just` profile takes precedence over npm/pytest fallback;
5. `just` command construction uses executable `just` and a single target argv value;
6. result metadata reports the expected runner-qualified script/command;
7. focused `test_paths` remain rejected for a configured `just` test profile;
8. existing `make` validation tests continue to pass.

## Documentation

Update setup documentation to state that repository-owned validation profiles support allowlisted `make` and `just` targets executed directly without a shell. Include a `just` example alongside the existing `make` example or use a mixed example that makes the supported shape obvious.

## Rejected alternatives

### Force `just` through npm scripts

Rejected because it adds an unnecessary Node adapter to repositories whose canonical task runner is already `just`. npm fallback remains useful, but it should not be required for this use case.

### Require a Makefile adapter

Rejected because it forces repositories to maintain duplicate task-runner surfaces solely for GPT Repo MCP.

### Generic executable runner

Rejected for this change because it expands the trust boundary from a small runner allowlist to arbitrary executable selection. Supporting additional runners should remain explicit and typed unless there is a separate design for a broader safe execution contract.

### Pass focused test paths to `just`

Rejected because recipe argument conventions are repository-specific. Automatically appending paths would silently impose a contract that does not currently exist and could break recipes or alter their meaning.

## Acceptance criteria

- `config.local.json` accepts `runner: "just"` anywhere an existing repository-owned validation profile is accepted.
- `repo_validate` executes configured `just` profiles as direct `just <target>` invocations.
- Existing `make`, npm, and pytest behavior remains compatible.
- Unsupported runners and unsafe profile shapes remain rejected by strict schema validation.
- No arbitrary shell or command execution capability is introduced.
- Tests and setup documentation cover the new runner.
