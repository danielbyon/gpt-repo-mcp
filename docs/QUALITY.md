# Quality Checklist

This contributor and maintainer checklist describes the engineering standards
expected for public changes. GPT Repo MCP is a closed-world MCP server for
approved local repositories, so changes should preserve its contract-first
architecture, clear tool surface, and conservative safety model.

## Architecture Invariants

- Tool flow stays `contracts -> toolContracts -> package definitions -> registry -> define-tool -> package handlers -> services`.
- `src/tools/catalog.ts` remains a thin compatibility re-export of the registry:
  no definitions, inline Zod schemas, or policy logic.
- Handlers stay thin: resolve context, create services, call services, return envelopes.
- Filesystem access stays behind the existing sandbox, ignore, classifier, reader, writer, and policy services.
- Mutating behavior stays separate from read services.

## Tool Contract Rules

- Every tool has one central input contract and one central output contract in `src/tools/contracts.ts`.
- Contracts use Zod objects and include field descriptions for public MCP usability.
- Output schemas describe successful `structuredContent`; errors use the shared MCP error envelope.
- Tool names, descriptions, annotations, and handlers are defined once in
  `src/tools/packages/*` and composed through the registry.
- Tests must prove registry entries use the central contract objects.

## MCP Surface Rules

- Tool descriptions start with `Use this when...`.
- Read tools use read-only annotations.
- Mutating tools use mutating annotations:
  - `readOnlyHint: false`
  - `destructiveHint: true`
  - `openWorldHint: false`
  - `idempotentHint: false`
- Tool results keep machine-readable data in `structuredContent` and short summaries in `content`.
- Do not add standard MCP `search` or `fetch` unless connector compatibility becomes an explicit project goal.

## Security Rules

- Do not expose caller-supplied shell text, arbitrary executable selection, or free-form runner arguments. Keep validation limited to fixed profiles and their supported inputs.
- On Windows, the supervisor starts only absolute paths to supported native executables and passes arguments separately. npm runs through the selected `node.exe` and its bundled `npm-cli.js`; Make and Just resolve to native executables. The supervisor rejects command shims and does not fall back to shell dispatch.
- Validation profiles may execute repository-defined npm scripts, Make/Just recipes, or pytest code. GPT Repo MCP does not inspect or sandbox that code; running validation is the operator's responsibility. Run it only on repository contents you trust.
- Repository-defined scripts, recipes, and tests can start shells, including `cmd.exe`, or other programs. Those executions are outside the supervisor dispatch boundary.
- A V2 validation receipt keeps command outcome separate from evidence eligibility. Its schema checks aggregate status and counts against the recorded command results. The reader checks pointer identity, artifact containment and digest, effective policy, current candidate inventory, and runner and toolchain identities. A resolved Rust toolchain mismatch makes the receipt ineligible; an unresolved current toolchain leaves it unverified. Structured task requests bind the requested profile and test paths. A task without a structured request keeps validation `not_applicable`.
- V1 receipts remain readable and have `unverified` eligibility. The reader does not promote them to V2 eligibility.
- Source evidence binds the bounded HEAD tree, logical index entries, worktree file modes and content, symlink targets, visible untracked files, and discovered recipe helpers, including Git-ignored files. Before and after snapshots cannot detect a change that occurs and is reverted between observations.
- Rust validation uses the configured Make or Just profile and requires one exact root toolchain pin, including when the recipe invokes a helper script. Imported and module-contained Just recipes receive the same pin and executable checks. Unresolved or ambiguous Just source paths fail closed. Toolchain checks and the validation command use the same `CARGO_HOME`, and `RUSTC` points to the verified compiler. V2 Rust receipts bind hashes for the Cargo home path and configuration. Before execution, the service rechecks the selected tool identities, recipe, and Cargo configuration; it stops if the evidence is missing or has changed. Cargo compiler overrides, wrappers, config includes, recipe `PATH` changes, and `--config PATH` arguments are rejected. Issue #25 selected-worktree guarantees remain deferred.
- Do not weaken approved-root, path traversal, symlink, secret, denied glob, expected SHA, expected HEAD, or exact staged path checks.
- Do not expose push, pull, reset, checkout, switch, rebase, merge, stash, clean, force, branch deletion, or arbitrary git command tools.
- Prefer repo-relative paths in outputs and logs.
- Keep generated backups and cleanup artifacts out of commits unless explicitly reviewed.

## Issue Admission

Before starting an implementation task from a GitHub issue, check its **live native
dependency state** using the repository-scoped guardrail:

```bash
npm run issue:ready -- 25 --repo danielbyon/gpt-repo-mcp
```

The command requires authenticated `gh`, verifies the issue is open, and reads
all pages of GitHub's `blocked_by` endpoint. Exit 0 allows task selection;
exit 2 means closed or blocked; exit 3 means unavailable/malformed evidence.
Fail closed on nonzero status. A `ready-for-agent` label is not an override.
This is an explicit task-admission step, not an automatic GitHub label change.
Run the command again when selecting a different issue; cached status is not
authoritative. See `scripts/check-issue-readiness.mjs` for the implementation.

## Required Verification

Run the focused checks for the area changed, then run:

```bash
npm run typecheck
npm test -- tests/tool-contracts.test.ts tests/mcp-contract.test.ts
npm run lint
npm run check:public
npm run verify:dist
git diff --check
```

Run service tests when touching service behavior:

```bash
npm test -- tests/file-writer.test.ts tests/git-operations-service.test.ts tests/cleanup-service.test.ts
```

## Release Readiness Checklist

- README describes the current tool surface and disabled-by-default mutating tools.
- `docs/SECURITY.md`, `docs/TOOL_SURFACE.md`,
  `docs/DELEGATION_ARTIFACTS.md`, `docs/WRITE_WORKFLOWS.md`, and this file are
  current.
- `docs/ERRORS.md` lists stable error codes.
- CI must pass before merge.
- Contract tests must run when the tool surface, annotations, or schemas change.
- Mutating tool schema descriptions must remain covered by tests.
- Public hygiene checks must pass before release.
- The built `dist/server.js` runtime smoke must pass before release.
- MCP contract tests pass and snapshots match intentional tool surface changes.
- No machine-specific paths, personal workflow instructions, credentials, or
  development planning notes are present in published documentation.
- Documentation links resolve to files available in the public repository or
  to an intentional external source.
- `package.json` metadata is accurate and `package-lock.json` is unchanged unless dependencies changed intentionally.

## How To Add A Tool

1. Add input and output contracts under `src/contracts/*`.
2. Add the tool to `src/tools/contracts.ts`.
3. Add a concise description in `src/tools/descriptions.ts`.
4. Add metadata and handler wiring in the matching `src/tools/packages/*` module.
5. Add a thin adapter in the matching `src/tools/handlers/*` module.
6. Put real logic in `src/services/*`.
7. Add service tests when behavior is non-trivial.
8. Update MCP contract tests, registry discipline tests, and docs.

## How To Add A Mutating Tool

1. Require explicit opt-in config with safe disabled defaults.
2. Use mutating annotations and add the tool to the shared mutating tool list.
3. Provide `dry_run` where practical.
4. Require explicit repo-relative paths where paths are applicable.
5. Do not expose caller-controlled shell text or arbitrary Git/command runners.
6. Put authorization decisions in a policy or service layer.
7. Put execution logic in a service, not a handler.
8. Add focused service tests for policy, safety, dry-run, and mutation behavior.
9. Add MCP contract and tool contract tests.
10. Update security, tool surface, workflow, and error docs.
