# Dependency security

This guide records dependency audit results and the decisions made for this
repository. The lockfile selects installed versions. The security scanner uses
a separate policy input for production decisions.

## Public audit results — 2026-11-01

The v5 lockfile was audited against the public npm registry after the compatible
production fixes. The full audit reports 11 moderate development findings and
no high or critical findings. The production-only audit reports no findings.

Four production dependency updates removed seven advisory records:

| Package | Previous | Selected | Advisory records |
| --- | --- | --- | --- |
| `@hono/node-server` | 2.0.12 | 2.1.5 | GHSA-rmxm-3fg6-px4f |
| `body-parser` | 2.3.0 | 2.4.0 | GHSA-27r3-jxmh-p828 |
| `fast-uri` | 3.1.8 | 3.1.9 | GHSA-333x-w4r6-6crp, GHSA-w74x-v6f9-j3xg, GHSA-wjr9-j795-jxcr, GHSA-xhq7-xmqj-769h |
| `zod` | 4.4.3 | 4.6.7 | GHSA-mrhx-c7xc-m3w5 |

The MCP SDK accepts `@hono/node-server` `^2.0.5`; its lockfile now selects the
fixed 2.1.5 release without an override. Express accepts `body-parser`
`^2.2.1`, Ajv accepts `fast-uri` `^3.0.1`, and the project’s `zod` range is
`^4.6.6`. These changes retain the existing major versions and Node engine
requirement.

The remaining finding is GHSA-g3hv-75wg-m249, a moderate Minimatch denial of
service advisory. It affects 11 development package records: `@eslint-community/eslint-utils`,
`@eslint/config-array`, `@eslint/eslintrc`, `@typescript-eslint/eslint-plugin`,
`@typescript-eslint/parser`, `@typescript-eslint/type-utils`,
`@typescript-eslint/typescript-estree`, `@typescript-eslint/utils`, `eslint`,
`minimatch`, and `typescript-eslint`. The affected dependency nodes are:

| Dependency chain | Installed Minimatch | Parent range |
| --- | --- | --- |
| ESLint → `@eslint/config-array` 0.21.2 | 3.1.5 | `^3.1.5` |
| ESLint → `@eslint/eslintrc` 3.3.5 | 3.1.5 | `^3.1.5` |
| `typescript-eslint` → `@typescript-eslint/typescript-estree` 8.60.0 | 10.2.5 | `^10.2.2` |

The advisory’s fixed version is 11.0.1. Those parent ranges do not admit it.
Minimatch 11.0.1 declares Node `18 || 20 || >=22`, which does not cover every
version allowed by this project’s `>=20` engine range. ESLint 10.14.0 also
requires `^20.19.0 || ^22.13.0 || >=24`. npm’s suggested ESLint 4.0.0 is an
out-of-range major downgrade. Its suggested `typescript-eslint` 8.14.0 uses a
Minimatch 9 range, which remains inside the advisory’s affected range.

No compatible remediation was identified within the declared parent ranges and
Node support. The advisory remains unresolved. No owner risk acceptance or
engine change is recorded. An owner decision is needed before changing the
lint toolchain or narrowing supported Node versions.

The previous review dates remain on record: the production dependency review
was due 2026-10-26, and the development tooling review was due 2026-08-31. The
2026-11-01 audit and outcomes above supersede those pending reviews; they do not
retroactively establish approval.

## Production scan policy

Production scanning requires an owner-authorized policy input and its trusted
digest. Those inputs are not available for this correction. Production policy
scans and history preflight remain `NOT_RUN`.

Local or synthetic policies may support tests. They do not grant production
authority. With an authorized policy, the scanner checks candidate files,
selected publication tags, and selected commit history. Before reading history
blobs, it checks paths in the selected commit trees and then scans that same
commit list in bounded batches.

A new package, changed severity, production finding, or expired deadline fails
the release security scan when an authorized policy is configured.

## Verification

Run dependency checks from the repository root:

```bash
npm audit --omit=dev
npm audit
npm ls @modelcontextprotocol/sdk @hono/node-server hono body-parser fast-uri ajv zod eslint minimatch typescript-eslint
```

Investigate new production advisories by tracing their dependency paths and
runtime reachability. Prefer compatible lockfile updates. Add an override only
when upstream has no usable fixed range and the affected path has integration
coverage. Do not use forced semver-major audit fixes.
