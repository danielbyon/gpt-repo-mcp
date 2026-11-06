# Security

GPT Repo MCP is a local-first MCP server for approved repositories. The detailed security model is documented in [docs/SECURITY.md](docs/SECURITY.md).

## Supported Versions

This project is pre-1.0. Security fixes are handled on the default public branch until a formal release policy is published.

## Reporting A Vulnerability

If you believe you have found a vulnerability, report it privately through GitHub Security Advisories when available. If advisories are not available, contact the maintainer through a private channel before sharing details publicly.

Do not open a public issue containing exploit details, secrets, tokens, private repository paths, tunnel URLs, connector IDs, or other sensitive local configuration.

## Scope

Security-sensitive areas include:

- approved-root enforcement and path sandboxing
- default excludes and secret-candidate blocking
- write, cleanup, and local git operation policy
- tunnel setup, public URL handling, and audit logging
- MCP tool schemas, tool annotations, and structured error output

GPT Repo MCP does not expose a caller-controlled shell or a general-purpose
command runner. The validation tool can execute scripts or recipes from an
approved repository; the server does not inspect or sandbox them, so operators
should run validation only when they trust those repository contents. The
server also does not provide push, pull, reset, checkout, switch, rebase, merge,
stash, clean, force, branch deletion, or direct Codex execution tools.

## Disclosure

Please allow reasonable time for investigation and a fix before public disclosure. Reports should include safe reproduction steps and relevant versions, but should not include real credentials, private keys, tokens, or private repository contents.
