# Contributing

## Setup

```bash
npm install
cp config.example.json config.local.json
```

## Checks

Run focused checks while developing, then run the relevant broader checks before committing:

```bash
npm run typecheck
npm test -- tests/tool-contracts.test.ts tests/mcp-contract.test.ts
npm run lint
npm run build
```

Use targeted tests for the area you changed before broad validation.

## Safety Rules

- Do not expose caller-supplied shell text, arbitrary executable selection, or free-form runner arguments. Keep validation limited to fixed, allowlisted profiles and their supported inputs.
- Do not weaken sandbox, secret, path, write, git, or cleanup policies.
- Keep tool changes contract-first: contracts -> tool registry -> handlers -> services.
- Keep tool definitions metadata-only and handlers thin.
- Put real behavior in services and policy decisions in policy/service layers.
- Mutating tools require explicit policy, safe defaults, and focused tests.
