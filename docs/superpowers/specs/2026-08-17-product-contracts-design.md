# EmuChef and Argus Repository Product Contracts

**Date:** 2026-08-17  
**Status:** Approved design  
**Scope:** Add repository-owned machine-readable product contracts for EmuChef and Argus ROM Toolkit.

## 1. Objective

Add the repository-owned product contracts required by GPT Repo MCP's product-grounded delegation workflow. The contracts must make durable product tasks possible for the `emuchef` and `argus-rom-toolkit` repositories without changing tunnel behavior, repository registration, or the product-contract loader.

The existing human-readable product documentation remains authoritative for product decisions. The new JSON files provide the bounded, machine-readable projection required by the delegation and product-brief contracts.

## 2. Artifact and scope

Create one file in each target repository:

- EmuChef: `docs/product-contract.json`
- Argus ROM Toolkit: `docs/product-contract.json`

Each file uses schema version 1 and contains one repository-level product contract with multiple users and jobs where the repository contains more than one product surface.

EmuChef is represented as one umbrella contract covering both EmuChef proper and Config Editor. The two products remain separate through distinct user and job entries; the contract does not merge their workflows or ownership.

Argus is represented as one ROM-library product contract covering its shared desktop and Android product behavior.

No separate per-application contract paths are introduced because GPT Repo MCP resolves the fixed repository-relative path `docs/product-contract.json`.

## 3. EmuChef contract model

### Primary users

- `emuchef-end-user`: A nontechnical Android handheld owner using EmuChef proper to detect a device, select a setup, provide inputs, review a plan, and simulate or apply a qualified configuration.
- `config-author`: A technical author maintaining recipes, application definitions, device profiles, and related catalog content through Config Editor.

### Jobs to be done

- `configure-supported-device`: Configure a supported Android handheld through a guided, reproducible workflow.
- `review-and-simulate-plan`: Understand planned impact and recovery before changing a real device, using simulation as the normal first step.
- `apply-qualified-configuration`: Apply an explicitly enabled and separately qualified configuration while preserving truthful status and recovery behavior.
- `qualify-authored-workflow`: Establish automated, evidence-backed qualification for an authored workflow before broader release or physical-device claims.
- `author-catalog-content`: Create, validate, and maintain recipes, application definitions, device profiles, and generated catalog content.
- `diagnose-and-recover`: Inspect bounded diagnostics and recover unsaved intent or failed workflow state without requiring a terminal.

### Product boundaries and principles

The contract will reduce uncertainty before device changes, repeated manual configuration work, unsafe or unreviewed real-device execution, authority confusion between Rust/Tauri and React, unrecoverable failures, and leakage of sensitive device or configuration data.

It must not become a generic shell or device-management tool, an unsandboxed execution engine, a hosted service, a frontend-owned authority layer, an automatic license-acceptance or SDK acquisition path, or a product that implies rollback capabilities the runtime does not provide.

Its principles are simulation and review before execution, trusted Rust/Tauri authority with sanitized presentation, truthful accessible status and recovery, bounded local control, explicit separation of EmuChef proper and Config Editor, and evidence before qualification or release claims.

## 4. Argus contract model

### Primary user

- `rom-library-owner`: A person managing local ROM libraries across supported desktop and Android platforms who needs an accurate, inspectable, and recoverable model of library contents and derived game information.

### Jobs to be done

- `manage-local-rom-library`: Configure, scan, inspect, and remove local library folders without modifying the underlying user files.
- `identify-and-enrich-games`: Identify game content and resolve metadata and artwork through bounded, provider-independent workflows.
- `verify-rom-content`: Verify local content against recognized hashes, including RetroAchievements-recognized content where supported.
- `monitor-and-recover-background-work`: Observe, cancel, retry, and recover durable background jobs while preserving authoritative state.
- `use-platform-adapted-workflows`: Use the same product capabilities through appropriate desktop and Android interactions without creating separate product architectures.

### Product boundaries and principles

The contract will reduce uncertainty about library contents and identity, accidental filesystem modification, opaque or lost background work, provider/runtime coupling, stale derived information, UI blocking, and platform inconsistency.

It must not become an emulator frontend, save manager, synchronization platform, cloud library, achievement-progress client, autonomous refresh system, generic plugin platform, or frontend-owned authority layer. It must not silently resume abandoned significant work.

Its principles are correctness and explainability before throughput, one authoritative Rust backend, presentation-only Flutter, explicit persisted jobs and recovery, provider independence, scalable incremental local-first operation, platform-adapted behavior instead of forced parity, and explicit MVP restraint.

## 5. Governance

Both contracts use:

```json
{
  "mode": "advisory",
  "product_review_required_for": ["product_slice", "product_correction"],
  "checkpoint_every_root_runs": 5
}
```

Advisory governance keeps product grounding and audit warnings visible while allowing the repositories' actively evolving product work to proceed. Product tasks still carry explicit product alignment and require the repository contract to be configured.

## 6. Canonical documents

The contracts reference only existing repository-relative POSIX paths.

### EmuChef

- `README.md`
- `PRODUCT.md`
- `docs/product/product-roadmap.md`
- `docs/product/remaining-product-backlog.md`
- `docs/product/phase-5-app-quality-roadmap.md`
- `docs/product/phase-6d1-execution-safety-audit.md`
- `docs/product/recipe-qualification-obtainium.md`
- `docs/product/recipe-qualification-bios.md`
- `docs/product/recipe-qualification-retroarch.md`
- `docs/product/recipe-qualification-retroarch-bios.md`

### Argus ROM Toolkit

- `README.md`
- `docs/README.md`
- `docs/architecture/architecture-overview.md`
- `docs/architecture/documentation-architecture.md`
- `docs/phases/phase-000-foundation.md`
- `docs/phases/phase-001-local-sources-and-indexing.md`
- `docs/specifications/backend/spec-be-004-application-runtime-command-pipeline-and-background-operations.md`
- `docs/specifications/backend/spec-be-013-library-source-management-scan-operations-and-source-projections.md`
- `docs/specifications/frontend/spec-fe-008-sources-and-library-folder-management.md`
- `docs/superpowers/specs/2026-08-15-phase-002-android-first-class-platform-support-design.md`

## 7. Implementation and verification

Implementation adds only the two JSON files and the required small pointer update to EmuChef's existing `CONTEXT.md`. Argus has no `CONTEXT.md`, and its existing working tree must remain untouched.

Verification must:

1. Load each file through GPT Repo MCP's existing `ProductContractService`.
2. Confirm the schema, canonical paths, path safety, size limit, and secret scanner all pass.
3. Run the focused GPT Repo MCP product-contract tests.
4. Run `git diff --check` in all affected repositories.
5. Confirm the Argus diff contains no changes outside the new contract file.

No tunnel configuration, repository registry entry, product documentation rewrite, contract-schema change, or architecture change is in scope.
