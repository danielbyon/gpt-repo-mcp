# Task execution boundary and preservation evidence

This runbook describes owner enrollment, the checks made before governed MCP work, and the limits of the local preservation receipt. It covers the enrolled server process. Shell commands, other MCP servers, and external agents remain outside its scope.

## Owner enrollment

The owner starts the server with `GPT_REPO_TASK_BOOTSTRAP_PATH` set to an owner-controlled version 2 descriptor. It identifies the task, allowed run IDs, repository, protected and execution roots, protected paths, authorized source paths, exact ref transitions, receipt directory, path-token key, and collection limits. Its expected baseline includes the HEAD SHA, a required worktree fingerprint, and a SHA-256 digest of the normalized V3 baseline, including initial changed paths and path states.

The server reads enrollment from its process environment. MCP arguments cannot supply or replace the descriptor. If the variable is absent, ordinary MCP operations keep their existing behavior. If it is present but empty, malformed, unsafe, or inconsistent with the live repository registration, governed work fails closed.

The loader uses a bounded no-follow read and checks file ownership, permissions, link count, strict descriptor schema, canonical roots, and receipt location. A version 1 descriptor lacks the full baseline pin and fails closed. Each operation resolves the requested repository ID through the live root registry and confirms that it maps to the enrolled execution root. A local prompt and `run.json` cannot prove which repository the server registered.

Enrollment does not add global configuration fields or change server startup, the root registry, or the Delegation v3 schemas.

## Operation checks

The MCP registration layer applies one `TaskExecutionBoundary` to task preparation and registration, agent replies, reviews, validation, and symbol-context analysis. It checks identity and authorization before work, samples preservation state before and after the operation, then writes a receipt. The task writer binds prompts through the active boundary session, which rechecks enrollment and repository registration before returning a prompt for writing. `repo_symbol_context` uses the same boundary with the `index` operation; the handler revalidates before native analysis, and `CodeIntelligenceService` revalidates again before creating a provider client.

`repo_code_index` status checks use the task boundary before querying Codebase Memory. They verify the live repository mapping and physical execution root, close the provider client before finishing the session, and never queue indexing. A start request keeps one boundary session from the initial project check through the background job and finishes it at most once. Before each provider call, the session rechecks the selected bootstrap, live repository mapping, physical execution root, Git registration, and expected HEAD. An enrolled initial-check cleanup error fails the request and records a failed `NOT_PROVEN` receipt. Unenrolled calls keep their existing provider fallback behavior. Indexing and validation without a run-specific selection record the full owner-authorized run set. A review with multiple runs requires an explicit selection. A changed mapping or enrollment prevents the queued index call and records a failed `NOT_PROVEN` receipt.

Identity and authorization failures block work. A collection limit, unsupported Git layout, or unavailable inventory can leave a snapshot incomplete; that does not by itself block otherwise authorized work. The receipt remains `NOT_PROVEN`, and the collector keeps the configured limits.

## Preservation receipts

The server writes one bounded JSON receipt per operation to the owner-controlled directory named in the descriptor. That directory must sit outside both repository roots. The server rejects unsafe ownership, permissions, and symlink substitutions, then publishes each receipt atomically without replacing an existing file.

Run-bound operations use receipt schema version 2. Version 3 is reserved for runless patchset and repository reviews, which record empty `run_ids` and `run_bindings` arrays. In version 2, `run_id` remains the primary run for compatibility, and `run_ids` records the full selected set. Each verified run has a `run_bindings` entry with its baseline and prompt SHA-256 digests. Completed registration, queue, resume, and review operations must include every verified binding. Failed run selection writes a receipt under the owner-authorized run set without recording an unapproved run ID. The reader also accepts version 1 receipts and verifies the task and run set, bootstrap digest, operation ID, and integrity value.

Receipts also include pre- and post-operation metadata, comparison results, limits, and a SHA-256 integrity value. Filesystem paths use keyed opaque tokens; protected path names and file contents are not exported.

Endpoint equality does not rule out transient writes. Working-file content equivalence remains `NOT_PROVEN`. A local receipt does not attest server identity or machine-wide control.

The existing `OperationReceiptService` records ordinary repository writes under `.chatgpt/operations`. Those records remain inside the repository and may contain repository paths. They do not replace the task receipt because they are not bound to a task and run or protected by this receipt integrity check.

## Ref changes and linked worktrees

A ref change is owner-authorized only when its refname, observed before OID (or absence), and observed after OID (or absence) all match one descriptor transition. Additions and deletions use `null` for the absent endpoint. A wrong endpoint or unrelated ref remains unattributed.

A linked worktree is accepted when its physical root is separate, Git reports it as registered under the expected common admin directory, and its root and HEAD match the descriptor and live registry. The receipt records linked-worktree and shared-admin state. Shared refs remain unattributed unless their exact before and after values match an authorized transition.

## Delegation v3 artifacts

The existing strict V3 schema remains unchanged. Before review or resume, the boundary checks the live registry entry, task and run IDs, strict manifest and embedded hashes, prompt hash and byte count, structured prompt binding, and authorized source paths. The manifest baseline must include a required worktree fingerprint and normalized initial changed paths and path states. Its digest must match the value pinned in the owner descriptor, so recomputing the manifest hashes or prompt cannot authorize a different baseline. After task registration or queueing, the boundary checks the written manifest and prompt against the same enrollment.

The owner source list uses exact string matches. An entry such as `src/**` permits that exact V3 scope value; it does not authorize a separate path such as `src/actual-file.ts`.

A locally self-consistent `PROMPT.md` and `run.json` do not independently prove server registration. The boundary checks them alongside the live repository mapping. The existing manual run remains `NOT_RUN`; no `RESULT.json` is created. A new formal run requires separate prospective approval for its exact source path set.

## Inventory count and current verdict

The read-only primary-checkout audit reported:

| Enumeration | Count |
| --- | ---: |
| `git ls-files --others -z` | 8,458 |
| `git ls-files --others --exclude-standard -z` | 81 |
| Ignored-only entries | 8,377 |

Disabling global Git configuration did not change either command's count. The ignored entries were 7,681 `node_modules` entries, 18 editor or repository index metadata entries, 3 build outputs, and 675 other ignored artifacts. The audit found no Git control metadata or nested repositories.

The difference is the ignored entries excluded by `--exclude-standard`. The isolated manual artifacts record 8,458 but do not identify the command that produced that historical count, so its producer remains unverified. Keep the preservation verdict `NOT_PROVEN` and the 1,000-entry inventory cap. This reconciliation does not establish which command the historical run used or prove a complete snapshot.

The collector uses `git ls-files --others --exclude-standard -z`; ignored entries are outside that inventory. It samples protected-path metadata separately and does not read protected file contents. Equal samples do not prove content equivalence or rule out a transient write.
