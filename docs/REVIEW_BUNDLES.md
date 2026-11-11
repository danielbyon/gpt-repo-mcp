# Content-addressed review bundles

Use this tool when an independent reviewer cannot access a temporary worktree.
It exports a **local-only snapshot** of the current checkout without staging,
committing, or modifying repository content. Only send the resulting bundle to
a reviewer you trust: tracked diffs and source files may contain sensitive data.

## Create a bundle

From the checkout or worktree being reviewed:

```sh
node scripts/create-review-bundle.mjs create \
  --base origin/main \
  --output /absolute/outside/repo/review-issue-50 \
  --reference docs/ARCHITECTURE.md \
  --issue '#50'
```

The output directory must be new, absolute, and outside the checkout.
The base ref must resolve to a commit that is an ancestor of HEAD; use the
stable branch-point commit (for example, the current merge-base against main)
rather than assuming a moving remote branch remains the appropriate baseline.
The creator refuses divergent bases and does not fetch remote refs.

The bundle contains a full-index binary `tracked.patch` against the verified
base commit, copies of eligible untracked source files under `untracked/`,
standards/architecture references under `references/`, and a `manifest.json`.
Tracked changes are a patch, **not** copies of every tracked source file.
Independent reviewers need the exact base Git tree and appropriate tools to
apply/inspect the patch, plus the separately included untracked source.
The manifest records the baseline, HEAD, changed paths, excluded untracked
paths, per-file SHA-256 digests, and the bundle content digest.

The inventory has explicit boundaries:

- Tracked changes: `tracked.patch` is Git's binary diff from the selected
  ancestor to the current worktree. Before generating it, the creator checks
  changed path modes across base-to-HEAD, base-to-index, and base-to-worktree
  metadata. It rejects symlinks, unsupported Git file modes, and existing paths
  that are hard-linked, nonregular, or reached through a symlinked ancestor.
  Git-recorded deletions are allowed. Regular additions, edits, renames,
  executable-bit changes, and binary patches remain supported. Tracked patches
  have a 16 MiB limit and no per-file copy limit; the 2 MiB per-file limit
  applies to copied untracked files and references. Restricted tracked paths
  cause capture to fail.
- Ordinary untracked files: Git's non-ignored inventory is enumerated.
  Eligible source, tests, scripts, docs, native code, approved root files, and
  workflow YAML are copied within limits of 256 files, 16 MiB combined, and
  2 MiB per file. Other ordinary untracked paths appear under
  `excluded_untracked_paths`. The verifier requires safe relative path syntax
  and permits restricted paths in this exclusion list.
- References: available default documents and caller-supplied references are
  limited to 16 files and 16 MiB combined, with a 2 MiB limit per file.
  Included defaults count toward both limits.
- Ignored source: a separate bounded Git-ignored inventory covers
  `src/`, `tests/`, `scripts/`, `docs/`, `native/`,
  `.github/workflows/`, and the named build definitions. Git can emit
  synthetic traversal ancestors alongside actual ignored directories; each
  candidate is classified by `git check-ignore --stdin` before counting or
  applying the fail-closed rule. A synthetic, nonignored parent does not
  cause a failure or appear as an ignored exclusion. An actually ignored
  reviewable source path or directory still **fails closed**, including
  ignored test files. It cannot silently disappear.
- Other ignored artifacts: ignored generated/blocked directories are collapsed
  by Git's directory enumeration and not recursively scanned. Nonrestricted
  exclusions appear under `excluded_ignored_paths`; restricted path names
  are suppressed and counted in `redacted_ignored_count`. The manifest
  includes `ignored_inventory_roots`, so these counts are not presented as
  a repository-wide ignored-file inventory.
- Credentials, private control files, symlinks, hard links, and restricted
  paths are never copied from the worktree. This is not secret-content
  scanning: review every bundle before distribution.

Git stores symlink modes and their target text, but it does not store hard-link
relationships. The creator checks tracked file types and link counts before
patch creation and again at the final snapshot. It cannot recover historical
hard-link state from Git blobs. Both ordinary and scoped ignored inventories
are captured again before completion. The creator and verifier enforce the
file and byte limits above. The creator removes partial output after a failed
capture.

Keep the printed **manifest SHA-256** outside the bundle. Its integrity
claim relies on obtaining the expected hash from a trusted independent
channel, not from the same potentially modified bundle.

## Verify a received bundle

```sh
node scripts/create-review-bundle.mjs verify \
  --bundle /absolute/path/to/review-issue-50 \
  --expected-manifest-sha256 <64-character-hex>
```

Verification checks the externally supplied manifest hash, manifest content
digest, every referenced file hash, and the exact expected file inventory.
Unexpected files, altered bytes, duplicate entries, and symlinked payload files
cause verification to fail. The manifest must also contain nonzero full Git
object IDs in `base_sha` and `head_sha`. Each ID must have 40 hexadecimal
characters (SHA-1) or 64 (SHA-256), and both fields must use the same format.
Equal identities are valid. These checks validate the fields' structure only.
Verification runs offline and does not prove that either commit exists, that
one is an ancestor of the other, or that they belong to a trusted repository.
The creator resolves the base commit and checks its ancestry against HEAD.

Verification checks content integrity. It does not make the bundle directory
immutable. Start and end snapshots cannot detect a writer that changes data and
restores the same state between observations. The bundle covers declared Git
changes, eligible untracked files, and the scoped ignored inventory. It does
not contain a full checkout or a repository-wide ignored-file inventory.
Verification does not run tests or approve the change. Record the manifest hash
with the reviewer verdict and rerun qualification when the candidate changes.
