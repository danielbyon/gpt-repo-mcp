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

- Tracked changes: the patch covers Git's differences from the specified
  ancestor through the current index and worktree; restricted tracked paths
  cause capture to fail.
- Ordinary untracked files: Git's non-ignored inventory is enumerated.
  Eligible source, tests, scripts, docs, native code, approved root files, and
  workflow YAML are copied within size/count limits. Other ordinary untracked
  paths appear under `excluded_untracked_paths`.
- Ignored source: a separate bounded Git-ignored inventory covers
  `src/`, `tests/`, `scripts/`, `docs/`, `native/`,
  `.github/workflows/`, and the named build definitions. An ignored
  reviewable source path or an ambiguous ignored directory in these roots
  **fails closed**, including ignored test files. It cannot silently disappear.
- Other ignored artifacts: ignored generated/blocked directories are collapsed
  by Git's directory enumeration and not recursively scanned. Nonrestricted
  exclusions appear under `excluded_ignored_paths`; restricted path names
  are suppressed and counted in `redacted_ignored_count`. The manifest
  includes `ignored_inventory_roots`, so these counts are not presented as
  a repository-wide ignored-file inventory.
- Credentials, private control files, symlinks, hard links, and restricted
  paths are never copied from the worktree. This is not secret-content
  scanning: review every bundle before distribution.

Both ordinary and scoped ignored inventories are captured again before
completion. The output has bounded files and bytes, and incomplete captures
are removed after a failure.

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
cause verification to fail.

This is content-addressed integrity, not an unchangeable filesystem archive.
The snapshot detects endpoint changes during capture but cannot prove that an
external writer did not temporarily alter and then restore identical bytes
between observations. The review evidence is bounded to the declared Git
diff, ordinary untracked paths, and the scoped ignored inventory; it does not
claim a full checkout archive or repository-wide ignored-file inventory. It also does not execute tests or provide independent
approval. Record the resulting manifest hash with the reviewer verdict and
rerun qualification when the candidate changes.
