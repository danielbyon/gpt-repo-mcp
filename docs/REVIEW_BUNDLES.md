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

The bundle contains a full-index binary `tracked.patch` against the verified
base commit, copies of eligible untracked source files under `untracked/`,
standards/architecture references under `references/`, and a `manifest.json`.
The manifest records the baseline, HEAD, changed paths, excluded untracked
paths, per-file SHA-256 digests, and the bundle content digest.

Untracked eligibility is deliberately conservative (source, tests, scripts,
documentation, native source, and workflow YAML). Generated, ignored,
credential-like, and private control files are excluded. All skipped untracked
paths are enumerated in the manifest so reviewers can detect omissions.
Restricted tracked changes cause the export to fail rather than silently
omit part of the patch.

Keep the printed **manifest SHA-256** outside the bundle. Reviewers must
compare against that value.

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
between observations. It also does not execute tests or provide independent
approval. Record the resulting manifest hash with the reviewer verdict and
rerun qualification when the candidate changes.
