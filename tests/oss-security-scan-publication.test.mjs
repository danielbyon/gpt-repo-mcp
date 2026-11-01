import { execFileSync } from "node:child_process";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { link, lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import { describe, expect, test, vi } from "vitest";
import {
  historyEmailOccurrences,
  publicationHistoryScope,
  runSecurityScan,
  verifyPublicationRefs
} from "../scripts/oss-security-scan.mjs";
import { resolvePublicationRefSet } from "../scripts/publication-ref-set.mjs";

const { openMock, readMock } = vi.hoisted(() => ({
  openMock: vi.fn(),
  readMock: vi.fn()
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    open: async (path, ...args) => {
      openMock(path);
      const handle = await actual.open(path, ...args);
      return new Proxy(handle, {
        get(target, property) {
          if (property === "read") {
            return (...readArgs) => {
              readMock(path, ...readArgs);
              return target.read(...readArgs);
            };
          }
          const value = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    }
  };
});

const OUTSIDE_EMAIL = "outside-scope@personal.invalid";
const PERSONAL_EMAIL = "inscope@example.com";

function git(root, args, environment = {}) {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, ...environment }
  }).trim();
}

async function commit(root, message, email) {
  await writeFile(join(root, `${message}.txt`), `${message}\n`);
  git(root, ["add", "--all"]);
  git(root, ["commit", "-qm", message], {
    GIT_AUTHOR_EMAIL: email,
    GIT_COMMITTER_EMAIL: email
  });
  return git(root, ["rev-parse", "HEAD"]);
}

async function fixtureRepository() {
  const root = await mkdtemp(join(await realpath(tmpdir()), "gpt-repo-publication-"));
  try {
    git(root, ["init", "-q", "-b", "main"]);
    git(root, ["config", "user.name", "Fixture"]);
    git(root, ["config", "user.email", "fixture@example.invalid"]);
    await writeFile(join(root, "README.md"), "fixture\n");
    const published = await commit(root, "published", PERSONAL_EMAIL);
    const outside = await commit(root, "outside", OUTSIDE_EMAIL);
    git(root, ["update-ref", "refs/heads/private-only", outside]);
    git(root, ["reset", "-q", "--hard", published]);
    await writeFile(join(root, "stashed.txt"), `${OUTSIDE_EMAIL}\n`);
    git(root, ["stash", "push", "-q", "-u", "-m", "stash with marker"]);
    git(root, ["notes", "add", "-m", `note ${OUTSIDE_EMAIL}`]);
    return { root, published, outside };
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function withFixtureRepository(run) {
  const fixture = await fixtureRepository();
  try {
    return await run(fixture);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
}

async function createUnrelatedCommit(root) {
  git(root, ["checkout", "-q", "--orphan", "unrelated-root"]);
  await writeFile(join(root, "unrelated.txt"), "unrelated\n");
  git(root, ["add", "unrelated.txt"]);
  git(root, ["commit", "-qm", "unrelated root"]);
  const unrelated = git(root, ["rev-parse", "HEAD"]);
  git(root, ["checkout", "-q", "main"]);
  return unrelated;
}

function refEntry(ref, commitSha) {
  return {
    ref,
    object_sha: commitSha,
    object_type: "commit",
    commit_sha: commitSha
  };
}

function publicationFor({ refs, commits, candidate, target, pinned = [] }) {
  return {
    schema_version: 1,
    fingerprint: "synthetic",
    candidate,
    target,
    refs,
    pinned_commits: pinned,
    commits,
    commit_count: commits.length,
    object_count: commits.length,
    tag_objects: [],
    diagnostics: {},
    note: "diagnostics intentionally ignore out-of-scope commits"
  };
}

function scopeFor({ published }) {
  return publicationHistoryScope(
    publicationFor({
      candidate: { kind: "ref", ref: "refs/heads/main" },
      target: { kind: "ref", ref: "refs/heads/main" },
      refs: [refEntry("refs/heads/main", published)],
      commits: [published],
      pinned: [published]
    })
  );
}

describe("OSS security scan publication scope", () => {
  test("requires an explicit policy instead of loading a default path", async () => {
    await expect(
      runSecurityScan({
        candidateRoot: "/nonexistent/candidate",
        exportReportPath: "/nonexistent/report.json",
        publicRepo: "/nonexistent/public",
        gitleaksBin: "/nonexistent/gitleaks"
      })
    ).resolves.toMatchObject({
      status: "NOT_RUN",
      code: "SCAN_INPUT_REQUIRED",
      scanner_invoked: false
    });
  });

  test.each([
    ["symlinked parent", "docs/sentinel.md", "parent"],
    ["traversal alias", "docs/../docs/sentinel.md", "parent"],
    ["final symlink", "docs/sentinel.md", "final"],
    ["hard-link alias", "docs/sentinel.md", "hardlink"]
  ])("rejects an exported %s before reading its target", async (_case, reportPath, aliasKind) => {
    const temporaryRoot = await realpath(tmpdir());
    const publicRoot = await mkdtemp(join(temporaryRoot, "gpt-repo-export-source-"));
    const scanRoot = await mkdtemp(join(temporaryRoot, "gpt-repo-export-scan-"));
    const sourceBytes = Buffer.from("synthetic export sentinel\n");
    try {
      git(publicRoot, ["init", "-q", "-b", "main"]);
      git(publicRoot, ["config", "user.name", "Fixture"]);
      git(publicRoot, ["config", "user.email", "fixture@example.invalid"]);
      await mkdir(join(publicRoot, "docs"));
      await mkdir(join(publicRoot, "Security"));
      await writeFile(join(publicRoot, "docs", "sentinel.md"), sourceBytes);
      await writeFile(
        join(publicRoot, "Security", "OSS-SECURITY-POLICY.JSON"),
        "synthetic restricted policy placeholder\n"
      );
      git(publicRoot, ["add", "--all"]);
      git(publicRoot, ["commit", "-qm", "source"], {
        GIT_AUTHOR_EMAIL: PERSONAL_EMAIL,
        GIT_COMMITTER_EMAIL: PERSONAL_EMAIL
      });
      const published = git(publicRoot, ["rev-parse", "HEAD"]);

      const candidate = join(scanRoot, "candidate");
      const externalRoot = join(scanRoot, "external");
      const sentinel = join(externalRoot, "sentinel.md");
      await mkdir(candidate);
      await mkdir(externalRoot);
      await writeFile(sentinel, sourceBytes);
      if (aliasKind === "final") {
        await mkdir(join(candidate, "docs"));
        await symlink(sentinel, join(candidate, "docs", "sentinel.md"));
      } else if (aliasKind === "hardlink") {
        await mkdir(join(candidate, "docs"));
        await link(sentinel, join(candidate, "docs", "sentinel.md"));
      } else {
        await symlink(externalRoot, join(candidate, "docs"));
      }

      const scannerPath = join(scanRoot, "gitleaks");
      const scannerBytes = Buffer.from(
        "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then printf '8.30.1\\n'; exit 0; fi\nexit 1\n"
      );
      const configPath = join(scanRoot, "gitleaks.toml");
      const configBytes = Buffer.from('title = "fixture"\n');
      const ignorePath = join(scanRoot, "gitleaksignore");
      const ignoreBytes = Buffer.from("\n");
      await writeFile(scannerPath, scannerBytes, { mode: 0o755 });
      await writeFile(configPath, configBytes);
      await writeFile(ignorePath, ignoreBytes);

      const entry = {
        path: reportPath,
        bytes: sourceBytes.byteLength,
        sha256: createHash("sha256").update(sourceBytes).digest("hex")
      };
      const treeSha256 = createHash("sha256")
        .update(entry.path)
        .update("\0")
        .update(entry.sha256)
        .update("\0")
        .update(String(entry.bytes))
        .update("\n")
        .digest("hex");
      const exportReportPath = join(scanRoot, "export.json");
      await writeFile(exportReportPath, JSON.stringify({
        source_commit: published,
        files: [entry],
        tree_sha256: treeSha256
      }));

      const scannerSha256 = createHash("sha256").update(scannerBytes).digest("hex");
      const policy = {
        schema_version: 1,
        policy_version: "fixture",
        gitleaks: {
          version: "8.30.1",
          assets: {
            [`${process.platform}_${process.arch}`]: { binary_sha256: scannerSha256 }
          }
        },
        email: {
          allowed_domains: [],
          allowed_addresses: [],
          reviewed_public_history_locations: []
        },
        licenses: { allowed: [] },
        known_development_advisories: [],
        dependency_audit: {
          executable_path: scannerPath,
          executable_sha256: scannerSha256,
          registry: "https://registry.npmjs.org",
          timeout_ms: 1000
        }
      };
      const policyProvenance = {
        kind: "synthetic_fixture",
        fixture_id: "export-" + _case.toLowerCase().replace(/[^a-z0-9]+/g, "-")
          .replace(/^-|-$/g, ""),
        policy_sha256: createHash("sha256").update(JSON.stringify(policy)).digest("hex")
      };

      openMock.mockClear();
      readMock.mockClear();
      const result = await runSecurityScan({
        candidateRoot: candidate,
        exportReportPath,
        publicRepo: publicRoot,
        gitleaksBin: scannerPath,
        gitleaksConfig: {
          path: configPath,
          sha256: createHash("sha256").update(configBytes).digest("hex")
        },
        gitleaksIgnore: {
          path: ignorePath,
          sha256: createHash("sha256").update(ignoreBytes).digest("hex")
        },
        policy,
        policyProvenance,
        publication: publicationFor({
          candidate: { kind: "ref", ref: "refs/heads/main" },
          target: { kind: "ref", ref: "refs/heads/main" },
          refs: [refEntry("refs/heads/main", published)],
          commits: [published],
          pinned: [published]
        })
      });

      expect(result).toMatchObject({ status: "INCOMPLETE", scanner_invoked: true });
      expect(result.mandatory_checks).toContainEqual(expect.objectContaining({
        name: "gitleaks_version",
        status: "complete"
      }));
      expect(result.mandatory_checks).toContainEqual(expect.objectContaining({
        name: "candidate_source_snapshot",
        status: "failed"
      }));
      expect(result.mandatory_checks).not.toContainEqual(expect.objectContaining({
        name: "candidate_gitleaks"
      }));
      const targetPaths = [
        resolve(sentinel),
        resolve(candidate, reportPath)
      ];
      const observedTargetAccess = [
        ...openMock.mock.calls.map(([path]) => resolve(path)),
        ...readMock.mock.calls.map(([path]) => resolve(path))
      ].filter((path) => targetPaths.includes(path));
      expect(observedTargetAccess).toEqual([]);
      expect(await readFile(sentinel)).toEqual(sourceBytes);
    } finally {
      await rm(publicRoot, { recursive: true, force: true });
      await rm(scanRoot, { recursive: true, force: true });
    }
  });

  test("rejects removed diagnostic mode with an explicit validation error", async () => {
    await expect(runSecurityScan({ diagnostic: true })).rejects.toMatchObject({
      code: "VALIDATION_ERROR",
      message: expect.stringContaining("Diagnostic mode is no longer supported")
    });
  });

  test("returns a migration result for retired host-attestation inputs", async () => {
    await expect(runSecurityScan({ trustedSource: {} })).resolves.toMatchObject({
      status: "NOT_RUN",
      code: "HOST_ATTESTATION_RETIRED",
      reason: expect.stringContaining("legacy trustedSource host-attestation input is retired"),
      obsolete_options: ["trustedSource"],
      scanner_invoked: false,
      production_eligible: false,
      publication_eligible: false,
      ok: false
    });
  });

  test("rejects incomplete or malformed publication ref sets", () => {
    expect(() => publicationHistoryScope(undefined)).toThrow(/publication/i);
    expect(() =>
      publicationHistoryScope({ refs: [], commits: [], commit_count: 0 })
    ).toThrow(/selected ref/i);
    expect(() =>
      publicationHistoryScope({ refs: [{ ref: "refs/heads/main" }], commits: [] })
    ).toThrow();
    expect(() =>
      publicationHistoryScope({
        refs: [refEntry("refs/heads/main", "a".repeat(40))],
        commits: ["short"],
        commit_count: 1
      })
    ).toThrow(/commit/i);
    expect(() =>
      publicationHistoryScope({
        refs: [refEntry("refs/heads/main", "a".repeat(40))],
        commits: ["a".repeat(40), "b".repeat(40)],
        commit_count: 1
      })
    ).toThrow(/count/i);
  });

  test.each([
    ["notes", "refs/notes/commits"],
    ["stash", "refs/stash"]
  ])("rejects %s refs in the publication ref set", (_label, ref) => {
    const commit = "a".repeat(40);
    expect(() =>
      publicationHistoryScope(
        publicationFor({
          candidate: { kind: "ref", ref: "refs/heads/main" },
          target: { kind: "ref", ref: "refs/heads/main" },
          refs: [refEntry("refs/heads/main", commit), refEntry(ref, commit)],
          commits: [commit]
        })
      )
    ).toThrow(/refs\/heads|refs\/tags|unsupported|ref/i);
  });

  test.each([["~1"], ["^"], ["^{commit}"]])(
    "rejects revision operator %s in selected ref names",
    (operator) => {
      const commit = "a".repeat(40);
      expect(() =>
        publicationHistoryScope(
          publicationFor({
            candidate: { kind: "ref", ref: "refs/heads/main" },
            target: { kind: "ref", ref: "refs/heads/main" },
            refs: [
              refEntry("refs/heads/main", commit),
              refEntry(`refs/heads/main${operator}`, commit)
            ],
            commits: [commit]
          })
        )
      ).toThrow(/ref name|invalid|unsupported/i);
    }
  );

  test("scopes history to selected commits so extra refs, stash and notes cannot leak in", async () => {
    await withFixtureRepository(async (fixture) => {
      const scope = scopeFor(fixture);
      const allRefsLog = git(fixture.root, ["log", "--all", "--format=%ae"]);
      expect(allRefsLog).toContain(OUTSIDE_EMAIL);

      const occurrences = await historyEmailOccurrences(fixture.root, scope);
      const addresses = occurrences.map((entry) => entry.address);
      expect(addresses).toContain(PERSONAL_EMAIL);
      expect(addresses).not.toContain(OUTSIDE_EMAIL);
      for (const occurrence of occurrences) {
        expect(occurrence.location.source).toBe("commit_metadata");
      }

      const publishedBlobScan = await historyEmailOccurrences(
        fixture.root,
        scope,
        { includeBlobs: true }
      );
      expect(
        publishedBlobScan.some(
          (entry) =>
            entry.location.source === "git_blob" &&
            entry.address === OUTSIDE_EMAIL
        )
      ).toBe(false);
    });
  });

  test("verifies selected refs still resolve to pinned commits", async () => {
    await withFixtureRepository(async (fixture) => {
      const scope = scopeFor(fixture);
      await expect(
        verifyPublicationRefs(fixture.root, scope)
      ).resolves.toMatchObject({ ref_count: 1, commit_count: 1 });
      git(fixture.root, ["update-ref", "refs/heads/main", fixture.outside]);
      await expect(verifyPublicationRefs(fixture.root, scope)).rejects.toThrow(
        /refs\/heads\/main/
      );
    });
  });

  test("rejects annotated tag when selected-chain metadata is omitted", async () => {
    await withFixtureRepository(async (fixture) => {
      git(fixture.root, [
        "-c",
        "advice.nestedTag=false",
        "tag",
        "-a",
        "annotated",
        "-m",
        "synthetic annotated tag",
        fixture.published
      ]);
      const publication = publicationFor({
        candidate: { kind: "ref", ref: "refs/heads/main" },
        target: { kind: "ref", ref: "refs/heads/main" },
        refs: [
          refEntry("refs/heads/main", fixture.published),
          refEntry("refs/tags/annotated", fixture.published)
        ],
        commits: [fixture.published],
        pinned: [fixture.published]
      });
      const scope = publicationHistoryScope(publication);
      await expect(verifyPublicationRefs(fixture.root, scope)).rejects.toThrow(
        /annotated-tag chain|tag metadata/i
      );

      const scanRoot = await mkdtemp(join(await realpath(tmpdir()), "gpt-repo-annotated-scan-"));
      try {
        const candidate = join(scanRoot, "candidate");
        await mkdir(candidate, { recursive: true });
        const content = "candidate\n";
        await writeFile(join(candidate, "README.md"), content);
        const reportPath = join(scanRoot, "export.json");
        await writeFile(
          reportPath,
          JSON.stringify({
            source_commit: fixture.published,
            files: [
              {
                path: "README.md",
                bytes: Buffer.byteLength(content),
                sha256: createHash("sha256").update(content).digest("hex")
              }
            ],
            tree_sha256: "0".repeat(64)
          })
        );
        await expect(
          runSecurityScan({
                candidateRoot: candidate,
            exportReportPath: reportPath,
            publicRepo: fixture.root,
            gitleaksBin: join(scanRoot, "gitleaks"),
            policy: {
              schema_version: 1,
              policy_version: "fixture",
              gitleaks: { version: "8.30.1", assets: {} },
              email: {
                allowed_domains: [],
                allowed_addresses: [],
                reviewed_public_history_locations: []
              },
              licenses: { allowed: [] },
              known_development_advisories: []
            },
            publication
          })
        ).resolves.toMatchObject({ status: "NOT_RUN", scanner_invoked: false, ok: false });
      } finally {
        await rm(scanRoot, { recursive: true, force: true });
      }
    });
  });

  test("verifies selected nested annotated tag chains", async () => {
    await withFixtureRepository(async (fixture) => {
      git(fixture.root, [
        "tag",
        "-a",
        "inner",
        "-m",
        "synthetic inner tag",
        fixture.published
      ]);
      git(fixture.root, [
        "-c",
        "advice.nestedTag=false",
        "tag",
        "-a",
        "outer",
        "-m",
        "synthetic outer tag",
        "inner"
      ]);
      const publication = await resolvePublicationRefSet({
        repoRoot: fixture.root,
        candidate: { kind: "ref", ref: "refs/heads/main" },
        target: { kind: "ref", ref: "refs/heads/main" },
        additionalRefs: [{ kind: "ref", ref: "refs/tags/outer" }]
      });
      expect(publication.tag_objects).toHaveLength(2);
      const scope = publicationHistoryScope(publication);
      expect(scope.tag_objects.map((entry) => entry.ref)).toEqual([
        "refs/tags/outer",
        "refs/tags/outer"
      ]);
      await expect(
        verifyPublicationRefs(fixture.root, scope)
      ).resolves.toMatchObject({ ref_count: 2, commit_count: 1 });
    });
  });

  test("accepts a lightweight tag whose object type is commit", async () => {
    await withFixtureRepository(async (fixture) => {
      git(fixture.root, ["tag", "lightweight", fixture.published]);
      const scope = publicationHistoryScope(
        publicationFor({
          candidate: { kind: "ref", ref: "refs/heads/main" },
          target: { kind: "ref", ref: "refs/heads/main" },
          refs: [
            refEntry("refs/heads/main", fixture.published),
            refEntry("refs/tags/lightweight", fixture.published)
          ],
          commits: [fixture.published],
          pinned: [fixture.published]
        })
      );
      await expect(verifyPublicationRefs(fixture.root, scope)).resolves.toMatchObject({
        ref_count: 2,
        commit_count: 1
      });
    });
  });

  test("rejects a selected ref whose actual object is not a commit", async () => {
    await withFixtureRepository(async (fixture) => {
      const tree = git(fixture.root, ["write-tree"]);
      git(fixture.root, ["update-ref", "refs/tags/tree-only", tree]);
      const scope = publicationHistoryScope(
        publicationFor({
          candidate: { kind: "ref", ref: "refs/heads/main" },
          target: { kind: "ref", ref: "refs/heads/main" },
          refs: [
            refEntry("refs/heads/main", fixture.published),
            refEntry("refs/tags/tree-only", fixture.published)
          ],
          commits: [fixture.published],
          pinned: [fixture.published]
        })
      );
      await expect(verifyPublicationRefs(fixture.root, scope)).rejects.toThrow(
        /commit object/i
      );
    });
  });

  test("rejects a substituted commit list with the same reachable count", async () => {
    await withFixtureRepository(async (fixture) => {
      const unrelated = await createUnrelatedCommit(fixture.root);
      expect(Number(git(fixture.root, ["rev-list", "--count", unrelated]))).toBe(1);
      const substituted = publicationHistoryScope(
        publicationFor({
          candidate: { kind: "commit", sha: unrelated },
          target: { kind: "ref", ref: "refs/heads/main" },
          refs: [refEntry("refs/heads/main", fixture.published)],
          commits: [unrelated],
          pinned: [unrelated]
        })
      );
      await expect(
        verifyPublicationRefs(fixture.root, substituted)
      ).rejects.toThrow(/closure|commit list|does not match/i);
    });
  });

  test("binds supplied refs to the intended candidate and target selection", async () => {
    await withFixtureRepository(async (fixture) => {
      const unrelated = await createUnrelatedCommit(fixture.root);
      expect(() =>
        publicationHistoryScope(
          publicationFor({
            candidate: { kind: "ref", ref: "refs/heads/main" },
            target: { kind: "ref", ref: "refs/heads/main" },
            refs: [refEntry("refs/heads/unrelated-root", unrelated)],
            commits: [unrelated]
          })
        )
      ).toThrow(/candidate|target|selection/i);

      const rewritten = publicationHistoryScope(
        publicationFor({
          candidate: { kind: "ref", ref: "refs/heads/unrelated-root" },
          target: { kind: "ref", ref: "refs/heads/unrelated-root" },
          refs: [refEntry("refs/heads/unrelated-root", unrelated)],
          commits: [unrelated]
        })
      );
      await expect(
        verifyPublicationRefs(fixture.root, rewritten, {
          candidate_commit: fixture.published
        })
      ).rejects.toThrow(/candidate/i);
    });
  });

  test("removes temporary repositories when an assertion fails", async () => {
    let root;
    await expect(
      withFixtureRepository(async (fixture) => {
        root = fixture.root;
        expect(fixture.published).toBe("not-a-commit");
      })
    ).rejects.toThrow();
    await expect(lstat(root)).rejects.toMatchObject({ code: "ENOENT" });
  });
});
