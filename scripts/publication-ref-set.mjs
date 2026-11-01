import { spawn } from "node:child_process";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { devNull } from "node:os";
import process from "node:process";
import { setTimeout, clearTimeout } from "node:timers";

const FULL_COMMIT_SHA = /^[a-f0-9]{40}$/;
const SUPPORTED_REF_PREFIXES = ["refs/heads/", "refs/tags/"];
const DEFAULT_MAX_COMMITS = 100_000;
const DEFAULT_MAX_OBJECTS = 500_000;
const GIT_TIMEOUT_MS = 60_000;
const MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024;
const MAX_TAG_CHAIN_DEPTH = 32;
const MAX_TAG_OBJECT_BYTES = 5 * 1024 * 1024;
const MAX_TAG_TOTAL_BYTES = 20 * 1024 * 1024;
const CONTROLLED_GIT_ENVIRONMENT = new Set([
  "GIT_DIR",
  "GIT_WORK_TREE",
  "GIT_COMMON_DIR",
  "GIT_INDEX_FILE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_NAMESPACE",
  "GIT_PREFIX",
  "GIT_QUARANTINE_PATH",
  "GIT_REPLACE_REF_BASE",
  "GIT_CEILING_DIRECTORIES",
  "GIT_CONFIG",
  "GIT_CONFIG_PARAMETERS",
  "GIT_CONFIG_COUNT",
  "GIT_GRAFT_FILE",
  "GIT_SHALLOW_FILE",
  "GIT_IMPLICIT_WORK_TREE",
  "GIT_REFERENCE_BACKEND",
  "GIT_REF_PARANOIA"
]);

export class PublicationRefError extends Error {
  constructor(code, message, diagnostics = {}) {
    super(message);
    this.name = "PublicationRefError";
    this.code = code;
    this.diagnostics = diagnostics;
  }
}

/**
 * Builds the environment for Git calls that resolve publication refs and
 * history. Repository redirection and configuration injection variables are
 * removed, and global and system configuration files are pointed at the null
 * device so ambient Git settings cannot change object or ref interpretation.
 * GIT_REF_PARANOIA is not a redirection variable, but an ambient value of zero
 * would disable missing or corrupt object checks; it is removed here and forced
 * on below.
 */
export function publicationGitEnvironment(environment = process.env) {
  const sanitized = Object.fromEntries(
    Object.entries(environment).filter(([key]) => {
      const normalizedKey = key.toUpperCase();
      return (
        !CONTROLLED_GIT_ENVIRONMENT.has(normalizedKey) &&
        !normalizedKey.startsWith("GIT_CONFIG_KEY_") &&
        !normalizedKey.startsWith("GIT_CONFIG_VALUE_")
      );
    })
  );
  return {
    ...sanitized,
    GIT_CONFIG_GLOBAL: devNull,
    GIT_CONFIG_SYSTEM: devNull,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_REF_PARANOIA: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0"
  };
}

async function runGit(repoRoot, args, input) {
  return await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn("git", ["-C", repoRoot, ...args], {
      env: publicationGitEnvironment(),
      stdio: ["pipe", "pipe", "pipe"]
    });
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    let settled = false;
    const fail = (message, diagnostics = {}) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill("SIGTERM");
      rejectPromise(new PublicationRefError("PUBLICATION_REFERENCE_UNRESOLVABLE", message, {
        git_command: args[0] ?? "git",
        ...diagnostics
      }));
    };
    const timer = setTimeout(() => fail("Git publication selection timed out."), GIT_TIMEOUT_MS);
    child.on("error", () => fail("Git could not resolve the requested publication selection."));
    child.stdout.on("data", (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_GIT_OUTPUT_BYTES) {
        fail("Git publication selection produced more output than the configured safety limit.");
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.stdin.on("error", (error) => {
      if (error?.code !== "EPIPE") fail("Git could not accept the publication selection input.");
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0) {
        const detail = Buffer.concat(stderr).toString("utf8");
        rejectPromise(new PublicationRefError(
          "PUBLICATION_REFERENCE_UNRESOLVABLE",
          "Git could not resolve the requested publication selection.",
          { git_command: args[0] ?? "git", stderr_lines: detail.trim().split("\n").filter(Boolean).slice(0, 4) }
        ));
        return;
      }
      resolvePromise({ stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
    });
    child.stdin.end(input);
  });
}

function text(buffer) {
  return buffer.toString("utf8").trim();
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function validateRefName(ref, label) {
  if (typeof ref !== "string" || ref.length === 0) {
    throw new PublicationRefError("PUBLICATION_REFERENCE_INVALID", `${label} must be an explicit Git ref name.`);
  }
  if (ref === "refs/stash" || ref.startsWith("refs/stash/")) {
    throw new PublicationRefError("PUBLICATION_REFERENCE_UNSUPPORTED", `${label} cannot select refs/stash.`);
  }
  if (!SUPPORTED_REF_PREFIXES.some((prefix) => ref.startsWith(prefix))) {
    throw new PublicationRefError(
      "PUBLICATION_REFERENCE_UNSUPPORTED",
      `${label} must be an exact refs/heads/* or refs/tags/* name.`
    );
  }
  if (/[\0\r\n]/.test(ref) || ref.includes("..") || ref.includes("@{") || ref.endsWith("/")) {
    throw new PublicationRefError("PUBLICATION_REFERENCE_INVALID", `${label} is not a safe Git ref name.`);
  }
}

function normalizeSelection(selection, label) {
  if (typeof selection === "string") {
    validateRefName(selection, label);
    return { kind: "ref", ref: selection };
  }
  if (!selection || typeof selection !== "object" || Array.isArray(selection)) {
    throw new PublicationRefError("PUBLICATION_REFERENCE_INVALID", `${label} must be a ref or pinned commit.`);
  }
  if (selection.kind === "ref") {
    validateRefName(selection.ref, label);
    return { kind: "ref", ref: selection.ref };
  }
  if (selection.kind === "commit") {
    if (typeof selection.sha !== "string" || !FULL_COMMIT_SHA.test(selection.sha)) {
      throw new PublicationRefError(
        "PUBLICATION_REFERENCE_INVALID",
        `${label} must pin a full 40-character lowercase commit SHA.`
      );
    }
    return { kind: "commit", sha: selection.sha };
  }
  throw new PublicationRefError("PUBLICATION_REFERENCE_UNSUPPORTED", `${label} uses an unsupported selector kind.`);
}

function selectionKey(selection) {
  return selection.kind === "ref" ? `ref:${selection.ref}` : `commit:${selection.sha}`;
}

function sortedUniqueSelections(selections) {
  const unique = new Map();
  for (const selection of selections) unique.set(selectionKey(selection), selection);
  return [...unique.values()].sort((left, right) => selectionKey(left).localeCompare(selectionKey(right)));
}

export function publicationSelectionFromRefSet(publication) {
  if (!publication || !publication.candidate || !publication.target || !Array.isArray(publication.refs)) {
    throw new PublicationRefError("PUBLICATION_REFERENCE_INVALID", "Resolved publication selection is required.");
  }
  const fixedRefs = new Set();
  if (publication.candidate.kind === "ref") fixedRefs.add(publication.candidate.ref);
  if (publication.target.kind === "ref") fixedRefs.add(publication.target.ref);
  return {
    candidate: publication.candidate,
    target: publication.target,
    additionalRefs: publication.refs
      .map((entry) => entry.ref)
      .filter((ref) => !fixedRefs.has(ref))
  };
}

async function requireRepositoryRoot(repoRoot) {
  if (typeof repoRoot !== "string" || !repoRoot) {
    throw new PublicationRefError("PUBLICATION_REPOSITORY_INVALID", "Publication repository root is required.");
  }
  let resolved;
  let topLevel;
  try {
    resolved = await realpath(repoRoot);
    topLevel = await realpath(text((await runGit(resolved, ["rev-parse", "--show-toplevel"])).stdout));
  } catch (error) {
    if (error instanceof PublicationRefError) throw error;
    throw new PublicationRefError("PUBLICATION_REPOSITORY_INVALID", "Publication repository is unavailable.");
  }
  if (resolved !== topLevel) {
    throw new PublicationRefError("PUBLICATION_REPOSITORY_INVALID", "Publication repository must be the Git root.");
  }
  const shallow = text((await runGit(resolved, ["rev-parse", "--is-shallow-repository"])).stdout);
  if (shallow !== "false") {
    throw new PublicationRefError("PUBLICATION_HISTORY_INCOMPLETE", "Publication history cannot be verified in a shallow repository.");
  }
  return resolved;
}

async function validateRefSyntax(repoRoot, ref, label) {
  try {
    await runGit(repoRoot, ["check-ref-format", ref]);
  } catch {
    throw new PublicationRefError("PUBLICATION_REFERENCE_INVALID", `${label} is not a valid Git ref name.`);
  }
}

export async function resolveTagObjectChain(repoRoot, initialTagObjectSha) {
  const chain = [];
  let current = initialTagObjectSha;
  while (true) {
    const objectType = text((await runGit(repoRoot, ["cat-file", "-t", current])).stdout);
    if (objectType !== "tag") break;
    if (chain.length >= MAX_TAG_CHAIN_DEPTH) {
      throw new PublicationRefError(
        "PUBLICATION_SELECTION_LIMIT",
        "Publication annotated-tag chain exceeds the configured depth limit.",
        { max_tag_chain_depth: MAX_TAG_CHAIN_DEPTH }
      );
    }
    if (chain.includes(current)) {
      throw new PublicationRefError("PUBLICATION_HISTORY_INCOMPLETE", "Publication tag chain contains a cycle.");
    }
    const tagSize = Number(text((await runGit(repoRoot, ["cat-file", "-s", current])).stdout));
    if (!Number.isSafeInteger(tagSize) || tagSize < 0 || tagSize > MAX_TAG_OBJECT_BYTES) {
      throw new PublicationRefError(
        "PUBLICATION_SELECTION_LIMIT",
        "Publication tag object exceeds the configured size limit.",
        { max_tag_object_bytes: MAX_TAG_OBJECT_BYTES }
      );
    }
    chain.push(current);
    const tagBody = text((await runGit(repoRoot, ["cat-file", "-p", current])).stdout);
    const match = /^object ([a-f0-9]{40})$/mu.exec(tagBody);
    if (!match) {
      throw new PublicationRefError("PUBLICATION_HISTORY_INCOMPLETE", "Publication tag object is malformed.");
    }
    current = match[1];
  }
  return chain;
}

async function resolveOneSelection(repoRoot, selection) {
  if (selection.kind === "commit") {
    const type = text((await runGit(repoRoot, ["cat-file", "-t", selection.sha])).stdout);
    if (type !== "commit") {
      throw new PublicationRefError("PUBLICATION_REFERENCE_INVALID", "Pinned publication selection must resolve to a commit.");
    }
    return {
      requested: selection.sha,
      kind: "commit",
      ref: undefined,
      object_sha: selection.sha,
      commit_sha: selection.sha,
      object_type: type,
      tag_object_sha: undefined,
      tag_object_shas: []
    };
  }
  await validateRefSyntax(repoRoot, selection.ref, "Publication ref");
  const objectSha = text((await runGit(repoRoot, ["rev-parse", "--verify", "--end-of-options", selection.ref])).stdout);
  const objectType = text((await runGit(repoRoot, ["cat-file", "-t", objectSha])).stdout);
  const commitSha = text((await runGit(repoRoot, ["rev-parse", "--verify", "--end-of-options", `${selection.ref}^{commit}`])).stdout);
  if (selection.ref.startsWith("refs/heads/") && objectType !== "commit") {
    throw new PublicationRefError("PUBLICATION_REFERENCE_INVALID", "Publication branch refs must resolve directly to commits.");
  }
  if (objectType !== "commit" && objectType !== "tag") {
    throw new PublicationRefError("PUBLICATION_REFERENCE_UNSUPPORTED", "Publication refs must resolve to commits or annotated tags.");
  }
  const tagObjectShas = objectType === "tag"
    ? await resolveTagObjectChain(repoRoot, objectSha)
    : [];
  return {
    requested: selection.ref,
    kind: "ref",
    ref: selection.ref,
    object_sha: objectSha,
    commit_sha: commitSha,
    object_type: objectType,
    tag_object_sha: tagObjectShas[0],
    tag_object_shas: tagObjectShas
  };
}

async function verifyObjectsAvailable(repoRoot, objectIds, maxObjects) {
  if (objectIds.length > maxObjects) {
    throw new PublicationRefError("PUBLICATION_SELECTION_LIMIT", "Publication object count exceeds the configured safety limit.", {
      object_count: objectIds.length,
      max_objects: maxObjects
    });
  }
  let output;
  try {
    output = await runGit(
      repoRoot,
      ["cat-file", "--batch-check=%(objectname) %(objecttype)"],
      Buffer.from(objectIds.join("\n") + "\n")
    );
  } catch (error) {
    throw new PublicationRefError("PUBLICATION_HISTORY_INCOMPLETE", "Publication history contains unavailable Git objects.", {
      git_command: "cat-file",
      object_diagnostics: error?.diagnostics?.stderr_lines ?? []
    });
  }
  const records = text(output.stdout).split("\n").filter(Boolean);
  if (records.length !== objectIds.length || records.some((line) => line.endsWith(" missing"))) {
    throw new PublicationRefError("PUBLICATION_HISTORY_INCOMPLETE", "Publication history contains unavailable Git objects.", {
      git_command: "cat-file",
      object_count: objectIds.length
    });
  }
}

async function resolveUnchecked(options) {
  const repoRoot = await requireRepositoryRoot(options.repoRoot);
  const candidate = normalizeSelection(options.candidate, "Publication candidate");
  const target = normalizeSelection(options.target, "Publication target");
  if (target.kind !== "ref" || !target.ref.startsWith("refs/heads/")) {
    throw new PublicationRefError("PUBLICATION_TARGET_INVALID", "Publication target must be an exact refs/heads/* branch.");
  }
  const additional = (options.additionalRefs ?? []).map((ref, index) => normalizeSelection(ref, `Additional publication ref ${index + 1}`));
  const selections = sortedUniqueSelections([candidate, target, ...additional]);
  const resolved = [];
  for (const selection of selections) resolved.push(await resolveOneSelection(repoRoot, selection));

  const commitArgs = [...new Set(resolved.map((entry) => entry.commit_sha))];
  const commitList = text((await runGit(repoRoot, ["rev-list", "--topo-order", "--reverse", ...commitArgs])).stdout)
    .split("\n")
    .filter(Boolean);
  if (commitList.length === 0) {
    throw new PublicationRefError("PUBLICATION_SELECTION_EMPTY", "Publication selection contains no commits.");
  }
  const maxCommits = options.maxCommits ?? DEFAULT_MAX_COMMITS;
  if (commitList.length > maxCommits) {
    throw new PublicationRefError("PUBLICATION_SELECTION_LIMIT", "Publication commit count exceeds the configured safety limit.", {
      commit_count: commitList.length,
      max_commits: maxCommits
    });
  }
  let objectOutput;
  try {
    objectOutput = await runGit(
      repoRoot,
      ["rev-list", "--objects", "--stdin"],
      Buffer.from(commitList.join("\n") + "\n")
    );
  } catch (error) {
    throw new PublicationRefError("PUBLICATION_HISTORY_INCOMPLETE", "Publication history contains unavailable or unreadable Git objects.", {
      git_command: "rev-list",
      stderr_lines: error?.diagnostics?.stderr_lines ?? []
    });
  }
  const objectLines = text(objectOutput.stdout)
    .split("\n")
    .filter(Boolean);
  const objectIds = [...new Set(objectLines.map((line) => line.split(" ", 1)[0]))].sort();
  await verifyObjectsAvailable(repoRoot, objectIds, options.maxObjects ?? DEFAULT_MAX_OBJECTS);

  const refs = resolved
    .filter((entry) => entry.kind === "ref")
    .map((entry) => ({
      ref: entry.ref,
      object_sha: entry.object_sha,
      object_type: entry.object_type,
      commit_sha: entry.commit_sha
    }))
    .sort((left, right) => left.ref.localeCompare(right.ref));
  const pinned = resolved
    .filter((entry) => entry.kind === "commit")
    .map((entry) => entry.commit_sha)
    .sort();
  const tagObjects = resolved
    .flatMap((entry) => entry.tag_object_shas.map((objectSha) => ({
      ref: entry.ref,
      object_sha: objectSha,
      commit_sha: entry.commit_sha
    })))
    .sort((left, right) => left.ref.localeCompare(right.ref));
  const fingerprint = sha256(JSON.stringify({
    schema_version: 1,
    refs,
    pinned_commits: pinned,
    commits: commitList,
    tag_objects: tagObjects.map((entry) => entry.object_sha)
  }));
  return Object.freeze({
    schema_version: 1,
    fingerprint,
    candidate: Object.freeze({ ...candidate }),
    target: Object.freeze({ ...target }),
    refs: Object.freeze(refs.map((entry) => Object.freeze(entry))),
    pinned_commits: Object.freeze(pinned),
    commits: Object.freeze(commitList),
    commit_count: commitList.length,
    object_count: objectIds.length,
    tag_objects: Object.freeze(tagObjects.map((entry) => Object.freeze(entry))),
    diagnostics: Object.freeze({
      candidate_kind: candidate.kind,
      candidate_git_ref: candidate.kind === "ref" ? candidate.ref : undefined,
      candidate_commit_sha: candidate.kind === "commit" ? candidate.sha : undefined,
      target_ref: target.ref,
      selected_ref_count: refs.length,
      selected_commit_count: commitList.length,
      selected_tag_object_count: tagObjects.length,
      local_only_refs_included: false
    })
  });
}

export async function resolvePublicationRefSet(options) {
  return resolveUnchecked(options);
}

export async function assertPublicationRefSetUnchanged(options, expected) {
  const current = await resolveUnchecked(options);
  if (current.fingerprint !== expected.fingerprint) {
    throw new PublicationRefError("PUBLICATION_SELECTION_CHANGED", "Publication selection moved during scanning.", {
      expected_fingerprint: expected.fingerprint,
      current_fingerprint: current.fingerprint
    });
  }
  return current;
}

export async function readPublicationTagMetadata(repoRoot, tagObjects) {
  const metadata = [];
  let totalBytes = 0;
  for (const tag of tagObjects) {
    const tagSize = Number(text((await runGit(repoRoot, ["cat-file", "-s", tag.object_sha])).stdout));
    if (!Number.isSafeInteger(tagSize) || tagSize < 0 || tagSize > MAX_TAG_OBJECT_BYTES) {
      throw new PublicationRefError(
        "PUBLICATION_SELECTION_LIMIT",
        "Publication tag object exceeds the configured size limit.",
        { max_tag_object_bytes: MAX_TAG_OBJECT_BYTES }
      );
    }
    totalBytes += tagSize;
    if (totalBytes > MAX_TAG_TOTAL_BYTES) {
      throw new PublicationRefError(
        "PUBLICATION_SELECTION_LIMIT",
        "Publication tag metadata exceeds the configured total size limit.",
        { max_tag_total_bytes: MAX_TAG_TOTAL_BYTES }
      );
    }
    const bytes = (await runGit(repoRoot, ["cat-file", "tag", tag.object_sha])).stdout;
    if (bytes.byteLength !== tagSize) {
      throw new PublicationRefError("PUBLICATION_HISTORY_INCOMPLETE", "Publication tag object changed while it was read.");
    }
    metadata.push({ ref: tag.ref, object_sha: tag.object_sha, bytes });
  }
  return metadata.sort((left, right) => left.ref.localeCompare(right.ref));
}
