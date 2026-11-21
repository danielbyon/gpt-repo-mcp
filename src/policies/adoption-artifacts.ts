import { posix } from "node:path";

/** Private directory for historical adoption artifacts. */
const ADOPTION_CONTROL_ROOT = ".chatgpt/adoptions";

/**
 * Returns whether a repository-relative path belongs to the private adoption
 * control namespace. These artifacts contain local state evidence and must not
 * be exposed through generic repository read, write, search, tree, index, or
 * export operations.
 */
export function isAdoptionControlArtifact(repoPath: string): boolean {
  const normalized = normalizeAdoptionPath(repoPath).toLowerCase();
  return normalized === ADOPTION_CONTROL_ROOT || normalized.startsWith(`${ADOPTION_CONTROL_ROOT}/`);
}

function normalizeAdoptionPath(repoPath: string): string {
  return posix.normalize(repoPath.replaceAll("\\", "/").replace(/^\/+/, "")).replace(/^\.\//, "");
}
