import { posix } from "node:path";

/** Private, Git-ignored directory reserved for owner-attested adoption artifacts. */
export const ADOPTION_CONTROL_ROOT = ".chatgpt/adoptions";

/** Maximum length accepted for a generated adoption identifier. */
export const MAX_ADOPTION_ID_LENGTH = 96;

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

/** Builds a normalized repository-relative adoption artifact path. */
export function adoptionArtifactPath(adoptionId: string, fileName: string): string {
  assertAdoptionId(adoptionId);
  if (!/^[a-z0-9][a-z0-9.-]{0,79}$/.test(fileName) || fileName.includes("..")) {
    throw new Error("ADOPTION_ARTIFACT_NAME_INVALID");
  }
  return `${ADOPTION_CONTROL_ROOT}/${adoptionId}/${fileName}`;
}

/** Validates the stable, path-safe identifier used for one adoption candidate. */
export function assertAdoptionId(adoptionId: string): void {
  if (
    adoptionId.length < 1
    || adoptionId.length > MAX_ADOPTION_ID_LENGTH
    || !/^[a-z0-9][a-z0-9-]*$/.test(adoptionId)
  ) {
    throw new Error("ADOPTION_ID_INVALID");
  }
}

function normalizeAdoptionPath(repoPath: string): string {
  return posix.normalize(repoPath.replaceAll("\\", "/").replace(/^\/+/, "")).replace(/^\.\//, "");
}
