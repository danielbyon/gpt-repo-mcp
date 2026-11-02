import { RepoReaderError } from "../runtime/errors.js";

export function errorReason(error: unknown): string {
  if (typeof error === "object" && error !== null && "diagnostics" in error) {
    const diagnostics = (error as { diagnostics?: { reason?: unknown } }).diagnostics;
    if (typeof diagnostics?.reason === "string") return diagnostics.reason;
  }
  if (typeof error === "object" && error !== null && "code" in error && typeof error.code === "string") {
    const filesystemCodes: Record<string, string> = {
      EACCES: "filesystem_access_denied",
      ELOOP: "symlink_loop",
      ENOENT: "filesystem_entry_missing",
      ENOTDIR: "path_component_not_directory",
      EPERM: "filesystem_access_denied",
      EROFS: "filesystem_read_only",
      ESTALE: "filesystem_state_stale"
    };
    if (filesystemCodes[error.code]) return filesystemCodes[error.code]!;
  }
  return "collection_failed";
}

export function taskExecutionError(reason: string): RepoReaderError {
  return new RepoReaderError("RUNNER_POLICY_BLOCKED", `Task execution validation failed: ${reason}.`, {
    diagnostics: { reason }
  });
}
