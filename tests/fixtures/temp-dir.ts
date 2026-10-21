import { rmSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const WORKER_TEMP_PREFIX = "gpt-repo-mcp-test-worker-";
let exitCleanupRegistered = false;

/**
 * Creates an isolated temporary directory owned by the current test worker.
 *
 * All fixture trees for one worker live under a process-specific parent. The
 * suite setup removes that parent after each test, so repeated runs do not
 * leave thousands of fixture trees in the host temporary directory. Cleanup
 * retries transient filesystem errors because short-lived Git children can
 * release their handles just after their parent process exits.
 */
export async function createTempDir(prefix: string): Promise<string> {
  registerExitCleanup();
  const base = workerTempRoot();
  await mkdir(base, { recursive: true });
  return mkdtemp(join(base, prefix));
}

export async function cleanupTempDirs(): Promise<void> {
  await rm(workerTempRoot(), {
    recursive: true,
    force: true,
    maxRetries: 10,
    retryDelay: 25
  });
}

function workerTempRoot(): string {
  return join(tmpdir(), `${WORKER_TEMP_PREFIX}${process.pid}`);
}

function registerExitCleanup(): void {
  if (exitCleanupRegistered) return;
  exitCleanupRegistered = true;
  process.once("exit", () => {
    rmSync(workerTempRoot(), {
      recursive: true,
      force: true,
      maxRetries: 10,
      retryDelay: 25
    });
  });
}
