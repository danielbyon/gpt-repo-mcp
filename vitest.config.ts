import { defineConfig } from "vitest/config";

/**
 * Many test files launch Git, Node, and package-manager subprocesses. Keeping
 * four test-file workers bounds the aggregate process count while preserving
 * parallel execution on both small and large CI runners.
 */
export default defineConfig({
  test: {
    maxWorkers: 4,
    setupFiles: ["./tests/setup/temp-dir.ts"]
  }
});
