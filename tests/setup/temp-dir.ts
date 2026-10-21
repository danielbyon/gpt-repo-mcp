import { afterAll, afterEach } from "vitest";
import { cleanupTempDirs } from "../fixtures/temp-dir.js";

// Git's configured trace2 event target can asynchronously recreate `.git/ai`
// after a fixture directory is removed. Tests do not consume those events, so
// route them to the null device before any fixture Git command runs.
process.env.GIT_TRACE2_EVENT = process.platform === "win32" ? "NUL" : "/dev/null";

afterEach(cleanupTempDirs);
afterAll(cleanupTempDirs);
