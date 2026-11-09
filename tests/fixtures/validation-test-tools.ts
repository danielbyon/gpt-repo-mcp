import { chmod, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";
import { createTempDir } from "./temp-dir.js";

/** Trusted test-only runner; never placed inside the checkout being validated. */
export async function createTrustedTestRunner(
  name: string,
  body: string,
  options: { dryRunOnly?: boolean } = {}
): Promise<{ bin: string; executable: string }> {
  if (!/^[a-z][a-z0-9-]*$/.test(name)) throw new Error("Invalid test runner name.");
  const bin = await createTempDir("gpt-trusted-runner-");
  const executable = join(bin, process.platform === "win32" ? name + ".exe" : name);
  if (process.platform === "win32" && !options.dryRunOnly) {
    throw new Error("Executable script fixtures are supported only on POSIX hosts.");
  }
  await writeFile(
    executable,
    process.platform === "win32"
      ? "MZ-native-runner-test-fixture\n"
      : "#!" + process.execPath + "\n" + body + "\n"
  );
  if (process.platform !== "win32") await chmod(executable, 0o755);
  return { bin, executable };
}

/** Keeps PATH fixture changes bounded to the async test operation. */
export async function withTrustedRunnerPath<T>(bin: string, operation: () => Promise<T>): Promise<T> {
  const previous = process.env.PATH;
  process.env.PATH = bin + (previous ? delimiter + previous : "");
  try {
    return await operation();
  } finally {
    if (previous === undefined) delete process.env.PATH;
    else process.env.PATH = previous;
  }
}

/** Coordination artifacts must not enter a source-bound validation snapshot. */
export async function createExternalValidationCoordination(): Promise<{
  startedPath: string;
  releasePath: string;
}> {
  const directory = await createTempDir("gpt-validation-coordination-");
  return {
    startedPath: join(directory, "started.txt"),
    releasePath: join(directory, "release.txt")
  };
}
