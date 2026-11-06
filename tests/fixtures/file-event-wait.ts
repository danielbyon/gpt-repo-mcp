import { watch } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname } from "node:path";

const DEFAULT_TIMEOUT_MS = 2_000;

/** Waits for a file condition with filesystem events and a deadline for failures. */
export function waitForFile(path: string, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<string> {
  return waitForFileCondition(path, () => true, timeoutMs, `Timed out waiting for ${path}.`);
}

export async function waitForFileLineCount(path: string, count: number, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<string[]> {
  const content = await waitForFileCondition(
    path,
    (value) => fileLines(value).length >= count,
    timeoutMs,
    `Timed out waiting for ${count} lines in ${path}.`
  );
  return fileLines(content);
}

function waitForFileCondition(
  path: string,
  isReady: (content: string) => boolean,
  timeoutMs: number,
  timeoutMessage: string
): Promise<string> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const watcher = watch(dirname(path), { persistent: false }, () => {
      void checkFile();
    });
    const timeout = setTimeout(() => finish(new Error(timeoutMessage)), timeoutMs);

    const finish = (error?: unknown, content?: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      watcher.close();
      if (error) reject(error);
      else resolve(content ?? "");
    };

    watcher.once("error", (error) => finish(error));

    const checkFile = async (): Promise<void> => {
      try {
        const content = await readFile(path, "utf8");
        if (isReady(content)) finish(undefined, content);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") finish(error);
      }
    };

    void checkFile();
  });
}

function fileLines(content: string): string[] {
  return content.split(/\r?\n/).filter((line) => line.length > 0);
}
