import { posix, win32 } from "node:path";

export type ConfigurationSourceIdentity =
  | Readonly<{ status: "none" }>
  | Readonly<{ status: "unavailable"; reason: "empty-path" | "parent-traversal" | "unsupported-path" }>
  | Readonly<{ status: "available"; platform: "posix" | "win32"; path: string }>;

/** Builds a comparison identity without changing the path passed to readFile. */
export function createConfigurationSourceIdentity(
  sourcePath: string | undefined,
  cwd: string,
  platform: NodeJS.Platform = process.platform
): ConfigurationSourceIdentity {
  if (sourcePath === undefined) return { status: "none" };
  if (sourcePath.length === 0) return { status: "unavailable", reason: "empty-path" };

  const pathApi = platform === "win32" ? win32 : posix;
  const platformName = platform === "win32" ? "win32" : "posix";
  if (!pathApi.isAbsolute(cwd)) return { status: "unavailable", reason: "unsupported-path" };
  if (sourcePath.split(/[\\/]/).includes("..")) {
    return { status: "unavailable", reason: "parent-traversal" };
  }
  const unsupportedWindowsPath = platform === "win32" && (
    /^(?:\\\\|\/\/)/.test(sourcePath) || /^[A-Za-z]:(?![\\/])/.test(sourcePath)
  );
  if (unsupportedWindowsPath || (platform !== "win32" && sourcePath.startsWith("//"))) {
    return { status: "unavailable", reason: "unsupported-path" };
  }

  return { status: "available", platform: platformName, path: pathApi.resolve(cwd, sourcePath) };
}

/** Compares normalized source paths exactly without filesystem canonicalization. */
export function configurationSourcesMatch(
  left: ConfigurationSourceIdentity,
  right: ConfigurationSourceIdentity
): boolean {
  return left.status === "available"
    && right.status === "available"
    && left.platform === right.platform
    && left.path === right.path;
}
