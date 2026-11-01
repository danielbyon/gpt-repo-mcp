/** Returns a conservative Unicode and platform-normalized spelling for path checks. */
export function foldPathForRestrictedComparison(path: string, platform?: string): string;

/** Detects Win32 trailing-dot/space and 8.3 short-name path spellings. */
export function hasUnsupportedWindowsPathAlias(path: unknown, platform?: string): boolean;

/** Detects exact and Unicode/platform-normalized suffix aliases of the restricted path. */
export function hasRestrictedPolicyPathSuffix(path: unknown, platform?: string): boolean;
