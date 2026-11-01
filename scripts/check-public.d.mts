export interface PublicScanOptions {
  root?: string;
  platform?: string;
  [option: string]: unknown;
}

export type PublicScanOutcome =
  | { status: "excluded" }
  | { status: "unsafe"; reason: string }
  | { status: "scanned"; text: string };

/** Reads a source manifest and returns its repository-relative file paths. */
export function manifestFiles(
  manifestPath: string,
  options?: PublicScanOptions
): string[];

/** Checks a source path and returns its scan outcome without following symlinks. */
export function readScannableText(
  file: string,
  options?: PublicScanOptions
): PublicScanOutcome;
