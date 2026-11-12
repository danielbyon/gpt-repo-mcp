import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { redactSecretValues } from "../policies/secret-patterns.js";
import { RepoReaderError, toRepoReaderError } from "./errors.js";

export type ToolContent = { type: "text"; text: string };

export type SuccessEnvelope<T> = {
  structuredContent: T;
  content: ToolContent[];
  _meta?: Record<string, unknown>;
  isError?: undefined;
};

export type ErrorEnvelope = {
  isError: true;
  structuredContent: {
    ok: false;
    error: {
      code: string;
      message: string;
      retryable: boolean;
      diagnostics?: Record<string, unknown>;
    };
  };
  content: ToolContent[];
};

// Unquoted paths stop at recognizable fields; quote paths with field-like components.
const EXTERNAL_VOLUME_PATH_START_PATTERN = /\/Volumes\//g;
const OUTPUT_FIELD_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]*=/;
const FILE_VOLUME_URI_PREFIX_PATTERN = /(?:^|[^A-Za-z0-9._+\/\-])file:\/\/[^\/\s"'`]*$/i;

export function redactSensitiveText(value: string): string {
  return redactExternalVolumePaths(redactSecretValues(value))
    .replace(/(?:\/Users|\/home|\/private|\/var|\/tmp)\/[^\s"'`]+/g, "[REDACTED_PATH]")
    .replace(/[A-Za-z]:\\[^\s"'`]+/g, "[REDACTED_PATH]");
}

function redactExternalVolumePaths(value: string): string {
  let output = "";
  let copiedThrough = 0;

  for (const match of value.matchAll(EXTERNAL_VOLUME_PATH_START_PATTERN)) {
    const start = match.index;
    if (start < copiedThrough || !hasExternalVolumePathBoundary(value, start)) {
      continue;
    }

    const quote = findContainingQuote(value, start);
    const end = quote
      ? findQuotedVolumePathEnd(value, start, quote)
      : findUnquotedVolumePathEnd(value, start);
    if (end <= start) {
      continue;
    }

    output += `${value.slice(copiedThrough, start)}[REDACTED_PATH]`;
    copiedThrough = end;
  }

  return output + value.slice(copiedThrough);
}

function hasExternalVolumePathBoundary(value: string, start: number): boolean {
  if (start === 0) {
    return true;
  }

  const previous = value[start - 1];
  if (!previous || isPathQuote(previous)) {
    return true;
  }
  if (/[A-Za-z0-9._~+\/]/.test(previous)) {
    return FILE_VOLUME_URI_PREFIX_PATTERN.test(value.slice(0, start));
  }
  return true;
}

function findContainingQuote(value: string, start: number): string | undefined {
  const previous = value[start - 1];
  if (previous && isPathQuote(previous)) {
    return previous;
  }

  const schemeStart = value.toLowerCase().lastIndexOf("file://", start);
  const schemeQuote = schemeStart > 0 ? value[schemeStart - 1] : undefined;
  return schemeQuote && isPathQuote(schemeQuote) ? schemeQuote : undefined;
}

function findQuotedVolumePathEnd(value: string, start: number, quote: string): number {
  let index = start;
  while (index < value.length) {
    const current = value[index];
    if (current === "\r" || current === "\n") {
      return index;
    }
    if (quote === "'" && value.startsWith("'\\''", index)) {
      index += 4;
      continue;
    }
    if (quote !== "'" && current === "\\") {
      index += 2;
      continue;
    }
    if (current === quote) {
      return index;
    }
    index += 1;
  }
  return value.length;
}

function findUnquotedVolumePathEnd(value: string, start: number): number {
  let index = start;
  while (index < value.length) {
    const current = value[index];
    if (current === "\r" || current === "\n") {
      return index;
    }
    if (isPathQuote(current)) {
      const quoteEnd = findQuotedVolumePathEnd(value, index + 1, current);
      if (quoteEnd >= value.length) {
        return quoteEnd;
      }
      index = quoteEnd + 1;
      continue;
    }
    if (isOutputFieldBoundary(value, index)) {
      return index;
    }
    index += 1;
  }
  return value.length;
}

function isOutputFieldBoundary(value: string, index: number): boolean {
  const current = value[index];
  let fieldStart = index;
  if (current === "," || current === ";" || current === ":") {
    if (!isWhitespace(value[index + 1])) {
      return false;
    }
    fieldStart += 1;
  } else if (!isWhitespace(current)) {
    return false;
  }

  while (isWhitespace(value[fieldStart])) {
    fieldStart += 1;
  }

  const field = OUTPUT_FIELD_NAME_PATTERN.exec(value.slice(fieldStart));
  if (!field) {
    return false;
  }
  return hasRecognizableOutputFieldValue(value.slice(fieldStart + field[0].length));
}

function hasRecognizableOutputFieldValue(value: string): boolean {
  const first = value[0];
  if (!first || isPathQuote(first)) {
    return true;
  }
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//i.test(value)) {
    return true;
  }
  if (/^\/[A-Za-z0-9_.-]+\//.test(value) || /^\.\.?\//.test(value)) {
    return true;
  }

  const token = value.split(/[\s,;:]/, 1)[0] ?? "";
  return token.length > 0 && !token.includes("/");
}

function isPathQuote(value: string | undefined): value is string {
  return value === "'" || value === "\"" || value === "\x60";
}

function isWhitespace(value: string | undefined): boolean {
  return value !== undefined && /\s/.test(value);
}

export function createSuccessEnvelope<T>(
  structuredContent: T,
  summary: string,
  meta?: Record<string, unknown>
): SuccessEnvelope<T> & CallToolResult {
  return {
    structuredContent,
    content: [{ type: "text", text: redactSensitiveText(summary) }],
    ...(meta ? { _meta: meta } : {})
  } as SuccessEnvelope<T> & CallToolResult;
}

export function createErrorEnvelope(error: RepoReaderError | Error | {
  code: string;
  message: string;
  retryable?: boolean;
  diagnostics?: Record<string, unknown>;
}): ErrorEnvelope & CallToolResult {
  const normalized = error instanceof RepoReaderError || error instanceof Error
    ? toRepoReaderError(error)
    : new RepoReaderError("INTERNAL_ERROR", error.message, {
        retryable: error.retryable,
        diagnostics: error.diagnostics
      });

  const message = redactSensitiveText(normalized.message);
  const diagnostics = sanitizeDiagnostics(normalized.diagnostics);
  return {
    isError: true,
    structuredContent: {
      ok: false,
      error: {
        code: normalized.code,
        message,
        retryable: normalized.retryable,
        ...(diagnostics
          ? { diagnostics }
          : {})
      }
    },
    content: [{ type: "text", text: `${normalized.code}: ${message}` }]
  } as ErrorEnvelope & CallToolResult;
}

function sanitizeDiagnostics(diagnostics: Record<string, unknown>): Record<string, unknown> | undefined {
  const safe: Record<string, unknown> = {};

  copyPathArrayDiagnostic(diagnostics, safe, "applied_paths");
  copyPathArrayDiagnostic(diagnostics, safe, "rolled_back_paths");
  copyPathArrayDiagnostic(diagnostics, safe, "actual_paths");
  copyPathArrayDiagnostic(diagnostics, safe, "expected_paths");
  copyPathDiagnostic(diagnostics, safe, "failed_path");
  copyShaDiagnostic(diagnostics, safe, "head_sha");
  copyShaDiagnostic(diagnostics, safe, "expected_head_sha");
  copyShaDiagnostic(diagnostics, safe, "current_sha256");
  copyShaDiagnostic(diagnostics, safe, "expected_old_sha256");
  copySafeTextDiagnostic(diagnostics, safe, "recovery_hint");

  return Object.keys(safe).length > 0 ? safe : undefined;
}

function copyPathArrayDiagnostic(source: Record<string, unknown>, target: Record<string, unknown>, key: string): void {
  const value = source[key];
  if (!Array.isArray(value)) {
    return;
  }
  const paths = value.filter(isSafeRepoPath);
  if (paths.length > 0) {
    target[key] = paths;
  }
}

function copyPathDiagnostic(source: Record<string, unknown>, target: Record<string, unknown>, key: string): void {
  const value = source[key];
  if (isSafeRepoPath(value)) {
    target[key] = value;
  }
}

function copyShaDiagnostic(source: Record<string, unknown>, target: Record<string, unknown>, key: string): void {
  const value = source[key];
  if (typeof value === "string" && /^[0-9a-f]{7,64}$/i.test(value)) {
    target[key] = value;
  }
}

function copySafeTextDiagnostic(source: Record<string, unknown>, target: Record<string, unknown>, key: string): void {
  const value = source[key];
  if (typeof value !== "string" || value.length > 300) {
    return;
  }
  const redacted = redactSensitiveText(value);
  if (redacted === value) {
    target[key] = value;
  }
}

function isSafeRepoPath(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) {
    return false;
  }
  if (value.startsWith("/") || /^[A-Za-z]:[\\/]/.test(value) || value.includes("\\")) {
    return false;
  }
  return value.split("/").every((part) => part.length > 0 && part !== "." && part !== "..");
}
