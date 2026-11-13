import {
  findContainingQuote,
  findPathEnd,
  type OutputLineBoundaryContext,
} from "./path-redaction-boundaries.js";

const FILE_URI_QUERY_PARAMETER_PATTERN = /([?&#;][^=&#;\s]+)=([^&#;]*)/g;

/** Redacts one file URI candidate and preserves a safe host and non-path suffix. */
export function redactFileUriAt(
  value: string,
  uriStart: number,
  context: OutputLineBoundaryContext,
): { prefix: string; copyThrough: number } | undefined {
  const schemeEnd = uriStart + "file:".length;
  const quote = findContainingQuote(value, uriStart);
  const scanEnd = findPathEnd(value, uriStart, quote, context);
  const pathStart = findFileUriPathStart(value, uriStart);

  if (pathStart !== undefined && pathStart < scanEnd) {
    const pathEnd = findFileUriSuffixStart(value, pathStart, scanEnd);
    if (hasSensitiveFileUriPathRoot(value.slice(uriStart, pathEnd))) {
      const uriSuffix = value.slice(pathEnd, scanEnd);
      const preservedUriSuffix = redactSensitivePathValues(uriSuffix);
      return {
        prefix: `${redactedFileUriPrefix(value.slice(uriStart, pathStart))}[REDACTED_PATH]${preservedUriSuffix}`,
        copyThrough: scanEnd,
      };
    }

    if (value.startsWith("//", schemeEnd)) {
      const authorityStart = schemeEnd + 2;
      const authority = value.slice(authorityStart, pathStart);
      return {
        prefix: `${value.slice(uriStart, authorityStart)}${stripFileUriAuthorityUserInfo(authority)}`,
        copyThrough: pathStart,
      };
    }

    return { prefix: value.slice(uriStart, pathStart), copyThrough: pathStart };
  }

  if (!value.startsWith("//", schemeEnd)) {
    return undefined;
  }

  const authorityStart = schemeEnd + 2;
  const authority = value.slice(authorityStart, scanEnd);
  return {
    prefix: `${value.slice(uriStart, authorityStart)}${stripFileUriAuthorityUserInfo(authority)}`,
    copyThrough: scanEnd,
  };
}

function stripFileUriUserInfo(fileUri: string): string {
  if (!fileUri.toLowerCase().startsWith("file://")) {
    return fileUri;
  }
  const authorityStart = "file://".length;
  const pathStart = fileUri.indexOf("/", authorityStart);
  if (pathStart <= authorityStart) {
    return fileUri;
  }
  const authority = fileUri.slice(authorityStart, pathStart);
  const safeAuthority = stripFileUriAuthorityUserInfo(authority);
  return safeAuthority === authority
    ? fileUri
    : `${fileUri.slice(0, authorityStart)}${safeAuthority}${fileUri.slice(pathStart)}`;
}

function stripFileUriAuthorityUserInfo(authority: string): string {
  const userInfoEnd = authority.lastIndexOf("@");
  return userInfoEnd < 0 ? authority : authority.slice(userInfoEnd + 1);
}

function redactedFileUriPrefix(fileUriPrefix: string): string {
  if (!fileUriPrefix.toLowerCase().startsWith("file://")) {
    return "file:///";
  }
  const authority = fileUriPrefix.slice("file://".length);
  const host = stripFileUriAuthorityUserInfo(authority);
  return host.length > 0 ? `file://${host}/` : "file:///";
}

/** Applies the same decoded-path policy to fields and URI query values. */
export function isSensitivePathValue(value: string): boolean {
  const decodedPath = decodePercentEncodedPathValue(value).replace(/\\/g, "/");
  if (/^[A-Za-z]:(?:\/|$)/.test(decodedPath)) {
    return true;
  }
  if (decodedPath.toLowerCase().startsWith("file:")) {
    return hasSensitiveFileUriPathRoot(decodedPath);
  }
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(decodedPath)) {
    return false;
  }
  return /(?:^|\/)(?:Volumes|Users|home|private|var|tmp)(?:\/|$|[?#])/i.test(
    decodedPath,
  );
}

/** Decodes percent-escaped bytes before checking path roots or URI authority. */
export function decodePercentEncodedPathValue(value: string): string {
  return value.replace(/%([0-9a-f]{2})/gi, (_match, byte: string) =>
    String.fromCharCode(Number.parseInt(byte, 16)),
  );
}

export function hasSensitiveFileUriPathRoot(fileUri: string): boolean {
  const safeFileUri = stripFileUriUserInfo(fileUri);
  let path: string;
  try {
    path = new URL(safeFileUri).pathname;
  } catch {
    const schemeEnd =
      safeFileUri.toLowerCase().indexOf("file:") + "file:".length;
    const remainder = safeFileUri.slice(schemeEnd);
    const pathStart = remainder.startsWith("//")
      ? remainder.indexOf("/", 2)
      : remainder.startsWith("/")
        ? 0
        : -1;
    if (pathStart < 0) {
      return false;
    }
    path = remainder.slice(pathStart);
  }

  const repeatedLeadingPathSlashes = path.startsWith("//");
  path = path.replace(/^\/+/, "/");
  const pathWithoutLeadingSlash = path.slice(1);
  const roots = pathWithoutLeadingSlash.split(/[/?#]/);
  const isSensitiveRoot = (root: string): boolean => {
    const partiallyDecodedRoot = root
      .replace(/%([0-9a-f]{2})/gi, (_match, byte: string) =>
        String.fromCharCode(Number.parseInt(byte, 16)),
      )
      .replace(/^\/+/, "");
    return (
      /^[A-Za-z]:(?:[\\/]|$)/i.test(partiallyDecodedRoot) ||
      /^(?:Volumes|Users|home|private|var|tmp)(?:\/|$|%)/i.test(
        partiallyDecodedRoot,
      )
    );
  };
  return (
    isSensitiveRoot(roots[0] ?? "") ||
    (repeatedLeadingPathSlashes &&
      (roots[0] ?? "").includes("@") &&
      isSensitiveRoot(roots[1] ?? ""))
  );
}

function redactSensitivePathValues(value: string): string {
  return value.replace(
    FILE_URI_QUERY_PARAMETER_PATTERN,
    (match, parameter: string, queryValue: string) =>
      isSensitivePathValue(queryValue)
        ? `${parameter}=[REDACTED_PATH]`
        : match,
  );
}

function findFileUriPathStart(
  value: string,
  uriStart: number,
): number | undefined {
  const schemeEnd = uriStart + "file:".length;
  if (value.startsWith("//", schemeEnd)) {
    const pathStart = value.indexOf("/", schemeEnd + 2);
    return pathStart < 0 ? undefined : pathStart;
  }
  return value[schemeEnd] === "/" ? schemeEnd : undefined;
}

function findFileUriSuffixStart(
  value: string,
  start: number,
  end: number,
): number {
  const suffix = /[?#]/.exec(value.slice(start, end));
  return suffix ? start + suffix.index : end;
}
