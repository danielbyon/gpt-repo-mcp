import { redactSecretValues } from "../policies/secret-patterns.js";
import {
  createOutputLineBoundaryContexts,
  findContainingQuote,
  findPathEnd,
} from "./path-redaction-boundaries.js";
import {
  decodePercentEncodedPathValue,
  isSensitivePathValue,
  redactFileUriAt,
} from "./file-uri-redaction.js";

const REDACTION_CANDIDATE_START_PATTERN =
  /(?<fileUriPrefix>^|[^A-Za-z0-9+._-])(?<fileUri>[Ff][Ii][Ll][Ee]:)|(?<volume>\/Volumes(?:\/|(?=$|[ \t,;:'"`])))|(?<posixPrefix>^|[^A-Za-z0-9._+/:?-]|-[A-Za-z]|(?:^|[ \t])error:)(?<posixPath>\/(?:Users|home|private|var|tmp)(?:\/|(?=$|[ \t,;:'"`])))|(?<windows>[A-Za-z]:(?:\\|\/))/g;
const ENCODED_QUERY_PARAMETER_PATTERN =
  /([?&#][^=&#;\s"'`]+)=([^&#;\s"'`]*)/g;

const ENCODED_FIELD_PARAMETER_PATTERN =
  /(^|[\r\n \t,;])([A-Za-z_][A-Za-z0-9_.-]*=)(["'\x60]?)([^ \t,;?&"'\x60]+)\3/gi;
const PERCENT_ENCODED_BYTE_PATTERN = /%[0-9a-f]{2}/i;
const TRAVERSAL_PATH_BOUNDARY_CHARACTER_PATTERN =
  /[A-Za-z0-9._+/:?-]/;

/** Redacts sensitive filesystem paths and file-URI user-info from diagnostic text. */
export function redactSensitiveText(value: string): string {
  return redactOutputPaths(
    redactEncodedFieldPathValues(
      redactEncodedQueryPathValues(redactSecretValues(value)),
    ),
  );
}

function redactEncodedQueryPathValues(value: string): string {
  return value.replace(
    ENCODED_QUERY_PARAMETER_PATTERN,
    (match, parameter: string, queryValue: string) => {
      const redactedValue = redactEncodedPathValue(queryValue);
      return redactedValue === undefined
        ? match
        : `${parameter}=${redactedValue}`;
    },
  );
}

function redactEncodedFieldPathValues(value: string): string {
  return value.replace(
    ENCODED_FIELD_PARAMETER_PATTERN,
    (
      match,
      prefix: string,
      parameter: string,
      quote: string,
      fieldValue: string,
    ) => {
      if (/^file:/i.test(fieldValue)) {
        return match;
      }
      const redactedValue = redactEncodedPathValue(fieldValue);
      return redactedValue === undefined
        ? match
        : prefix + parameter + quote + redactedValue + quote;
    },
  );
}

function redactEncodedPathValue(value: string): string | undefined {
  if (!PERCENT_ENCODED_BYTE_PATTERN.test(value)) {
    return undefined;
  }
  const decodedValue = decodePercentEncodedPathValue(value);
  if (decodedValue.toLowerCase().startsWith("file:")) {
    const sanitizedUri = redactSensitiveText(decodedValue);
    return sanitizedUri === decodedValue ? undefined : sanitizedUri;
  }
  return isSensitivePathValue(value) ? "[REDACTED_PATH]" : undefined;
}

/** Redacts file URIs and filesystem paths in source order while retaining output labels. */
function redactOutputPaths(value: string): string {
  const output: string[] = [];
  let copiedThrough = 0;
  const lineContexts = createOutputLineBoundaryContexts(value);
  const nonFileUriRanges = findNonFileUriPathRanges(value);
  let traversalPathStart = -1;
  let boundaryScanThrough = 0;
  let lineContextIndex = 0;

  for (const match of value.matchAll(REDACTION_CANDIDATE_START_PATTERN)) {
    while (boundaryScanThrough < match.index) {
      const character = value[boundaryScanThrough]!;
      if (character === "\r" || character === "\n") {
        traversalPathStart = -1;
      } else if (
        character === "/" &&
        (boundaryScanThrough === 0 ||
          !TRAVERSAL_PATH_BOUNDARY_CHARACTER_PATTERN.test(
            value[boundaryScanThrough - 1]!,
          ))
      ) {
        traversalPathStart = boundaryScanThrough;
      }
      boundaryScanThrough += 1;
    }

    const groups = match.groups;
    if (match.index < copiedThrough) {
      continue;
    }
    while (
      lineContextIndex + 1 < lineContexts.length &&
      lineContexts[lineContextIndex]!.lineEnd < match.index
    ) {
      lineContextIndex += 1;
    }
    const lineContext = lineContexts[lineContextIndex];
    if (!lineContext) {
      continue;
    }

    if (groups?.fileUri) {
      const uriStart = match.index + (groups.fileUriPrefix?.length ?? 0);
      const fileUri = redactFileUriAt(value, uriStart, lineContext);
      if (fileUri) {
        output.push(value.slice(copiedThrough, uriStart), fileUri.prefix);
        copiedThrough = fileUri.copyThrough;
      }
      continue;
    }

    const kind = groups?.volume
      ? "volume"
      : groups?.posixPath
        ? "posix"
        : "windows";
    let start = match.index;
    if (kind === "posix") {
      start += groups?.posixPrefix?.length ?? 0;
    }

    if (kind === "volume") {
      if (hasNonFileUriSchemePrefix(nonFileUriRanges, start)) {
        continue;
      }
      const hasLocalTraversalPath =
        traversalPathStart >= copiedThrough &&
        !/[\s,;]/.test(value.slice(traversalPathStart, start));
      if (
        value.startsWith("/..", start - 3) &&
        hasLocalTraversalPath
      ) {
        start = traversalPathStart;
      }
      const previous = value[start - 1];
      const shortOptionPrefix =
        value[start - 2] === "-" &&
        previous !== undefined &&
        /[A-Za-z]/.test(previous);
      if (
        previous &&
        /[A-Za-z0-9._+/-]/.test(previous) &&
        !shortOptionPrefix
      ) {
        continue;
      }
    }

    if (kind === "windows") {
      const slashPrefixedDrive =
        value[start - 1] === "/" &&
        (value[start - 2] === undefined ||
          !/[A-Za-z0-9/]/.test(value[start - 2]) ||
          value[start - 3] === "-");
      if (slashPrefixedDrive) {
        start -= 1;
      }
      const optionPathPrefix =
        value[start - 1] === "-" &&
        value[start + 1] === ":" &&
        /[\\/]/.test(value[start + 2] ?? "");
      if (optionPathPrefix) {
        start += 2;
      }
      const previous = value[start - 1];
      const shortOptionPrefix =
        value[start - 2] === "-" &&
        previous !== undefined &&
        /[A-Za-z]/.test(previous);
      if (
        hasNonFileUriSchemePrefix(nonFileUriRanges, start) ||
        (previous && /[A-Za-z0-9/]/.test(previous) && !shortOptionPrefix)
      ) {
        continue;
      }
    }

    const quote = findContainingQuote(value, start);
    const scanEnd = findPathEnd(value, start, quote, lineContext);
    if (scanEnd <= start) {
      continue;
    }

    output.push(value.slice(copiedThrough, start), "[REDACTED_PATH]");
    copiedThrough = scanEnd;
  }

  output.push(value.slice(copiedThrough));
  return output.join("");
}

type NonFileUriPathRange = {
  start: number;
  end: number;
};

function findNonFileUriPathRanges(value: string): NonFileUriPathRange[] {
  const ranges: NonFileUriPathRange[] = [];
  let index = 0;
  while (index < value.length) {
    const character = value[index]!;
    if (
      !/[A-Za-z]/.test(character) ||
      (index > 0 && /[A-Za-z0-9+.-]/.test(value[index - 1]!))
    ) {
      index += 1;
      continue;
    }

    let colon = index + 1;
    while (
      colon < value.length &&
      /[A-Za-z0-9+.-]/.test(value[colon]!)
    ) {
      colon += 1;
    }
    if (value[colon] !== ":" || value.slice(colon + 1, colon + 3) !== "//") {
      index += 1;
      continue;
    }

    const scheme = value.slice(index, colon).toLowerCase();
    if (scheme.length <= 1 || ["error", "file"].includes(scheme)) {
      index = colon + 1;
      continue;
    }

    let uriEnd = colon + 3;
    while (uriEnd < value.length && !isUriPathTerminator(value[uriEnd])) {
      uriEnd += 1;
    }
    const queryOrFragment = findQueryOrFragment(value, colon + 3, uriEnd);
    ranges.push({ start: index, end: queryOrFragment });
    index = queryOrFragment;
  }
  return ranges;
}

function isUriPathTerminator(character: string | undefined): boolean {
  return character === undefined || /[\s"'\x60\\?#]/.test(character);
}

function findQueryOrFragment(
  value: string,
  start: number,
  end: number,
): number {
  for (let index = start; index < end; index += 1) {
    if (value[index] === "?" || value[index] === "#") {
      return index;
    }
  }
  return end;
}

function hasNonFileUriSchemePrefix(
  ranges: NonFileUriPathRange[],
  start: number,
): boolean {
  let lower = 0;
  let upper = ranges.length;
  while (lower < upper) {
    const middle = Math.floor((lower + upper) / 2);
    if (ranges[middle]!.end <= start) {
      lower = middle + 1;
    } else {
      upper = middle;
    }
  }
  const range = ranges[lower];
  return range !== undefined && range.start < start && start < range.end;
}
