const OUTPUT_TOKEN_SEPARATOR_PATTERN = /[ \t]+|[,;][ \t]+/g;
/**
 * Only bounded scalar values and URI values can end a path scan. Free-form
 * values can be path components, so treating every key-value token as metadata
 * could leave part of a sensitive path visible.
 */
const SAFE_OUTPUT_SCALAR_VALUE_PATTERN =
  /^(?:true|false|ok|failed|passed|skipped|\d+(?:\.\d+)*)$/i;
const SAFE_OUTPUT_URI_VALUE_PATTERN =
  /^(?!file:)[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s,;]+$/i;
const OUTPUT_FIELD_NAME_PATTERN = /^[a-z_][a-z0-9_.-]*$/;
const OUTPUT_FILE_DIAGNOSTIC_SUFFIX_PATTERN =
  /:[ \t]+[A-Za-z][A-Za-z0-9 ,.'()_-]*$/;
const OUTPUT_DETAIL_FIELD_SUFFIX_PATTERN =
  /[,;][ \t]+detail=(?:permission denied|no such file or directory)$/i;
const PATH_SHAPED_FIELD_PREFIX_PATTERN =
  /^[A-Za-z_][A-Za-z0-9_.-]*=(?:[A-Za-z]:(?:\\|\/)|\/(?:Volumes|Users|home|private|var|tmp)(?:\/|$|[?#])|file:\/\/[^/\s"'`\\]*\/)/i;
const QUOTED_SCALAR_FIELD_VALUE_PATTERN =
  /(["'`])(true|false|ok|failed|passed|skipped|\d+(?:\.\d+)*)\1/gi;

type OutputToken = {
  value: string;
  separator: string;
  separatorStart: number;
  start: number;
};

export type OutputLineBoundaryContext = {
  lineEnd: number;
  diagnosticSuffixStart?: number;
  detailSuffixStart?: number;
  fieldBoundary?: number;
  fieldBoundaryBeforeDetail?: number;
  pathFieldBoundaries: number[];
};

/** Builds one boundary index per line so path candidates share the same scan. */
export function createOutputLineBoundaryContexts(
  value: string,
): OutputLineBoundaryContext[] {
  const contexts: OutputLineBoundaryContext[] = [];
  let lineStart = 0;
  while (lineStart < value.length) {
    let lineEnd = lineStart;
    while (
      lineEnd < value.length &&
      value[lineEnd] !== "\r" &&
      value[lineEnd] !== "\n"
    ) {
      lineEnd += 1;
    }
    contexts.push(createOutputLineBoundaryContext(value, lineStart, lineEnd));
    if (lineEnd === value.length) {
      break;
    }
    lineStart += value.startsWith("\r\n", lineEnd) ? 2 : 1;
  }
  return contexts;
}

/** Finds whether a quoted field encloses a filesystem path. */
export function findContainingQuote(
  value: string,
  start: number,
): string | undefined {
  const previous = value[start - 1];
  return previous && isPathQuote(previous) ? previous : undefined;
}

/** Finds a path end while retaining recognized output fields and file diagnostics. */
export function findPathEnd(
  value: string,
  start: number,
  quote: string | undefined,
  context: OutputLineBoundaryContext,
): number {
  if (quote !== undefined) {
    return findClosingPathQuote(value, start, context.lineEnd, quote) ?? context.lineEnd;
  }

  if (
    context.diagnosticSuffixStart !== undefined &&
    context.diagnosticSuffixStart >= start
  ) {
    return context.diagnosticSuffixStart;
  }

  const boundary = findOutputFieldBoundary(context, start);
  return boundary === undefined ? context.lineEnd : boundary;
}

function findClosingPathQuote(
  value: string,
  start: number,
  lineEnd: number,
  quote: string,
): number | undefined {
  let index = start;
  while (index < lineEnd) {
    if (quote === "'" && value.startsWith("'\\''", index)) {
      index += 4;
      continue;
    }
    if (quote !== "'" && value[index] === "\\") {
      index += 2;
      continue;
    }
    if (value[index] === quote) {
      return index;
    }
    index += 1;
  }
  return undefined;
}

function createOutputLineBoundaryContext(
  value: string,
  lineStart: number,
  lineEnd: number,
): OutputLineBoundaryContext {
  const line = value.slice(lineStart, lineEnd);
  const tokens = tokenizeOutputLine(line);
  const diagnosticSuffix = OUTPUT_FILE_DIAGNOSTIC_SUFFIX_PATTERN.exec(line);
  const detailSuffix = OUTPUT_DETAIL_FIELD_SUFFIX_PATTERN.exec(line);
  const detailSuffixStart = detailSuffix
    ? lineStart + detailSuffix.index
    : undefined;
  const detailStart = detailSuffix
    ? lineStart +
      detailSuffix.index +
      detailSuffix[0].toLowerCase().indexOf("detail=")
    : undefined;
  const detailIndex = detailStart === undefined
    ? -1
    : tokens.findIndex((token) => lineStart + token.start === detailStart);
  const pathFieldBoundaries = tokens
    .filter(
      (token) =>
        token.separatorStart >= 0 &&
        PATH_SHAPED_FIELD_PREFIX_PATTERN.test(token.value),
    )
    .map((token) => lineStart + token.separatorStart);

  return {
    lineEnd,
    ...(diagnosticSuffix
      ? { diagnosticSuffixStart: lineStart + diagnosticSuffix.index }
      : {}),
    ...(detailSuffixStart === undefined ? {} : { detailSuffixStart }),
    fieldBoundary: findRecognizedOutputFieldBoundary(
      tokens,
      tokens.length - 1,
      lineStart,
    ),
    fieldBoundaryBeforeDetail: findRecognizedOutputFieldBoundary(
      tokens,
      detailIndex >= 0 ? detailIndex - 1 : tokens.length - 1,
      lineStart,
    ),
    pathFieldBoundaries,
  };
}

function findRecognizedOutputFieldBoundary(
  tokens: OutputToken[],
  endIndex: number,
  lineStart: number,
): number | undefined {
  let startIndex = endIndex;
  if (endIndex < 0 || !isRecognizedOutputField(tokens[endIndex]!.value)) {
    return undefined;
  }

  while (
    startIndex > 0 &&
    isRecognizedOutputField(tokens[startIndex - 1]!.value)
  ) {
    startIndex -= 1;
  }

  const separatorStart = tokens[startIndex]!.separatorStart;
  return separatorStart >= 0 ? lineStart + separatorStart : undefined;
}

function findOutputFieldBoundary(
  context: OutputLineBoundaryContext,
  start: number,
): number | undefined {
  let earliestBoundary =
    context.detailSuffixStart !== undefined &&
    context.detailSuffixStart >= start
      ? context.fieldBoundaryBeforeDetail
      : context.fieldBoundary;

  const pathFieldBoundary = firstBoundaryAtOrAfter(
    context.pathFieldBoundaries,
    start,
  );
  if (
    pathFieldBoundary !== undefined &&
    (earliestBoundary === undefined || pathFieldBoundary < earliestBoundary)
  ) {
    earliestBoundary = pathFieldBoundary;
  }
  return earliestBoundary !== undefined && earliestBoundary >= start
    ? earliestBoundary
    : undefined;
}

function firstBoundaryAtOrAfter(
  boundaries: number[],
  target: number,
): number | undefined {
  let lower = 0;
  let upper = boundaries.length;
  while (lower < upper) {
    const middle = Math.floor((lower + upper) / 2);
    if (boundaries[middle]! < target) {
      lower = middle + 1;
    } else {
      upper = middle;
    }
  }
  return boundaries[lower];
}

function tokenizeOutputLine(line: string): OutputToken[] {
  const tokens: OutputToken[] = [];
  let tokenStart = 0;
  let separatorStart = -1;
  let separator = "";

  for (const match of line.matchAll(OUTPUT_TOKEN_SEPARATOR_PATTERN)) {
    const matchStart = match.index!;
    if (matchStart > tokenStart) {
      tokens.push({
        value: line.slice(tokenStart, matchStart),
        separator,
        separatorStart,
        start: tokenStart,
      });
    }
    separatorStart = matchStart;
    separator = match[0];
    tokenStart = matchStart + match[0].length;
  }

  if (tokenStart < line.length) {
    tokens.push({
      value: line.slice(tokenStart),
      separator,
      separatorStart,
      start: tokenStart,
    });
  }
  return tokens;
}

function isRecognizedOutputField(value: string): boolean {
  const separator = value.indexOf("=");
  if (
    separator < 1 ||
    !OUTPUT_FIELD_NAME_PATTERN.test(value.slice(0, separator))
  ) {
    return false;
  }
  const fieldValue = value
    .slice(separator + 1)
    .replace(QUOTED_SCALAR_FIELD_VALUE_PATTERN, "$2");
  const quote = fieldValue[0];
  const unquotedValue =
    quote && isPathQuote(quote) && fieldValue.at(-1) === quote
      ? fieldValue.slice(1, -1)
      : fieldValue;
  return (
    SAFE_OUTPUT_SCALAR_VALUE_PATTERN.test(fieldValue) ||
    SAFE_OUTPUT_URI_VALUE_PATTERN.test(unquotedValue)
  );
}

function isPathQuote(value: string | undefined): value is string {
  return value === "'" || value === '"' || value === "\x60";
}
