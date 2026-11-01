import process from "node:process";

const WINDOWS_SHORT_NAME_COMPONENT = /~[0-9]+(?:\.[^/\\]*)?$/u;

/**
 * Converts a path spelling to a conservative comparison form for the
 * restricted policy path. NFKD handles canonical and compatibility
 * normalization, combining marks are ignored, and full-fold expansions that
 * matter for ASCII names are applied before comparison. On Windows, trailing
 * periods and spaces are removed from each comparison component because
 * ordinary Win32 path handling ignores them. This comparison spelling is
 * never used for filesystem access.
 *
 * @param {string} path Filesystem or package path spelling.
 * @param {string} [platform=process.platform] Platform whose path spelling is compared.
 * @returns {string} Normalized slash-separated comparison spelling.
 */
export function foldPathForRestrictedComparison(path, platform = process.platform) {
  let normalized = path.replaceAll("\\", "/").normalize("NFKD");
  if (platform === "win32") {
    normalized = normalized.replace(/[. ]+(?=\/|$)/gu, "");
  }
  return normalized
    .toLowerCase()
    .replace(/\p{M}/gu, "")
    .replaceAll("ß", "ss")
    .replaceAll("ς", "σ");
}

/**
 * Identifies path syntax that can select a different name through Win32
 * canonicalization. A component ending in a period or space is ambiguous, and
 * a tilde-number component may be an 8.3 short-name alias. An initial drive
 * prefix such as `C:` is allowed, but a later colon can select an alternate
 * data stream. The checker rejects stream syntax, including `::$DATA`, before
 * callers inspect the target. It rejects short-name shapes without resolving
 * them, because that would require filesystem access to the target.
 *
 * @param {unknown} path Candidate path spelling.
 * @param {string} [platform=process.platform] Platform whose alias rules apply.
 * @returns {boolean} Whether the path uses unsupported Windows alias syntax.
 */
export function hasUnsupportedWindowsPathAlias(path, platform = process.platform) {
  if (typeof path !== "string" || platform !== "win32") return false;
  const normalizedPath = path.replaceAll("\\", "/");
  const drivePrefixLength = /^[A-Za-z]:/u.test(normalizedPath) ? 2 : 0;
  if (normalizedPath.slice(drivePrefixLength).includes(":")) return true;
  return normalizedPath.split("/").some((component) => {
    const normalized = component.normalize("NFKD");
    return /[. ]+$/u.test(normalized) || WINDOWS_SHORT_NAME_COMPONENT.test(normalized);
  });
}

/**
 * Detects the restricted policy path as a whole suffix, including nested
 * repository paths and Unicode normalization or case-fold aliases. Win32
 * trailing-period and trailing-space aliases are normalized for comparison;
 * paths using those forms or an 8.3 short-name shape are rejected separately
 * by hasUnsupportedWindowsPathAlias before filesystem access.
 *
 * @param {unknown} path Candidate path spelling.
 * @param {string} [platform=process.platform] Platform whose path rules apply.
 * @returns {boolean} Whether the path could identify the restricted path.
 */
export function hasRestrictedPolicyPathSuffix(path, platform = process.platform) {
  if (typeof path !== "string") return false;
  const normalized = foldPathForRestrictedComparison(path, platform).replace(/\/+$/, "");
  const restrictedSuffix = "security/oss-security-policy.json";
  return normalized === restrictedSuffix || normalized.endsWith(`/${restrictedSuffix}`);
}
