/**
 * Parse an HTTP Cookie header value into a map of cookie name → value.
 *
 * Behavior:
 * - Whitespace around name/value is trimmed.
 * - Duplicate names: last occurrence wins (browsers send duplicates most-recent-last).
 * - Empty pairs, pairs without '=', and pairs with empty names: silently skipped.
 * - Values are returned as-is (no decodeURIComponent — cookie values in AuthKit are
 *   sealed strings that must not be decoded).
 * - Returns {} for null, undefined, empty string.
 */
export function parseCookieHeader(header: string | null | undefined): Record<string, string> {
  if (!header) return {};
  const out: Record<string, string> = {};
  for (const pair of header.split(';')) {
    const trimmed = pair.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const name = trimmed.slice(0, eq).trim();
    if (!name) continue;
    const value = trimmed.slice(eq + 1).trim();
    out[name] = value;
  }
  return out;
}
