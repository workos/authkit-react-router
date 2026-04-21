import { unsealData } from 'iron-session';
import * as v from 'valibot';
import { getConfig } from './config.js';
import { State, StateSchema } from './interfaces.js';

export const PKCE_COOKIE_NAME = 'wos-auth-verifier';

// 10 minutes. PKCE cookies are single-use and short-lived, and the OAuth
// authorization request should complete long before this expires.
const PKCE_COOKIE_MAX_AGE = 600;

/**
 * 32-bit FNV-1a non-cryptographic hash. Inlined here rather than pulled in as
 * `@sindresorhus/fnv1a` because that package is ESM-only and this SDK ships
 * CommonJS. FNV-1a is a well-known, ~15-line algorithm — see RFC draft-eastlake-fnv.
 *
 * Note: this hashes UTF-16 code units (via `charCodeAt`) rather than UTF-8
 * bytes. Callers only feed this ASCII-safe iron-session seals (base64url), so
 * the distinction is irrelevant in practice — but don't reuse the function for
 * non-ASCII input without re-encoding to bytes first.
 */
function fnv1a32(input: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  // Force an unsigned 32-bit integer
  return hash >>> 0;
}

/**
 * Short, deterministic hex fingerprint of an arbitrary string.
 * Used to give each PKCE flow its own cookie name without depending on the
 * internal format of the sealed state value.
 */
function shortHash(input: string): string {
  return fnv1a32(input).toString(16).padStart(8, '0');
}

/**
 * Derive a flow-specific cookie name so concurrent auth flows don't overwrite
 * each other's PKCE cookies. Uses an FNV-1a hash of the full sealed state.
 */
export function getPKCECookieNameForState(state: string): string {
  return `${PKCE_COOKIE_NAME}-${shortHash(state)}`;
}

/**
 * Build a `Set-Cookie` header string for the PKCE verifier cookie.
 *
 * `SameSite=Strict` would be stripped on the cross-site redirect back from
 * WorkOS, so it is downgraded to `Lax`. `SameSite=None` is preserved for
 * iframe / cross-origin embed flows.
 */
export function getPKCECookieString(sealedState: string, expired = false): string {
  const name = getPKCECookieNameForState(sealedState);
  const value = expired ? '' : sealedState;

  const redirectUri = getConfig('redirectUri');
  let secure = true;
  try {
    secure = new URL(redirectUri).protocol === 'https:';
  } catch {
    secure = true;
  }

  const parts = [
    `${name}=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${expired ? 0 : PKCE_COOKIE_MAX_AGE}`,
  ];
  if (secure) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

/**
 * Read the PKCE cookie value for a given OAuth state from a Cookie header.
 * Returns `undefined` when the browser didn't send back the cookie (which
 * indicates either a brand-new user, a stolen authorization URL, or an
 * unrelated cross-site redirect — all of which are CSRF-failure conditions).
 */
export function readPKCECookie(cookieHeader: string | null, state: string): string | undefined {
  if (!cookieHeader) {
    return undefined;
  }
  const name = getPKCECookieNameForState(state);
  // Cookie header values are `name1=value1; name2=value2`. Split on `;` and
  // match the first exact-name entry — cookie values themselves never contain
  // `;` (they are percent-encoded) so this is safe.
  for (const raw of cookieHeader.split(';')) {
    const trimmed = raw.trim();
    if (trimmed.startsWith(`${name}=`)) {
      return trimmed.slice(name.length + 1);
    }
  }
  return undefined;
}

/**
 * Read and unseal the PKCE cookie, returning the code verifier, nonce, and
 * any caller-supplied custom state and return pathname.
 *
 * Throws if the cookie was tampered with, encrypted under a different
 * password, or is missing required fields. Runtime validation via valibot
 * is an acceptable tradeoff here — this is not a hot path, and
 * sealing/unsealing does not prove the unsealed payload has the expected
 * shape.
 */
export async function getStateFromPKCECookieValue(cookieValue: string): Promise<State> {
  const unsealed = await unsealData(cookieValue, {
    password: getConfig('cookiePassword'),
  });

  return v.parse(StateSchema, unsealed);
}
