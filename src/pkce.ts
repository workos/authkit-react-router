import { createHash } from 'node:crypto';
import { unsealData } from 'iron-session';
import * as v from 'valibot';
import { getConfig } from './config.js';
import { State, StateSchema } from './interfaces.js';

export const PKCE_COOKIE_NAME = 'wos-auth-verifier';

// 10 minutes. PKCE cookies are single-use and short-lived, and the OAuth
// authorization request should complete long before this expires.
const PKCE_COOKIE_MAX_AGE = 600;

/**
 * Short, deterministic hex fingerprint of an arbitrary string.
 * Used to give each PKCE flow its own cookie name without depending on the
 * internal format of the sealed state value. Collision resistance is not
 * security-critical here (cookie values are still integrity-checked via
 * iron-session); the fingerprint only needs to spread concurrent flows
 * across distinct cookie names.
 */
function shortHash(input: string): string {
  return createHash('sha256').update(input).digest('hex').slice(0, 8);
}

/**
 * Derive a flow-specific cookie name so concurrent auth flows don't overwrite
 * each other's PKCE cookies.
 */
export function getPKCECookieNameForState(state: string): string {
  return `${PKCE_COOKIE_NAME}-${shortHash(state)}`;
}

/**
 * Decide whether the PKCE cookie should carry the `Secure` attribute.
 *
 * Preference order:
 *   1. An explicit `secure` override from the caller.
 *   2. `X-Forwarded-Proto` from the incoming request — the canonical signal
 *      when TLS is terminated upstream (load balancer, reverse proxy) and
 *      the app receives a plain http:// request for an https:// site.
 *   3. The live request protocol — the cookie is set on *this* response,
 *      and the browser will drop `Secure` cookies on http:// pages even if
 *      the configured redirect URI is https://.
 *   4. The per-call `redirectUri` override, when provided, so that a caller
 *      passing `getAuthorizationUrl({ redirectUri })` without a request can
 *      still control the cookie's Secure attribute for that specific flow.
 *   5. Fall back to the configured redirectUri's protocol.
 *
 * A misconfigured / unparseable redirectUri is not fatal; we default to
 * `Secure=true` and warn so the misconfiguration is visible.
 */
function resolveSecure({
  secure,
  request,
  redirectUri,
}: { secure?: boolean; request?: Request; redirectUri?: string } = {}): boolean {
  if (typeof secure === 'boolean') return secure;

  if (request) {
    const forwardedProto = request.headers.get('x-forwarded-proto');
    if (forwardedProto) {
      // X-Forwarded-Proto may be a comma-separated list when multiple proxies
      // chain; the leftmost value is the client-facing protocol.
      return forwardedProto.split(',')[0].trim().toLowerCase() === 'https';
    }
    try {
      return new URL(request.url).protocol === 'https:';
    } catch {
      // fall through to redirectUri-based detection
    }
  }

  const uri = redirectUri ?? getConfig('redirectUri');
  try {
    return new URL(uri).protocol === 'https:';
  } catch {
    console.warn(
      `[AuthKit] Could not parse redirectUri (${JSON.stringify(uri)}); defaulting PKCE cookie to Secure=true.`,
    );
    return true;
  }
}

/**
 * Build a `Set-Cookie` header string for the PKCE verifier cookie.
 *
 * `SameSite=Strict` would be stripped on the cross-site redirect back from
 * WorkOS, so it is set to `Lax` — the minimum that survives a top-level
 * cross-site navigation back to our origin.
 *
 * Callers that have the incoming `Request` in hand should pass it via
 * `options.request` so the `Secure` attribute reflects the actual protocol
 * in use rather than the configured redirect URI's — otherwise running
 * `npm run dev` on http:// while `WORKOS_REDIRECT_URI=https://…` would mint
 * a `Secure` cookie the browser silently drops.
 */
export function getPKCECookieString(
  sealedState: string,
  options: { expired?: boolean; request?: Request; secure?: boolean; redirectUri?: string } = {},
): string {
  const { expired = false, request, secure, redirectUri } = options;
  const name = getPKCECookieNameForState(sealedState);
  const value = expired ? '' : sealedState;

  const parts = [
    `${name}=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${expired ? 0 : PKCE_COOKIE_MAX_AGE}`,
  ];
  if (resolveSecure({ secure, request, redirectUri })) {
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
