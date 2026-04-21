import { getConfig } from './config.js';
import type { CookieOptions } from './interfaces.js';
import {
  PKCE_COOKIE_MAX_AGE,
  PKCE_COOKIE_NAME_INSECURE,
  PKCE_COOKIE_NAME_SECURE,
} from './pkce.js';

/**
 * True if the configured `redirectUri` is HTTP (local dev). Used by the
 * callback to decide whether to accept the bare-name fallback cookie.
 */
export function isInsecureRedirectUri(): boolean {
  try {
    return new URL(getConfig('redirectUri')).protocol === 'http:';
  } catch {
    return false;
  }
}

/**
 * Returns `{ name, options }` for the PKCE verifier cookie. The name is
 * `__Host-wos-auth-verifier` when `redirectUri` is HTTPS and the bare
 * `wos-auth-verifier` when HTTP (local dev). `__Host-` requires `Secure`,
 * `Path=/`, and no `Domain` — enforced structurally here so callers cannot
 * loosen them.
 *
 * `SameSite=Lax` is used because `Strict` blocks the cookie on the cross-site
 * redirect back from WorkOS.
 */
export function getPKCECookie(expired: boolean = false): { name: string; options: CookieOptions } {
  const secure = !isInsecureRedirectUri();
  const name = secure ? PKCE_COOKIE_NAME_SECURE : PKCE_COOKIE_NAME_INSECURE;
  const options: CookieOptions = {
    path: '/',
    httpOnly: true,
    secure,
    sameSite: 'lax',
    maxAge: expired ? 0 : PKCE_COOKIE_MAX_AGE,
    domain: undefined,
  };
  return { name, options };
}

/**
 * Build a `Set-Cookie` header attribute string (everything after `name=value`)
 * for the PKCE cookie. Used when composing multi-`Set-Cookie` responses.
 */
export function getPKCECookieHeaderAttrs(expired: boolean = false): string {
  const { options } = getPKCECookie(expired);
  const parts = ['Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${options.maxAge}`];
  if (options.secure) parts.push('Secure');
  if (expired) parts.push(`Expires=${new Date(0).toUTCString()}`);
  return parts.join('; ');
}

/**
 * Build the full `Set-Cookie` header value for the PKCE cookie, given a
 * sealed-state body. Used by `redirectToSignIn`/`redirectToSignUp` and by
 * `session.ts` re-auth paths.
 */
export function buildPKCECookieHeader(sealedState: string, expired: boolean = false): string {
  const { name } = getPKCECookie(expired);
  const body = expired ? '' : sealedState;
  return `${name}=${body}; ${getPKCECookieHeaderAttrs(expired)}`;
}

/**
 * When cleanup is needed and the configured redirectUri is HTTP (local dev),
 * emit expiry for both cookie names so dev→prod transitions don't leave
 * zombie cookies. In HTTPS prod, only the `__Host-` name is emitted — the
 * bare cookie would be ignored on read anyway.
 */
export function buildExpiredPKCECookieHeaders(): string[] {
  const attrs = getPKCECookieHeaderAttrs(true);
  if (isInsecureRedirectUri()) {
    return [
      `${PKCE_COOKIE_NAME_SECURE}=; ${attrs}`,
      `${PKCE_COOKIE_NAME_INSECURE}=; ${attrs}`,
    ];
  }
  return [`${PKCE_COOKIE_NAME_SECURE}=; ${attrs}`];
}
