import { sealData } from 'iron-session';
import { getConfig } from './config.js';
import type { GetAuthURLOptions, GetAuthURLResult, PKCECookiePayload, State } from './interfaces.js';
import { getPKCECookieString } from './pkce.js';
import { sanitizeReturnPathname } from './return-pathname.js';
import { getWorkOS } from './workos.js';

/**
 * Build an AuthKit authorization URL and the PKCE / CSRF cookie that must
 * travel back with the user on the cross-site redirect.
 *
 * The caller attaches the returned `headers` to their redirect response:
 *
 * ```ts
 * const { url, headers } = await getAuthorizationUrl({ returnPathname: '/dashboard' });
 * return redirect(url, { headers });
 * ```
 *
 * Internally this:
 * 1. Generates a PKCE verifier / challenge pair (RFC 7636, S256).
 * 2. Seals `{ nonce, customState, returnPathname }` (no secret) and sends it
 *    as the OAuth `state` parameter.
 * 3. Seals `{ nonce, codeVerifier }` separately and sets it as an HTTP-only,
 *    flow-specific cookie (`wos-auth-verifier-<hash>`). The `codeVerifier`
 *    lives only in this cookie, never in the URL, so the callback can:
 *      - prove the response came from a flow this browser initiated by
 *        matching the cookie's `nonce` against the URL state's `nonce`; and
 *      - recover the `codeVerifier` (from the cookie) to complete the PKCE
 *        exchange.
 *
 * Because the verifier never travels in the URL, possession of a leaked
 * callback URL alone cannot complete the exchange — the initiating browser's
 * HttpOnly cookie is required.
 */
export async function getAuthorizationUrl(options: GetAuthURLOptions = {}): Promise<GetAuthURLResult> {
  const {
    returnPathname,
    screenHint,
    organizationId,
    redirectUri,
    loginHint,
    prompt,
    state: customState,
    request,
  } = options;

  const pkce = await getWorkOS().pkce.generate();
  const nonce = crypto.randomUUID();

  const state = {
    nonce,
    customState,
    // Sanitize before sealing so a hostile caller can't plant a malicious
    // return target (absolute URL, CRLF smuggle, dot-segment traversal, etc.)
    // that the callback would later redirect to.
    returnPathname: returnPathname !== undefined ? sanitizeReturnPathname(returnPathname) : undefined,
  } satisfies State;

  const sealedState = await sealData(state, {
    password: getConfig('cookiePassword'),
    // Match the PKCE cookie's Max-Age so a stale sealed state can't be
    // replayed after the cookie itself has expired.
    ttl: 600,
  });

  // The PKCE verifier is the secret that binds the authorization code to this
  // browser. It lives ONLY in the HttpOnly cookie, never in the URL state, so
  // a leaked callback URL can't be exchanged without the initiating browser's
  // cookie. `nonce` ties it back to the URL state.
  const sealedVerifier = await sealData({ nonce, codeVerifier: pkce.codeVerifier } satisfies PKCECookiePayload, {
    password: getConfig('cookiePassword'),
    ttl: 600,
  });

  const url = getWorkOS().userManagement.getAuthorizationUrl({
    provider: 'authkit',
    clientId: getConfig('clientId'),
    redirectUri: redirectUri || getConfig('redirectUri'),
    screenHint,
    organizationId,
    loginHint,
    prompt,
    state: sealedState,
    codeChallenge: pkce.codeChallenge,
    codeChallengeMethod: pkce.codeChallengeMethod,
  });

  return {
    url,
    headers: { 'Set-Cookie': getPKCECookieString(sealedState, { value: sealedVerifier, request, redirectUri }) },
  };
}
