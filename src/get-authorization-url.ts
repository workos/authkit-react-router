import { sealData } from 'iron-session';
import { getConfig } from './config.js';
import type { GetAuthURLOptions, GetAuthURLResult, State } from './interfaces.js';
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
 * 2. Seals `{ nonce, codeVerifier, customState, returnPathname }` with
 *    iron-session under the configured cookie password.
 * 3. Sends the sealed value as the OAuth `state` parameter.
 * 4. Sets an HTTP-only, flow-specific cookie (`wos-auth-verifier-<hash>`)
 *    with the same sealed value so the callback can:
 *      - prove the response came from a flow this browser initiated
 *        (CSRF: `cookie === state`); and
 *      - recover the `codeVerifier` to complete the PKCE exchange.
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

  const state = {
    nonce: crypto.randomUUID(),
    codeVerifier: pkce.codeVerifier,
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
    headers: { 'Set-Cookie': getPKCECookieString(sealedState, { request, redirectUri }) },
  };
}
