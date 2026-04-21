import { LoaderFunctionArgs, data, redirect } from 'react-router';
import { getConfig } from './config.js';
import { buildExpiredPKCECookieHeaders, isInsecureRedirectUri } from './cookie.js';
import type { HandleAuthOptions } from './interfaces.js';
import { parseCookieHeader } from './parse-cookie-header.js';
import {
  PKCE_COOKIE_NAME_INSECURE,
  PKCE_COOKIE_NAME_SECURE,
  getStateFromPKCECookieValue,
} from './pkce.js';
import { sanitizeReturnPathname } from './return-pathname.js';
import { encryptSession } from './session.js';
import { configureSessionStorage } from './sessionStorage.js';
import { getWorkOS } from './workos.js';

export function authLoader(options: HandleAuthOptions = {}) {
  return async function loader({ request }: LoaderFunctionArgs) {
    const { storage, cookie, returnPathname: returnPathnameOption = '/', onSuccess } = options;
    const cookieName = cookie?.name ?? getConfig('cookieName');
    const { getSession, commitSession } = await configureSessionStorage({ storage, cookieName });

    const expiredPKCECookies = buildExpiredPKCECookieHeaders();

    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    // Preserve prior behavior: no code → no response. Nothing to clean up.
    if (!code) return undefined;

    try {
      if (!state) throw new Error('Missing required auth parameter: state');

      const cookies = parseCookieHeader(request.headers.get('Cookie'));
      // Prefer __Host- always. Only honor the bare fallback when the configured
      // redirectUri is HTTP — otherwise an attacker with HTTP access to a
      // sibling subdomain could satisfy an HTTPS-prod callback's check.
      const allowInsecureFallback = isInsecureRedirectUri();
      const pkceCookie =
        cookies[PKCE_COOKIE_NAME_SECURE] ??
        (allowInsecureFallback ? cookies[PKCE_COOKIE_NAME_INSECURE] : undefined);

      if (!pkceCookie) {
        throw new Error(
          'Auth cookie missing — cannot verify OAuth state. Ensure Set-Cookie headers are propagated on redirects.',
        );
      }
      if (state !== pkceCookie) {
        throw new Error('OAuth state mismatch');
      }

      const {
        codeVerifier,
        customState,
        returnPathname: returnPathnameState,
      } = await getStateFromPKCECookieValue(pkceCookie);

      const { accessToken, refreshToken, user, impersonator, oauthTokens, organizationId } =
        await getWorkOS().userManagement.authenticateWithCode({
          clientId: getConfig('clientId'),
          code,
          codeVerifier,
        });

      // Sanitize each candidate separately — a hostile sealed-state value must
      // not erase a legitimate configured default.
      const safeFromState = returnPathnameState ? sanitizeReturnPathname(returnPathnameState) : '/';
      const safeFromOption = sanitizeReturnPathname(returnPathnameOption);
      const returnPathname = safeFromState !== '/' ? safeFromState : safeFromOption;

      url.searchParams.delete('code');
      url.searchParams.delete('state');

      const parsedReturn = new URL(returnPathname, 'https://placeholder.invalid');
      url.pathname = parsedReturn.pathname;
      for (const [key, value] of parsedReturn.searchParams) {
        url.searchParams.append(key, value);
      }
      url.hash = parsedReturn.hash;

      const encryptedSession = await encryptSession({
        accessToken,
        refreshToken,
        user,
        impersonator,
        headers: {},
      });

      const session = await getSession(cookieName);
      session.set('jwt', encryptedSession);
      const sessionCookie = await commitSession(session);

      if (onSuccess) {
        await onSuccess({
          accessToken,
          impersonator: impersonator ?? null,
          oauthTokens: oauthTokens ?? null,
          refreshToken,
          user,
          organizationId: organizationId ?? null,
          state: customState,
        });
      }

      // Fix protocol mismatch for TLS-terminating load balancers: if the
      // configured redirectUri is HTTPS but the request reaching the app is
      // HTTP, upgrade the redirect URL to HTTPS.
      const redirectUri = getConfig('redirectUri');
      const configUrl = new URL(redirectUri);
      if (configUrl.protocol === 'https:' && url.protocol === 'http:') {
        url.protocol = 'https:';
      }

      const response = redirect(url.toString());
      response.headers.append('Set-Cookie', sessionCookie);
      for (const c of expiredPKCECookies) {
        response.headers.append('Set-Cookie', c);
      }
      return response;
    } catch (error) {
      console.error('[AuthKit callback error]', error instanceof Error ? error.message : String(error));
      return errorResponse();
    }

    function errorResponse() {
      const headers = new Headers();
      for (const c of expiredPKCECookies) headers.append('Set-Cookie', c);
      return data(
        {
          error: {
            message: 'Something went wrong',
            description: "Couldn’t sign in. If you are not sure what happened, please contact your organization admin.",
          },
        },
        { status: 500, headers },
      );
    }
  };
}
