import { LoaderFunctionArgs, data, redirect } from 'react-router';
import { getConfig } from './config.js';
import { HandleAuthOptions } from './interfaces.js';
import { getPKCECookieString, getStateFromPKCECookieValue, readPKCECookie } from './pkce.js';
import { sanitizeReturnPathname } from './return-pathname.js';
import { encryptSession } from './session.js';
import { configureSessionStorage } from './sessionStorage.js';
import { getWorkOS } from './workos.js';

/**
 * Build a `Set-Cookie` header that clears the PKCE cookie associated with a
 * given sealed state value. PKCE cookies are single-use — we always clear
 * them, whether the exchange succeeded or failed, to prevent replays and
 * stale cookies affecting future auth attempts.
 */
function clearPKCECookie(state: string, request: Request): string {
  return getPKCECookieString(state, { expired: true, request });
}

export function authLoader(options: HandleAuthOptions = {}) {
  return async function loader({ request }: LoaderFunctionArgs) {
    const { storage, cookie, returnPathname: returnPathnameOption = '/', onSuccess } = options;
    const cookieName = cookie?.name ?? getConfig('cookieName');
    const { getSession, commitSession } = await configureSessionStorage({ storage, cookieName });

    const url = new URL(request.url);

    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    // We always want to clear the PKCE cookie at the end of this handler,
    // success or failure. `pkceClearCookie` is populated as soon as we know
    // the state value and appended to every response below — including
    // early exits for WorkOS error callbacks (`?error=…&state=…`) that
    // would otherwise leave an orphan verifier cookie in the browser.
    const pkceClearCookie = state ? clearPKCECookie(state, request) : null;

    if (!code) {
      if (pkceClearCookie) {
        return new Response(null, { headers: { 'Set-Cookie': pkceClearCookie } });
      }
      return;
    }

    try {
      if (!state) {
        throw new Error('Missing required auth parameter: state');
      }

      const pkceCookieValue = readPKCECookie(request.headers.get('Cookie'), state);

      // CSRF verification (double-submit cookie): both the cookie and the URL
      // state must be present and identical. A missing cookie means either
      // the browser never started this flow (forged link) or the cookie has
      // been cleared (expired / tampered).
      if (!pkceCookieValue) {
        throw new Error(
          'Auth cookie missing — cannot verify OAuth state. Ensure Set-Cookie headers are propagated on the redirect that started this flow.',
        );
      }

      if (state !== pkceCookieValue) {
        throw new Error('OAuth state mismatch');
      }

      const {
        codeVerifier,
        customState,
        returnPathname: returnPathnameState,
      } = await getStateFromPKCECookieValue(pkceCookieValue);

      const { accessToken, refreshToken, user, impersonator, oauthTokens, authenticationMethod, organizationId } =
        await getWorkOS().userManagement.authenticateWithCode({
          clientId: getConfig('clientId'),
          code,
          codeVerifier,
        });

      // Clean up params
      url.searchParams.delete('code');
      url.searchParams.delete('state');

      // Sanitize each candidate separately so a hostile sealed-state value
      // (e.g. an absolute URL, CRLF smuggle, or encoded traversal) can't
      // erase a legitimate configured default. `sanitizeReturnPathname`
      // collapses both rejection and a legitimate '/' input into the same
      // '/' result, so we detect rejection by comparing against the raw
      // input — that way an explicit `returnPathname: '/'` from the caller
      // still wins over a configured option like `'/dashboard'`.
      let returnPathname: string;
      if (returnPathnameState !== undefined) {
        const sanitizedState = sanitizeReturnPathname(returnPathnameState);
        const stateWasRejected = sanitizedState === '/' && returnPathnameState !== '/';
        returnPathname = stateWasRejected ? sanitizeReturnPathname(returnPathnameOption) : sanitizedState;
      } else {
        returnPathname = sanitizeReturnPathname(returnPathnameOption);
      }

      // Reconstruct pathname + search + hash together. Using `.pathname = ...`
      // on a raw string with a fragment would percent-encode the `#`, so we
      // parse the return target and reassign each piece.
      const parsedReturn = new URL(returnPathname, 'https://placeholder.invalid');
      url.pathname = parsedReturn.pathname;
      for (const [key, value] of parsedReturn.searchParams) {
        url.searchParams.append(key, value);
      }
      url.hash = parsedReturn.hash;

      // The refreshToken should never be accessible publicly, hence why we encrypt it
      // in the cookie session. Alternatively you could persist the refresh token in a
      // backend database.
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
          authenticationMethod,
          state: customState,
        });
      }

      // Fix protocol mismatch for load balancer scenarios
      // If WORKOS_REDIRECT_URI is HTTPS but request is HTTP, use HTTPS for redirect
      const redirectUri = getConfig('redirectUri');
      const configUrl = new URL(redirectUri);
      if (configUrl.protocol === 'https:' && url.protocol === 'http:') {
        url.protocol = 'https:';
      }

      const headers = new Headers();
      headers.append('Set-Cookie', sessionCookie);
      if (pkceClearCookie) {
        headers.append('Set-Cookie', pkceClearCookie);
      }

      return redirect(url.toString(), { headers });
    } catch (error) {
      const errorRes = {
        error: error instanceof Error ? error.message : String(error),
      };

      console.error(errorRes);

      const headers = new Headers();
      if (pkceClearCookie) {
        headers.append('Set-Cookie', pkceClearCookie);
      }

      return data(
        {
          error: {
            message: 'Something went wrong',
            description: 'Couldn’t sign in. If you are not sure what happened, please contact your organization admin.',
          },
        },
        { status: 500, headers },
      );
    }
  };
}
