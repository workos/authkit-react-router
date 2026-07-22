import { LoaderFunctionArgs, data, redirect } from 'react-router';
import { getConfig } from './config.js';
import { HandleAuthOptions } from './interfaces.js';
import { getPKCECookieString, getStateFromUrlValue, getVerifierFromPKCECookieValue, readPKCECookie } from './pkce.js';
import { sanitizeReturnPathname } from './return-pathname.js';
import { encryptSession } from './session.js';
import { configureSessionStorage } from './sessionStorage.js';
import { getWorkOS } from './workos.js';

export function authLoader(options: HandleAuthOptions = {}) {
  return async function loader({ request }: LoaderFunctionArgs) {
    const { storage, cookie, returnPathname: returnPathnameOption = '/', onSuccess } = options;
    const cookieName = cookie?.name ?? getConfig('cookieName');
    const { getSession, commitSession } = await configureSessionStorage({ storage, cookieName });

    const url = new URL(request.url);

    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    // Cleared on every exit (success, failure, and WorkOS error callbacks
    // where `?error=…&state=…` arrives with no code) so abandoned flows
    // don't leave orphan verifier cookies until their 10-minute TTL expires.
    const pkceClearCookie = state ? getPKCECookieString(state, { expired: true, request }) : null;

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

      // The PKCE verifier lives only in this HttpOnly cookie, never in the URL
      // state. A missing cookie means either the browser never started this
      // flow (forged / leaked link) or the cookie was cleared (expired /
      // tampered) — in every case we cannot recover the verifier.
      if (!pkceCookieValue) {
        throw new Error(
          'Auth cookie missing — cannot verify OAuth state. Ensure Set-Cookie headers are propagated on the redirect that started this flow.',
        );
      }

      // Recover the verifier from the cookie and the flow metadata from the
      // URL state. Both are sealed under the app's cookie password; replaying
      // the URL `state` as the cookie fails here because it unseals to the
      // state payload (no `codeVerifier`).
      const { nonce: cookieNonce, codeVerifier } = await getVerifierFromPKCECookieValue(pkceCookieValue);
      const { nonce: stateNonce, customState, returnPathname: returnPathnameState } = await getStateFromUrlValue(state);

      // Binding check: the secret verifier cookie must carry the same nonce as
      // the URL state. Because the verifier is only ever presentable by the
      // browser that initiated the flow, possession of the callback URL alone
      // can never satisfy this.
      if (cookieNonce !== stateNonce) {
        throw new Error('OAuth state mismatch');
      }

      const { accessToken, refreshToken, user, impersonator, oauthTokens, authenticationMethod, organizationId } =
        await getWorkOS().userManagement.authenticateWithCode({
          clientId: getConfig('clientId'),
          code,
          codeVerifier,
        });

      // Clean up params
      url.searchParams.delete('code');
      url.searchParams.delete('state');

      // `sanitizeReturnPathname` maps both rejection and a legitimate '/'
      // to '/'; disambiguate by comparing to the raw input so an explicit
      // '/' from the caller still beats the configured option.
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
