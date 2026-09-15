import { LoaderFunctionArgs, data, redirect } from 'react-router';
import { getAuthorizationUrl } from './get-authorization-url.js';
import { getClaimsFromAccessToken, getSessionFromCookie, refreshSession, terminateSession } from './session.js';
import { GetAuthURLResult, NoUserInfo, UserInfo } from './interfaces.js';
import { getConfig } from './config.js';
import { sanitizeReturnPathname } from './return-pathname.js';

/**
 * Build a sign-in URL and the short-lived PKCE / CSRF cookie that must travel
 * back to the browser on the redirect.
 *
 * Pass `request` when calling from a loader so the cookie's `Secure`
 * attribute matches the live protocol (important for local dev on
 * `http://` against an `https://` redirect URI).
 *
 * @example
 * export async function loader({ request }: LoaderFunctionArgs) {
 *   const { url, headers } = await getSignInUrl('/dashboard', request);
 *   return redirect(url, { headers });
 * }
 */
export async function getSignInUrl(returnPathname?: string, request?: Request): Promise<GetAuthURLResult> {
  return getAuthorizationUrl({ returnPathname, screenHint: 'sign-in', request });
}

/**
 * Build a sign-up URL and the short-lived PKCE / CSRF cookie that must travel
 * back to the browser on the redirect.
 *
 * Pass `request` when calling from a loader so the cookie's `Secure`
 * attribute matches the live protocol.
 *
 * @example
 * export async function loader({ request }: LoaderFunctionArgs) {
 *   const { url, headers } = await getSignUpUrl('/welcome', request);
 *   return redirect(url, { headers });
 * }
 */
export async function getSignUpUrl(returnPathname?: string, request?: Request): Promise<GetAuthURLResult> {
  return getAuthorizationUrl({ returnPathname, screenHint: 'sign-up', request });
}

export async function signOut(request: Request, options?: { returnTo?: string }) {
  return await terminateSession(request, options);
}

/**
 * Given a loader's args, this function will check if the user is authenticated.
 * If the user is authenticated, it will return their information.
 * If the user is not authenticated, it will return an object with user set to null.
 * IMPORTANT: This authkitLoader must be used in a parent/root loader
 * to handle session refresh and cookie management.
 * @param args - The loader's arguments.
 * @returns An object containing user information
 */
export async function withAuth(args: LoaderFunctionArgs): Promise<UserInfo | NoUserInfo> {
  const { request } = args;
  const cookieHeader = request.headers.get('Cookie') as string;
  const cookieName = getConfig('cookieName');

  // Simple check without environment detection
  if (!cookieHeader || !cookieHeader.includes(cookieName)) {
    console.warn(
      `[AuthKit] No session cookie "${cookieName}" found. ` + `Make sure authkitLoader is used in a parent/root route.`,
    );
  }
  const session = await getSessionFromCookie(cookieHeader);

  if (!session?.accessToken) {
    return {
      user: null,
    };
  }

  const {
    sessionId,
    organizationId,
    permissions,
    entitlements,
    featureFlags,
    role,
    roles,
    exp = 0,
  } = getClaimsFromAccessToken(session.accessToken);

  if (Date.now() >= exp * 1000) {
    // The access token is expired. This function does not handle token refresh.
    // Ensure that token refresh is implemented in the parent/root loader as documented.
    console.warn(
      '[AuthKit] Access token expired. Ensure authkitLoader is used in a parent/root route to handle automatic token refresh.',
    );
    return {
      user: null,
    };
  }

  return {
    user: session.user,
    sessionId,
    organizationId,
    role,
    roles,
    permissions,
    entitlements,
    featureFlags,
    impersonator: session.impersonator,
    accessToken: session.accessToken,
  };
}

/**
 * Switches the current session to a different organization.
 * @param request - The incoming request object.
 * @param organizationId - The ID of the organization to switch to.
 * @param options - Optional parameters. `returnTo` must be a same-origin
 * pathname (e.g. `/dashboard`); anything else redirects to `/`.
 * @returns A redirect response to the specified returnTo path or a data response with the updated auth data.
 */
export async function switchToOrganization(
  request: Request,
  organizationId: string,
  { returnTo }: { returnTo?: string } = {},
) {
  try {
    const {
      user,
      sessionId,
      organizationId: newOrganizationId,
      role,
      roles,
      permissions,
      entitlements,
      featureFlags,
      impersonator,
      headers,
    } = await refreshSession(request, { organizationId });

    // Only display-safe claims go back to the browser. `accessToken`,
    // `sealedSession`, and the raw `Set-Cookie` string stay server-side; the
    // session travels via the response header alone (same invariant as
    // authkitLoader post-CVE-2025-55008).
    const auth = {
      user,
      sessionId,
      organizationId: newOrganizationId,
      role,
      roles,
      permissions,
      entitlements,
      featureFlags,
      impersonator,
    };

    // `refreshSession` always returns a `Set-Cookie` header for a successful
    // refresh; guard with `as Record<string, string>` to satisfy the wider
    // typing on AuthLoaderSuccessData without silently emitting an empty
    // `Set-Cookie` header if the invariant ever changes.
    const setCookie = (headers as Record<string, string> | undefined)?.['Set-Cookie'];
    const responseHeaders = setCookie ? { 'Set-Cookie': setCookie } : undefined;

    // if returnTo is provided, redirect there. Same-origin pathname only, so a
    // request-controlled value can't turn this into an open redirect.
    if (returnTo) {
      return redirect(sanitizeReturnPathname(returnTo), responseHeaders ? { headers: responseHeaders } : undefined);
    }

    // otherwise return the updated auth data
    return data({ success: true, auth }, responseHeaders ? { headers: responseHeaders } : undefined);
  } catch (error) {
    if (error instanceof Response && error.status === 302) {
      throw error;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const errorCause: any = error instanceof Error ? error.cause : null;
    if (errorCause?.error === 'sso_required' || errorCause?.error === 'mfa_enrollment') {
      const { url, headers } = await getAuthorizationUrl({ organizationId, request });
      return redirect(url, { headers });
    }

    return data(
      {
        success: false,
        error: error instanceof Error ? error.message : String(error),
      },
      { status: 400 },
    );
  }
}
