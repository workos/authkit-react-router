import { data, redirect, type LoaderFunctionArgs } from 'react-router';
import { getAuthkit } from './authkit.js';
import { refreshSession, terminateSession } from './session.js';
import type { DataWithResponseInit, NoUserInfo, UserInfo } from './interfaces.js';
import { getConfig } from './config.js';

interface SwitchOrgSuccess {
  success: true;
  auth: Awaited<ReturnType<typeof refreshSession>>;
}

interface SwitchOrgError {
  success: false;
  error: string;
}

/**
 * Get the sign-in URL for AuthKit.
 */
export async function getSignInUrl(returnPathname?: string) {
  const authkit = getAuthkit();
  return authkit.getSignInUrl({ returnPathname });
}

/**
 * Get the sign-up URL for AuthKit.
 */
export async function getSignUpUrl(returnPathname?: string) {
  const authkit = getAuthkit();
  return authkit.getSignUpUrl({ returnPathname });
}

/**
 * Sign out the current user.
 */
export async function signOut(request: Request, options?: { returnTo?: string }) {
  return await terminateSession(request, options);
}

/**
 * Given a loader's args, this function will check if the user is authenticated.
 * If the user is authenticated, it will return their information.
 * If the user is not authenticated, it will return an object with user set to null.
 * IMPORTANT: This authkitLoader must be used in a parent/root loader
 * to handle session refresh and cookie management.
 */
export async function withAuth(args: LoaderFunctionArgs): Promise<UserInfo | NoUserInfo> {
  const { request } = args;
  const authkit = getAuthkit();
  const cookieHeader = request.headers.get('Cookie') as string;
  const cookieName = getConfig('cookieName');

  // Simple check without environment detection
  if (!cookieHeader || !cookieHeader.includes(cookieName)) {
    console.warn(
      `[AuthKit] No session cookie "${cookieName}" found. ` + `Make sure authkitLoader is used in a parent/root route.`,
    );
  }

  const result = await authkit.withAuth(request);

  if (!result.auth.user) {
    return {
      user: null,
    };
  }

  // Check if token is expired
  const now = Date.now();
  const claims = result.auth.claims;
  const exp = claims?.exp ?? 0;

  if (now >= exp * 1000) {
    console.warn(
      '[AuthKit] Access token expired. Ensure authkitLoader is used in a parent/root route to handle automatic token refresh.',
    );
    return {
      user: null,
    };
  }

  return {
    user: result.auth.user,
    sessionId: result.auth.sessionId,
    organizationId: result.auth.organizationId,
    role: result.auth.role,
    roles: result.auth.roles,
    permissions: result.auth.permissions,
    entitlements: result.auth.entitlements,
    featureFlags: result.auth.featureFlags,
    impersonator: result.auth.impersonator,
    accessToken: result.auth.accessToken,
  };
}

/**
 * Switches the current session to a different organization.
 */
export async function switchToOrganization(
  request: Request,
  organizationId: string,
  { returnTo }: { returnTo?: string } = {},
): Promise<Response | DataWithResponseInit<SwitchOrgSuccess> | DataWithResponseInit<SwitchOrgError>> {
  try {
    const auth = await refreshSession(request, { organizationId });

    // if returnTo is provided, redirect to there
    if (returnTo) {
      return redirect(returnTo, {
        headers: {
          'Set-Cookie': auth.headers?.get('Set-Cookie') ?? '',
        },
      });
    }

    // otherwise return the updated auth data
    return data(
      { success: true, auth },
      {
        headers: {
          'Set-Cookie': auth.headers?.get('Set-Cookie') ?? '',
        },
      },
    );
  } catch (error) {
    if (error instanceof Response && error.status === 302) {
      throw error;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const errorCause: any = error instanceof Error ? error.cause : null;
    if (errorCause?.error === 'sso_required' || errorCause?.error === 'mfa_enrollment') {
      const authkit = getAuthkit();
      return redirect(await authkit.getAuthorizationUrl({ organizationId }));
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
