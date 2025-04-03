import { data, redirect } from 'react-router';
import { getAuthorizationUrl } from './get-authorization-url.js';
import { refreshSession, terminateSession } from './session.js';

export async function getSignInUrl(returnPathname?: string) {
  return getAuthorizationUrl({ returnPathname, screenHint: 'sign-in' });
}

export async function getSignUpUrl(returnPathname?: string) {
  return getAuthorizationUrl({ returnPathname, screenHint: 'sign-up' });
}

export async function signOut(request: Request) {
  return await terminateSession(request);
}

export async function switchToOrganization(
  request: Request,
  organizationId: string,
  { returnTo }: { returnTo?: string } = {},
) {
  try {
    const auth = await refreshSession(request, { organizationId });

    // if returnTo is provided, redirect to there
    if (returnTo) {
      return redirect(returnTo, {
        headers: {
          'Set-Cookie': auth.headers?.['Set-Cookie'] ?? '',
        },
      });
    }

    // otherwise return the updated auth data
    return data(
      { success: true, auth },
      {
        headers: {
          'Set-Cookie': auth.headers?.['Set-Cookie'] ?? '',
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
      // return redirect(await getAuthorizationUrl({ organizationId }));
      return redirect(await getAuthorizationUrl());
    }

    return data(
      {
        successs: false,
        error: error instanceof Error ? error.message : String(error),
      },
      { status: 400 },
    );
  }
}
