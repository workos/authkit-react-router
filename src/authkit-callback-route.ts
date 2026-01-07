import { data, redirect, type LoaderFunctionArgs } from 'react-router';
import { getAuthkit } from './authkit.js';
import type { HandleAuthOptions } from './interfaces.js';
import { getConfig } from './config.js';

/**
 * Creates a callback route handler for OAuth authentication.
 * This should be used in your callback route to complete the authentication flow.
 */
export function authLoader(options: HandleAuthOptions = {}) {
  return async function loader({ request }: LoaderFunctionArgs) {
    const { returnPathname: returnPathnameOption = '/', onSuccess } = options;
    const authkit = getAuthkit();

    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    if (!code) {
      return errorResponse();
    }

    try {
      const response = new Response();
      const result = await authkit.handleCallback(request, response, {
        code,
        state: state ?? undefined,
      });

      const { authResponse, returnPathname: stateReturnPathname } = result;

      // Use state returnPathname if available, otherwise use option
      const returnPathname = stateReturnPathname || returnPathnameOption;

      // Clean up params
      url.searchParams.delete('code');
      url.searchParams.delete('state');

      // Set the redirect target
      if (returnPathname.includes('?')) {
        const targetUrl = new URL(returnPathname, 'https://example.com');
        url.pathname = targetUrl.pathname;
        for (const [key, value] of targetUrl.searchParams) {
          url.searchParams.append(key, value);
        }
      } else {
        url.pathname = returnPathname;
      }

      // Call success callback if provided
      if (onSuccess) {
        await onSuccess({
          accessToken: authResponse.accessToken,
          impersonator: authResponse.impersonator ?? null,
          oauthTokens: authResponse.oauthTokens ?? null,
          refreshToken: authResponse.refreshToken,
          user: authResponse.user,
          organizationId: authResponse.organizationId ?? null,
        });
      }

      // Fix protocol mismatch for load balancer scenarios
      const redirectUri = getConfig('redirectUri');
      const configUrl = new URL(redirectUri);
      if (configUrl.protocol === 'https:' && url.protocol === 'http:') {
        url.protocol = 'https:';
      }

      // Extract session cookie from result
      const setCookieValue = result.headers?.['Set-Cookie'] ?? result.response?.headers?.get('Set-Cookie');
      const setCookie = Array.isArray(setCookieValue) ? setCookieValue[0] : setCookieValue;

      return redirect(url.toString(), {
        headers: setCookie ? { 'Set-Cookie': setCookie } : undefined,
      });
    } catch (error) {
      console.error('OAuth callback failed:', error);
      return errorResponse();
    }
  };
}

function errorResponse() {
  return data(
    {
      error: {
        message: 'Something went wrong',
        description: "Couldn't sign in. If you are not sure what happened, please contact your organization admin.",
      },
    },
    { status: 500 },
  );
}
