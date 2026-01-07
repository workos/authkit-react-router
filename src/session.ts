import { data, redirect, type LoaderFunctionArgs } from 'react-router';
import { getAuthkit } from './authkit.js';
import type {
  AuthKitLoaderOptions,
  AuthorizedData,
  DataWithResponseInit,
  Session,
  UnauthorizedData,
  UnwrapData,
} from './interfaces.js';
import type { AuthenticationResponse } from '@workos-inc/node';

// Re-export error class from authkit-session
export { TokenRefreshError as SessionRefreshError } from '@workos/authkit-session';

// must be a type since this is a subtype of response
// interfaces must conform to the types they extend
export type TypedResponse<T> = Response & {
  json(): Promise<T>;
};

type LoaderValue<Data> = Response | TypedResponse<Data> | NonNullable<Data> | null;
type LoaderReturnValue<Data> = Promise<LoaderValue<Data>> | LoaderValue<Data>;

type AuthLoader<Data> = (
  args: LoaderFunctionArgs & {
    auth: AuthorizedData | UnauthorizedData;
    getAccessToken: () => string | null;
  },
) => LoaderReturnValue<Data>;

type AuthorizedAuthLoader<Data> = (
  args: LoaderFunctionArgs & {
    auth: AuthorizedData;
    getAccessToken: () => string;
  },
) => LoaderReturnValue<Data>;

/**
 * Helper to build a Headers object from session data
 */
function buildSessionHeaders(sessionData?: string): Headers {
  const headers = new Headers();
  if (sessionData) {
    headers.set('Set-Cookie', sessionData);
  }
  return headers;
}

/**
 * Convert AuthService result to AuthorizedData shape
 */
function toAuthorizedData(auth: {
  user: NonNullable<unknown>;
  sessionId: string;
  accessToken: string;
  organizationId?: string;
  role?: string;
  roles?: string[];
  permissions?: string[];
  entitlements?: string[];
  featureFlags?: string[];
  impersonator?: unknown;
}): AuthorizedData {
  return {
    user: auth.user,
    sessionId: auth.sessionId,
    organizationId: auth.organizationId ?? null,
    role: auth.role ?? null,
    roles: auth.roles ?? null,
    permissions: auth.permissions ?? [],
    entitlements: auth.entitlements ?? [],
    featureFlags: auth.featureFlags ?? [],
    impersonator: auth.impersonator ?? null,
  } as AuthorizedData;
}

/**
 * Get the return pathname from a URL
 */
function getReturnPathname(url: string): string {
  const newUrl = new URL(url);
  return `${newUrl.pathname}${newUrl.searchParams.size > 0 ? '?' + newUrl.searchParams.toString() : ''}`;
}

/**
 * This loader handles authentication state, session management, and access token refreshing
 * automatically, making it easier to build authenticated routes.
 *
 * Creates an authentication-aware loader function for React Router.
 *
 * @overload
 * Basic usage with enforced authentication that redirects unauthenticated users to sign in.
 */
export async function authkitLoader(
  loaderArgs: LoaderFunctionArgs,
  options: AuthKitLoaderOptions & { ensureSignedIn: true },
): Promise<DataWithResponseInit<AuthorizedData>>;

/**
 * @overload
 * Basic usage without enforced authentication, allowing both signed-in and anonymous users.
 */
export async function authkitLoader(
  loaderArgs: LoaderFunctionArgs,
  options?: AuthKitLoaderOptions,
): Promise<DataWithResponseInit<AuthorizedData | UnauthorizedData>>;

/**
 * @overload
 * Custom loader with enforced authentication.
 */
export async function authkitLoader<Data = unknown>(
  loaderArgs: LoaderFunctionArgs,
  loader: AuthorizedAuthLoader<Data>,
  options: AuthKitLoaderOptions & { ensureSignedIn: true },
): Promise<DataWithResponseInit<UnwrapData<Data> & AuthorizedData>>;

/**
 * @overload
 * Custom loader without enforced authentication.
 */
export async function authkitLoader<Data = unknown>(
  loaderArgs: LoaderFunctionArgs,
  loader: AuthLoader<Data>,
  options?: AuthKitLoaderOptions,
): Promise<DataWithResponseInit<UnwrapData<Data> & (AuthorizedData | UnauthorizedData)>>;

export async function authkitLoader<Data = unknown>(
  loaderArgs: LoaderFunctionArgs,
  loaderOrOptions?: AuthLoader<Data> | AuthorizedAuthLoader<Data> | AuthKitLoaderOptions,
  options: AuthKitLoaderOptions = {},
) {
  const loader = typeof loaderOrOptions === 'function' ? loaderOrOptions : undefined;
  const {
    ensureSignedIn = false,
    debug = false,
    onSessionRefreshSuccess,
    onSessionRefreshError,
  } = typeof loaderOrOptions === 'object' ? loaderOrOptions : options;

  const { request } = loaderArgs;
  const authkit = getAuthkit();

  try {
    const result = await authkit.withAuth(request);
    const headers = buildSessionHeaders(result.refreshedSessionData);

    // No authenticated user
    if (!result.auth.user) {
      if (ensureSignedIn) {
        const returnPathname = getReturnPathname(request.url);
        const signInUrl = await authkit.getSignInUrl({ returnPathname });
        throw redirect(signInUrl);
      }

      const auth: UnauthorizedData = {
        user: null,
        impersonator: null,
        organizationId: null,
        permissions: null,
        entitlements: null,
        featureFlags: null,
        role: null,
        roles: null,
        sessionId: null,
      };

      return handleAuthLoader(loader, loaderArgs, auth);
    }

    // Authenticated user
    const auth = toAuthorizedData(result.auth);

    // Call success callback if session was refreshed
    if (result.refreshedSessionData && onSessionRefreshSuccess) {
      await onSessionRefreshSuccess({
        accessToken: result.auth.accessToken,
        user: result.auth.user,
        impersonator: result.auth.impersonator ?? null,
        organizationId: result.auth.organizationId ?? null,
      });
    }

    // istanbul ignore next
    if (debug) console.log('Session validated', { sessionId: auth.sessionId });

    return handleAuthLoader(loader, loaderArgs, auth, {
      accessToken: result.auth.accessToken,
      headers,
    });
  } catch (error) {
    // Handle cookie parsing errors (e.g., old iron-session format)
    // These occur when upgrading from older versions with different cookie formats
    if (isCookieParseError(error)) {
      if (debug) console.log('Invalid session cookie format, treating as no session');

      if (ensureSignedIn) {
        const returnPathname = getReturnPathname(request.url);
        const signInUrl = await authkit.getSignInUrl({ returnPathname });
        throw redirect(signInUrl);
      }

      const auth: UnauthorizedData = {
        user: null,
        impersonator: null,
        organizationId: null,
        permissions: null,
        entitlements: null,
        featureFlags: null,
        role: null,
        roles: null,
        sessionId: null,
      };

      return handleAuthLoader(loader, loaderArgs, auth);
    }

    // Handle refresh errors
    if (error instanceof Error && error.name === 'TokenRefreshError') {
      if (onSessionRefreshError) {
        try {
          const errorResult = await onSessionRefreshError({
            error: error.cause,
            request,
            sessionData: {},
          });

          if (errorResult instanceof Response) {
            return errorResult;
          }
        } catch (callbackError) {
          if (callbackError instanceof Response) {
            throw callbackError;
          }
        }
      }

      const returnPathname = getReturnPathname(request.url);
      const signInUrl = await authkit.getSignInUrl({ returnPathname });
      throw redirect(signInUrl);
    }

    throw error;
  }
}

async function handleAuthLoader(
  loader: AuthLoader<unknown> | AuthorizedAuthLoader<unknown> | undefined,
  args: LoaderFunctionArgs,
  auth: AuthorizedData | UnauthorizedData,
  session?: { accessToken: string; headers: Headers },
) {
  if (!loader) {
    return data(auth, session ? { headers: session.headers } : undefined);
  }

  let loaderResult;

  if (auth.user) {
    const getAccessToken = () => {
      if (!session?.accessToken) {
        throw new Error('No access token available');
      }
      return session.accessToken;
    };
    loaderResult = await (loader as AuthorizedAuthLoader<unknown>)({
      ...args,
      auth: auth as AuthorizedData,
      getAccessToken,
    });
  } else {
    const getAccessToken = () => null;
    loaderResult = await (loader as AuthLoader<unknown>)({
      ...args,
      auth,
      getAccessToken,
    });
  }

  if (loaderResult instanceof Response) {
    if (isRedirect(loaderResult)) {
      throw loaderResult;
    }

    const newResponse = new Response(loaderResult.body, loaderResult);
    if (session?.headers) {
      const setCookie = session.headers.get('Set-Cookie');
      if (setCookie) {
        newResponse.headers.append('Set-Cookie', setCookie);
      }
    }

    if (!isJsonResponse(newResponse)) {
      return newResponse;
    }

    const responseData = await newResponse.json();
    return data({ ...responseData, ...auth }, newResponse);
  }

  const actualData = isDataWithResponseInit(loaderResult) ? loaderResult.data : loaderResult;
  const mergedHeaders = isDataWithResponseInit(loaderResult) ? new Headers(loaderResult.init?.headers) : new Headers();

  if (session?.headers) {
    const setCookie = session.headers.get('Set-Cookie');
    if (setCookie) {
      mergedHeaders.set('Set-Cookie', setCookie);
    }
  }

  const mergedData = actualData && typeof actualData === 'object' ? { ...actualData, ...auth } : { ...auth };
  return data(mergedData, { headers: mergedHeaders });
}

/**
 * Refresh the session by using the refresh token.
 */
export async function refreshSession(request: Request, options: { organizationId?: string } = {}) {
  const authkit = getAuthkit();
  const session = await authkit.getSession(request);

  if (!session) {
    const signInUrl = await authkit.getSignInUrl();
    throw redirect(signInUrl);
  }

  const result = await authkit.refreshSession(session, options.organizationId);
  const headers = buildSessionHeaders(result.encryptedSession);

  // Extract user info from auth result
  const auth = result.auth;
  if (!auth.user) {
    throw new Error('Session refresh failed - no user returned');
  }

  return {
    user: auth.user,
    sessionId: auth.sessionId,
    accessToken: auth.accessToken,
    organizationId: auth.organizationId ?? null,
    role: auth.role ?? null,
    roles: auth.roles ?? null,
    permissions: auth.permissions ?? [],
    entitlements: auth.entitlements ?? [],
    featureFlags: auth.featureFlags ?? [],
    impersonator: auth.impersonator ?? null,
    sealedSession: result.encryptedSession,
    headers,
  };
}

/**
 * Saves a WorkOS session to a cookie for use with AuthKit.
 *
 * This function is intended for advanced use cases where you need to manually
 * manage sessions, such as custom authentication flows (email verification,
 * etc.) that don't use the standard AuthKit authentication flow.
 */
export async function saveSession(
  sessionOrResponse: Session | AuthenticationResponse,
  request: Request,
): Promise<Session> {
  const authkit = getAuthkit();
  const { accessToken, refreshToken, user, impersonator } = sessionOrResponse;

  // Create a response to pass to the storage adapter
  const response = new Response();
  const session: Session = {
    accessToken,
    refreshToken,
    user,
    impersonator,
    headers: {},
  };

  // Use the core encryption through a workaround - get the session storage
  // to encrypt and save the session
  const result = await authkit.saveSession(response, JSON.stringify(session));

  const setCookie = result.headers?.['Set-Cookie'] ?? result.response?.headers?.get('Set-Cookie') ?? '';

  session.headers = {
    'Set-Cookie': typeof setCookie === 'string' ? setCookie : setCookie[0] ?? '',
  };

  return session;
}

/**
 * Terminate the current session and redirect to logout URL.
 */
export async function terminateSession(request: Request, { returnTo }: { returnTo?: string } = {}) {
  const authkit = getAuthkit();
  const result = await authkit.withAuth(request);

  if (result.auth.user) {
    const { logoutUrl, headers } = await authkit.signOut(result.auth.sessionId, { returnTo });
    return redirect(logoutUrl, {
      headers: headers as HeadersInit,
    });
  }

  return redirect(returnTo ?? '/');
}

// Helper functions
function isRedirect(res: Response) {
  return res.status >= 300 && res.status < 400;
}

function isJsonResponse(res: Response): boolean {
  const contentType = res.headers.get('Content-Type')?.toLowerCase();
  return !!contentType?.includes('application/json');
}

function isDataWithResponseInit(value: unknown): value is DataWithResponseInit<unknown> {
  return (
    typeof value === 'object' &&
    value != null &&
    'type' in value &&
    'data' in value &&
    'init' in value &&
    value.type === 'DataWithResponseInit'
  );
}

/**
 * Detect cookie parsing errors that occur when encountering
 * incompatible cookie formats (e.g., upgrading from old versions)
 */
function isCookieParseError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;

  // DOMException from atob (InvalidCharacterError)
  if (error.name === 'InvalidCharacterError') return true;

  // iron-session decryption failures
  if (error.message?.includes('Unable to decrypt')) return true;
  if (error.message?.includes('Invalid character')) return true;

  return false;
}
