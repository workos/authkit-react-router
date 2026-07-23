import { data, redirect, type LoaderFunctionArgs, type SessionData } from 'react-router';
import { getAuthorizationUrl } from './get-authorization-url.js';
import type {
  AccessToken,
  AuthKitFeatureFlagsOptions,
  AuthKitLoaderOptions,
  AuthorizedData,
  DataWithResponseInit,
  FeatureFlagsErrorOptions,
  Session,
  UnauthorizedData,
  UnwrapData,
} from './interfaces.js';
import { getWorkOS } from './workos.js';

import { sealData, unsealData } from 'iron-session';
import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';
import { getConfig } from './config.js';
import { getPKCECleanupCookieStrings } from './pkce.js';
import { configureSessionStorage, getSessionStorage } from './sessionStorage.js';
import { isDataWithResponseInit, isJsonResponse, isRedirect, isResponse } from './utils.js';
import type { AuthenticationResponse, EvaluationContext } from '@workos-inc/node';

// must be a type since this is a subtype of response
// interfaces must conform to the types they extend
export type TypedResponse<T> = Response & {
  json(): Promise<T>;
};

export class SessionRefreshError extends Error {
  /**
   * Whether the refresh failed for a transient reason (network error, timeout,
   * 429, or 5xx) rather than a terminal one (the refresh token is dead). When
   * `true`, the existing session is still valid and should be preserved and
   * retried rather than destroyed.
   */
  readonly isTransient: boolean;

  constructor(cause: unknown) {
    super('Session refresh error', { cause });
    this.name = 'SessionRefreshError';
    this.isTransient = isTransientRefreshError(cause);
  }
}

// The WorkOS SDK's HTTP client already retries these with backoff + jitter
// internally. If one of these still surfaces, the failure is transient rather
// than a dead refresh token: request timeouts (normalized to 408), rate limits
// (429), and 5xx.
const RETRYABLE_REFRESH_STATUS_CODES = new Set([408, 429, 500, 502, 503, 504]);

// A network-level fetch failure surfaces as a TypeError ("fetch failed" /
// "Failed to fetch"). Match its message so an unrelated programming TypeError
// (e.g. from a helper after a successful exchange) is not misclassified.
const NETWORK_ERROR_MESSAGE = /fetch failed|failed to fetch|network|load failed|terminated/i;

// A raw network TypeError is not an HttpClientError, so the WorkOS SDK re-wraps
// it in a plain Error whose `cause` is the original TypeError. Follow the cause
// chain to recognize it.
function isNetworkError(error: unknown): boolean {
  if (error instanceof TypeError) {
    return NETWORK_ERROR_MESSAGE.test(error.message);
  }

  if (error instanceof Error && error.cause != null && error.cause !== error) {
    return isNetworkError(error.cause);
  }

  return false;
}

/**
 * Classifies a refresh failure as transient (retryable) rather than terminal.
 * Transient failures carry a retryable numeric `status` (408/429/5xx, mirroring
 * the SDK's own retry set) or are network failures (a "fetch failed" `TypeError`,
 * possibly wrapped by the SDK with the original `TypeError` as its `cause`).
 * Anything else (a terminal `invalid_grant` at 400, a 401, or an unrecognized
 * error) is treated as terminal.
 */
export function isTransientRefreshError(error: unknown): boolean {
  // A known HTTP status is authoritative: a retryable code is transient, and
  // any other status (e.g. a terminal 400 `invalid_grant`) is terminal. Return
  // eagerly so a terminal response is never reclassified as transient by the
  // network-cause fallback below.
  if (typeof error === 'object' && error !== null && 'status' in error) {
    const { status } = error;
    if (typeof status === 'number') {
      return RETRYABLE_REFRESH_STATUS_CODES.has(status);
    }
  }

  return isNetworkError(error);
}

/**
 * This function is used to refresh the session by using the refresh token.
 * It will authenticate the user with the refresh token and return a new session object.
 * @param request - The request object
 * @param options - Optional configuration options
 * @returns A promise that resolves to the new session object
 */
export async function refreshSession(request: Request, options: { organizationId?: string } = {}) {
  const { organizationId } = options;
  const { getSession } = await getSessionStorage();
  const cookie = request.headers.get('Cookie');
  const session = cookie ? await getSessionFromCookie(cookie) : null;
  if (!session) {
    const { url, headers } = await getAuthorizationUrl({ request });
    throw redirect(url, { headers });
  }

  try {
    const refreshResult = await getWorkOS().userManagement.authenticateWithRefreshToken({
      clientId: getConfig('clientId'),
      refreshToken: session.refreshToken,
      organizationId,
    });
    const { headers } = await saveSession(refreshResult, request);
    const cookieSession = await getSession(cookie);
    const { accessToken, user, impersonator } = refreshResult;

    const {
      sessionId,
      organizationId: newOrgId,
      role,
      roles,
      permissions,
      entitlements,
      featureFlags,
    } = getClaimsFromAccessToken(accessToken);

    return {
      user,
      sessionId,
      accessToken,
      organizationId: newOrgId,
      role,
      roles,
      permissions,
      entitlements,
      featureFlags,
      impersonator: impersonator ?? null,
      sealedSession: cookieSession.get('jwt'),
      headers,
    };
  } catch (error) {
    throw new Error(`Failed to refresh session: ${error instanceof Error ? error.message : String(error)}`, {
      cause: error,
    });
  }
}

/**
 * Saves a WorkOS session to a cookie for use with AuthKit.
 *
 * This function is intended for advanced use cases where you need to manually
 * manage sessions, such as custom authentication flows (email verification,
 * etc.) that don't use the standard AuthKit authentication flow.
 *
 * @param sessionOrResponse The WorkOS session or AuthenticationResponse
 * containing access token, refresh token, and user information.
 * @param request A Request object, used to determine cookie settings.
 *
 * @example
 * import { saveSession } from '@workos-inc/authkit-react-router';
 *
 * async function handleEmailVerification(req: Request) {
 *   const { code } = await req.json();
 *   const authResponse = await workos.userManagement.authenticateWithEmailVerification({
 *     clientId: process.env.WORKOS_CLIENT_ID,
 *     code,
 *   });
 *
 *   await saveSession(authResponse, req);
 * }
 */
export async function saveSession(
  sessionOrResponse: Session | AuthenticationResponse,
  request: Request,
): Promise<Session> {
  const { getSession, commitSession } = await getSessionStorage();
  const { accessToken, refreshToken, user, impersonator } = sessionOrResponse;
  const newSession: Session = {
    accessToken,
    refreshToken,
    user,
    impersonator,
    headers: {},
  };
  const cookieSession = await getSession(request.headers.get('Cookie'));
  cookieSession.set('jwt', await encryptSession(newSession));
  const cookie = await commitSession(cookieSession);
  newSession.headers = {
    'Set-Cookie': cookie,
  };

  return newSession;
}

async function updateSession(request: Request, debug: boolean): Promise<Session | null> {
  const session = await getSessionFromCookie(request.headers.get('Cookie') as string);
  const { commitSession, getSession } = await getSessionStorage();

  // If no session, just continue
  if (!session) {
    return null;
  }

  const hasValidSession = await verifyAccessToken(session.accessToken);

  if (hasValidSession) {
    // istanbul ignore next
    if (debug) console.log('Session is valid');
    return session;
  }

  try {
    // istanbul ignore next
    if (debug) console.log(`Session invalid. Refreshing access token that ends in ${session.accessToken.slice(-10)}`);

    const { organizationId } = getClaimsFromAccessToken(session.accessToken);
    // If the session is invalid (i.e. the access token has expired) attempt to re-authenticate with the refresh token
    const { accessToken, refreshToken, user, impersonator } =
      await getWorkOS().userManagement.authenticateWithRefreshToken({
        clientId: getConfig('clientId'),
        refreshToken: session.refreshToken,
        organizationId,
      });

    // istanbul ignore next
    if (debug) console.log(`Refresh successful. New access token ends in ${accessToken.slice(-10)}`);

    const newSession = {
      accessToken,
      refreshToken,
      user,
      impersonator,
      headers: {},
    };

    // Encrypt session with new access and refresh tokens
    const updatedSession = await getSession(request.headers.get('Cookie'));
    updatedSession.set('jwt', await encryptSession(newSession));

    newSession.headers = {
      'Set-Cookie': await commitSession(updatedSession),
    };

    return newSession;
  } catch (e) {
    // istanbul ignore next
    if (debug) console.log('Failed to refresh. Deleting cookie and redirecting.', e);

    throw new SessionRefreshError(e);
  }
}

export async function encryptSession(session: Session | AuthenticationResponse) {
  return sealData(session, {
    password: getConfig('cookiePassword'),
    ttl: 0,
  });
}

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
 * This loader handles authentication state, session management, and access token refreshing
 * automatically, making it easier to build authenticated routes.
 *
 * Creates an authentication-aware loader function for React Router.
 *
 * @overload
 * Basic usage with enforced authentication that redirects unauthenticated users to sign in.
 *
 * @param loaderArgs - The loader arguments provided by React Router
 * @param options - Configuration options with enforced sign-in
 *
 * @example
 * export async function loader({ request }: LoaderFunctionArgs) {
 *   return authkitLoader(
 *     { request },
 *     { ensureSignedIn: true }
 *   );
 * }
 */
export async function authkitLoader(
  loaderArgs: LoaderFunctionArgs,
  options: AuthKitLoaderOptions & { ensureSignedIn: true },
): Promise<DataWithResponseInit<AuthorizedData>>;

/**
 * This loader handles authentication state, session management, and access token refreshing
 * automatically, making it easier to build authenticated routes.
 *
 * @overload
 * Basic usage without enforced authentication, allowing both signed-in and anonymous users.
 *
 * @param loaderArgs - The loader arguments provided by React Router
 * @param options - Optional configuration options
 *
 * @example
 * export async function loader({ request }: LoaderFunctionArgs) {
 *   return authkitLoader({ request });
 * }
 */
export async function authkitLoader(
  loaderArgs: LoaderFunctionArgs,
  options?: AuthKitLoaderOptions,
): Promise<DataWithResponseInit<AuthorizedData | UnauthorizedData>>;

/**
 * This loader handles authentication state, session management, and access token refreshing
 * automatically, making it easier to build authenticated routes.
 *
 * @overload
 * Custom loader with enforced authentication, providing your own loader function
 * that will only be called for authenticated users.
 *
 * @param loaderArgs - The loader arguments provided by React Router
 * @param loader - A custom loader function that receives authentication data
 * @param options - Configuration options with enforced sign-in
 *
 * @example
 * export async function loader({ request }: LoaderFunctionArgs) {
 *   return authkitLoader(
 *     { request },
 *     async ({ auth }) => {
 *       // This will only be called for authenticated users
 *       const userData = await fetchUserData(auth.accessToken);
 *       return { userData };
 *     },
 *     { ensureSignedIn: true }
 *   );
 * }
 */
export async function authkitLoader<Data = unknown>(
  loaderArgs: LoaderFunctionArgs,
  loader: AuthorizedAuthLoader<Data>,
  options: AuthKitLoaderOptions & { ensureSignedIn: true },
): Promise<DataWithResponseInit<UnwrapData<Data> & AuthorizedData>>;

/**
 * This loader handles authentication state, session management, and access token refreshing
 * automatically, making it easier to build authenticated routes.
 *
 * @overload
 * Custom loader without enforced authentication, providing your own loader function
 * that will be called for both authenticated and unauthenticated users.
 *
 * @param loaderArgs - The loader arguments provided by React Router
 * @param loader - A custom loader function that receives authentication data
 * @param options - Optional configuration options
 *
 * @example
 * export async function loader({ request }: LoaderFunctionArgs) {
 *   return authkitLoader(
 *     { request },
 *     async ({ auth }) => {
 *       if (auth.user) {
 *         // User is authenticated
 *         const userData = await fetchUserData(auth.accessToken);
 *         return { userData };
 *       } else {
 *         // User is not authenticated
 *         return { publicData: await fetchPublicData() };
 *       }
 *     }
 *   );
 * }
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
    onFeatureFlagsError,
    storage,
    cookie,
    featureFlags: featureFlagsOptions,
  } = typeof loaderOrOptions === 'object' ? loaderOrOptions : options;

  const cookieName = cookie?.name ?? getConfig('cookieName');
  const { getSession, destroySession } = await configureSessionStorage({
    storage,
    cookieName,
  });

  const { request } = loaderArgs;

  try {
    // Try to get session, this might throw SessionRefreshError
    const session = await updateSession(request, debug);

    if (!session) {
      // No session found case (not authenticated)
      if (ensureSignedIn) {
        const returnPathname = getReturnPathname(request.url);
        const cookieSession = await getSession(request.headers.get('Cookie'));

        const { url, headers: authHeaders } = await getAuthorizationUrl({ returnPathname, request });
        throw redirect(url, {
          headers: [
            ['Set-Cookie', await destroySession(cookieSession)],
            ['Set-Cookie', authHeaders['Set-Cookie']],
          ],
        });
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

      return await handleAuthLoader(loader, loaderArgs, auth);
    }

    // Session found and valid (or refreshed successfully)
    const {
      sessionId,
      organizationId = null,
      role = null,
      roles = null,
      permissions = [],
      entitlements = [],
      featureFlags: tokenFeatureFlags = [],
    } = getClaimsFromAccessToken(session.accessToken);

    const { impersonator = null } = session;

    // checking for 'headers' in session determines if the session was refreshed or not
    if (onSessionRefreshSuccess && 'headers' in session) {
      await onSessionRefreshSuccess({
        accessToken: session.accessToken,
        user: session.user,
        impersonator,
        organizationId,
      });
    }

    const featureFlags = await getFeatureFlags({
      options: featureFlagsOptions,
      tokenFeatureFlags,
      request,
      user: session.user,
      userId: session.user?.id,
      organizationId,
      debug,
      onFeatureFlagsError,
    });

    const auth: AuthorizedData = {
      user: session.user,
      sessionId,
      organizationId,
      role,
      roles,
      permissions,
      entitlements,
      featureFlags,
      impersonator,
    };

    return await handleAuthLoader(loader, loaderArgs, auth, session);
  } catch (error) {
    if (error instanceof SessionRefreshError) {
      const cookieSession = await getSession(request.headers.get('Cookie'));

      if (onSessionRefreshError) {
        try {
          const result = await onSessionRefreshError({
            error: error.cause,
            request,
            sessionData: cookieSession,
            isTransient: error.isTransient,
          });

          if (result instanceof Response) {
            return result;
          }
        } catch (callbackError) {
          // If callback throws a Response (like redirect), propagate it
          if (callbackError instanceof Response) {
            throw callbackError;
          }
        }
      }

      const returnPathname = getReturnPathname(request.url);
      const { url, headers: authHeaders } = await getAuthorizationUrl({ returnPathname, request });

      // Only destroy the session for a terminal failure. A transient failure
      // (network error, timeout, 429, or 5xx that survived the SDK's internal
      // retries) leaves the refresh token valid, so keep the sealed cookie and
      // let a later request refresh successfully rather than forcing the user
      // to re-authenticate.
      if (error.isTransient) {
        throw redirect(url, { headers: [['Set-Cookie', authHeaders['Set-Cookie']]] });
      }

      throw redirect(url, {
        headers: [
          ['Set-Cookie', await destroySession(cookieSession)],
          ['Set-Cookie', authHeaders['Set-Cookie']],
        ],
      });
    }

    // Propagate other errors
    throw error;
  }
}

async function getFeatureFlags({
  options,
  tokenFeatureFlags,
  request,
  user,
  userId,
  organizationId,
  debug,
  onFeatureFlagsError,
}: {
  options?: AuthKitFeatureFlagsOptions;
  tokenFeatureFlags: string[];
  request: Request;
  user: FeatureFlagsErrorOptions['user'];
  userId?: string;
  organizationId: string | null;
  debug: boolean;
  onFeatureFlagsError?: (options: FeatureFlagsErrorOptions) => void | Promise<void>;
}) {
  if (!options) {
    return tokenFeatureFlags;
  }

  try {
    if (options.waitUntilReady) {
      await options.runtimeClient.waitUntilReady(options.waitUntilReady === true ? undefined : options.waitUntilReady);
    }

    const context: EvaluationContext = {};
    if (userId) {
      context.userId = userId;
    }
    if (organizationId) {
      context.organizationId = organizationId;
    }

    return Object.entries(options.runtimeClient.getAllFlags(context))
      .filter(([, enabled]) => enabled)
      .map(([flag]) => flag);
  } catch (error) {
    if (onFeatureFlagsError) {
      try {
        await onFeatureFlagsError({
          error,
          request,
          user,
          organizationId,
          tokenFeatureFlags,
        });
      } catch (callbackError) {
        // istanbul ignore next
        if (debug) {
          console.warn('[AuthKit] Feature flags error callback failed.', callbackError);
        }
      }
    }

    // istanbul ignore next
    if (debug) {
      console.warn(
        '[AuthKit] Failed to evaluate feature flags with the WorkOS runtime client. Falling back to access token feature flags.',
        error,
      );
    }

    return tokenFeatureFlags;
  }
}

async function handleAuthLoader(
  loader: AuthLoader<unknown> | AuthorizedAuthLoader<unknown> | undefined,
  args: LoaderFunctionArgs,
  auth: AuthorizedData | UnauthorizedData,
  session?: Session,
) {
  if (!loader) {
    return data(auth, session ? { headers: { ...session.headers } } : undefined);
  }

  // If there's a custom loader, get the resulting data and return it with our
  // auth data plus session cookie header
  let loaderResult;

  if (auth.user) {
    // Authorized case
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
    // Unauthorized case
    const getAccessToken = () => null;
    loaderResult = await (loader as AuthLoader<unknown>)({
      ...args,
      auth,
      getAccessToken,
    });
  }

  if (isResponse(loaderResult)) {
    // If the result is a redirect, return it unedited
    if (isRedirect(loaderResult)) {
      throw loaderResult;
    }

    const newResponse = new Response(loaderResult.body, loaderResult);

    if (session) {
      newResponse.headers.append('Set-Cookie', session.headers['Set-Cookie']);
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
    Object.entries(session.headers).forEach(([key, value]) => {
      mergedHeaders.set(key, value);
    });
  }

  const mergedData = actualData && typeof actualData === 'object' ? { ...actualData, ...auth } : { ...auth };

  // Always pass headers (empty headers object is valid)
  return data(mergedData, { headers: mergedHeaders });
}

export async function terminateSession(request: Request, { returnTo }: { returnTo?: string } = {}) {
  const { getSession, destroySession } = await getSessionStorage();
  const cookieHeader = request.headers.get('Cookie');
  const encryptedSession = await getSession(cookieHeader);
  const { accessToken } = (await getSessionFromCookie(cookieHeader as string, encryptedSession)) as Session;

  const { sessionId } = getClaimsFromAccessToken(accessToken);

  // Destroy the session cookie plus any orphan `wos-auth-verifier-*` cookies
  // from abandoned OAuth flows — the per-flow cookie scheme means an
  // unfinished flow leaves a cookie behind that the browser will keep
  // sending until its 10-minute Max-Age expires, and stacking enough of
  // them can exceed the per-domain cookie cap.
  const headers = new Headers({
    'Set-Cookie': await destroySession(encryptedSession),
  });
  for (const cleanup of getPKCECleanupCookieStrings(cookieHeader, { request })) {
    headers.append('Set-Cookie', cleanup);
  }

  if (sessionId) {
    return redirect(getWorkOS().userManagement.getLogoutUrl({ sessionId, returnTo }), {
      headers,
    });
  }

  return redirect(returnTo ?? '/', {
    headers,
  });
}

export function getClaimsFromAccessToken(accessToken: string) {
  const {
    sid: sessionId,
    org_id: organizationId,
    role,
    roles,
    permissions,
    entitlements,
    feature_flags: featureFlags,
    exp,
    iss,
  } = decodeJwt<AccessToken>(accessToken);

  return {
    iss,
    exp,
    sessionId,
    organizationId,
    role,
    roles,
    permissions,
    entitlements,
    featureFlags,
  };
}

export async function getSessionFromCookie(cookie: string, session?: SessionData) {
  const { getSession } = await getSessionStorage();
  if (!session) {
    session = await getSession(cookie);
  }

  if (session.has('jwt')) {
    return unsealData<Session>(session.get('jwt'), {
      password: getConfig('cookiePassword'),
    });
  } else {
    return null;
  }
}

let cachedJWKS: ReturnType<typeof createRemoteJWKSet> | undefined;
let cachedJWKSUrl: string | undefined;

function getJWKS(): ReturnType<typeof createRemoteJWKSet> {
  const jwksUrl = getWorkOS().userManagement.getJwksUrl(getConfig('clientId'));
  if (!cachedJWKS || cachedJWKSUrl !== jwksUrl) {
    cachedJWKS = createRemoteJWKSet(new URL(jwksUrl));
    cachedJWKSUrl = jwksUrl;
  }
  return cachedJWKS;
}
// WorkOS access tokens carry a fixed `iss` claim regardless of environment
// or client id; see
// https://workos.com/docs/reference/user-management/session-tokens/access-token.
// Validating it defends against tokens signed by a different WorkOS project
// whose JWKS happens to resolve to the same keys, and matches the team's
// "always validate iss" JWT rule.
//
// WorkOS access tokens do not carry a standard `aud` claim — the target
// client is encoded as `client_id` instead — so we do not pass `audience`
// to jwtVerify here; doing so would reject every token.
const WORKOS_JWT_ISSUER = 'https://api.workos.com';

async function verifyAccessToken(accessToken: string) {
  const JWKS = getJWKS();
  try {
    await jwtVerify(accessToken, JWKS, { issuer: WORKOS_JWT_ISSUER });
    return true;
  } catch (e) {
    return false;
  }
}

function getReturnPathname(url: string): string {
  const newUrl = new URL(url);

  // istanbul ignore next
  return `${newUrl.pathname}${newUrl.searchParams.size > 0 ? '?' + newUrl.searchParams.toString() : ''}`;
}
