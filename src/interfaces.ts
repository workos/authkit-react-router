import type { SessionStorage, SessionIdStorageStrategy, data, SessionData } from 'react-router';
import type { AuthenticationResponse, OauthTokens, User } from '@workos-inc/node';
import * as v from 'valibot';

export type DataWithResponseInit<T> = ReturnType<typeof data<T>>;

export type UnwrapData<T> = T extends DataWithResponseInit<infer U> ? U : T;

export type HandleAuthOptions = {
  returnPathname?: string;
  onSuccess?: (data: AuthLoaderSuccessData) => void | Promise<void>;
} & (
  | {
      storage?: never;
      cookie?: SessionIdStorageStrategy['cookie'];
    }
  | {
      storage: SessionStorage;
      cookie: SessionIdStorageStrategy['cookie'];
    }
);

export interface AuthLoaderSuccessData {
  accessToken: string;
  impersonator: Impersonator | null;
  oauthTokens: OauthTokens | null;
  refreshToken: string;
  user: User;
  organizationId: string | null;
  authenticationMethod?: AuthenticationResponse['authenticationMethod'];
  state?: string;
}

export interface RefreshErrorOptions {
  error: unknown;
  request: Request;
  sessionData: SessionData;
}

export interface RefreshSuccessOptions {
  accessToken: string;
  user: User;
  impersonator: Impersonator | null;
  organizationId: string | null;
}

export interface Impersonator {
  email: string;
  reason: string | null;
}

export interface Session {
  accessToken: string;
  refreshToken: string;
  user: User;
  impersonator?: Impersonator;
  headers: Record<string, string>;
}

export interface AccessToken {
  sid: string;
  org_id?: string;
  role?: string;
  roles?: string[];
  permissions?: string[];
  entitlements?: string[];
  feature_flags?: string[];
}

export interface UserInfo {
  user: User;
  sessionId: string;
  organizationId?: string;
  role?: string;
  roles?: string[];
  permissions?: string[];
  entitlements?: string[];
  featureFlags?: string[];
  impersonator?: Impersonator;
  accessToken: string;
}

export interface NoUserInfo {
  user: null;
  sessionId?: undefined;
  organizationId?: undefined;
  role?: undefined;
  roles?: undefined;
  permissions?: undefined;
  entitlements?: undefined;
  featureFlags?: undefined;
  impersonator?: undefined;
  accessToken?: undefined;
}

export interface GetAuthURLOptions {
  screenHint?: 'sign-up' | 'sign-in';
  returnPathname?: string;
  organizationId?: string;
  redirectUri?: string;
  loginHint?: string;
  prompt?: 'consent';
  /**
   * Custom state value echoed back to `onSuccess` after a successful callback.
   * The library always generates its own internal OAuth `state` parameter so
   * that PKCE and CSRF protection cannot be bypassed — this value is sealed
   * alongside it for round-trip delivery only.
   */
  state?: string;
}

/**
 * Result of building an authorization URL. The caller must attach `headers`
 * to whatever redirect response they return so the short-lived PKCE /
 * CSRF-binding cookie is set on the browser before WorkOS redirects back.
 *
 * @example
 * const { url, headers } = await getSignInUrl('/dashboard');
 * return redirect(url, { headers });
 */
export interface GetAuthURLResult {
  url: string;
  headers: { 'Set-Cookie': string };
}

/**
 * Sealed state stored in the PKCE cookie and round-tripped through WorkOS as
 * the OAuth `state` parameter. `codeVerifier` is the PKCE secret that binds
 * the authorization code to this browser session.
 */
export const StateSchema = v.object({
  nonce: v.string(),
  customState: v.optional(v.string()),
  returnPathname: v.optional(v.string()),
  codeVerifier: v.string(),
});

export type State = v.InferOutput<typeof StateSchema>;

export type AuthKitLoaderOptions = {
  ensureSignedIn?: boolean;
  debug?: boolean;
  onSessionRefreshError?: (options: RefreshErrorOptions) => void | Response | Promise<void | Response>;
  onSessionRefreshSuccess?: (options: RefreshSuccessOptions) => void | Promise<void>;
} & (
  | {
      storage?: never;
      cookie?: SessionIdStorageStrategy['cookie'];
    }
  | {
      storage: SessionStorage;
      cookie: SessionIdStorageStrategy['cookie'];
    }
);

export interface AuthorizedData {
  user: User;
  sessionId: string;
  organizationId: string | null;
  role: string | null;
  roles: string[] | null;
  permissions: string[];
  entitlements: string[];
  featureFlags: string[];
  impersonator: Impersonator | null;
}

export interface UnauthorizedData {
  user: null;
  sessionId: null;
  organizationId: null;
  role: null;
  roles: null;
  permissions: null;
  entitlements: null;
  featureFlags: null;
  impersonator: null;
}

/**
 * AuthKit Configuration Options
 */
export interface AuthKitConfig {
  /**
   * The WorkOS Client ID
   * Equivalent to the WORKOS_CLIENT_ID environment variable
   */
  clientId: string;

  /**
   * The WorkOS API Key
   * Equivalent to the WORKOS_API_KEY environment variable
   */
  apiKey: string;

  /**
   * The redirect URI for the authentication callback
   * Equivalent to the WORKOS_REDIRECT_URI environment variable
   */
  redirectUri: string;

  /**
   * The password used to encrypt the session cookie
   * Equivalent to the WORKOS_COOKIE_PASSWORD environment variable
   * Must be at least 32 characters long
   */
  cookiePassword: string;

  /**
   * The hostname of the API to use
   * Equivalent to the WORKOS_API_HOSTNAME environment variable
   */
  apiHostname?: string;

  /**
   * Whether to use HTTPS for API requests
   * Equivalent to the WORKOS_API_HTTPS environment variable
   */
  apiHttps: boolean;

  /**
   * The port to use for the API
   * Equivalent to the WORKOS_API_PORT environment variable
   */
  apiPort?: number;

  /**
   * The maximum age of the session cookie in seconds
   * Equivalent to the WORKOS_COOKIE_MAX_AGE environment variable
   */
  cookieMaxAge: number;

  /**
   * The name of the session cookie
   * Equivalent to the WORKOS_COOKIE_NAME environment variable
   * Defaults to "wos-session"
   */
  cookieName: string;
}
