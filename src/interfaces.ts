import type { SessionData, data } from 'react-router';
import type { OauthTokens } from '@workos-inc/node';

// Re-export types from authkit-session
export type {
  Session as AuthkitSession,
  AuthResult,
  User,
  Impersonator,
  BaseTokenClaims as AccessToken,
} from '@workos/authkit-session';

// Import types for internal use
import type { User, Impersonator, BaseTokenClaims } from '@workos/authkit-session';

export type DataWithResponseInit<T> = ReturnType<typeof data<T>>;

export type UnwrapData<T> = T extends DataWithResponseInit<infer U> ? U : T;

export type HandleAuthOptions = {
  returnPathname?: string;
  onSuccess?: (data: AuthLoaderSuccessData) => void | Promise<void>;
};

export interface AuthLoaderSuccessData {
  accessToken: string;
  impersonator: Impersonator | null;
  oauthTokens: OauthTokens | null;
  refreshToken: string;
  user: User;
  organizationId: string | null;
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

/**
 * Session type for React Router (includes headers for cookie management)
 */
export interface Session {
  accessToken: string;
  refreshToken: string;
  user: User;
  impersonator?: Impersonator;
  headers: Record<string, string>;
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
}

export type AuthKitLoaderOptions = {
  ensureSignedIn?: boolean;
  debug?: boolean;
  onSessionRefreshError?: (options: RefreshErrorOptions) => void | Response | Promise<void | Response>;
  onSessionRefreshSuccess?: (options: RefreshSuccessOptions) => void | Promise<void>;
};

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

// Re-export AuthKitConfig from authkit-session
export type { AuthKitConfig } from '@workos/authkit-session';
