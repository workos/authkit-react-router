// Core functions
export { authLoader } from './authkit-callback-route.js';
export { authkitLoader, refreshSession, saveSession, SessionRefreshError, terminateSession } from './session.js';
export { getSignInUrl, getSignUpUrl, signOut, switchToOrganization, withAuth } from './auth.js';
export { getWorkOS } from './workos.js';

// Configuration
export { configure, getConfig } from './config.js';

// AuthKit service (for advanced use cases)
export { getAuthkit, resetAuthkit } from './authkit.js';

// Types
export type {
  AuthorizedData,
  UnauthorizedData,
  UserInfo,
  NoUserInfo,
  HandleAuthOptions,
  AuthKitLoaderOptions,
  Session,
  AuthResult,
  User,
  Impersonator,
  AccessToken,
  AuthKitConfig,
  RefreshErrorOptions,
  RefreshSuccessOptions,
  AuthLoaderSuccessData,
} from './interfaces.js';
