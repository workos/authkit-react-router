import { createAuthService, type AuthService } from '@workos/authkit-session';
import { ReactRouterCookieSessionStorage } from './storage.js';

let authkitInstance: AuthService<Request, Response> | null = null;

/**
 * Get the AuthKit service instance.
 * Uses lazy initialization - creates the service on first call.
 */
export function getAuthkit(): AuthService<Request, Response> {
  if (!authkitInstance) {
    authkitInstance = createAuthService({
      sessionStorageFactory: (config) => new ReactRouterCookieSessionStorage(config),
    });
  }
  return authkitInstance;
}

/**
 * Reset the AuthKit instance.
 * Useful for testing.
 */
export function resetAuthkit(): void {
  authkitInstance = null;
}

export type { AuthService };
