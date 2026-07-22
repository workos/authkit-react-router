/* istanbul ignore file */

import type { User } from '@workos-inc/node';
import { sealData } from 'iron-session';
import { getConfig } from '../config.js';
import { getPKCECookieNameForState } from '../pkce.js';
import type { State } from '../interfaces.js';

type SearchParamsModifier = Record<string, string> | ((params: URLSearchParams) => void);

/**
 * Asserts that the given value is a Response object.
 * This is useful for type guards and uses Jest's expect to throw an error if the value is not a Response.
 * @param response - The value to assert is a Response object.
 */
export function assertIsResponse(response: unknown): asserts response is Response {
  expect(response).toBeInstanceOf(Response);
}

/**
 * Creates a new Request object with the given search parameters.
 * @param request - The original Request object.
 * @param modifier - The search parameters to add or modify.
 * @returns A new Request object with the modified search parameters.
 */
export function createRequestWithSearchParams(request: Request, modifier: SearchParamsModifier): Request {
  const url = new URL(request.url);

  if (typeof modifier === 'function') {
    // Allow direct manipulation of searchParams
    modifier(url.searchParams);
  } else {
    // Simple key-value setting
    Object.entries(modifier).forEach(([key, value]) => {
      url.searchParams.set(key, value);
    });
  }

  return new Request(url, request);
}

/**
 * Build a sealed PKCE state value and matching Cookie header, the way
 * `getAuthorizationUrl` would emit them on the outbound redirect.
 *
 * Returns `{ sealedState, cookieHeader, codeVerifier }` — pass `sealedState`
 * as the URL's `state` search param and `cookieHeader` as the inbound
 * `Cookie` header in the callback request.
 */
export async function createSealedState(
  overrides: Partial<State & { codeVerifier: string }> = {},
): Promise<{ sealedState: string; cookieHeader: string; codeVerifier: string }> {
  const nonce = overrides.nonce ?? 'test-nonce';
  const codeVerifier = overrides.codeVerifier ?? 'test-code-verifier';

  // The OAuth `state` URL param carries no secret — only the nonce and any
  // caller flow metadata.
  const state: State = {
    nonce,
    customState: overrides.customState,
    returnPathname: overrides.returnPathname,
  };
  const sealedState = await sealData(state, { password: getConfig('cookiePassword') });

  // The PKCE verifier lives only in the HttpOnly cookie, sealed separately and
  // bound to the same nonce.
  const sealedVerifier = await sealData({ nonce, codeVerifier }, { password: getConfig('cookiePassword') });
  const cookieHeader = `${getPKCECookieNameForState(sealedState)}=${sealedVerifier}`;
  return { sealedState, cookieHeader, codeVerifier };
}

/**
 * Mutate an existing Request to include the given `Cookie` header plus the
 * given search params, returning a fresh Request instance.
 */
export function createRequestWithCookieAndParams(
  request: Request,
  cookieHeader: string,
  modifier: SearchParamsModifier,
): Request {
  const next = createRequestWithSearchParams(request, modifier);
  const headers = new Headers(next.headers);
  // Append rather than set so callers can stack cookies
  const existing = headers.get('Cookie');
  headers.set('Cookie', existing ? `${existing}; ${cookieHeader}` : cookieHeader);
  return new Request(next.url, { ...next, headers, body: next.body });
}

/**
 * Creates a mock WorkOS authentication response object.
 * @param overrides - Any properties to override in the mock response.
 * @returns A mock WorkOS authentication response object.
 */
export function createAuthWithCodeResponse(overrides: Record<string, unknown> = {}) {
  return {
    accessToken: 'access123',
    refreshToken: 'refresh123',
    user: {
      id: 'user_123',
      email: 'test@example.com',
      emailVerified: true,
      profilePictureUrl: 'https://example.com/photo.jpg',
      firstName: 'Test',
      lastName: 'User',
      object: 'user' as const,
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      lastSignInAt: '2024-01-01T00:00:00Z',
      externalId: null,
      locale: null,
      metadata: {},
    } satisfies User,
    ...overrides,
  };
}
