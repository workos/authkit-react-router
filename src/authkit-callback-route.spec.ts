import { getWorkOS } from './workos.js';
import { authLoader } from './authkit-callback-route.js';
import {
  assertIsResponse,
  createAuthWithCodeResponse,
  createRequestWithCookieAndParams,
  createRequestWithSearchParams,
  createSealedState,
} from './test-utils/test-helpers.js';
import { configureSessionStorage } from './sessionStorage.js';
import { isDataWithResponseInit } from './utils.js';
import { DataWithResponseInit } from './interfaces.js';
import type { LoaderFunctionArgs } from 'react-router';

// Mock dependencies
const fakeWorkosInstance = {
  userManagement: {
    authenticateWithCode: jest.fn(),
    getJwksUrl: jest.fn(() => 'https://api.workos.com/sso/jwks/client_1234567890'),
  },
};

jest.mock('./workos.js', () => ({
  getWorkOS: jest.fn(() => fakeWorkosInstance),
}));

describe('authLoader', () => {
  let loader: ReturnType<typeof authLoader>;
  let request: Request;
  let sealedState: string;
  let cookieHeader: string;
  let codeVerifier: string;
  const workos = getWorkOS();
  const authenticateWithCode = jest.mocked(workos.userManagement.authenticateWithCode);

  beforeAll(() => {
    // Silence console.error during tests
    jest.spyOn(console, 'error').mockImplementation(() => {});
    configureSessionStorage();
  });

  beforeEach(async () => {
    const mockAuthResponse = createAuthWithCodeResponse();
    authenticateWithCode.mockResolvedValue(mockAuthResponse);

    ({ sealedState, cookieHeader, codeVerifier } = await createSealedState());

    loader = authLoader();
    const url = new URL('http://example.com/callback');

    request = createRequestWithCookieAndParams(new Request(url), cookieHeader, {
      code: 'test-code',
      state: sealedState,
    });
  });

  describe('error handling', () => {
    it('returns undefined if there is no code', async () => {
      const response = await loader({
        request: new Request('https://example.com'),
        params: {},
        context: {},
      } as LoaderFunctionArgs);

      expect(response).toBeUndefined();
    });

    it('returns 500 when state is missing', async () => {
      request = createRequestWithSearchParams(new Request('http://example.com/callback'), {
        code: 'test-code',
      });
      const response = (await loader({
        request,
        params: {},
        context: {},
      } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;

      expect(isDataWithResponseInit(response)).toBeTruthy();
      expect(response?.init?.status).toBe(500);
    });

    it('returns 500 when PKCE cookie is missing (possible CSRF)', async () => {
      request = createRequestWithSearchParams(new Request('http://example.com/callback'), {
        code: 'test-code',
        state: sealedState,
      });
      const response = (await loader({
        request,
        params: {},
        context: {},
      } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;

      expect(isDataWithResponseInit(response)).toBeTruthy();
      expect(response?.init?.status).toBe(500);
      // Still clears the PKCE cookie even when it wasn't present — harmless and
      // matches the invariant that the cookie is always cleared post-callback.
      expect(findSetCookie(response?.init?.headers, 'wos-auth-verifier-')).toMatch(/Max-Age=0/);
    });

    it('returns 500 when state does not match the PKCE cookie value', async () => {
      // Valid cookie issued for a different flow
      const other = await createSealedState({ nonce: 'other' });
      request = createRequestWithCookieAndParams(new Request('http://example.com/callback'), other.cookieHeader, {
        code: 'test-code',
        state: sealedState,
      });
      const response = (await loader({
        request,
        params: {},
        context: {},
      } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;

      expect(isDataWithResponseInit(response)).toBeTruthy();
      expect(response?.init?.status).toBe(500);
      expect(authenticateWithCode).not.toHaveBeenCalled();
    });

    it('clears the PKCE cookie on authentication failure', async () => {
      authenticateWithCode.mockRejectedValue(new Error('Auth failed'));
      const response = (await loader({
        request,
        params: {},
        context: {},
      } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;

      expect(isDataWithResponseInit(response)).toBeTruthy();
      expect(response?.init?.status).toBe(500);
      expect(findSetCookie(response?.init?.headers, 'wos-auth-verifier-')).toMatch(/Max-Age=0/);
    });

    it('should handle authentication failure with string error', async () => {
      authenticateWithCode.mockRejectedValue('Auth failed');
      const response = (await loader({
        request,
        params: {},
        context: {},
      } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;
      expect(isDataWithResponseInit(response)).toBeTruthy();

      expect(response?.init?.status).toBe(500);
    });
  });

  it('passes the PKCE code verifier to authenticateWithCode', async () => {
    await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);

    expect(workos.userManagement.authenticateWithCode).toHaveBeenCalledWith({
      clientId: process.env.WORKOS_CLIENT_ID,
      code: 'test-code',
      codeVerifier,
    });
  });

  it('returns a response when a code is present', async () => {
    const response = await loader({
      request,
      params: {},
      context: {},
    } as LoaderFunctionArgs);

    assertIsResponse(response);
    expect(response.status).toBe(302);
    expect(response.headers.get('Set-Cookie')).toBeDefined();
  });

  it('clears the PKCE cookie on successful sign-in', async () => {
    const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);

    assertIsResponse(response);
    const setCookies = response.headers.getSetCookie();
    expect(setCookies.some((c) => c.startsWith('wos-auth-verifier-') && /Max-Age=0/.test(c))).toBe(true);
  });

  it('should redirect to the returnPathname', async () => {
    loader = authLoader({ returnPathname: '/dashboard' });
    const response = await loader({
      request,
      params: {},
      context: {},
    } as LoaderFunctionArgs);

    assertIsResponse(response);
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('http://example.com/dashboard');
  });

  it('copies search params from returnPathname', async () => {
    loader = authLoader({ returnPathname: '/dashboard?foo=bar' });
    const response = await loader({
      request,
      params: {},
      context: {},
    } as LoaderFunctionArgs);

    assertIsResponse(response);
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('http://example.com/dashboard?foo=bar');
  });

  it('preserves the fragment on the returnPathname', async () => {
    loader = authLoader({ returnPathname: '/dashboard#section' });
    const response = await loader({
      request,
      params: {},
      context: {},
    } as LoaderFunctionArgs);

    assertIsResponse(response);
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('http://example.com/dashboard#section');
  });

  it('preserves search params and fragment together', async () => {
    loader = authLoader({ returnPathname: '/dashboard?foo=bar#section' });
    const response = await loader({
      request,
      params: {},
      context: {},
    } as LoaderFunctionArgs);

    assertIsResponse(response);
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('http://example.com/dashboard?foo=bar#section');
  });

  it('falls back to the configured returnPathname when the sealed state value is hostile', async () => {
    // Simulate a tampered / hand-forged sealed state that bypasses the
    // sanitization in getAuthorizationUrl. The callback must reject the
    // hostile value and fall back to the configured option rather than
    // redirecting the user to an attacker-controlled destination.
    loader = authLoader({ returnPathname: '/dashboard' });
    const scoped = await createSealedState({ returnPathname: '//evil.com/pwn' });
    request = createRequestWithCookieAndParams(new Request('http://example.com/callback'), scoped.cookieHeader, {
      code: 'test-code',
      state: scoped.sealedState,
    });

    const response = await loader({
      request,
      params: {},
      context: {},
    } as LoaderFunctionArgs);

    assertIsResponse(response);
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('http://example.com/dashboard');
  });

  it('rejects a CRLF-smuggled returnPathname in the sealed state', async () => {
    loader = authLoader({ returnPathname: '/dashboard' });
    const scoped = await createSealedState({ returnPathname: '/foo\r\nSet-Cookie: bad' });
    request = createRequestWithCookieAndParams(new Request('http://example.com/callback'), scoped.cookieHeader, {
      code: 'test-code',
      state: scoped.sealedState,
    });

    const response = await loader({
      request,
      params: {},
      context: {},
    } as LoaderFunctionArgs);

    assertIsResponse(response);
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('http://example.com/dashboard');
  });

  it('handles calling onSuccess when provided', async () => {
    const onSuccess = jest.fn();
    loader = authLoader({ onSuccess });
    await loader({
      request,
      params: {},
      context: {},
    } as LoaderFunctionArgs);

    expect(onSuccess).toHaveBeenCalled();
  });

  it('uses returnPathname from the sealed state when provided', async () => {
    const scoped = await createSealedState({ returnPathname: '/profile' });
    request = createRequestWithCookieAndParams(new Request('http://example.com/callback'), scoped.cookieHeader, {
      code: 'test-code',
      state: scoped.sealedState,
    });

    const response = await loader({
      request,
      params: {},
      context: {},
    } as LoaderFunctionArgs);
    assertIsResponse(response);
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('http://example.com/profile');
  });

  it('forwards customState from the sealed state to onSuccess', async () => {
    const onSuccess = jest.fn();
    loader = authLoader({ onSuccess });

    const scoped = await createSealedState({ customState: 'caller-state' });
    request = createRequestWithCookieAndParams(new Request('http://example.com/callback'), scoped.cookieHeader, {
      code: 'test-code',
      state: scoped.sealedState,
    });

    await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
    expect(onSuccess).toHaveBeenCalledWith(expect.objectContaining({ state: 'caller-state' }));
  });

  it('provides impersonator to onSuccess callback when provided', async () => {
    const onSuccess = jest.fn();
    authenticateWithCode.mockResolvedValue(
      createAuthWithCodeResponse({
        impersonator: {
          email: 'test@example.com',
        },
      }),
    );

    loader = authLoader({ onSuccess });

    await loader({
      request,
      params: {},
      context: {},
    } as LoaderFunctionArgs);

    expect(onSuccess).toHaveBeenCalledWith(expect.objectContaining({ impersonator: { email: 'test@example.com' } }));
  });

  it('provides oauthTokens to onSuccess callback when provided', async () => {
    const onSuccess = jest.fn();
    authenticateWithCode.mockResolvedValue(
      createAuthWithCodeResponse({
        oauthTokens: {
          accessToken: 'access123',
          refreshToken: 'refresh123',
          expiresAt: 1719811200,
          scopes: ['foo', 'bar'],
        },
      }),
    );

    loader = authLoader({ onSuccess });

    await loader({
      request,
      params: {},
      context: {},
    } as LoaderFunctionArgs);

    expect(onSuccess).toHaveBeenCalledWith(
      expect.objectContaining({
        oauthTokens: expect.objectContaining({ accessToken: 'access123' }),
      }),
    );
  });

  it('fixes protocol mismatch for load balancer TLS termination', async () => {
    // Set WORKOS_REDIRECT_URI to HTTPS (as configured for production)
    const originalRedirectUri = process.env.WORKOS_REDIRECT_URI;
    process.env.WORKOS_REDIRECT_URI = 'https://example.com/callback';

    try {
      const scoped = await createSealedState();
      const req = createRequestWithCookieAndParams(new Request('http://example.com/callback'), scoped.cookieHeader, {
        code: 'test-code-123',
        state: scoped.sealedState,
      });

      const loader = authLoader();
      const response = await loader({
        request: req,
        params: {},
        context: {},
      } as LoaderFunctionArgs);

      // Should be a redirect response
      assertIsResponse(response);
      expect(response.status).toBe(302);

      // The redirect URL should be fixed to HTTPS (not HTTP)
      const location = response.headers.get('Location');
      expect(location).toBe('https://example.com/');
      expect(new URL(location!).protocol).toBe('https:');
    } finally {
      // Restore original env var
      if (originalRedirectUri) {
        process.env.WORKOS_REDIRECT_URI = originalRedirectUri;
      } else {
        delete process.env.WORKOS_REDIRECT_URI;
      }
    }
  });

  it('preserves port from request URL when fixing protocol mismatch', async () => {
    // Set WORKOS_REDIRECT_URI to HTTPS with different port
    const originalRedirectUri = process.env.WORKOS_REDIRECT_URI;
    process.env.WORKOS_REDIRECT_URI = 'https://example.com:8443/callback';

    try {
      const scoped = await createSealedState();
      const req = createRequestWithCookieAndParams(
        new Request('http://example.com:3000/callback'),
        scoped.cookieHeader,
        {
          code: 'test-code-123',
          state: scoped.sealedState,
        },
      );

      const loader = authLoader();
      const response = await loader({
        request: req,
        params: {},
        context: {},
      } as LoaderFunctionArgs);

      // Should be a redirect response
      assertIsResponse(response);
      expect(response.status).toBe(302);

      // The redirect URL should use HTTPS but preserve the request port (3000)
      // The redirect URL should use HTTPS and preserve the request port (3000)
      const location = response.headers.get('Location');
      expect(location).toBe('https://example.com:3000/');
      expect(new URL(location!).port).toBe('3000');
    } finally {
      // Restore original env var
      if (originalRedirectUri) {
        process.env.WORKOS_REDIRECT_URI = originalRedirectUri;
      } else {
        delete process.env.WORKOS_REDIRECT_URI;
      }
    }
  });
});

function findSetCookie(headers: HeadersInit | undefined, prefix: string): string | undefined {
  if (!headers) return undefined;
  const h = new Headers(headers);
  return h.getSetCookie().find((c) => c.startsWith(prefix));
}
