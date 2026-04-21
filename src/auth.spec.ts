import { User } from '@workos-inc/node';
import {
  getSignInUrl,
  getSignUpUrl,
  redirectToSignIn,
  redirectToSignUp,
  signOut,
  switchToOrganization,
  withAuth,
} from './auth.js';
import * as authorizationUrl from './get-authorization-url.js';
import * as session from './session.js';
import * as configModule from './config.js';
import { data, redirect, LoaderFunctionArgs } from 'react-router';
import { assertIsResponse } from './test-utils/test-helpers.js';

const terminateSession = jest.mocked(session.terminateSession);
const refreshSession = jest.mocked(session.refreshSession);
const getSessionFromCookie = jest.mocked(session.getSessionFromCookie);
const getClaimsFromAccessToken = jest.mocked(session.getClaimsFromAccessToken);
const getConfig = jest.mocked(configModule.getConfig);

jest.mock('./session', () => ({
  terminateSession: jest.fn().mockResolvedValue(new Response()),
  refreshSession: jest.fn(),
  getSessionFromCookie: jest.fn(),
  getClaimsFromAccessToken: jest.fn(),
}));

jest.mock('./config', () => ({
  getConfig: jest.fn(),
}));

function envDelegatingGetConfig(key: string): unknown {
  if (key === 'redirectUri') return process.env.WORKOS_REDIRECT_URI;
  if (key === 'cookieName') return 'wos-session';
  if (key === 'clientId') return process.env.WORKOS_CLIENT_ID;
  if (key === 'cookiePassword') return process.env.WORKOS_COOKIE_PASSWORD;
  return undefined;
}

jest.mock('react-router', () => {
  const originalModule = jest.requireActual('react-router');
  return {
    ...originalModule,
    redirect: jest.fn().mockImplementation((to, init) => {
      const response = new Response(null, {
        status: 302,
        headers: { Location: to, ...(init?.headers || {}) },
      });
      return response;
    }),
    data: jest.fn().mockImplementation((value, init) => ({
      data: value,
      init,
    })),
  };
});

async function withRedirectUri(value: string, fn: () => void | Promise<void>) {
  const prev = process.env.WORKOS_REDIRECT_URI;
  process.env.WORKOS_REDIRECT_URI = value;
  try {
    await fn();
  } finally {
    if (prev !== undefined) {
      process.env.WORKOS_REDIRECT_URI = prev;
    } else {
      delete process.env.WORKOS_REDIRECT_URI;
    }
  }
}

describe('auth', () => {
  beforeEach(() => {
    jest.spyOn(authorizationUrl, 'getAuthorizationUrl');
    getConfig.mockImplementation(envDelegatingGetConfig as typeof configModule.getConfig);
  });

  describe('getSignInUrl (deprecated throwing stub)', () => {
    it('throws with CWE reference and migration URL', async () => {
      await expect(getSignInUrl('/test')).rejects.toThrow(/CWE-352/);
      await expect(getSignInUrl('/test')).rejects.toThrow(/SECURITY\.md/);
    });

    it('throws even with no argument', async () => {
      await expect(getSignInUrl()).rejects.toThrow(/redirectToSignIn/);
    });
  });

  describe('getSignUpUrl (deprecated throwing stub)', () => {
    it('throws with CWE reference and migration URL', async () => {
      await expect(getSignUpUrl()).rejects.toThrow(/CWE-352/);
      await expect(getSignUpUrl()).rejects.toThrow(/redirectToSignUp/);
    });
  });

  describe('redirectToSignIn', () => {
    it('returns a 302 Response with Location + __Host- PKCE cookie when HTTPS', async () => {
      await withRedirectUri('https://app.example.com/callback', async () => {
        (authorizationUrl.getAuthorizationUrl as jest.Mock).mockResolvedValueOnce({
          url: 'https://api.workos.com/user_management/authorize?foo=bar',
          sealedState: 'sealed-abc',
        });

        const response = await redirectToSignIn();
        expect(response.status).toBe(302);
        expect(response.headers.get('Location')).toBe(
          'https://api.workos.com/user_management/authorize?foo=bar',
        );
        const cookies = response.headers.getSetCookie();
        expect(cookies).toHaveLength(1);
        expect(cookies[0]).toMatch(/^__Host-wos-auth-verifier=sealed-abc; /);
        expect(cookies[0]).toContain('Secure');
        expect(cookies[0]).toContain('HttpOnly');
        expect(cookies[0]).toContain('SameSite=Lax');
      });
    });

    it('uses bare cookie name when HTTP redirectUri', async () => {
      await withRedirectUri('http://localhost:5173/callback', async () => {
        (authorizationUrl.getAuthorizationUrl as jest.Mock).mockResolvedValueOnce({
          url: 'https://api.workos.com/user_management/authorize',
          sealedState: 'sealed-abc',
        });

        const response = await redirectToSignIn();
        const cookies = response.headers.getSetCookie();
        expect(cookies[0]).toMatch(/^wos-auth-verifier=sealed-abc; /);
        expect(cookies[0]).not.toContain('Secure');
      });
    });

    it('threads screenHint=sign-in into getAuthorizationUrl', async () => {
      (authorizationUrl.getAuthorizationUrl as jest.Mock).mockResolvedValueOnce({
        url: 'https://api.workos.com/x',
        sealedState: 's',
      });
      await redirectToSignIn({ returnTo: '/dashboard', organizationId: 'org_1' });
      expect(authorizationUrl.getAuthorizationUrl).toHaveBeenCalledWith(
        expect.objectContaining({
          returnPathname: '/dashboard',
          organizationId: 'org_1',
          screenHint: 'sign-in',
        }),
      );
    });
  });

  describe('redirectToSignUp', () => {
    it('threads screenHint=sign-up into getAuthorizationUrl', async () => {
      (authorizationUrl.getAuthorizationUrl as jest.Mock).mockResolvedValueOnce({
        url: 'https://api.workos.com/x',
        sealedState: 's',
      });
      await redirectToSignUp({ returnTo: '/welcome' });
      expect(authorizationUrl.getAuthorizationUrl).toHaveBeenCalledWith(
        expect.objectContaining({
          returnPathname: '/welcome',
          screenHint: 'sign-up',
        }),
      );
    });

    it('returns Response with Set-Cookie for PKCE', async () => {
      await withRedirectUri('https://app.example.com/callback', async () => {
        (authorizationUrl.getAuthorizationUrl as jest.Mock).mockResolvedValueOnce({
          url: 'https://api.workos.com/authorize',
          sealedState: 'sealed-xyz',
        });
        const response = await redirectToSignUp();
        expect(response.status).toBe(302);
        const cookies = response.headers.getSetCookie();
        expect(cookies[0]).toContain('__Host-wos-auth-verifier=sealed-xyz');
      });
    });
  });

  describe('signOut', () => {
    it('should return a response', async () => {
      const request = new Request('https://example.com');
      const response = await signOut(request);
      expect(response).toBeInstanceOf(Response);
      expect(terminateSession).toHaveBeenCalledWith(request, undefined);
    });

    it('should return a response with returnTo', async () => {
      const request = new Request('https://example.com');
      const returnTo = '/dashboard';
      const response = await signOut(request, { returnTo });
      expect(response).toBeInstanceOf(Response);
      expect(terminateSession).toHaveBeenCalledWith(request, { returnTo });
    });
  });

  describe('switchToOrganization', () => {
    const request = new Request('https://example.com');
    const organizationId = 'org_123456';

    const mockUser = {
      id: 'user-1',
      email: 'test@example.com',
      emailVerified: true,
      firstName: 'Test',
      lastName: 'User',
      profilePictureUrl: 'https://example.com/avatar.jpg',
      object: 'user',
      createdAt: '2021-01-01T00:00:00Z',
      updatedAt: '2021-01-01T00:00:00Z',
      lastSignInAt: '2021-01-01T00:00:00Z',
      externalId: null,
      locale: null,
      metadata: {},
    } satisfies User;

    const mockAuthResponse = {
      user: mockUser,
      sessionId: 'session-123',
      accessToken: 'new-access-token',
      organizationId: 'org_123456' as string | undefined,
      role: 'admin' as string | undefined,
      roles: ['admin'] as string[] | undefined,
      permissions: ['read', 'write'] as string[] | undefined,
      entitlements: ['premium'] as string[] | undefined,
      featureFlags: ['flag-1', 'flag-2'] as string[] | undefined,
      impersonator: null,
      sealedSession: 'sealed-session-data',
      headers: {
        'Set-Cookie': 'new-cookie-value',
      },
    };

    beforeEach(() => {
      refreshSession.mockResolvedValue(mockAuthResponse);
    });

    it('should call refreshSession with the correct params', async () => {
      await switchToOrganization(request, organizationId);
      expect(refreshSession).toHaveBeenCalledWith(request, { organizationId });
    });

    it('should return data with success and auth when no returnTo is provided', async () => {
      const result = await switchToOrganization(request, organizationId);
      expect(data).toHaveBeenCalledWith(
        { success: true, auth: mockAuthResponse },
        { headers: { 'Set-Cookie': 'new-cookie-value' } },
      );
      expect(result).toEqual({
        data: { success: true, auth: mockAuthResponse },
        init: { headers: { 'Set-Cookie': 'new-cookie-value' } },
      });
    });

    it('should redirect to returnTo when provided', async () => {
      const returnTo = '/dashboard';
      const result = await switchToOrganization(request, organizationId, { returnTo });
      expect(redirect).toHaveBeenCalledWith(returnTo, {
        headers: { 'Set-Cookie': 'new-cookie-value' },
      });
      assertIsResponse(result);
      expect(result.status).toBe(302);
    });

    it('should handle case when refreshSession throws a redirect', async () => {
      const redirectResponse = new Response(null, {
        status: 302,
        headers: { Location: '/login' },
      });
      refreshSession.mockRejectedValueOnce(redirectResponse);

      try {
        await switchToOrganization(request, organizationId);
        fail('Expected redirect response to be thrown');
      } catch (response) {
        assertIsResponse(response);
        expect(response.status).toBe(302);
      }
    });

    it('should redirect with PKCE cookie for SSO_required errors', async () => {
      await withRedirectUri('https://app.example.com/callback', async () => {
        const authUrl = 'https://api.workos.com/sso/authorize';
        refreshSession.mockRejectedValueOnce(
          new Error('SSO Required', { cause: { error: 'sso_required' } }),
        );
        (authorizationUrl.getAuthorizationUrl as jest.Mock).mockResolvedValueOnce({
          url: authUrl,
          sealedState: 'sealed-sso',
        });

        const result = await switchToOrganization(request, organizationId);
        expect(authorizationUrl.getAuthorizationUrl).toHaveBeenCalledWith({ organizationId });
        assertIsResponse(result);
        expect(result.status).toBe(302);
        expect(result.headers.get('Location')).toBe(authUrl);
        const cookies = result.headers.getSetCookie();
        expect(cookies[0]).toMatch(/^__Host-wos-auth-verifier=sealed-sso; /);
      });
    });

    it('should redirect with PKCE cookie for mfa_enrollment errors', async () => {
      await withRedirectUri('https://app.example.com/callback', async () => {
        const authUrl = 'https://api.workos.com/sso/authorize';
        refreshSession.mockRejectedValueOnce(
          new Error('MFA Enrollment Required', { cause: { error: 'mfa_enrollment' } }),
        );
        (authorizationUrl.getAuthorizationUrl as jest.Mock).mockResolvedValueOnce({
          url: authUrl,
          sealedState: 'sealed-mfa',
        });

        const result = await switchToOrganization(request, organizationId);
        assertIsResponse(result);
        expect(result.status).toBe(302);
        const cookies = result.headers.getSetCookie();
        expect(cookies[0]).toContain('sealed-mfa');
      });
    });

    it('should return error data for Error instances', async () => {
      const error = new Error('Invalid organization');
      refreshSession.mockRejectedValueOnce(error);

      const result = await switchToOrganization(request, organizationId);
      expect(data).toHaveBeenCalledWith(
        { success: false, error: 'Invalid organization' },
        { status: 400 },
      );
      expect(result).toEqual({
        data: { success: false, error: 'Invalid organization' },
        init: { status: 400 },
      });
    });

    it('should return error data for non-Error objects', async () => {
      refreshSession.mockRejectedValueOnce('String error message');
      await switchToOrganization(request, organizationId);
      expect(data).toHaveBeenCalledWith(
        { success: false, error: 'String error message' },
        { status: 400 },
      );
    });

    it('should handle when Set-Cookie header is missing', async () => {
      refreshSession.mockResolvedValueOnce({ ...mockAuthResponse, headers: {} });
      await switchToOrganization(request, organizationId);
      expect(data).toHaveBeenCalledWith(
        { success: true, auth: { ...mockAuthResponse, headers: {} } },
        { headers: { 'Set-Cookie': '' } },
      );
    });

    it('should handle when returnTo is provided but Set-Cookie header is missing', async () => {
      refreshSession.mockResolvedValueOnce({ ...mockAuthResponse, headers: {} });
      await switchToOrganization(request, organizationId, { returnTo: '/dashboard' });
      expect(redirect).toHaveBeenCalledWith('/dashboard', {
        headers: { 'Set-Cookie': '' },
      });
    });
  });

  describe('withAuth', () => {
    const createMockRequest = (cookie?: string) => {
      return {
        request: new Request('https://example.com', {
          headers: cookie ? { Cookie: cookie } : {},
        }),
      } as LoaderFunctionArgs;
    };

    beforeEach(() => {
      jest.clearAllMocks();
      getConfig.mockImplementation(envDelegatingGetConfig as typeof configModule.getConfig);
    });

    it('should return user info when a valid session exists', async () => {
      const mockSession = {
        accessToken: 'valid-access-token',
        refreshToken: 'refresh-token',
        user: {
          id: 'user-1',
          email: 'test@example.com',
          firstName: 'Test',
          lastName: 'User',
          emailVerified: true,
          profilePictureUrl: 'https://example.com/profile.jpg',
          object: 'user' as const,
          createdAt: '2023-01-01T00:00:00Z',
          updatedAt: '2023-01-01T00:00:00Z',
          lastSignInAt: '2023-01-01T00:00:00Z',
          externalId: null,
          locale: null,
          metadata: {},
        } satisfies User,
        impersonator: { email: 'admin@example.com', reason: 'testing' },
        headers: {},
      };

      const mockClaims = {
        sessionId: 'session-123',
        organizationId: 'org-456',
        role: 'admin',
        roles: ['admin'],
        permissions: ['read', 'write'],
        entitlements: ['feature-1', 'feature-2'],
        featureFlags: ['flag-1', 'flag-2'],
        exp: Date.now() / 1000 + 3600,
        iss: 'https://api.workos.com',
      };

      getSessionFromCookie.mockResolvedValue(mockSession);
      getClaimsFromAccessToken.mockReturnValue(mockClaims);

      const result = await withAuth(createMockRequest('wos-session=valid-session-data'));

      expect(getSessionFromCookie).toHaveBeenCalledWith('wos-session=valid-session-data');
      expect(getClaimsFromAccessToken).toHaveBeenCalledWith('valid-access-token');
      expect(result).toEqual({
        user: mockSession.user,
        sessionId: mockClaims.sessionId,
        organizationId: mockClaims.organizationId,
        role: mockClaims.role,
        roles: mockClaims.roles,
        permissions: mockClaims.permissions,
        entitlements: mockClaims.entitlements,
        featureFlags: mockClaims.featureFlags,
        impersonator: mockSession.impersonator,
        accessToken: mockSession.accessToken,
      });
    });

    it('should handle expired access tokens', async () => {
      const mockSession = {
        accessToken: 'expired-access-token',
        refreshToken: 'refresh-token',
        user: {
          id: 'user-1',
          email: 'test@example.com',
          firstName: 'Test',
          lastName: 'User',
          emailVerified: true,
          profilePictureUrl: 'https://example.com/profile.jpg',
          object: 'user' as const,
          createdAt: '2023-01-01T00:00:00Z',
          updatedAt: '2023-01-01T00:00:00Z',
          lastSignInAt: '2023-01-01T00:00:00Z',
          externalId: null,
          locale: null,
          metadata: {},
        } satisfies User,
        headers: {},
      };

      const mockClaims = {
        sessionId: 'session-123',
        organizationId: 'org-456',
        role: 'admin',
        roles: ['admin'],
        permissions: ['read', 'write'],
        entitlements: ['feature-1', 'feature-2'],
        featureFlags: ['flag-1', 'flag-2'],
        exp: Date.now() / 1000 - 3600,
        iss: 'https://api.workos.com',
      };

      getSessionFromCookie.mockResolvedValue(mockSession);
      getClaimsFromAccessToken.mockReturnValue(mockClaims);

      const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
      const result = await withAuth(createMockRequest('wos-session=expired-session-data'));

      expect(consoleWarnSpy).toHaveBeenCalledWith(
        '[AuthKit] Access token expired. Ensure authkitLoader is used in a parent/root route to handle automatic token refresh.',
      );
      expect(result).toEqual({ user: null });
      consoleWarnSpy.mockRestore();
    });

    it('should return NoUserInfo when no session exists', async () => {
      getSessionFromCookie.mockResolvedValue(null);
      const result = await withAuth(createMockRequest());
      expect(result).toEqual({ user: null });
      expect(getClaimsFromAccessToken).not.toHaveBeenCalled();
    });

    it('should return NoUserInfo when session exists but has no access token', async () => {
      getSessionFromCookie.mockResolvedValue({
        user: {
          id: 'user-1',
          email: 'test@example.com',
          firstName: 'Test',
          lastName: 'User',
          emailVerified: true,
          profilePictureUrl: 'https://example.com/profile.jpg',
          object: 'user' as const,
          createdAt: '2023-01-01T00:00:00Z',
          updatedAt: '2023-01-01T00:00:00Z',
          lastSignInAt: '2023-01-01T00:00:00Z',
          externalId: null,
          locale: null,
          metadata: {},
        } satisfies User,
        refreshToken: 'refresh-token',
        headers: {},
        accessToken: '',
      });

      const result = await withAuth(createMockRequest('wos-session=invalid-session-data'));
      expect(result).toEqual({ user: null });
      expect(getClaimsFromAccessToken).not.toHaveBeenCalled();
    });

    it('should warn when no cookie header includes the cookie name', async () => {
      const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
      getSessionFromCookie.mockResolvedValue(null);
      await withAuth(createMockRequest('other-cookie=value'));
      expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('No session cookie "wos-session" found.'));
      consoleWarnSpy.mockRestore();
    });
  });
});
