import { authLoader } from './authkit-callback-route.js';
import { sealState, PKCE_COOKIE_NAME_INSECURE, PKCE_COOKIE_NAME_SECURE } from './pkce.js';
import { configureSessionStorage } from './sessionStorage.js';
import { isDataWithResponseInit } from './utils.js';
import type { DataWithResponseInit, State } from './interfaces.js';
import {
  assertIsResponse,
  createAuthWithCodeResponse,
  createRequestWithSearchParams,
} from './test-utils/test-helpers.js';
import { getWorkOS } from './workos.js';
import type { LoaderFunctionArgs } from 'react-router';

const fakeWorkosInstance = {
  userManagement: {
    authenticateWithCode: jest.fn(),
    getJwksUrl: jest.fn(() => 'https://api.workos.com/sso/jwks/client_1234567890'),
  },
};

jest.mock('./workos.js', () => ({
  getWorkOS: jest.fn(() => fakeWorkosInstance),
}));

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

async function buildValidRequest(opts: {
  code?: string | null;
  state?: string | null;
  cookieHeader?: string | null;
  baseUrl?: string;
} = {}) {
  const baseUrl = opts.baseUrl ?? 'http://example.com/callback';
  let request = new Request(baseUrl);
  const params: Record<string, string> = {};
  if (opts.code !== null) params.code = opts.code ?? 'test-code';
  if (opts.state !== null && opts.state !== undefined) params.state = opts.state;
  request = createRequestWithSearchParams(request, params);
  if (opts.cookieHeader) {
    request = new Request(request, { headers: { Cookie: opts.cookieHeader } });
  }
  return request;
}

function makeState(overrides: Partial<State> = {}): State {
  return {
    nonce: 'nonce-1',
    codeVerifier: 'verifier-1',
    returnPathname: '/dashboard',
    ...overrides,
  };
}

const workos = getWorkOS();
const authenticateWithCode = jest.mocked(workos.userManagement.authenticateWithCode);

describe('authLoader', () => {
  beforeAll(() => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    configureSessionStorage();
  });

  beforeEach(() => {
    authenticateWithCode.mockResolvedValue(createAuthWithCodeResponse());
  });

  describe('no-op paths', () => {
    it('returns undefined when there is no code', async () => {
      const loader = authLoader();
      const response = await loader({
        request: new Request('https://example.com'),
        params: {},
        context: {},
      } as LoaderFunctionArgs);
      expect(response).toBeUndefined();
    });
  });

  describe('error responses', () => {
    it('returns 500 when state is missing', async () => {
      const loader = authLoader();
      const request = await buildValidRequest({ state: null });
      const response = (await loader({
        request, params: {}, context: {},
      } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;
      expect(isDataWithResponseInit(response)).toBe(true);
      expect(response.init?.status).toBe(500);
    });

    it('returns 500 when the PKCE cookie is missing', async () => {
      const sealed = await sealState(makeState());
      const loader = authLoader();
      const request = await buildValidRequest({ state: sealed });
      const response = (await loader({
        request, params: {}, context: {},
      } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;
      expect(response.init?.status).toBe(500);
    });

    it('returns 500 when state and cookie do not byte-match', async () => {
      const sealedA = await sealState(makeState({ nonce: 'a' }));
      const sealedB = await sealState(makeState({ nonce: 'b' }));
      const loader = authLoader();
      const request = await buildValidRequest({
        state: sealedA,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealedB}`,
      });
      const response = (await loader({
        request, params: {}, context: {},
      } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;
      expect(response.init?.status).toBe(500);
    });

    it('returns 500 when the sealed state has been tampered', async () => {
      const sealed = await sealState(makeState());
      const tampered = sealed.slice(0, -1) + (sealed.slice(-1) === 'A' ? 'B' : 'A');
      const loader = authLoader();
      const request = await buildValidRequest({
        state: tampered,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${tampered}`,
      });
      const response = (await loader({
        request, params: {}, context: {},
      } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;
      expect(response.init?.status).toBe(500);
    });

    it('returns 500 when authenticateWithCode throws', async () => {
      authenticateWithCode.mockRejectedValue(new Error('Auth failed'));
      const sealed = await sealState(makeState());
      const loader = authLoader();
      const request = await buildValidRequest({
        state: sealed,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealed}`,
      });
      const response = (await loader({
        request, params: {}, context: {},
      } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;
      expect(response.init?.status).toBe(500);
    });

    it('emits PKCE cookie expiry on error responses', async () => {
      const loader = authLoader();
      const request = await buildValidRequest({ state: null });
      const response = (await loader({
        request, params: {}, context: {},
      } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;
      const headers = response.init?.headers as Headers;
      const setCookies = headers.getSetCookie();
      expect(setCookies.some((c) => c.includes(`${PKCE_COOKIE_NAME_INSECURE}=; `))).toBe(true);
      expect(setCookies.some((c) => c.includes(`${PKCE_COOKIE_NAME_SECURE}=; `))).toBe(true);
    });
  });

  describe('happy path', () => {
    it('threads codeVerifier through to authenticateWithCode', async () => {
      const state = makeState({ codeVerifier: 'my-verifier-789' });
      const sealed = await sealState(state);
      const loader = authLoader();
      const request = await buildValidRequest({
        state: sealed,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealed}`,
      });

      await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);

      expect(authenticateWithCode).toHaveBeenCalledWith({
        clientId: process.env.WORKOS_CLIENT_ID,
        code: 'test-code',
        codeVerifier: 'my-verifier-789',
      });
    });

    it('returns 302 to sealed-state returnPathname on success', async () => {
      const sealed = await sealState(makeState({ returnPathname: '/profile' }));
      const loader = authLoader();
      const request = await buildValidRequest({
        state: sealed,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealed}`,
      });
      const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
      assertIsResponse(response);
      expect(response.status).toBe(302);
      expect(response.headers.get('Location')).toBe('http://example.com/profile');
    });

    it('emits session cookie + expired PKCE cookie on success', async () => {
      const sealed = await sealState(makeState());
      const loader = authLoader();
      const request = await buildValidRequest({
        state: sealed,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealed}`,
      });
      const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
      assertIsResponse(response);
      const cookies = response.headers.getSetCookie();
      expect(cookies.length).toBeGreaterThanOrEqual(2);
      expect(cookies.some((c) => c.includes(`${PKCE_COOKIE_NAME_INSECURE}=; `))).toBe(true);
    });

    it('passes customState to onSuccess as state', async () => {
      const onSuccess = jest.fn();
      const sealed = await sealState(makeState({ customState: 'my-custom' }));
      const loader = authLoader({ onSuccess });
      const request = await buildValidRequest({
        state: sealed,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealed}`,
      });
      await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
      expect(onSuccess).toHaveBeenCalledWith(expect.objectContaining({ state: 'my-custom' }));
    });

    it('copies search params from sealed returnPathname', async () => {
      const sealed = await sealState(makeState({ returnPathname: '/dashboard?foo=bar' }));
      const loader = authLoader();
      const request = await buildValidRequest({
        state: sealed,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealed}`,
      });
      const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
      assertIsResponse(response);
      expect(response.headers.get('Location')).toBe('http://example.com/dashboard?foo=bar');
    });

    it('preserves hash fragment from sealed returnPathname', async () => {
      const sealed = await sealState(makeState({ returnPathname: '/dashboard#section-2' }));
      const loader = authLoader();
      const request = await buildValidRequest({
        state: sealed,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealed}`,
      });
      const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
      assertIsResponse(response);
      expect(response.headers.get('Location')).toBe('http://example.com/dashboard#section-2');
    });

    it('returns onSuccess impersonator + oauthTokens when provided', async () => {
      const onSuccess = jest.fn();
      authenticateWithCode.mockResolvedValue(
        createAuthWithCodeResponse({
          impersonator: { email: 'admin@example.com' },
          oauthTokens: {
            accessToken: 'a',
            refreshToken: 'r',
            expiresAt: 1,
            scopes: ['x'],
          },
        }),
      );
      const sealed = await sealState(makeState());
      const loader = authLoader({ onSuccess });
      const request = await buildValidRequest({
        state: sealed,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealed}`,
      });
      await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
      expect(onSuccess).toHaveBeenCalledWith(
        expect.objectContaining({
          impersonator: { email: 'admin@example.com' },
          oauthTokens: expect.objectContaining({ accessToken: 'a' }),
        }),
      );
    });
  });

  describe('cookie handling', () => {
    it('last-write-wins on duplicate PKCE cookies (takes the second value)', async () => {
      const sealedA = await sealState(makeState({ nonce: 'a' }));
      const sealedB = await sealState(makeState({ nonce: 'b' }));
      const loader = authLoader();
      // URL state matches the second cookie value (last-write wins) → should succeed.
      const request = await buildValidRequest({
        state: sealedB,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealedA}; ${PKCE_COOKIE_NAME_INSECURE}=${sealedB}`,
      });
      const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
      assertIsResponse(response);
      expect(response.status).toBe(302);
    });

    it('handles malformed Cookie header without crashing', async () => {
      const loader = authLoader();
      const request = await buildValidRequest({
        state: 'unused-state',
        cookieHeader: ';;=foo; =bar; justaname; trailing;',
      });
      const response = (await loader({
        request, params: {}, context: {},
      } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;
      // No cookie matched → 500 (missing cookie) but no crash
      expect(response.init?.status).toBe(500);
    });

    it('ignores bare fallback cookie when redirectUri is HTTPS (cookie-confusion defense)', async () => {
      await withRedirectUri('https://example.com/callback', async () => {
        const sealed = await sealState(makeState());
        const loader = authLoader();
        const request = await buildValidRequest({
          baseUrl: 'https://example.com/callback',
          state: sealed,
          cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealed}`,
        });
        const response = (await loader({
          request, params: {}, context: {},
        } as LoaderFunctionArgs)) as DataWithResponseInit<unknown>;
        expect(response.init?.status).toBe(500);
      });
    });

    it('accepts __Host- prefixed cookie when redirectUri is HTTPS', async () => {
      await withRedirectUri('https://example.com/callback', async () => {
        const sealed = await sealState(makeState());
        const loader = authLoader();
        const request = await buildValidRequest({
          baseUrl: 'https://example.com/callback',
          state: sealed,
          cookieHeader: `${PKCE_COOKIE_NAME_SECURE}=${sealed}`,
        });
        const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
        assertIsResponse(response);
        expect(response.status).toBe(302);
      });
    });

    it('accepts bare cookie when redirectUri is HTTP (local dev)', async () => {
      const sealed = await sealState(makeState());
      const loader = authLoader();
      const request = await buildValidRequest({
        state: sealed,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealed}`,
      });
      const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
      assertIsResponse(response);
      expect(response.status).toBe(302);
    });
  });

  describe('returnPathname sanitization', () => {
    it('redirects to configured option when sealed returnPathname is hostile', async () => {
      const sealed = await sealState(makeState({ returnPathname: 'https://evil.com' }));
      const loader = authLoader({ returnPathname: '/safe-default' });
      const request = await buildValidRequest({
        state: sealed,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealed}`,
      });
      const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
      assertIsResponse(response);
      expect(response.headers.get('Location')).toBe('http://example.com/safe-default');
    });

    it('falls back to / when both sealed and option are hostile', async () => {
      const sealed = await sealState(makeState({ returnPathname: '//evil.com' }));
      const loader = authLoader({ returnPathname: 'javascript:alert(1)' });
      const request = await buildValidRequest({
        state: sealed,
        cookieHeader: `${PKCE_COOKIE_NAME_INSECURE}=${sealed}`,
      });
      const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
      assertIsResponse(response);
      expect(response.headers.get('Location')).toBe('http://example.com/');
    });
  });

  describe('protocol mismatch fix (TLS-terminating LB)', () => {
    it('upgrades redirect to HTTPS when configured redirectUri is HTTPS', async () => {
      await withRedirectUri('https://example.com/callback', async () => {
        const sealed = await sealState(makeState({ returnPathname: '/' }));
        const loader = authLoader();
        const request = await buildValidRequest({
          baseUrl: 'http://example.com/callback',
          state: sealed,
          // redirectUri is HTTPS → bare is ignored. Use __Host- cookie.
          cookieHeader: `${PKCE_COOKIE_NAME_SECURE}=${sealed}`,
        });
        const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
        assertIsResponse(response);
        const location = response.headers.get('Location');
        expect(new URL(location!).protocol).toBe('https:');
      });
    });

    it('preserves port when fixing protocol mismatch', async () => {
      await withRedirectUri('https://example.com:8443/callback', async () => {
        const sealed = await sealState(makeState({ returnPathname: '/' }));
        const loader = authLoader();
        const request = await buildValidRequest({
          baseUrl: 'http://example.com:3000/callback',
          state: sealed,
          cookieHeader: `${PKCE_COOKIE_NAME_SECURE}=${sealed}`,
        });
        const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);
        assertIsResponse(response);
        const location = response.headers.get('Location');
        expect(location).toBe('https://example.com:3000/');
      });
    });
  });
});
