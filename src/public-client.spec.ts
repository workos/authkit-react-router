/**
 * Wire-level tests for public-client (keyless) mode.
 *
 * These drive the real sign-in callback and refresh paths against the real
 * WorkOS SDK, with only `fetch` mocked, and assert on the request body the SDK
 * actually sends to `/user_management/authenticate`.
 */
import type { LoaderFunctionArgs } from 'react-router';

const API_KEY = 'sk_test_confidential';

function base64url(value: object) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

// Decoded (never verified) by the refresh path to read claims.
const accessToken = `${base64url({ alg: 'none' })}.${base64url({
  sid: 'session_123',
  exp: Math.floor(Date.now() / 1000) + 300,
})}.sig`;

function authenticateResponse(refreshToken: string) {
  return new Response(
    JSON.stringify({
      user: {
        object: 'user',
        id: 'user_123',
        email: 'test@example.com',
        email_verified: true,
        first_name: 'Test',
        last_name: 'User',
        profile_picture_url: null,
        last_sign_in_at: null,
        locale: null,
        external_id: null,
        metadata: {},
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      },
      access_token: accessToken,
      refresh_token: refreshToken,
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

function cookiePair(setCookie: string) {
  return setCookie.split(';')[0];
}

describe.each([
  ['public client (no API key)', undefined],
  ['confidential client (API key)', API_KEY],
] as const)('%s', (_label, apiKey) => {
  let savedApiKey: string | undefined;
  let originalFetch: typeof fetch;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    jest.resetModules();
    savedApiKey = process.env.WORKOS_API_KEY;
    if (apiKey) {
      process.env.WORKOS_API_KEY = apiKey;
    } else {
      delete process.env.WORKOS_API_KEY;
    }
    // The SDK binds globalThis.fetch when the client is constructed.
    originalFetch = globalThis.fetch;
    fetchMock = jest.fn();
    globalThis.fetch = fetchMock;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    if (savedApiKey !== undefined) {
      process.env.WORKOS_API_KEY = savedApiKey;
    } else {
      delete process.env.WORKOS_API_KEY;
    }
  });

  function lastAuthenticateCall() {
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe('https://api.workos.com/user_management/authenticate');
    const headers = new Headers(init.headers);
    return { body: JSON.parse(init.body), authorization: headers.get('Authorization') };
  }

  it('exchanges the code and refreshes the session with the expected client credentials', async () => {
    const { getWorkOS } = await import('./workos.js');
    expect(getWorkOS().key).toBe(apiKey);

    const { configureSessionStorage } = await import('./sessionStorage.js');
    const { getAuthorizationUrl } = await import('./get-authorization-url.js');
    const { authLoader } = await import('./authkit-callback-route.js');
    const { refreshSession } = await import('./session.js');
    await configureSessionStorage();

    // 1. Start sign-in: PKCE challenge in the URL, verifier in a cookie.
    const { url, headers } = await getAuthorizationUrl();
    const authorizationUrl = new URL(url);
    expect(authorizationUrl.searchParams.get('code_challenge')).toBeTruthy();
    expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256');
    const state = authorizationUrl.searchParams.get('state')!;

    // 2. Callback: exchange the code.
    fetchMock.mockResolvedValueOnce(authenticateResponse('refresh_1'));
    const callbackUrl = new URL(process.env.WORKOS_REDIRECT_URI!);
    callbackUrl.searchParams.set('code', 'code_123');
    callbackUrl.searchParams.set('state', state);
    const callbackResponse = (await authLoader()({
      request: new Request(callbackUrl, { headers: { Cookie: cookiePair(headers['Set-Cookie']) } }),
      params: {},
      context: {},
    } as LoaderFunctionArgs)) as Response;
    expect(callbackResponse.status).toBe(302);

    const exchange = lastAuthenticateCall();
    expect(exchange.body).toMatchObject({
      grant_type: 'authorization_code',
      client_id: process.env.WORKOS_CLIENT_ID,
      code: 'code_123',
      code_verifier: expect.any(String),
    });
    if (apiKey) {
      expect(exchange.body.client_secret).toBe(apiKey);
      expect(exchange.authorization).toBe(`Bearer ${apiKey}`);
    } else {
      expect(exchange.body).not.toHaveProperty('client_secret');
      expect(exchange.authorization).toBeNull();
    }

    // 3. Refresh the session using the sealed session cookie.
    fetchMock.mockClear();
    fetchMock.mockResolvedValueOnce(authenticateResponse('refresh_2'));
    const sessionCookie = callbackResponse.headers.getSetCookie().find((c) => c.startsWith('wos-session='))!;
    const refreshed = await refreshSession(
      new Request('http://localhost:5173/', { headers: { Cookie: cookiePair(sessionCookie) } }),
    );
    expect(refreshed.user?.id).toBe('user_123');
    expect(refreshed.sessionId).toBe('session_123');

    const refresh = lastAuthenticateCall();
    expect(refresh.body).toMatchObject({
      grant_type: 'refresh_token',
      client_id: process.env.WORKOS_CLIENT_ID,
      refresh_token: 'refresh_1',
    });
    if (apiKey) {
      expect(refresh.body.client_secret).toBe(apiKey);
      expect(refresh.authorization).toBe(`Bearer ${apiKey}`);
    } else {
      expect(refresh.body).not.toHaveProperty('client_secret');
      expect(refresh.authorization).toBeNull();
    }
  });
});
