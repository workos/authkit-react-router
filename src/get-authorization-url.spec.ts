import { unsealData } from 'iron-session';
import type { LoaderFunctionArgs } from 'react-router';
import { authLoader } from './authkit-callback-route.js';
import { getWorkOS } from './workos.js';
import {
  assertIsResponse,
  createAuthWithCodeResponse,
  createRequestWithCookieAndParams,
} from './test-utils/test-helpers.js';
import { getAuthorizationUrl } from './get-authorization-url.js';
import { getConfig } from './config.js';
import { getPKCECookieNameForState, PKCE_COOKIE_NAME } from './pkce.js';
import type { PKCECookiePayload, State } from './interfaces.js';

describe('getAuthorizationUrl', () => {
  it('generates a valid WorkOS authorization URL with PKCE parameters', async () => {
    const { url } = await getAuthorizationUrl();

    expect(url).toMatch(/^https:\/\/api\.workos\.com\/user_management\/authorize\?/);
    expect(url).toContain(`client_id=${getConfig('clientId')}`);
    expect(url).toContain(`redirect_uri=${encodeURIComponent(getConfig('redirectUri'))}`);
    expect(url).toContain('provider=authkit');
    expect(url).toMatch(/code_challenge=[^&]+/);
    expect(url).toContain('code_challenge_method=S256');
  });

  it('seals return-trip state into the OAuth state parameter without the code verifier', async () => {
    const { url } = await getAuthorizationUrl({ returnPathname: '/dashboard' });
    const parsed = new URL(url);
    const state = parsed.searchParams.get('state');
    expect(state).toBeTruthy();

    const unsealed = await unsealData<State & { codeVerifier?: string }>(state!, {
      password: getConfig('cookiePassword'),
    });
    expect(unsealed.returnPathname).toBe('/dashboard');
    expect(unsealed.nonce).toEqual(expect.any(String));
    // The PKCE secret must never travel in the URL state.
    expect(unsealed.codeVerifier).toBeUndefined();
  });

  it('keeps the code verifier only in the HttpOnly cookie, not the URL', async () => {
    const { url, headers } = await getAuthorizationUrl();

    const state = new URL(url).searchParams.get('state')!;
    const setCookie = headers['Set-Cookie'];
    const cookieName = getPKCECookieNameForState(state);
    const cookieValue = setCookie.slice(`${cookieName}=`.length).split(';')[0];

    // The cookie value is a distinct sealed blob, NOT a copy of the URL state.
    expect(setCookie).toContain(`${cookieName}=`);
    expect(cookieValue).not.toBe(state);

    const stateNonce = (await unsealData<State>(state, { password: getConfig('cookiePassword') })).nonce;
    const cookie = await unsealData<PKCECookiePayload>(cookieValue, { password: getConfig('cookiePassword') });
    expect(cookie.codeVerifier).toEqual(expect.any(String));
    // The cookie is bound to the URL state via the shared nonce.
    expect(cookie.nonce).toBe(stateNonce);
  });

  it('emits a flow-specific PKCE cookie with the expected attributes', async () => {
    const { url, headers } = await getAuthorizationUrl();

    const state = new URL(url).searchParams.get('state')!;
    const setCookie = headers['Set-Cookie'];
    expect(setCookie).toContain(`${getPKCECookieNameForState(state)}=`);
    expect(setCookie).toContain('Path=/');
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('SameSite=Lax');
    expect(setCookie).toMatch(/Max-Age=600\b/);
  });

  it('gives concurrent flows distinct cookie names', async () => {
    const a = await getAuthorizationUrl();
    const b = await getAuthorizationUrl();

    const aName = a.headers['Set-Cookie'].split('=')[0];
    const bName = b.headers['Set-Cookie'].split('=')[0];
    expect(aName).toMatch(new RegExp(`^${PKCE_COOKIE_NAME}-[0-9a-f]{8}$`));
    expect(bName).toMatch(new RegExp(`^${PKCE_COOKIE_NAME}-[0-9a-f]{8}$`));
    expect(aName).not.toBe(bName);
  });

  it('accepts genuine concurrent callbacks with propagated cookies and custom state', async () => {
    const authenticateWithCode = jest
      .spyOn(getWorkOS().userManagement, 'authenticateWithCode')
      .mockResolvedValue(createAuthWithCodeResponse());
    const onSuccess = jest.fn();
    const loader = authLoader({ onSuccess });
    // A verifier property inside caller-supplied data is not legacy URL state.
    const customState = JSON.stringify({ codeVerifier: 'caller-data' });

    try {
      const flows = await Promise.all([
        getAuthorizationUrl({ state: customState, returnPathname: '/account' }),
        getAuthorizationUrl({ state: 'second-flow', returnPathname: '/dashboard' }),
      ]);
      const cookieHeader = flows.map(({ headers }) => headers['Set-Cookie'].split(';')[0]).join('; ');

      for (const [index, flow] of flows.entries()) {
        const state = new URL(flow.url).searchParams.get('state')!;
        const cookieName = getPKCECookieNameForState(state);
        const cookieValue = flow.headers['Set-Cookie'].slice(cookieName.length + 1).split(';')[0];
        const verifier = await unsealData<PKCECookiePayload>(cookieValue, { password: getConfig('cookiePassword') });
        const request = createRequestWithCookieAndParams(new Request('http://example.com/callback'), cookieHeader, {
          code: `test-code-${index}`,
          state,
        });

        const response = await loader({ request, params: {}, context: {} } as LoaderFunctionArgs);

        assertIsResponse(response);
        expect(response.status).toBe(302);
        expect(response.headers.get('Location')).toBe(`http://example.com${index === 0 ? '/account' : '/dashboard'}`);
        expect(authenticateWithCode).toHaveBeenNthCalledWith(index + 1, {
          clientId: getConfig('clientId'),
          code: `test-code-${index}`,
          codeVerifier: verifier.codeVerifier,
        });
        expect(onSuccess).toHaveBeenNthCalledWith(
          index + 1,
          expect.objectContaining({ state: index === 0 ? customState : 'second-flow' }),
        );
        const setCookies = response.headers.getSetCookie();
        expect(setCookies.some((cookie) => cookie.startsWith(`${getConfig('cookieName')}=`))).toBe(true);
        expect(setCookies.filter((cookie) => cookie.startsWith(`${PKCE_COOKIE_NAME}-`))).toEqual([
          expect.stringMatching(new RegExp(`^${cookieName}=;.*Max-Age=0`)),
        ]);
      }
    } finally {
      authenticateWithCode.mockRestore();
    }
  });

  it('includes screenHint when provided', async () => {
    const { url } = await getAuthorizationUrl({ screenHint: 'sign-up' });
    expect(url).toContain('screen_hint=sign-up');
  });

  it('forwards caller-provided custom state through the sealed payload', async () => {
    const { url } = await getAuthorizationUrl({ state: 'caller-state', returnPathname: '/foo' });
    const state = new URL(url).searchParams.get('state')!;
    const unsealed = await unsealData<State>(state, { password: getConfig('cookiePassword') });
    expect(unsealed.customState).toBe('caller-state');
    expect(unsealed.returnPathname).toBe('/foo');
  });
});
