import { unsealData } from 'iron-session';
import { getAuthorizationUrl } from './get-authorization-url.js';
import { getConfig } from './config.js';
import { getPKCECookieNameForState, PKCE_COOKIE_NAME } from './pkce.js';
import type { State } from './interfaces.js';

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

  it('seals return-trip state into the OAuth state parameter', async () => {
    const { url } = await getAuthorizationUrl({ returnPathname: '/dashboard' });
    const parsed = new URL(url);
    const state = parsed.searchParams.get('state');
    expect(state).toBeTruthy();

    const unsealed = await unsealData<State>(state!, { password: getConfig('cookiePassword') });
    expect(unsealed.returnPathname).toBe('/dashboard');
    expect(unsealed.codeVerifier).toEqual(expect.any(String));
    expect(unsealed.nonce).toEqual(expect.any(String));
  });

  it('emits a flow-specific PKCE cookie tied to the sealed state', async () => {
    const { url, headers } = await getAuthorizationUrl();

    const state = new URL(url).searchParams.get('state')!;
    const setCookie = headers['Set-Cookie'];
    expect(setCookie).toContain(`${getPKCECookieNameForState(state)}=${state}`);
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
