import { getAuthorizationUrl } from './get-authorization-url.js';
import { getStateFromPKCECookieValue } from './pkce.js';
import { getConfig } from './config.js';

describe('getAuthorizationUrl', () => {
  it('returns { url, sealedState } and the URL points at WorkOS', async () => {
    const { url, sealedState } = await getAuthorizationUrl();
    expect(url).toMatch(/^https:\/\/api\.workos\.com\/user_management\/authorize\?/);
    expect(url).toContain(`client_id=${getConfig('clientId')}`);
    expect(url).toContain(`redirect_uri=${encodeURIComponent(getConfig('redirectUri'))}`);
    expect(url).toContain('provider=authkit');
    expect(typeof sealedState).toBe('string');
    expect(sealedState.length).toBeGreaterThan(0);
  });

  it('includes code_challenge and code_challenge_method=S256', async () => {
    const { url } = await getAuthorizationUrl();
    const parsed = new URL(url);
    expect(parsed.searchParams.get('code_challenge_method')).toBe('S256');
    const challenge = parsed.searchParams.get('code_challenge');
    expect(challenge).toBeTruthy();
    expect(challenge).toHaveLength(43);
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('sealed state contains a codeVerifier that round-trips', async () => {
    const { url, sealedState } = await getAuthorizationUrl();
    const state = await getStateFromPKCECookieValue(sealedState);
    expect(state.codeVerifier).toBeTruthy();
    expect(state.nonce).toBeTruthy();
    // URL state param equals sealedState
    const parsed = new URL(url);
    expect(parsed.searchParams.get('state')).toBe(sealedState);
  });

  it('threads screenHint into the URL', async () => {
    const { url } = await getAuthorizationUrl({ screenHint: 'sign-up' });
    expect(url).toContain('screen_hint=sign-up');
  });

  it('threads organizationId, loginHint, prompt into the URL', async () => {
    const { url } = await getAuthorizationUrl({
      organizationId: 'org_123',
      loginHint: 'user@example.com',
      prompt: 'consent',
    });
    expect(url).toContain('organization_id=org_123');
    expect(url).toContain(`login_hint=${encodeURIComponent('user@example.com')}`);
    expect(url).toContain('prompt=consent');
  });

  it('seals returnPathname into state when provided', async () => {
    const { sealedState } = await getAuthorizationUrl({ returnPathname: '/dashboard' });
    const state = await getStateFromPKCECookieValue(sealedState);
    expect(state.returnPathname).toBe('/dashboard');
  });

  it('sanitizes hostile returnPathname in sealed state', async () => {
    const { sealedState } = await getAuthorizationUrl({ returnPathname: 'https://evil.com' });
    const state = await getStateFromPKCECookieValue(sealedState);
    expect(state.returnPathname).toBe('/');
  });

  it('sanitizes protocol-relative returnPathname', async () => {
    const { sealedState } = await getAuthorizationUrl({ returnPathname: '//evil.com' });
    const state = await getStateFromPKCECookieValue(sealedState);
    expect(state.returnPathname).toBe('/');
  });

  it('threads customState into sealed state as customState', async () => {
    const { sealedState } = await getAuthorizationUrl({ state: 'my-custom' });
    const state = await getStateFromPKCECookieValue(sealedState);
    expect(state.customState).toBe('my-custom');
  });

  it('uses custom redirectUri when provided', async () => {
    const { url } = await getAuthorizationUrl({ redirectUri: 'https://other.example.com/cb' });
    expect(url).toContain(`redirect_uri=${encodeURIComponent('https://other.example.com/cb')}`);
  });

  it('each call uses a distinct nonce (multi-tab safety)', async () => {
    const a = await getAuthorizationUrl();
    const b = await getAuthorizationUrl();
    expect(a.sealedState).not.toBe(b.sealedState);
    const stateA = await getStateFromPKCECookieValue(a.sealedState);
    const stateB = await getStateFromPKCECookieValue(b.sealedState);
    expect(stateA.nonce).not.toBe(stateB.nonce);
    expect(stateA.codeVerifier).not.toBe(stateB.codeVerifier);
  });
});
