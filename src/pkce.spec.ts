import {
  PKCE_COOKIE_MAX_AGE,
  PKCE_COOKIE_NAME_INSECURE,
  PKCE_COOKIE_NAME_SECURE,
  getStateFromPKCECookieValue,
  sealState,
} from './pkce.js';
import type { State } from './interfaces.js';

const validState: State = {
  nonce: 'nonce-abc',
  codeVerifier: 'verifier-123',
  returnPathname: '/dashboard',
  customState: 'custom',
};

describe('pkce', () => {
  describe('constants', () => {
    it('exports the secure and insecure cookie names', () => {
      expect(PKCE_COOKIE_NAME_SECURE).toBe('__Host-wos-auth-verifier');
      expect(PKCE_COOKIE_NAME_INSECURE).toBe('wos-auth-verifier');
    });

    it('uses a 10-minute TTL', () => {
      expect(PKCE_COOKIE_MAX_AGE).toBe(600);
    });
  });

  describe('sealState / getStateFromPKCECookieValue', () => {
    it('round-trips a full state object', async () => {
      const sealed = await sealState(validState);
      expect(typeof sealed).toBe('string');
      expect(sealed.length).toBeGreaterThan(0);

      const unsealed = await getStateFromPKCECookieValue(sealed);
      expect(unsealed).toEqual(validState);
    });

    it('round-trips with only required fields', async () => {
      const minimal: State = { nonce: 'n', codeVerifier: 'v' };
      const sealed = await sealState(minimal);
      const unsealed = await getStateFromPKCECookieValue(sealed);
      expect(unsealed).toEqual(minimal);
    });

    it('rejects a tampered sealed value', async () => {
      const sealed = await sealState(validState);
      const tampered = sealed.slice(0, -1) + (sealed.slice(-1) === 'A' ? 'B' : 'A');
      await expect(getStateFromPKCECookieValue(tampered)).rejects.toThrow();
    });

    it('rejects arbitrary garbage', async () => {
      await expect(getStateFromPKCECookieValue('not-a-sealed-value')).rejects.toThrow();
    });

    it('rejects a payload missing codeVerifier (schema enforcement)', async () => {
      // seal something that unseals to a wrong shape — iron-session round-trips
      // whatever the caller gives it, but the schema parse should reject.
      const { sealData } = await import('iron-session');
      const bogus = await sealData(
        { nonce: 'n' }, // missing codeVerifier
        { password: process.env.WORKOS_COOKIE_PASSWORD!, ttl: 600 },
      );
      await expect(getStateFromPKCECookieValue(bogus)).rejects.toThrow();
    });

    it('produces a different sealed string for each call (nonce randomness)', async () => {
      const a = await sealState({ ...validState, nonce: 'nonce-1' });
      const b = await sealState({ ...validState, nonce: 'nonce-2' });
      expect(a).not.toBe(b);
    });
  });
});
