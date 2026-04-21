import { getPKCECookieString } from './pkce.js';
import * as configModule from './config.js';

jest.mock('./config', () => ({
  getConfig: jest.fn(),
}));

const getConfig = jest.mocked(configModule.getConfig);

function cookieAttrs(cookie: string): Set<string> {
  return new Set(cookie.split(';').map((s) => s.trim()));
}

describe('getPKCECookieString', () => {
  const sealedState = 'sealed-state-value';

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Secure attribute', () => {
    it('uses the live request protocol over the configured redirectUri', () => {
      // Simulate the footgun: redirect URI is https but dev server is http.
      getConfig.mockImplementation((key: string) =>
        key === 'redirectUri' ? 'https://app.example.com/callback' : undefined,
      );

      const cookie = getPKCECookieString(sealedState, {
        request: new Request('http://localhost:5173/login'),
      });

      expect(cookieAttrs(cookie)).not.toContain('Secure');
    });

    it('marks the cookie Secure when the request is https', () => {
      getConfig.mockImplementation((key: string) => (key === 'redirectUri' ? 'http://localhost/callback' : undefined));

      const cookie = getPKCECookieString(sealedState, {
        request: new Request('https://app.example.com/login'),
      });

      expect(cookieAttrs(cookie)).toContain('Secure');
    });

    it('falls back to redirectUri when no request is supplied', () => {
      getConfig.mockImplementation((key: string) =>
        key === 'redirectUri' ? 'https://app.example.com/callback' : undefined,
      );

      expect(cookieAttrs(getPKCECookieString(sealedState))).toContain('Secure');

      getConfig.mockImplementation((key: string) => (key === 'redirectUri' ? 'http://localhost/callback' : undefined));

      expect(cookieAttrs(getPKCECookieString(sealedState))).not.toContain('Secure');
    });

    it('honors X-Forwarded-Proto=https behind a TLS-terminating proxy', () => {
      // TLS terminator forwards a plain http:// request upstream but the
      // public site is https://. The PKCE cookie must still be Secure.
      getConfig.mockImplementation((key: string) =>
        key === 'redirectUri' ? 'https://app.example.com/callback' : undefined,
      );

      const cookie = getPKCECookieString(sealedState, {
        request: new Request('http://internal.lb:8080/login', {
          headers: { 'X-Forwarded-Proto': 'https' },
        }),
      });

      expect(cookieAttrs(cookie)).toContain('Secure');
    });

    it('honors X-Forwarded-Proto=http even when request.url is https', () => {
      getConfig.mockImplementation((key: string) =>
        key === 'redirectUri' ? 'https://app.example.com/callback' : undefined,
      );

      const cookie = getPKCECookieString(sealedState, {
        request: new Request('https://internal.lb/login', {
          headers: { 'X-Forwarded-Proto': 'http' },
        }),
      });

      expect(cookieAttrs(cookie)).not.toContain('Secure');
    });

    it('uses the leftmost entry of a chained X-Forwarded-Proto header', () => {
      getConfig.mockImplementation((key: string) =>
        key === 'redirectUri' ? 'http://localhost/callback' : undefined,
      );

      const cookie = getPKCECookieString(sealedState, {
        request: new Request('http://internal.lb/login', {
          headers: { 'X-Forwarded-Proto': 'https, http' },
        }),
      });

      expect(cookieAttrs(cookie)).toContain('Secure');
    });

    it('prefers a per-call redirectUri override over the global config when no request is supplied', () => {
      // Global config says https, but this specific flow is being initiated
      // against a different redirect URI (e.g. a dev tunnel on http).
      getConfig.mockImplementation((key: string) =>
        key === 'redirectUri' ? 'https://app.example.com/callback' : undefined,
      );

      const cookie = getPKCECookieString(sealedState, {
        redirectUri: 'http://localhost:5173/callback',
      });

      expect(cookieAttrs(cookie)).not.toContain('Secure');
    });

    it('honors an explicit secure override over both request and redirectUri', () => {
      getConfig.mockImplementation((key: string) =>
        key === 'redirectUri' ? 'https://app.example.com/callback' : undefined,
      );

      const cookie = getPKCECookieString(sealedState, {
        request: new Request('https://app.example.com/login'),
        secure: false,
      });

      expect(cookieAttrs(cookie)).not.toContain('Secure');
    });

    it('defaults to Secure=true and warns when redirectUri is unparseable', () => {
      getConfig.mockImplementation((key: string) => (key === 'redirectUri' ? 'not a url' : undefined));

      const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
      try {
        const cookie = getPKCECookieString(sealedState);
        expect(cookieAttrs(cookie)).toContain('Secure');
        expect(warn).toHaveBeenCalledWith(expect.stringContaining('redirectUri'));
      } finally {
        warn.mockRestore();
      }
    });
  });

  describe('expired variant', () => {
    it('emits Max-Age=0 and an empty value so the browser clears the cookie', () => {
      getConfig.mockImplementation((key: string) =>
        key === 'redirectUri' ? 'https://app.example.com/callback' : undefined,
      );

      const cookie = getPKCECookieString(sealedState, { expired: true });

      expect(cookie).toMatch(/^wos-auth-verifier-[0-9a-f]{8}=;/);
      expect(cookieAttrs(cookie)).toContain('Max-Age=0');
    });
  });
});
