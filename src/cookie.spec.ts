import {
  buildExpiredPKCECookieHeaders,
  buildPKCECookieHeader,
  getPKCECookie,
  getPKCECookieHeaderAttrs,
  isInsecureRedirectUri,
} from './cookie.js';

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

describe('cookie', () => {
  describe('isInsecureRedirectUri', () => {
    it('returns true for http://', () => {
      withRedirectUri('http://localhost:5173/callback', () => {
        expect(isInsecureRedirectUri()).toBe(true);
      });
    });

    it('returns false for https://', () => {
      withRedirectUri('https://app.example.com/callback', () => {
        expect(isInsecureRedirectUri()).toBe(false);
      });
    });
  });

  describe('getPKCECookie', () => {
    it('uses __Host- name with Secure when HTTPS', () => {
      withRedirectUri('https://app.example.com/callback', () => {
        const { name, options } = getPKCECookie();
        expect(name).toBe('__Host-wos-auth-verifier');
        expect(options).toEqual({
          path: '/',
          httpOnly: true,
          secure: true,
          sameSite: 'lax',
          maxAge: 600,
          domain: undefined,
        });
      });
    });

    it('uses bare name without Secure when HTTP', () => {
      withRedirectUri('http://localhost:5173/callback', () => {
        const { name, options } = getPKCECookie();
        expect(name).toBe('wos-auth-verifier');
        expect(options.secure).toBe(false);
        expect(options.sameSite).toBe('lax');
        expect(options.domain).toBeUndefined();
      });
    });

    it('sets maxAge=0 when expired=true', () => {
      withRedirectUri('https://app.example.com/callback', () => {
        const { options } = getPKCECookie(true);
        expect(options.maxAge).toBe(0);
      });
    });
  });

  describe('getPKCECookieHeaderAttrs', () => {
    it('includes Secure when HTTPS', () => {
      withRedirectUri('https://app.example.com/callback', () => {
        const header = getPKCECookieHeaderAttrs();
        expect(header).toContain('Path=/');
        expect(header).toContain('HttpOnly');
        expect(header).toContain('SameSite=Lax');
        expect(header).toContain('Max-Age=600');
        expect(header).toContain('Secure');
      });
    });

    it('omits Secure when HTTP', () => {
      withRedirectUri('http://localhost:5173/callback', () => {
        const header = getPKCECookieHeaderAttrs();
        expect(header).not.toContain('Secure');
        expect(header).toContain('SameSite=Lax');
        expect(header).toContain('Max-Age=600');
      });
    });

    it('expired=true sets Max-Age=0 and adds Expires epoch', () => {
      withRedirectUri('https://app.example.com/callback', () => {
        const header = getPKCECookieHeaderAttrs(true);
        expect(header).toContain('Max-Age=0');
        expect(header).toContain('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
      });
    });
  });

  describe('buildPKCECookieHeader', () => {
    it('composes name=sealed-body + attrs', () => {
      withRedirectUri('https://app.example.com/callback', () => {
        const header = buildPKCECookieHeader('sealed-value-here');
        expect(header.startsWith('__Host-wos-auth-verifier=sealed-value-here; ')).toBe(true);
        expect(header).toContain('Secure');
      });
    });

    it('uses bare name when HTTP', () => {
      withRedirectUri('http://localhost:5173/callback', () => {
        const header = buildPKCECookieHeader('sealed-value-here');
        expect(header.startsWith('wos-auth-verifier=sealed-value-here; ')).toBe(true);
      });
    });

    it('expired=true produces empty body', () => {
      withRedirectUri('https://app.example.com/callback', () => {
        const header = buildPKCECookieHeader('sealed-value-here', true);
        expect(header.startsWith('__Host-wos-auth-verifier=;')).toBe(true);
      });
    });
  });

  describe('buildExpiredPKCECookieHeaders', () => {
    it('emits only __Host- expiry in HTTPS prod', () => {
      withRedirectUri('https://app.example.com/callback', () => {
        const headers = buildExpiredPKCECookieHeaders();
        expect(headers).toHaveLength(1);
        expect(headers[0].startsWith('__Host-wos-auth-verifier=;')).toBe(true);
      });
    });

    it('emits both names in HTTP dev', () => {
      withRedirectUri('http://localhost:5173/callback', () => {
        const headers = buildExpiredPKCECookieHeaders();
        expect(headers).toHaveLength(2);
        expect(headers[0].startsWith('__Host-wos-auth-verifier=;')).toBe(true);
        expect(headers[1].startsWith('wos-auth-verifier=;')).toBe(true);
      });
    });
  });
});
