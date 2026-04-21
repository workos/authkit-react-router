import { generatePKCE } from './pkce-generator.js';

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

describe('generatePKCE', () => {
  it('returns a 43-char base64url codeVerifier', async () => {
    const { codeVerifier } = await generatePKCE();
    expect(codeVerifier).toHaveLength(43);
    expect(codeVerifier).toMatch(BASE64URL_RE);
    expect(codeVerifier).not.toMatch(/[+/=]/);
  });

  it('returns a 43-char base64url codeChallenge', async () => {
    const { codeChallenge } = await generatePKCE();
    expect(codeChallenge).toHaveLength(43);
    expect(codeChallenge).toMatch(BASE64URL_RE);
    expect(codeChallenge).not.toMatch(/[+/=]/);
  });

  it('codeChallenge is SHA-256(codeVerifier) base64url-encoded', async () => {
    const { codeVerifier, codeChallenge } = await generatePKCE();
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
    const bytes = new Uint8Array(digest);
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    const expected = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(codeChallenge).toBe(expected);
  });

  it('matches RFC 7636 Appendix B vector', async () => {
    // From RFC 7636 Appendix B:
    // code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    // code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    const bytes = new Uint8Array(digest);
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    const challenge = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('produces different values on successive calls (randomness)', async () => {
    const a = await generatePKCE();
    const b = await generatePKCE();
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
    expect(a.codeChallenge).not.toBe(b.codeChallenge);
  });
});
