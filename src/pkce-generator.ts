export interface PKCEPair {
  codeVerifier: string;
  codeChallenge: string;
}

/** RFC 7636 S256 PKCE generator using Web Crypto (Node ≥20). */
export async function generatePKCE(): Promise<PKCEPair> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const codeVerifier = base64urlEncode(bytes);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  const codeChallenge = base64urlEncode(new Uint8Array(digest));
  return { codeVerifier, codeChallenge };
}

function base64urlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
