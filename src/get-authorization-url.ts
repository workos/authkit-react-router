import { getConfig } from './config.js';
import { getWorkOS } from './workos.js';
import { sealState } from './pkce.js';
import { generatePKCE } from './pkce-generator.js';
import { sanitizeReturnPathname } from './return-pathname.js';
import type { GetAuthURLOptions, GetAuthURLResult, State } from './interfaces.js';

export async function getAuthorizationUrl(options: GetAuthURLOptions = {}): Promise<GetAuthURLResult> {
  const {
    returnPathname,
    screenHint,
    organizationId,
    loginHint,
    prompt,
    state: customState,
    redirectUri,
  } = options;

  const pkce = await generatePKCE();

  const state: State = {
    nonce: crypto.randomUUID(),
    codeVerifier: pkce.codeVerifier,
    customState,
    returnPathname: returnPathname ? sanitizeReturnPathname(returnPathname) : undefined,
  };

  const sealedState = await sealState(state);

  const url = getWorkOS().userManagement.getAuthorizationUrl({
    provider: 'authkit',
    clientId: getConfig('clientId'),
    redirectUri: redirectUri ?? getConfig('redirectUri'),
    screenHint,
    organizationId,
    loginHint,
    prompt,
    state: sealedState,
    codeChallenge: pkce.codeChallenge,
    codeChallengeMethod: 'S256',
  });

  return { url, sealedState };
}
