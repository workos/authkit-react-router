import { sealData, unsealData } from 'iron-session';
import * as v from 'valibot';
import { getConfig } from './config.js';
import { StateSchema, type State } from './interfaces.js';

/**
 * The `__Host-` prefix makes the cookie host-only (no `Domain`), `Path=/`,
 * and `Secure`-required — structurally defeating cookie-tossing from sibling
 * subdomains. Browsers reject `__Host-` cookies without `Secure`, so a bare
 * fallback is needed for local HTTP dev only. See `cookie.ts` for selection.
 */
export const PKCE_COOKIE_NAME_SECURE = '__Host-wos-auth-verifier';
export const PKCE_COOKIE_NAME_INSECURE = 'wos-auth-verifier';
export const PKCE_COOKIE_MAX_AGE = 600;

export async function sealState(state: State): Promise<string> {
  return sealData(state, {
    password: getConfig('cookiePassword'),
    ttl: PKCE_COOKIE_MAX_AGE,
  });
}

/**
 * Unseal the PKCE cookie and validate the resulting shape. Throws if the
 * signature fails or the payload shape does not match `StateSchema`.
 */
export async function getStateFromPKCECookieValue(cookieValue: string): Promise<State> {
  const unsealed = await unsealData(cookieValue, {
    password: getConfig('cookiePassword'),
  });
  return v.parse(StateSchema, unsealed);
}
