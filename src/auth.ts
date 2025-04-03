import { getAuthorizationUrl } from './get-authorization-url.js';
import { terminateSession } from './session.js';

export async function getSignInUrl(returnPathname?: string) {
  return getAuthorizationUrl({ returnPathname, screenHint: 'sign-in' });
}

export async function getSignUpUrl(returnPathname?: string) {
  return getAuthorizationUrl({ returnPathname, screenHint: 'sign-up' });
}

export async function signOut(request: Request) {
  return await terminateSession(request);
}
