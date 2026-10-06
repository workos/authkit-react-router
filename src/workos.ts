import { WorkOS } from '@workos-inc/node';
import { getConfig } from './config.js';
import { lazy } from './utils.js';

const VERSION = '0.10.0';

/**
 * Create a WorkOS instance from the AuthKit configuration.
 *
 * With an API key this is a confidential client. Without one it is a PKCE
 * public client: sign-in, callback, refresh and sign-out work, but WorkOS
 * management APIs (and feature flags) reject the request.
 *
 * Note: when no API key is configured, the WorkOS SDK itself falls back to
 * `process.env.WORKOS_API_KEY`. So if that variable is set in the process
 * environment, a key is always in play, even when a custom value source
 * passed to `configure()` doesn't provide one.
 */
export function createWorkOSInstance() {
  // Optional: absent means public-client (keyless) mode
  const apiKey = getConfig('apiKey');
  const clientId = getConfig('clientId');

  // Get optional settings
  const apiHostname = getConfig('apiHostname');
  const apiHttps = getConfig('apiHttps');
  const apiPort = getConfig('apiPort');

  // Initialize the WorkOS client with config values
  const workos = new WorkOS({
    apiKey,
    clientId,
    apiHostname,
    https: apiHttps,
    port: apiPort,
    appInfo: {
      name: 'authkit-react-router',
      version: VERSION,
    },
  });

  return workos;
}

/**
 * Returns the shared WorkOS client used by AuthKit.
 * This function is lazy loaded to avoid loading the WorkOS SDK when it's not needed.
 *
 * Calling WorkOS management APIs directly (e.g. `getWorkOS().organizations`,
 * `getWorkOS().userManagement.getUser`) requires an API key
 * (`WORKOS_API_KEY` or `configure({ apiKey })`). In public-client (keyless)
 * mode those calls throw an `ApiKeyRequiredException`.
 */
export const getWorkOS = lazy(createWorkOSInstance);
