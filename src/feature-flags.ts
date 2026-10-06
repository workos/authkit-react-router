import type { FeatureFlagsRuntimeClient, RuntimeClientOptions } from '@workos-inc/node';
import { lazy } from './utils.js';
import { getWorkOS } from './workos.js';

export const FEATURE_FLAGS_API_KEY_REQUIRED =
  'Feature flags require a WorkOS API key; set WORKOS_API_KEY or configure({ apiKey }). ' +
  'Public-client (keyless) mode supports sign-in only.';

/**
 * Returns a shared WorkOS Feature Flags runtime client.
 *
 * The runtime client keeps feature flag state in sync in the background, so it
 * should be created once per server process instead of once per request.
 * Options are only used when the client is created for the first time.
 *
 * Requires a WorkOS API key (`WORKOS_API_KEY` or `configure({ apiKey })`).
 * Throws in public-client (keyless) mode.
 */
export const getFeatureFlagsRuntimeClient = lazy((options?: RuntimeClientOptions): FeatureFlagsRuntimeClient => {
  const workos = getWorkOS();
  // Check the client's effective key (which includes the SDK's own
  // WORKOS_API_KEY env fallback) so this matches what requests would send.
  if (!workos.key) {
    throw new Error(FEATURE_FLAGS_API_KEY_REQUIRED);
  }
  return workos.featureFlags.createRuntimeClient(options);
});
