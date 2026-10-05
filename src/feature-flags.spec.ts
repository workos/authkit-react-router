import type { FeatureFlagsRuntimeClient } from '@workos-inc/node';
import { getWorkOS } from './workos.js';

describe('feature flags', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    jest.resetModules();
  });

  it('memoizes the feature flags runtime client', async () => {
    const runtimeClient = {
      close: jest.fn(),
      getAllFlags: jest.fn(),
      getFlag: jest.fn(),
      getStats: jest.fn(),
      isEnabled: jest.fn(),
      waitUntilReady: jest.fn(),
    } as unknown as FeatureFlagsRuntimeClient;
    const createRuntimeClient = jest
      .spyOn(getWorkOS().featureFlags, 'createRuntimeClient')
      .mockReturnValue(runtimeClient);
    const { getFeatureFlagsRuntimeClient } = await import('./feature-flags.js');

    expect(getFeatureFlagsRuntimeClient({ pollingIntervalMs: 5000 })).toBe(runtimeClient);
    expect(getFeatureFlagsRuntimeClient({ pollingIntervalMs: 30000 })).toBe(runtimeClient);
    expect(createRuntimeClient).toHaveBeenCalledTimes(1);
    expect(createRuntimeClient).toHaveBeenCalledWith({ pollingIntervalMs: 5000 });
  });

  describe('without an API key', () => {
    let savedApiKey: string | undefined;

    beforeEach(() => {
      savedApiKey = process.env.WORKOS_API_KEY;
      delete process.env.WORKOS_API_KEY;
      jest.resetModules();
    });

    afterEach(() => {
      if (savedApiKey !== undefined) process.env.WORKOS_API_KEY = savedApiKey;
    });

    it('throws an actionable error before creating a client or calling the network', async () => {
      const fetchSpy = jest.spyOn(globalThis, 'fetch');
      const { getWorkOS: getKeylessWorkOS } = await import('./workos.js');
      const workos = getKeylessWorkOS();
      expect(workos.key).toBeUndefined();
      const createRuntimeClient = jest.spyOn(workos.featureFlags, 'createRuntimeClient');
      const { getFeatureFlagsRuntimeClient } = await import('./feature-flags.js');

      expect(() => getFeatureFlagsRuntimeClient()).toThrow(
        'Feature flags require a WorkOS API key; set WORKOS_API_KEY or configure({ apiKey }). ' +
          'Public-client (keyless) mode supports sign-in only.',
      );
      expect(createRuntimeClient).not.toHaveBeenCalled();
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });
});
