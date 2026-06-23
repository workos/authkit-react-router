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
});
