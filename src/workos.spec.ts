import type { AuthKitConfig } from './interfaces.js';

describe('workos', () => {
  const config = {
    apiKey: 'sk_test_1234567890',
    clientId: 'client_1234567890',
    cookiePassword: 'kR620keEzOIzPThfnMEAba8XYgKdQ5vg',
    redirectUri: 'http://localhost:5173/callback',
    cookieDomain: 'example.com',
    apiHostname: 'api.workos.com',
  } as const;

  let configure: (config: Partial<AuthKitConfig>) => void;

  beforeEach(async () => {
    jest.resetModules();
    ({ configure } = await import('./config.js'));
  });

  it('should initialize WorkOS with correct API key and options', async () => {
    configure({ ...config });
    const { getWorkOS } = await import('./workos.js');
    const workos = getWorkOS();

    expect(workos).toBeDefined();
    expect(workos.options.apiHostname).toBe(config.apiHostname);
    expect(workos.options.https).toBe(true);
    expect(workos.options.port).toBeUndefined();
    expect(workos.options.appInfo).toEqual({
      name: 'authkit-react-router',
      version: expect.any(String),
    });
  });

  it('sets https when apiHttps is set', async () => {
    configure({ ...config, apiHttps: false });
    const { getWorkOS } = await import('./workos.js');
    const workos = getWorkOS();

    expect(workos.options.https).toBe(false);
  });

  describe('client construction', () => {
    const publicConfig = {
      clientId: config.clientId,
      cookiePassword: config.cookiePassword,
      redirectUri: config.redirectUri,
      apiHostname: config.apiHostname,
    };
    let savedApiKey: string | undefined;
    let WorkOSMock: jest.Mock;

    beforeEach(() => {
      savedApiKey = process.env.WORKOS_API_KEY;
      WorkOSMock = jest.fn();
      jest.doMock('@workos-inc/node', () => ({ WorkOS: WorkOSMock }));
    });

    afterEach(() => {
      jest.dontMock('@workos-inc/node');
      if (savedApiKey !== undefined) process.env.WORKOS_API_KEY = savedApiKey;
    });

    it('passes apiKey and clientId in confidential mode', async () => {
      configure({ ...config });
      const { createWorkOSInstance } = await import('./workos.js');
      createWorkOSInstance();

      expect(WorkOSMock).toHaveBeenCalledTimes(1);
      expect(WorkOSMock).toHaveBeenCalledWith({
        apiKey: process.env.WORKOS_API_KEY,
        clientId: process.env.WORKOS_CLIENT_ID,
        apiHostname: config.apiHostname,
        https: true,
        port: undefined,
        appInfo: { name: 'authkit-react-router', version: expect.any(String) },
      });
      expect(WorkOSMock.mock.calls[0]).toHaveLength(1);
    });

    it('passes clientId and no apiKey in public mode', async () => {
      delete process.env.WORKOS_API_KEY;
      configure({ ...publicConfig });
      const { createWorkOSInstance } = await import('./workos.js');
      createWorkOSInstance();

      expect(WorkOSMock).toHaveBeenCalledTimes(1);
      const [options] = WorkOSMock.mock.calls[0];
      expect(options.apiKey).toBeUndefined();
      expect(options.clientId).toBe(process.env.WORKOS_CLIENT_ID);
    });

    it('builds a real keyless client in public mode', async () => {
      jest.dontMock('@workos-inc/node');
      delete process.env.WORKOS_API_KEY;
      configure({ ...publicConfig });
      const { getWorkOS } = await import('./workos.js');
      const workos = getWorkOS();

      expect(workos.key).toBeUndefined();
      expect(workos.clientId).toBe(process.env.WORKOS_CLIENT_ID);
    });

    it('picks up WORKOS_API_KEY from process.env even when a custom value source omits it', async () => {
      // Documented behavior: the WorkOS SDK falls back to process.env, so a key
      // in the process environment always ends up on the client.
      jest.dontMock('@workos-inc/node');
      process.env.WORKOS_API_KEY = 'sk_test_from_process_env';
      const { configure: configureSource } = await import('./config.js');
      configureSource((key: string) => (key === 'WORKOS_API_KEY' ? undefined : process.env[key]));
      const { getWorkOS } = await import('./workos.js');

      expect(getWorkOS().key).toBe('sk_test_from_process_env');
    });
  });

  it('sets the port when provided', async () => {
    configure({ ...config, apiPort: 3000 });
    const { getWorkOS } = await import('./workos.js');
    const workos = getWorkOS();

    expect(workos.options.port).toBe(3000);
  });
});
