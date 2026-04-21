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

  it('sets the port when provided', async () => {
    configure({ ...config, apiPort: 3000 });
    const { getWorkOS } = await import('./workos.js');
    const workos = getWorkOS();

    expect(workos.options.port).toBe(3000);
  });
});
