import { createCookieSessionStorage, type SessionStorage } from 'react-router';
import { CookieSessionStorage } from '@workos/authkit-session';
import type { AuthKitConfig } from '@workos/authkit-session';

type HeadersBag = Record<string, string | string[]>;

/**
 * React Router cookie session storage adapter.
 *
 * Uses React Router's createCookieSessionStorage internally to maintain
 * backwards compatibility with the previous cookie format. The iron-sealed
 * session data is stored in a 'jwt' field within the React Router session.
 */
export class ReactRouterCookieSessionStorage extends CookieSessionStorage<Request, Response> {
  private sessionStorage: SessionStorage | null = null;
  private readonly password: string;

  constructor(config: AuthKitConfig) {
    super(config);
    this.password = config.cookiePassword;
  }

  /**
   * Lazily initialize React Router session storage
   */
  private getSessionStorage(): SessionStorage {
    if (!this.sessionStorage) {
      this.sessionStorage = createCookieSessionStorage({
        cookie: {
          name: this.cookieName,
          path: '/',
          httpOnly: true,
          secure: this.cookieOptions?.secure ?? true,
          sameSite: 'lax',
          maxAge: this.cookieOptions?.maxAge,
          domain: this.cookieOptions?.domain,
          secrets: [this.password],
        },
      });
    }
    return this.sessionStorage;
  }

  /**
   * Extract encrypted session from Request cookies.
   * Uses React Router session storage to handle cookie signing/parsing.
   */
  override async getSession(request: Request): Promise<string | null> {
    const cookieHeader = request.headers.get('Cookie');
    if (!cookieHeader) return null;

    try {
      const storage = this.getSessionStorage();
      const session = await storage.getSession(cookieHeader);

      // Extract the iron-sealed data from the 'jwt' field
      const jwt = session.get('jwt');
      return typeof jwt === 'string' ? jwt : null;
    } catch {
      // Invalid or corrupted session cookie
      return null;
    }
  }

  /**
   * Save encrypted session to Response.
   * Uses React Router session storage to handle cookie signing.
   */
  override async saveSession(
    response: Response | undefined,
    sessionData: string,
  ): Promise<{ response?: Response; headers?: HeadersBag }> {
    const storage = this.getSessionStorage();
    const session = await storage.getSession();

    // Store iron-sealed data in 'jwt' field (matches old format)
    session.set('jwt', sessionData);

    const cookie = await storage.commitSession(session);

    if (response) {
      response.headers.append('Set-Cookie', cookie);
      return { response };
    }

    return { headers: { 'Set-Cookie': cookie } };
  }

  /**
   * Clear the session cookie.
   */
  override async clearSession(
    response: Response,
  ): Promise<{ response?: Response; headers?: HeadersBag }> {
    const storage = this.getSessionStorage();
    const session = await storage.getSession();
    const cookie = await storage.destroySession(session);

    response.headers.append('Set-Cookie', cookie);
    return { response };
  }
}
