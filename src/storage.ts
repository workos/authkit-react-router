import { CookieSessionStorage } from '@workos/authkit-session';

/**
 * React Router cookie session storage adapter.
 * Extends CookieSessionStorage to handle Request/Response cookie operations.
 */
export class ReactRouterCookieSessionStorage extends CookieSessionStorage<Request, Response> {
  /**
   * Extract encrypted session from Request cookies
   */
  async getSession(request: Request): Promise<string | null> {
    const cookieHeader = request.headers.get('Cookie');
    if (!cookieHeader) return null;

    const cookies = this.parseCookies(cookieHeader);
    const value = cookies[this.cookieName];
    return value ? decodeURIComponent(value) : null;
  }

  /**
   * Parse cookie header string into key-value pairs
   */
  private parseCookies(cookieHeader: string): Record<string, string> {
    return Object.fromEntries(
      cookieHeader.split(';').map((cookie) => {
        const [key, ...valueParts] = cookie.trim().split('=');
        return [key, valueParts.join('=')];
      }),
    );
  }
}
