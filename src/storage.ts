import { CookieSessionStorage } from '@workos/authkit-session';

/**
 * React Router cookie session storage adapter.
 * Extends CookieSessionStorage to handle Request/Response cookie operations.
 *
 * Includes backwards compatibility for migrating from the old cookie format
 * (React Router session storage wrapping iron-session) to the new format
 * (iron-session directly).
 */
export class ReactRouterCookieSessionStorage extends CookieSessionStorage<Request, Response> {
  /**
   * Extract encrypted session from Request cookies.
   * Handles both new format (iron-session directly) and legacy format
   * (React Router session storage with jwt field).
   */
  async getSession(request: Request): Promise<string | null> {
    const cookieHeader = request.headers.get('Cookie');
    if (!cookieHeader) return null;

    const cookies = this.parseCookies(cookieHeader);
    const value = cookies[this.cookieName];
    if (!value) return null;

    const decoded = decodeURIComponent(value);

    // New format: iron-session sealed data starts with "Fe26."
    if (decoded.startsWith('Fe26.')) {
      return decoded;
    }

    // Legacy format: React Router session storage with signed cookie
    // Format: base64(JSON).signature
    const legacySession = this.extractLegacySession(decoded);
    if (legacySession) {
      return legacySession;
    }

    // Unknown format - return as-is and let iron-session handle/reject it
    return decoded;
  }

  /**
   * Extract iron-session data from legacy React Router session format.
   * Legacy format: base64({"jwt":"Fe26.2*..."}).signature
   */
  private extractLegacySession(cookieValue: string): string | null {
    try {
      // React Router signed cookies are: base64data.signature
      const dotIndex = cookieValue.lastIndexOf('.');
      if (dotIndex === -1) return null;

      const base64Part = cookieValue.substring(0, dotIndex);

      // Decode base64 (handle URL-safe base64)
      const jsonStr = Buffer.from(base64Part, 'base64').toString('utf-8');
      const sessionData = JSON.parse(jsonStr);

      // Extract the jwt field which contains the iron-session sealed data
      if (sessionData && typeof sessionData.jwt === 'string' && sessionData.jwt.startsWith('Fe26.')) {
        return sessionData.jwt;
      }

      return null;
    } catch {
      // Not valid legacy format
      return null;
    }
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
