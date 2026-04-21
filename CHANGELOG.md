# Changelog

## 0.11.0 — unreleased

### BREAKING — Security fix (CWE-352, CWE-384)

Fixes login-CSRF / session-fixation in the OAuth flow. Prior to this release the
`state` parameter was an unsigned base64 JSON blob and the callback accepted any
`state` value — an attacker could trick a victim's browser into completing a
callback for the attacker's credentials, logging the victim into the attacker's
account.

The fix binds every OAuth flow to the initiating browser via a sealed state
parameter and a double-submit `__Host-wos-auth-verifier` cookie, and adds PKCE
(`S256`) to the authorization code exchange.

**API changes:**

- **Removed (throws at runtime):** `getSignInUrl`, `getSignUpUrl`. The names
  remain importable so JS/CJS callers get a loud, diagnosable runtime failure
  pointing at the migration guide. TypeScript users will see the behavioral
  change via JSDoc `@deprecated`.
- **Added:** `redirectToSignIn(options?)`, `redirectToSignUp(options?)` —
  return a `Response` with both the `Location` header (WorkOS auth URL) and the
  `Set-Cookie` header (sealed PKCE state). Return them directly from a loader.
- `authLoader`'s `onSuccess` callback receives a new `state` field carrying any
  caller-supplied `options.state` that was passed to `getAuthorizationUrl`.

**Migration:**

Replace the `<Link to={signInUrl}>` eager-generation pattern with an
intermediate-route pattern. See the README for the new pattern. Brief diff:

```diff
- import { getSignInUrl } from '@workos-inc/authkit-react-router';
+ import { redirectToSignIn } from '@workos-inc/authkit-react-router';

- const signInUrl = await getSignInUrl();
- <Link to={signInUrl}>Log in</Link>
+ // app/routes/auth.sign-in.tsx
+ export const loader = () => redirectToSignIn();
+ // elsewhere:
+ <Link to="/auth/sign-in">Log in</Link>
```

See `SECURITY.md` for the full advisory and `README.md` for updated usage
examples.

### Other changes

- Adds `valibot` as a runtime dependency (used for sealed-state shape validation).
- `returnPathname` / `returnTo` is sanitized at the seal and unseal boundaries:
  absolute URLs, protocol-relative paths, CRLF, and dot-segment traversal are
  rejected and fall back to `/`. This closes an open-redirect regression.
- The session re-auth paths in `src/session.ts` (`refreshSession` no-cookie,
  `authkitLoader` `ensureSignedIn` no-session, `authkitLoader` refresh-failure)
  now emit the PKCE verifier cookie alongside their existing session-destroy
  cookie — the same CSRF binding is enforced on every re-authentication.

### Not changed

- `@workos-inc/node` stays at `^7.41.0`. PKCE generation is handled by a small
  local helper so consumers are not forced onto the SDK v8 major at the same
  time as this security release.
