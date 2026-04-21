# Changelog

All notable changes to `@workos-inc/authkit-react-router` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the package is pre-1.0, minor version bumps (e.g. `0.4.x → 0.10.0`) are
used to signal breaking changes.

## [Unreleased]

### Added

- **PKCE + CSRF protection** on the authorization-code flow. Each sign-in /
  sign-up redirect now sets a short-lived (10 minute), flow-specific
  `wos-auth-verifier-<hash>` cookie containing a sealed OAuth `state` value,
  and the callback verifies the round-tripped `state` matches the cookie
  (double-submit) before exchanging the code plus PKCE verifier. Concurrent
  flows get distinct cookie names so stacked sign-in attempts don't
  overwrite each other.
- `getSignInUrl` / `getSignUpUrl` / `getAuthorizationUrl` now accept the
  incoming `Request` so the PKCE cookie's `Secure` attribute reflects the
  live request protocol (fixes local-dev with `http://localhost` and an
  `https://` `WORKOS_REDIRECT_URI`).

### Changed

- **Breaking:** `getSignInUrl`, `getSignUpUrl`, and `getAuthorizationUrl`
  now return `{ url, headers }` instead of a bare URL string. The
  `headers` include a `Set-Cookie` that **must** travel to the browser on
  the redirect response; otherwise the callback will reject the flow as
  a CSRF failure. See the
  [migration guide](./README.md#migrating-from-04x) for the redirect-route
  pattern that replaces the old "render a sign-in URL in a `<Link>`"
  approach.
- **Breaking:** Minimum `@workos-inc/node` is now `^8.9.0` (for the
  `pkce` namespace).
- `authkitLoader` and `switchToOrganization` automatically forward the
  new PKCE cookie on redirects they initiate, so most consumers don't
  need to thread it through manually.
- `switchToOrganization` no longer emits an empty `Set-Cookie: ''` header
  when `refreshSession` returns without one.
- `signOut` / `terminateSession` now also clears any orphan
  `wos-auth-verifier-*` cookies left behind by abandoned OAuth flows
  (tabs closed mid-sign-in, etc.) so they don't accumulate under the
  browser's per-domain cookie cap.

### Docs

- New **Sign-in endpoint** section documenting the `initiate_login_uri`
  dashboard setting, including a callout that a configured sign-in
  endpoint is required for dashboard impersonation to work.
- New **Troubleshooting** entry for the
  `Missing required auth parameter` error surfaced when an
  impersonation flow reaches the callback without routing through the
  sign-in endpoint.
