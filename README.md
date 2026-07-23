# AuthKit React Router Library

> [!IMPORTANT]
> This SDK focuses on React Router framework mode, with more support for library mode and additional features planned.

The AuthKit library for React Router 7+ provides convenient helpers for authentication and session management using WorkOS & AuthKit with React Router. You can find this library in action in the [react-router-authkit-example](https://github.com/workos/react-router-authkit-example) repo.

## Installation

Install the package with:

```
npm i @workos-inc/authkit-react-router
```

or

```
yarn add @workos-inc/authkit-react-router
```

## Configuration

AuthKit for React Router offers a flexible configuration system that allows you to customize various settings. You can configure the library in three ways:

### 1. Environment Variables

The simplest way is to set environment variables in your `.env.local` file:

```bash
WORKOS_CLIENT_ID="client_..." # retrieved from the WorkOS dashboard
WORKOS_API_KEY="sk_test_..." # retrieved from the WorkOS dashboard
WORKOS_REDIRECT_URI="http://localhost:5173/callback" # configured in the WorkOS dashboard
WORKOS_COOKIE_PASSWORD="<your password>" # generate a secure password here
```

### 2. Programmatic Configuration

You can also configure AuthKit programmatically by importing the `configure` function:

```typescript
import { configure } from '@workos-inc/authkit-react-router';
// In your root or entry file
configure({
  clientId: 'client_1234567890',
  apiKey: 'sk_test_1234567890',
  redirectUri: 'http://localhost:5173/callback',
  cookiePassword: 'your-secure-cookie-password',
  // Optional settings
  cookieName: 'my-custom-cookie-name',
  apiHttps: true,
  cookieMaxAge: 60 * 60 * 24 * 30, // 30 days
});
```

### 3. Custom Environment Source

For non-standard environments (like Deno or Edge functions), you can provide a custom environment variable source:

> [!Warning]
>
> While this library includes support for custom environment sources that could theoretically work in non-Node.js runtimes like Deno or Edge functions, this functionality has not been extensively tested (yet). If you're planning to use AuthKit in these environments, you may encounter unexpected issues. We welcome feedback and contributions from users who test in these environments.

```typescript
import { configure } from '@workos-inc/authkit-react-router';

configure((key) => Deno.env.get(key));
// Or combine with explicit values
configure({ clientId: 'client_1234567890' }, (key) => Deno.env.get(key));
```

### Configuration Priority

When retrieving configuration values, AuthKit follows this priority order:

1. Programmatically provided values via `configure()`
2. Environment variables (prefixed with `WORKOS_`)
3. Default values for optional settings

### Available Configuration Options

> [!NOTE]
>
> To print out the entire config, a `getFullConfig` function is provided for debugging purposes.

| Option           | Environment Variable     | Default               | Required | Description                                   |
| ---------------- | ------------------------ | --------------------- | -------- | --------------------------------------------- |
| `clientId`       | `WORKOS_CLIENT_ID`       | -                     | Yes      | Your WorkOS Client ID                         |
| `apiKey`         | `WORKOS_API_KEY`         | -                     | Yes      | Your WorkOS API Key                           |
| `redirectUri`    | `WORKOS_REDIRECT_URI`    | -                     | Yes      | The callback URL configured in WorkOS         |
| `cookiePassword` | `WORKOS_COOKIE_PASSWORD` | -                     | Yes      | Password for cookie encryption (min 32 chars) |
| `cookieName`     | `WORKOS_COOKIE_NAME`     | `wos-session`         | No       | Name of the session cookie                    |
| `apiHttps`       | `WORKOS_API_HTTPS`       | `true`                | No       | Whether to use HTTPS for API calls            |
| `cookieMaxAge`   | `WORKOS_COOKIE_MAX_AGE`  | `34560000` (400 days) | No       | Maximum age of cookie in seconds              |
| `apiHostname`    | `WORKOS_API_HOSTNAME`    | `api.workos.com`      | No       | WorkOS API hostname                           |
| `apiPort`        | `WORKOS_API_PORT`        | -                     | No       | Port to use for API calls                     |

> [!NOTE]
>
> The `cookiePassword` must be at least 32 characters long for security reasons.

## Setup

### Callback route

AuthKit requires that you have a callback URL to redirect users back to after they've authenticated. In your React Router app, [create a new route](https://reactrouter.com/start/framework/routing) and add the following:

```ts
import { authLoader } from '@workos-inc/authkit-react-router';

export const loader = authLoader();
```

Make sure this route matches the `WORKOS_REDIRECT_URI` variable and the configured redirect URI in your WorkOS dashboard. For instance if your redirect URI is `http://localhost:2884/callback` then you'd put the above code in `/app/routes/callback.ts`.

You can also control the pathname the user will be sent to after signing-in by passing a `returnPathname` option to `authLoader` like so:

```ts
export const loader = authLoader({ returnPathname: '/dashboard' });
```

If your application needs to persist `oauthTokens` or other auth-related information after the callback is successful, you can pass an `onSuccess` option:

```ts
export const loader = authLoader({
  onSuccess: async ({ oauthTokens }) => {
    await saveToDatabase(oauthTokens);
  },
});
```

## Usage

### Access authentication data in your React Router application

Use `authkitLoader` to configure AuthKit for your React Router application routes.

```tsx
import { type LoaderFunctionArgs, useLoaderData } from 'react-router';
import { authkitLoader } from '@workos-inc/authkit-react-router';

export const loader = (args: LoaderFunctionArgs) => authkitLoader(args);

export function App() {
  // Retrieves the user from the session or returns `null` if no user is signed in.
  // Other supported values include `sessionId`, `organizationId`,
  // `role`, `permissions`, `entitlements`, `featureFlags`, and `impersonator`.
  const { user } = useLoaderData<typeof loader>();

  return (
    <div>
      <p>Welcome back {user?.firstName && `, ${user?.firstName}`}</p>
    </div>
  );
}
```

### Evaluate feature flags

By default, `authkitLoader` reads `featureFlags` from the `feature_flags`
claim in the WorkOS access token. This is convenient for small flag sets, but
changes are reflected only after the user's access token refreshes.

Use the Feature Flags runtime client when you need server-side flag evaluation
that stays in sync independently of the user's session. The runtime client keeps
flag configuration in memory and syncs changes in the background, so create one
shared instance per server process rather than one client per request.

```tsx
import { type LoaderFunctionArgs, useLoaderData } from 'react-router';
import { authkitLoader, getFeatureFlagsRuntimeClient } from '@workos-inc/authkit-react-router';

const featureFlags = getFeatureFlagsRuntimeClient();

export const loader = (args: LoaderFunctionArgs) =>
  authkitLoader(args, {
    featureFlags: {
      runtimeClient: featureFlags,
      waitUntilReady: { timeoutMs: 5000 },
    },
    onFeatureFlagsError: ({ error }) => {
      console.error('Feature flags runtime client failed:', error);
    },
  });

export function Dashboard() {
  const { featureFlags } = useLoaderData<typeof loader>();
  const hasAdvancedAnalytics = featureFlags?.includes('advanced-analytics');

  return hasAdvancedAnalytics ? <AdvancedAnalytics /> : <BasicAnalytics />;
}
```

After opting in, downstream route code can continue reading
`auth.featureFlags` as before, but the values normally come from the runtime
client instead of the JWT. The JWT claim is used only as a fallback if runtime
evaluation fails.

#### Source of `auth.featureFlags`

`authkitLoader` preserves the existing token-based behavior unless you opt in to
the runtime client:

- Without `featureFlags.runtimeClient`, `auth.featureFlags` is read from the
  access token's `feature_flags` claim.
- With `featureFlags.runtimeClient`, `auth.featureFlags` is evaluated by the
  runtime client using the signed-in user's `userId` and current
  `organizationId`.
- If runtime evaluation fails, `authkitLoader` falls back to the access token's
  `feature_flags` claim so authentication can continue. Use
  `onFeatureFlagsError` to report this fallback to your monitoring system. When
  `debug: true` is enabled, this fallback also emits a warning.

The `getFeatureFlagsRuntimeClient` helper returns the same runtime client for
every call in the current server process. Options passed to
`getFeatureFlagsRuntimeClient(options)` are only used when the client is created
for the first time.

### Sign-in and sign-up routes

`getSignInUrl` and `getSignUpUrl` return a `{ url, headers }` pair. The
`headers` contain a short-lived `Set-Cookie` used for PKCE + CSRF
protection, which **must** travel to the browser on the same redirect
response that sends the user to AuthKit. Create dedicated redirect routes
for sign-in and sign-up and link to those routes from your pages:

```ts
// app/routes/login.ts
import { redirect, type LoaderFunctionArgs } from 'react-router';
import { getSignInUrl } from '@workos-inc/authkit-react-router';

export async function loader({ request }: LoaderFunctionArgs) {
  const url = new URL(request.url);
  const { url: authUrl, headers } = await getSignInUrl(url.searchParams.get('returnTo') ?? undefined, request);
  return redirect(authUrl, { headers });
}
```

```ts
// app/routes/signup.ts
import { redirect, type LoaderFunctionArgs } from 'react-router';
import { getSignUpUrl } from '@workos-inc/authkit-react-router';

export async function loader({ request }: LoaderFunctionArgs) {
  const url = new URL(request.url);
  const { url: authUrl, headers } = await getSignUpUrl(url.searchParams.get('returnTo') ?? undefined, request);
  return redirect(authUrl, { headers });
}
```

Passing `request` ensures the `Secure` attribute on the PKCE cookie
matches your app's live protocol (important in local dev, where the app
runs on `http://localhost` even if `WORKOS_REDIRECT_URI` is an `https://`
URL).

Then link to those routes from any page where you want to offer sign-in
or sign-up:

```tsx
// app/routes/_index.tsx
import { type ActionFunctionArgs, type LoaderFunctionArgs, Form, Link, useLoaderData } from 'react-router';
import { signOut, authkitLoader } from '@workos-inc/authkit-react-router';

export const loader = (args: LoaderFunctionArgs) => authkitLoader(args);

export async function action({ request }: ActionFunctionArgs) {
  return await signOut(request);
}

export default function HomePage() {
  const { user } = useLoaderData<typeof loader>();

  if (!user) {
    return (
      <>
        <Link to="/login">Log in</Link>
        <br />
        <Link to="/signup">Sign Up</Link>
      </>
    );
  }

  return (
    <Form method="post">
      <p>Welcome back {user?.firstName && `, ${user?.firstName}`}</p>
      <button type="submit">Sign out</button>
    </Form>
  );
}
```

> [!NOTE]
>
> Prior to `0.10.0`, `getSignInUrl` / `getSignUpUrl` returned a bare URL
> string that could be rendered directly in a `<Link>`. That pattern is
> no longer supported — see [Migrating from 0.4.x](#migrating-from-04x)
> below.

### Sign-in endpoint

The sign-in route above doubles as your **Sign-in endpoint** (also known
as `initiate_login_uri`) — the URL WorkOS redirects to when it needs to
start an authentication flow on your app's behalf (for example, when an
admin impersonates a user from the dashboard, or when a password-reset
email lands on a device that is not already signed in).

In the [WorkOS dashboard](https://dashboard.workos.com), go to
**Redirects** and set the **Sign-in endpoint** to the public URL of the
route (e.g., `http://localhost:5173/login` in development,
`https://your-app.com/login` in production).

> [!IMPORTANT]
> A configured Sign-in endpoint is required for
> [impersonation](https://workos.com/docs/user-management/impersonation)
> to work. Without it, WorkOS-initiated flows (such as impersonating a
> user from the dashboard) redirect directly to your callback URL
> without a `state` parameter and fail the PKCE/CSRF verification this
> library enforces on every callback, surfacing as a
> `Missing required auth parameter` error.

### Requiring auth

For pages where a signed-in user is mandatory, you can use the `ensureSignedIn` option:

```tsx
export const loader = (args: LoaderFunctionArgs) => authkitLoader(args, { ensureSignedIn: true });
```

Enabling `ensureSignedIn` will redirect users to AuthKit if they attempt to access the page without being authenticated.

### Signing out

Use the `signOut` method to sign out the current logged in user, end the session, and redirect to your app's homepage. The homepage redirect is set in your WorkOS dashboard settings under "Redirect".

If you would like to specify where a user is redirected, an optional `returnTo` argument can be passed. Allowed values are configured in the WorkOS Dashboard under _[Logout redirects](https://workos.com/docs/user-management/sessions/configuring-sessions/logout-redirect)_.

```ts
export async function action({ request }: ActionFunctionArgs) {
  // Called when the form in SignInButton is submitted
  return await signOut(request, { returnTo: 'https://example.com' });
}
```

### Get the access token

Access tokens are available through the `getAccessToken()` function within your loader. This design encourages server-side token usage while making the security implications explicit.

```tsx
import { data, type LoaderFunctionArgs } from 'react-router';
import { authkitLoader } from '@workos-inc/authkit-react-router';

export const loader = (args: LoaderFunctionArgs) =>
  authkitLoader(args, async ({ auth, getAccessToken }) => {
    if (!auth.user) {
      // Not signed in - getAccessToken() would return null
      return data({ data: null });
    }

    // Explicitly call the function to get the access token
    const accessToken = getAccessToken();

    const serviceData = await fetch('/api/path', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    return data({
      data: await serviceData.json(),
    });
  });
```

#### Security Considerations

By default, access tokens are not included in the data sent to React components. This helps prevent unintentional token exposure in:

- Browser developer tools
- HTML source code
- Client-side logs or error reporting

If you need to expose the access token to client-side code, you can explicitly return it from your loader:

```tsx
export const loader = (args: LoaderFunctionArgs) =>
  authkitLoader(
    args,
    async ({ auth, getAccessToken }) => {
      const accessToken = getAccessToken();

      return {
        // Only expose to client if absolutely necessary
        accessToken,
        userData: await fetchUserData(accessToken),
      };
    },
    { ensureSignedIn: true },
  );
```

**Note:** Only expose access tokens to the client when necessary for your use case (e.g., making direct API calls from the browser). Consider alternatives like:

- Making API calls server-side in your loaders
- Creating proxy endpoints in your application
- Using separate client-specific tokens with limited scope

#### Using with `ensureSignedIn`

When using the `ensureSignedIn` option, you can be confident that `getAccessToken()` will always return a valid token:

```tsx
export const loader = (args: LoaderFunctionArgs) =>
  authkitLoader(
    args,
    async ({ auth, getAccessToken }) => {
      // With ensureSignedIn: true, the user is guaranteed to be authenticated
      const accessToken = getAccessToken();

      // Use the token for your API calls
      const data = await fetchProtectedData(accessToken);

      return { data };
    },
    { ensureSignedIn: true },
  );
```

### Using withAuth for low-level access

For advanced use cases, the `withAuth` function provides direct access to authentication data, including the access token. Unlike `authkitLoader`, this function:

- Does not handle automatic token refresh
- Does not manage cookies or session updates
- Returns the access token directly as a property
- Requires manual redirect handling for unauthenticated users

```tsx
import { withAuth } from '@workos-inc/authkit-react-router';
import { redirect, type LoaderFunctionArgs } from 'react-router';

export const loader = async (args: LoaderFunctionArgs) => {
  const auth = await withAuth(args);

  if (!auth.user) {
    // Manual redirect - withAuth doesn't handle this automatically
    throw redirect('/sign-in');
  }

  // Access token is directly available as a property
  const { accessToken, user, sessionId } = auth;

  // Use the token for server-side operations
  const apiData = await fetch('https://api.example.com/data', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  // Be careful what you return - accessToken will be exposed if included
  return {
    user,
    apiData: await apiData.json(),
    // accessToken, // ⚠️ Only include if client-side access is necessary
  };
};
```

**When to use `withAuth` vs `authkitLoader`:**

- Use `authkitLoader` for most cases - it handles token refresh, cookies, and provides safer defaults
- Use `withAuth` when you need more control or are building custom authentication flows
- `withAuth` is useful for API routes or middleware where you don't need the full loader functionality

### Advanced: Direct access to the WorkOS client

For advanced use cases or functionality not covered by the helper methods, you can access the underlying WorkOS client directly:

```ts
import { getWorkOS } from '@workos-inc/authkit-react-router';

// Get the configured WorkOS client instance
const workos = getWorkOS();

// Use any WorkOS SDK method
const organizations = await workos.organizations.listOrganizations({
  limit: 10,
});
```

### Advanced: Custom authentication flows

While the standard authentication flow handles session management automatically, some use cases require manually creating and storing a session. This is useful for custom authentication flows like email verification or token exchange.

For these scenarios, you can use the `saveSession` function:

```ts
import { redirect } from 'react-router';
import { getWorkOS, saveSession } from '@workos-inc/authkit-react-router';

// Example: Email verification flow
async function handleEmailVerification(request: Request) {
  const { code } = await request.json();

  // Authenticate with the WorkOS API directly
  const authResponse = await getWorkOS().userManagement.authenticateWithEmailVerification({
    clientId: process.env.WORKOS_CLIENT_ID,
    code,
  });

  // Save the session data to a cookie
  await saveSession(
    {
      accessToken: authResponse.accessToken,
      refreshToken: authResponse.refreshToken,
      user: authResponse.user,
      impersonator: authResponse.impersonator,
    },
    request,
  );

  return redirect('/dashboard');
}
```

### Debugging

To enable debug logs, pass in the debug flag when using `authkitLoader`.

```ts
import { authkitLoader } from '@workos-inc/authkit-react-router';

export const loader = (args: LoaderFunctionArgs) => authkitLoader(args, { debug: true });
```

If providing a loader function, you can pass the options object as the third parameter

```ts
import { authkitLoader } from '@workos-inc/authkit-react-router';

export const loader = (args: LoaderFunctionArgs) =>
  authkitLoader(
    args,
    async ({ auth }) => {
      return json({ foo: 'bar' });
    },
    { debug: true },
  );
```

## Customizing Session Storage

By default, AuthKit for React Router uses cookie-based session storage with these settings:

```typescript
{
  name: "wos-session", // Default or WORKOS_COOKIE_NAME if set
  path: "/",
  httpOnly: true,
  secure: true, // When redirect URI uses HTTPS
  sameSite: "lax",
  maxAge: 34560000, // 400 days (configurable via WORKOS_COOKIE_MAX_AGE)
  secrets: [/* your cookie password, configurable via WORKOS_COOKIE_PASSWORD */],
}
```

### Custom Session Storage

You can provide your own session storage implementation to both `authkitLoader` and `authLoader`:

```typescript
import { createMemorySessionStorage } from '@react-router/node';
import { authkitLoader, authLoader } from '@workos-inc/authkit-react-router';

// Create memory-based session storage
const memoryStorage = createMemorySessionStorage({
  cookie: {
    name: 'auth-session',
    secrets: ['test-secret'],
    sameSite: 'lax',
    path: '/',
    httpOnly: true,
    secure: false, // Use false for testing
    maxAge: 60 * 60 * 24, // 1 day
  },
});

// In your root loader
export const loader = (args) =>
  authkitLoader(args, {
    storage: memoryStorage,
    cookie: { name: 'auth-session' },
  });

// In your callback route
export const loader = authLoader({
  storage: memoryStorage,
  cookie: { name: 'auth-session' },
});
```

For code reuse and consistency, consider using a shared function:

```typescript
// app/lib/session.ts
export function getAuthStorage() {
  const storage = createCookieSessionStorage({
    /* config */
  });
  return { storage, cookie: { name: 'my-custom-session' } };
}

// Then in your routes
import { getAuthStorage } from '~/lib/session';
export const loader = (args) =>
  authkitLoader(args, {
    ...getAuthStorage(),
    // Other options...
  });
```

> [!NOTE]
> When deploying to serverless environments like AWS Lambda, ensure you pass the same storage configuration to both your main routes and the callback route to handle cold starts properly.

AuthKit works with any session storage that implements React Router's `SessionStorage` interface, including Redis-based or database-backed implementations.

## Troubleshooting

### `Missing required auth parameter` when impersonating from the WorkOS dashboard

This error occurs when WorkOS-initiated flows (such as dashboard
impersonation) redirect directly to your callback URL without going
through your application's sign-in flow. Because this library enforces
PKCE/CSRF verification on every callback, the request is rejected when
the required `state` parameter is missing.

**Fix:** Configure a [sign-in endpoint](#sign-in-endpoint) in your
WorkOS dashboard so that impersonation flows route through your app
first, allowing the PKCE verifier and CSRF state to be set up before
redirecting to WorkOS.

## Migrating from 0.4.x

`0.10.0` is a breaking release that adds PKCE and CSRF protection to the
authorization-code flow. Upgrading from `0.4.x` requires small changes to
any route that builds a sign-in or sign-up URL.

### 1. `getSignInUrl` / `getSignUpUrl` now return `{ url, headers }`

They used to return a bare URL string. They now return an object with a
`url` and a `Set-Cookie` header that **must** travel to the browser on
the redirect that starts the OAuth flow, so that the callback can verify
the response came from this browser (CSRF) and recover the PKCE code
verifier.

```ts
// 0.4.x
const signInUrl = await getSignInUrl();
return redirect(signInUrl);

// 0.10.0+
const { url, headers } = await getSignInUrl('/dashboard', request);
return redirect(url, { headers });
```

### 2. Use a dedicated redirect route for sign-in / sign-up

The old "load the URL into your page data and render it in a `<Link>`"
pattern no longer works: the cookie and the URL must leave the server on
the same response. Move the URL generation into a loader that returns a
redirect, and link to that loader's path from your page:

```ts
// app/routes/login.ts
export async function loader({ request }: LoaderFunctionArgs) {
  const { url, headers } = await getSignInUrl(undefined, request);
  return redirect(url, { headers });
}
```

```tsx
// Any page:
<Link to="/login">Log in</Link>
```

See [Sign-in and sign-up routes](#sign-in-and-sign-up-routes) above for
the full pattern.

### 3. Pass `request` when calling from a loader

`getSignInUrl` / `getSignUpUrl` (and `getAuthorizationUrl`) accept the
incoming `Request` as their second argument. Pass it when available so
the PKCE cookie's `Secure` attribute reflects the live request protocol
rather than the configured `redirectUri`'s — otherwise local dev on
`http://localhost` with `WORKOS_REDIRECT_URI=https://…` mints a `Secure`
cookie the browser silently drops, and the callback fails with
`Auth cookie missing`.

### 4. `@workos-inc/node` minimum is `^8.9.0`

PKCE is implemented in `@workos-inc/node`'s `pkce` namespace, which
requires `^8.9.0`. If your app pins an older version, upgrade:

```bash
npm install @workos-inc/node@^8.9.0
```
