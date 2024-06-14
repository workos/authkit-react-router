# AuthKit Remix Library

The AuthKit library for Remix provides convenient helpers for authentication and session management using WorkOS & AuthKit with Remix. You can find this library in action in the [remix-authkit-example](https://github.com/workos/remix-authkit-example) repo.

## Installation

Install the package with:

```
npm i @workos-inc/authkit-remix
```

or

```
yarn add @workos-inc/authkit-remix
```

## Pre-flight

Make sure the following values are present in your `.env.local` environment variables file. The client ID and API key can be found in the [WorkOS dashboard](https://dashboard.workos.com), and the redirect URI can also be configured there.

```sh
WORKOS_CLIENT_ID="client_..." # retrieved from the WorkOS dashboard
WORKOS_API_KEY="sk_test_..." # retrieved from the WorkOS dashboard
WORKOS_REDIRECT_URI="http://localhost:3000/callback" # configured in the WorkOS dashboard
WORKOS_COOKIE_PASSWORD="<your password>" # generate a secure password here
```

`WORKOS_COOKIE_PASSWORD` is the private key used to encrypt the session cookie. It has to be at least 32 characters long. You can use the [1Password generator](https://1password.com/password-generator/) or the `openssl` library to generate a strong password via the command line:

```
openssl rand -base64 24
```

To use the `signOut` method, you'll need to set your app's homepage in your WorkOS dashboard settings under "Redirects".

### Optional configuration

Certain environment variables are optional and can be used to debug or configure cookie settings.

```sh
WORKOS_COOKIE_MAX_AGE='600' # maximum age of the cookie in seconds. Defaults to 31 days
WORKOS_API_HOSTNAME='api.workos.com' # base WorkOS API URL
WORKOS_API_HTTPS=true # whether to use HTTPS in API calls
WORKOS_API_PORT=3000 # port to use for API calls
```

## Setup

### Callback route

WorkOS requires that you have a callback URL to redirect users back to after they've authenticated. In your Remix app, [create a new route](https://remix.run/docs/en/main/discussion/routes) and add the following:

```ts
import { authLoader } from '@workos-inc/authkit-remix';

export const loader = authLoader();
```

Make sure this route matches the `WORKOS_REDIRECT_URI` variable and the configured redirect URI in your WorkOS dashboard. For instance if your redirect URI is `http://localhost:3000/callback` then you'd put the above code in `/app/routes/callback.ts`.

You can also control the pathname the user will be sent to after signing-in by passing a `returnPathname` option to `authLoader` like so:

```ts
export const loader = authLoader({ returnPathname: '/dashboard' });
```

## Usage

### Get the current user

For pages where you want to display a signed-in and signed-out view, use `withAuth` to retrieve the user profile from WorkOS.

```jsx
import type { ActionFunctionArgs, LoaderFunctionArgs } from '@remix-run/node';
import { Link, useRouteLoaderData, json, Form } from '@remix-run/react';
import { getSignInUrl, getSignUpUrl, withAuth, signOut } from '@workos-inc/authkit-remix';

export async function loader({ request }: LoaderFunctionArgs) {
  const {
    user,
    sessionId,
    organizationId,
    role,
    impersonator,
    accessToken
  } = await withAuth(request);

  return json({
    signInUrl: await getSignInUrl(),
    signUpUrl: await getSignUpUrl(),
    user,
  });
}

export async function action({ request }: ActionFunctionArgs) {
  return await signOut(request);
}

export default function HomePage() {
  // Retrieves the user from the session or returns `null` if no user is signed in
  const { user, signInUrl, signUpUrl } = useLoaderData<typeof loader>();

  if (!user) {
    return (
      <>
        <Link to={signInUrl}>Log in</Link>
        <Link to={signUpUrl}>Sign Up</Link>
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

### Requiring auth

For pages where a signed-in user is mandatory, you can use the `ensureSignedIn` option:

```jsx
const { user } = await withAuth(request, { ensureSignedIn: true });
```

Enabling `ensureSignedIn` will redirect users to AuthKit if they attempt to access the page without being authenticated.

### Signing out

Use the `signOut` method to sign out the current logged in user, end the session, and redirect to your app's homepage. The homepage redirect is set in your WorkOS dashboard settings under "Redirect".

### Get the access token

Sometimes it is useful to obtain the access token directly, for instance to make API requests to another service.

```jsx
import type { LoaderFunctionArgs, json } from '@remix-run/node';
import { withAuth } from '@workos-inc/authkit-remix';

export async function loader({ request }: LoaderFunctionArgs) {
  const { accessToken } = await withAuth(request);

  if (!accesstoken) {
    // Not signed in
  }

  const serviceData = await fetch('/api/path', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  return json({
    data: serviceData,
  });
}
```

### Debugging

To enable debug logs, pass in the debug flag when using `withAuth`.

```js
import { withAuth, getSignInUrl, getSignUpUrl } from '@workos-inc/authkit-remix';

export async function loader({ request }: LoaderFunctionArgs) {
  const { user } = await withAuth(request, {
    debug: true,
  });

  return json({
    signInUrl: await getSignInUrl(),
    signUpUrl: await getSignUpUrl(),
    user,
  });
}
```
