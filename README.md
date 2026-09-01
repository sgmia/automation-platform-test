# entra-static-server

A browser-based HTTP request tool, served behind Microsoft Entra ID sign-in.

The page lets you compose a request — method, URL, URL parameters, headers, body — send it from the
browser, and inspect the status, response headers and body. Nobody reaches it without a valid Entra ID
account in the tenant.

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- An Entra ID app registration (see [Setup](#setup))

## Quick start

```bash
uv sync
uv run entra-static-server
```

Then open <http://localhost:3000>. You will be redirected to Microsoft to sign in, and back to the
tool afterwards.

## Setup

In the Azure portal, under **App registrations** → your app:

1. **Authentication** → **Add a platform** → **Web** → redirect URI `http://localhost:3000/oauth2/token`
2. Under **Implicit grant and hybrid flows**, tick **ID tokens**

No client secret is required. The app uses the implicit `id_token` flow with `response_mode=form_post`,
so Microsoft POSTs the token to the callback rather than putting it in a URL that would end up in
browser history and server logs.

## Configuration

All configuration lives in **[.env](.env)**, read at startup from the working directory. Two files are
read, in order, and later values win:

| File | Committed | For |
| --- | --- | --- |
| `.env` | yes | Every setting. No secrets — the tenant and client IDs are public identifiers. |
| `.env.local` | no | The client secret and personal overrides. Start from `.env.local.example`. |

An `ENTRA_`-prefixed environment variable overrides both, which is how to configure a container.

`ENTRA_TENANT_ID` and `ENTRA_CLIENT_ID` are required and have no defaults: there is no sane fallback
for which directory to authenticate against. Everything else falls back to the default below if you
leave it out. Because the files are resolved against the working directory, start the server from the
project root — if you don't, it exits with a message naming the directory it searched.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ENTRA_TENANT_ID` | *required* | Directory (tenant) ID. Single tenant only — tokens from any other issuer are rejected. |
| `ENTRA_CLIENT_ID` | *required* | Application (client) ID. Also the audience a token must carry. |
| `ENTRA_BASE_URL` | `http://localhost:3000` | Public URL. Determines the host/port served, the redirect URI, and whether the session cookie is marked `Secure`. |
| `ENTRA_STATIC_DIR` | the package's `static/` | Directory to serve. Only this directory is ever exposed. |
| `ENTRA_SESSION_TTL` | `28800` (8h) | Session lifetime. A session never outlives the token it came from. |
| `ENTRA_LOGIN_TTL` | `600` (10m) | How long a sign-in in progress stays valid. |
| `ENTRA_COOKIE_SECRET` | a new key per process | Signs the session cookie. Unset, a restart signs everyone out; set it to keep sessions across one. Belongs in `.env.local`. |
| `ENTRA_CLOCK_SKEW` | `60` | Leeway in seconds on `exp`/`nbf`/`iat`. |
| `ENTRA_HTTP_TIMEOUT` | `10.0` | Timeout for calls to Entra ID. |
| `ENTRA_BACKEND_CLIENT_ID` | — | Client ID of the app registration used to call the backend. |
| `ENTRA_BACKEND_CLIENT_SECRET` | — | Its client secret. Stays on the server. |
| `ENTRA_BACKEND_SCOPE` | — | Usually `api://<backend-app-id>/.default`. |
| `ENTRA_BACKEND_URL` | — | The backend's base URL. The token is sent only to this prefix. |

Serving over HTTPS is a matter of setting `ENTRA_BASE_URL` to the `https://` URL and adding the
matching redirect URI to the app registration.

## Calling a backend API

The four `ENTRA_BACKEND_*` settings turn on authenticated calls to a backend. Set all four, or the
feature stays off and requests are sent unauthenticated. The secret goes in `.env.local`, the rest in
`.env`:

```ini
# .env
ENTRA_BACKEND_CLIENT_ID=…
ENTRA_BACKEND_SCOPE=api://<backend-app-id>/.default
ENTRA_BACKEND_URL=https://backend.example.com/api

# .env.local  (git-ignored)
ENTRA_BACKEND_CLIENT_SECRET=…
```

This is a **second app registration** in the same tenant, confidential this time. Give it a client
secret, grant it an application permission on the backend API, and grant admin consent — the client
credentials flow uses application permissions, not delegated ones. The server exchanges the secret for
an access token at startup and renews it five minutes before it expires, so a request never carries a
token that dies in flight.

The page then sends that token as `Authorization: Bearer …`, and the response panel says
`Bearer token sent` when it did.

**The token is only ever attached to URLs at or below `ENTRA_BACKEND_URL`.** This tool sends requests
to whatever URL you type, and a backend access token is a credential for the application itself — so
attaching it unconditionally would hand it to any host you pointed the tool at. The check compares the
full origin (scheme, host and port) and requires a real path-segment prefix, so `https://backend…/apiXX`
does not match `/api`. A note under the URL field says which case applies, and an `Authorization`
header you add by hand always wins.

Note that this token authenticates the *application*, not the signed-in user: everyone who can sign in
gets the same one, with the same permissions.

So that a backend can tell **who** is calling, the page also sends the signed-in visitor's `id_token`
in a header named `token`, next to the `Authorization` header, and the response panel says `id_token
sent` when it did. It comes from `GET /oauth2/id-token`, which hands a visitor their own token and no
one else's, out of the session cookie.

**The `token` header follows the same rule as the bearer token: `ENTRA_BACKEND_URL` only.** It is a
bearer assertion of the user's identity, so a host you typed into the tool must never receive it. A
`token` header you add by hand wins, as with `Authorization`.

The backend should validate that `id_token` as a token in its own right — signature against the
tenant's JWKS, issuer, and an audience of `ENTRA_CLIENT_ID` (this app, not the backend's own client
id). It is *not* an access token for the backend API: proper delegated access would be the
on-behalf-of flow, which exchanges this token for one the backend is the audience of.

## The tool

- **Method, URL and body.** The body is disabled for methods that cannot carry one.
- **URL parameters** as name/value rows, with a live preview of the assembled request URL and an
  **Extract from URL** button that pulls an existing query string apart into rows.
- **Headers** as name/value rows, with the ones the page adds for the backend — `Authorization` and
  `token` — listed below them as disabled rows. Their values are masked (`Bearer •••••••••••••••• (1462
  characters)`): the point is to show *that* a credential is attached and how big it is, without
  putting it on screen for a screenshot or a shoulder to catch. They are sent in full. A header you
  type yourself wins and drops the matching row from the list.
- **Replace this page with the response** — renders the response body as the entire document, for when
  you want to look at returned HTML rather than at its source. Reload to come back; the form is
  restored as you left it.

Requests are sent by the browser with `fetch`, so they carry your cookies for the target origin and are
subject to CORS. A response from a server that does not send permissive CORS headers will fail — this
is a browser restriction, not a limitation of the tool.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /{path}` | The static site. Requires a session. |
| `GET /oauth2/login?next=…` | Start a sign-in explicitly. |
| `POST /oauth2/token` | Where Entra ID posts the `id_token`. |
| `GET /oauth2/logout` | Clear the session cookie. |
| `GET /oauth2/me` | The claims of the validated token this session came from. |
| `GET /oauth2/id-token` | The visitor's own `id_token`, for the page to send to the backend. Requires a session. |
| `GET /oauth2/backend-token` | A backend access token for the page. Requires a session; 404 when no backend is configured. |

## How sign-in works

A request without a valid session cookie is redirected to Entra ID with a freshly generated `state` and
`nonce`. Microsoft authenticates the user and POSTs an `id_token` back to `/oauth2/token`, where it is
validated before anything is trusted:

- **Signature** against the tenant's published JWKS, with **RS256 pinned** so a token cannot select its
  own algorithm (`alg=none` and HS256 confusion attacks both fail)
- **Issuer** exactly this tenant, **audience** exactly this client id
- **`exp`/`nbf`/`iat`**, with the configured clock skew
- **`nonce`** matching the one sent with the authorization request, compared in constant time, so a
  token obtained elsewhere or replayed cannot be posted to the callback
- The `state` is single-use and expires, so a callback cannot be replayed either

Only then is a session issued, as a `HttpOnly`, `SameSite=Lax` cookie.

The session **is** that cookie: it carries the `id_token` itself and an expiry, signed with HMAC-SHA256
so it cannot be forged. The claims are read back out of the token rather than stored beside it. Nothing about the session is kept on the server, which has two consequences.
`GET /oauth2/logout` clears the cookie but cannot revoke a copy taken beforehand, and the signing key
must be stable for a session to survive a restart — set `ENTRA_COOKIE_SECRET` in `.env.local`, or leave
it unset and each process signs with its own key, ending every session on restart.

In-flight logins are still held in memory, so running more than one worker would need a shared store for
those. The static directory is the only thing served, and path traversal and dotfiles are refused, so
the project's own sources are unreachable.

## Development

```bash
uv run pytest
uv run pytest -k nonce        # by name
uv run ruff check .           # lint
node tests/page.js            # the page's send path, outside pytest
```

The tests stub Entra ID's endpoints in memory and mint their own tokens with throwaway RSA keys, so the
suite runs offline in a fraction of a second. Most of it is about the ways an `id_token` can be wrong:
expired, wrong audience, wrong tenant, unknown signing key, tampered payload, missing claims, replayed
nonce, unsigned, algorithm-confused. The rest covers the sign-in round trip, path handling, and backend
token caching and renewal.

Layout:

```
src/entra_server/
  main.py       FastAPI app: routes, auth dependency, static serving
  oidc.py       discovery, signing keys, id_token validation, backend tokens
  sessions.py   signed session cookies, and pending logins in memory
  settings.py   configuration
  static/       the web page
tests/
  page.js       the page's send path, run with node rather than pytest
```
