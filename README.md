# entra-static-server

A browser-based HTTP request tool, served behind Microsoft Entra ID sign-in.

The page lets you compose a request — method, URL, URL parameters, headers, body — send it, and inspect
the status, response headers and body. Nobody reaches it without a valid Entra ID account in the
tenant. Requests to a configured backend API are made by the server, with the credentials for it; every
other request is sent straight from the browser.

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
| `ENTRA_BACKEND_URL` | — | The backend's base URL. The only prefix this server will forward a request to. |
| `ENTRA_BACKEND_TIMEOUT` | `30.0` | Timeout for a forwarded request. Separate from `ENTRA_HTTP_TIMEOUT`: an API can take longer to answer than Entra ID does. |

Serving over HTTPS is a matter of setting `ENTRA_BASE_URL` to the `https://` URL and adding the
matching redirect URI to the app registration.

## Calling a backend API

The four `ENTRA_BACKEND_*` settings turn on authenticated calls to a backend. Set all four, or the
feature stays off and every request is sent from the browser, unauthenticated. The secret goes in
`.env.local`, the rest in `.env`:

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

### The request is made by the server, not by the page

A request aimed at the backend is **not sent from the browser**. The page posts what it wants sent to
`POST /api/send`, and this server makes the call, attaching:

| Header | What it is |
| --- | --- |
| `Authorization: Bearer …` | The application's access token, from the client credentials flow. Says *which application* is calling; every signed-in user gets the same one, with the same permissions. |
| `token: <id_token>` | The signed-in visitor's own id_token, out of their session cookie. Says *who* is calling. |

**Neither ever reaches a browser.** There is no route that hands out either token, so there is nothing
for a page — or anything running in it — to read and send somewhere else. The response comes back to
the page as JSON and is displayed as usual; the panel lists which headers the server added, and an
`Authorization` or `token` header you type into the form is forwarded as you typed it instead.

**Only URLs at or below `ENTRA_BACKEND_URL` are forwarded**, and here that check is the entire security
boundary rather than a nicety. The tool sends requests to whatever URL you type, so without it this
route would forward the application's credentials — and the server's network position, which is
usually further inside than your laptop — to any host a signed-in visitor named. Anything else is
refused with a 400 before a single byte is sent, and the page sends it straight from the browser
instead, with nothing of this application's attached.

The check compares the full origin (scheme, host and port) and requires a real path-segment prefix, so
`https://backend…/apiXX` does not match `/api`. It is applied to the URL *as the HTTP client will
request it*, which matters: `https://backend…/api/../admin` is `/admin` by the time it goes out, and a
check on the text would have seen it start with `/api/`.

Two more things the server does with a forwarded request:

- **Redirects are not followed.** A `302` is handed back to the page as the response. Following one
  would take the credentials wherever `Location` pointed, which need not be the backend.
- **Nothing of the browser's own hop is passed on** — not its cookies (including the session cookie),
  not its user agent. Only the method, URL, headers and body the form asked for.

The backend should validate that `id_token` as a token in its own right — signature against the
tenant's JWKS, issuer, and an audience of `ENTRA_CLIENT_ID` (this app, not the backend's own client
id). It is *not* an access token for the backend API: proper delegated access would be the
on-behalf-of flow, which exchanges this token for one the backend is the audience of.

### What the backend has to allow

**Nothing.** Because the request is made from the server, it is not cross-origin, so CORS does not
apply to it: no `Access-Control-*` headers, and no preflight `OPTIONS` to answer before the real
request. Every response header comes back to the page, not the handful a browser would expose.

This is worth knowing if you are used to the other arrangement. A browser preflight carries no
credentials at all — by specification it has no `Authorization`, no custom headers and no cookies — so
a backend that requires authentication on `OPTIONS` blocks every browser client it has, and there is
nothing a page can do about it. Sending from the server sidesteps that question rather than answering
it.

Requests to anything else are still sent by the browser and are still subject to CORS in the usual
way.

## The tool

- **Method, URL and body.** The body is disabled for methods that cannot carry one.
- **URL parameters** as name/value rows, with a live preview of the assembled request URL and an
  **Extract from URL** button that pulls an existing query string apart into rows.
- **Headers** as name/value rows, with the ones the server will add for the backend — `Authorization`
  and `token` — listed below them as disabled rows reading *added by this server*. There is no value
  to show: the page never receives either token. A header you type yourself wins and drops the
  matching row from the list.
- **Replace this page with the response** — renders the response body as the entire document, for when
  you want to look at returned HTML rather than at its source. Reload to come back; the form is
  restored as you left it.

A request to the backend is [made by this server](#the-request-is-made-by-the-server-not-by-the-page)
and the response panel says `sent by this server`, along with which headers it added. Everything else
is sent by the browser with `fetch`, and is subject to CORS: a response from a server that does not
send the right CORS headers will fail, and so will a request whose preflight is refused. That is a
browser restriction, not a limitation of the tool. `fetch` defaults to `credentials: 'same-origin'`
and the page does not change it, so your cookies go to this server and nowhere else.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /{path}` | The static site. Requires a session. |
| `GET /oauth2/login?next=…` | Start a sign-in explicitly. |
| `POST /oauth2/token` | Where Entra ID posts the `id_token`. |
| `GET /oauth2/logout` | Clear the session cookie. |
| `GET /oauth2/me` | The claims of the validated token this session came from. |
| `GET /api/backend` | Whether a backend is configured, and its URL — so the page knows which requests to route through this server. Requires a session. |
| `POST /api/send` | Make a request to the backend, with both credentials attached here. Requires a session; 400 for any URL outside `ENTRA_BACKEND_URL`, 404 when no backend is configured. |

No route hands out a token. `/api/*` answers `401` rather than redirecting, because a `fetch` cannot
follow a redirect to Microsoft.

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
so it cannot be forged. The claims are read back out of the token rather than stored beside it. Nothing
about the session is kept on the server, which has two consequences.
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
nonce, unsigned, algorithm-confused. The rest covers the sign-in round trip, path handling, backend
token caching and renewal, and which URLs the server will and will not forward a credential to.

`node tests/page.js` is not part of the pytest suite and nothing runs it for you. It runs the page's
real script against a small DOM shim, and is what proves the browser holds no token and hands only
backend URLs to `/api/send`.

Layout:

```
src/entra_server/
  main.py       FastAPI app: routes, auth dependency, static serving
  backend.py    forwarding a request to the backend, with the credentials attached
  oidc.py       discovery, signing keys, id_token validation, backend tokens
  sessions.py   signed session cookies, and pending logins in memory
  settings.py   configuration
  static/       the web page
tests/
  page.js       the page's send path, run with node rather than pytest
```
