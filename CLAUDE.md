# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A static web server that serves a single-page HTTP request tool
([static/index.html](src/entra_server/static/index.html)) to visitors who have signed in with Microsoft
Entra ID. Single tenant, single process, no database.

## Commands

Always use `uv` for dependency management — never bare `pip`, and never edit `pyproject.toml`
dependencies by hand (use `uv add` / `uv remove` so `uv.lock` stays in step).

```bash
uv sync                                              # install, including the dev group
uv run entra-static-server                           # serve on http://localhost:3000
uv run pytest                                        # whole suite
uv run pytest tests/test_oidc.py::test_valid_token_is_accepted   # one test
uv run pytest -k nonce                               # by name
uv run ruff check .                                  # lint (--fix to apply)
```

`ruff format` has never been run here; the code is hand-formatted to a 110-column limit. Don't
introduce it without asking.

## Architecture

Request flow, all of it in [main.py](src/entra_server/main.py):

1. Any unauthenticated request raises `NotAuthenticated`, which an `@app.exception_handler` turns into
   a 302 to Entra's authorization endpoint. Auth is enforced by the `CurrentUser` dependency, so a new
   route is protected by declaring `user: CurrentUser` and unprotected by omitting it.
2. Entra POSTs the `id_token` back to `/oauth2/token` (`CALLBACK_PATH`), which validates it and sets a
   `session` cookie.
3. `GET /{path:path}` serves the static site to signed-in visitors.
4. A request the page wants made against the backend is posted to `POST /api/send` and made *here*,
   by [backend.py](src/entra_server/backend.py), with both credentials attached. Everything else the
   page still sends itself with `fetch`.

The module split: [settings.py](src/entra_server/settings.py) (config), [oidc.py](src/entra_server/oidc.py)
(everything that talks to Entra or validates a token), [sessions.py](src/entra_server/sessions.py)
(signed session cookies, and pending logins in memory), [backend.py](src/entra_server/backend.py)
(the URL check and the forwarded request), [main.py](src/entra_server/main.py) (routes).

There are **two Entra identities in play**, and they are unrelated. `EntraID` signs *users* in (public
client, implicit flow, no secret). `ClientCredentials` gets an access token for the *backend API*
(confidential client, client credentials flow, its own client id and secret in the same tenant). A
backend token says nothing about who is signed in — every user gets the same one. Identity is carried
separately: the server attaches the visitor's own `id_token`, out of their session cookie, in a header
named `token`, for the backend to validate itself (audience `client_id`, this app). That is not
delegated access — a token the backend is the *audience* of would need the on-behalf-of flow.

**Neither token is ever served to a browser.** `/oauth2/id-token` and `/oauth2/backend-token` used to
hand them out and were removed; `test_the_routes_that_handed_out_tokens_are_gone` fails if either comes
back. Sending from the server also takes CORS out of the backend path entirely, which is what closed
the preflight problem: a browser preflight carries no headers and no credentials, the browser composes
the `OPTIONS` itself, and a backend that requires auth on `OPTIONS` blocks every browser client there
is. CORS still applies to the requests the page sends direct.

### The auth design, and why

This is the **implicit `id_token` flow with `response_mode=form_post`** — not authorization code +
PKCE. It needs no client secret, and the token arrives in a POST body rather than a URL that would
land in browser history and server logs. Switching to auth code would mean adding a secret and a token
endpoint call; it is a deliberate trade-off, not an oversight.

Two consequences that look like mistakes but aren't:

- **`state` lives server-side in `PendingLogins`, not in a cookie** — the one store that stayed after
  sessions moved into a cookie. The callback is a cross-site POST, so a `SameSite=Lax` cookie is not
  sent with it. A cookie-based state check would simply never match, and `SameSite=None` would require
  https, which the default `http://localhost:3000` is not.
- **`CALLBACK_PATH` has an explicit `GET` handler returning 405.** Without it, a stray GET falls
  through to the static catch-all, because Starlette prefers a fully matching route over a method
  match. Deleting it silently reopens that hole.

### Invariants worth not breaking

- **Token validation** ([oidc.py](src/entra_server/oidc.py)): RS256 is pinned in `algorithms` so a token
  can never choose its own algorithm; the nonce is compared with `secrets.compare_digest`; `require`
  lists the claims that must be present. Each of these has a test that fails if it is loosened.
- **JWKS is refetched only on a kid cache miss**, not per token. `_signing_key` must not eagerly await
  `_refresh_keys()` — that bug shipped once and `test_signing_keys_are_not_refetched_per_token` exists
  to catch it.
- **Only `settings.static_root` is ever served.** The web assets live *inside* the package
  (`src/entra_server/static/`) precisely so the catch-all cannot reach `pyproject.toml`, `uv.lock` or
  the sources. `resolve_static_file` additionally refuses traversal and dotfiles.
- **`main.py` must not be renamed back to `app.py`.** `__init__.py` re-exports `app`, which would
  shadow a submodule of the same name and break `from entra_server import app`.
- **The session is the cookie.** `SessionCookie` signs `base64(payload).base64(hmac-sha256)` and keeps
  no copy, so there is nothing to revoke: `/oauth2/logout` clears the cookie and a copy taken first
  keeps working until its `exp`. `read()` must verify the signature *before* it parses anything, and
  must re-validate what is inside through `IdTokenClaims` afterwards. An unset `cookie_secret` means a
  key per process, which is deliberate — it reproduces the old in-memory behaviour of signing everyone
  out on restart rather than falling back to a fixed, guessable key.
- **The payload holds the `id_token` itself, not a copy of its claims**, because `/api/send` sends the
  token on to the backend and two copies could disagree. `unverified_claims` reads it back without
  checking the RS256 signature, which is sound *only* for a token that `verify_id_token` accepted
  before the cookie was signed over it. Never point it at a token that arrived from a browser.
- **Pending logins are a plain dict with no locking**, which is safe only because every handler is
  async on one thread. More than one worker needs a shared store. `ClientCredentials` is the one
  exception: it holds an `asyncio.Lock`, because fetching a token awaits, so concurrent callers *can*
  interleave and each start their own fetch.
- **`targets_backend()` in [backend.py](src/entra_server/backend.py) is a security boundary, not a
  convenience.** `/api/send` attaches an application credential *and* an assertion of the user's
  identity, and the tool sends requests to whatever URL is typed into it — so without the check the
  route is an open proxy that hands both to any host a signed-in visitor names, from wherever the
  server sits. It compares the whole origin (scheme, host, port, default ports made explicit) and
  requires a path-segment prefix, so `/apiXX` is not below `/api`. `settings.backend_enabled` requires
  all four `backend_*` settings so the feature cannot come up half-configured with nothing to scope
  the tokens to. The page has its own `targetsBackend()`, but only to decide where to send; it is not
  what enforces anything.
- **The URL is parsed with `httpx2.URL`, the same library that sends it.** `httpx2` resolves dot
  segments before the request goes out, so `https://backend/api/../admin` leaves as `/admin` — a check
  against the raw text would have seen `/api/` and passed it. Anything that re-parses with `urlsplit`
  or compares strings reopens that. There is a test for exactly this URL.
- **`follow_redirects=False` on the proxy client.** Following a `Location` would carry the credentials
  to wherever it pointed, which need not be the backend. Redirects are returned to the page as the
  response.
- **New routes must be declared above `static_files`.** FastAPI matches in declaration order, and
  `GET /{path:path}` swallows everything after it. A route under `API_PREFIX` (`/api/`) is answered
  with a 401 rather than a 302 when the session is gone, because a `fetch` cannot follow a redirect to
  Microsoft — see the top of `start_sign_in`.

### HTTP client

Use **`httpx2`**, not `httpx`. Starlette 1.6's `TestClient` prefers `httpx2` and warns when it falls
back, so the app and the tests deliberately share one library. `httpx` is no longer a dependency.
Note that `httpx2` pulls in `truststore`, so TLS validates against the OS trust store rather than
certifi — relevant in a container with no system certs.

## Configuration

Values live in [.env](.env) (committed, no secrets) and `.env.local` (git-ignored, secrets and
overrides), read in that order by [settings.py](src/entra_server/settings.py); `ENTRA_*` environment
variables beat both. Don't reintroduce literal config values as field defaults — `tenant_id` and
`client_id` are deliberately required so a missing env file fails loudly instead of authenticating
against a stale hardcoded tenant.

The env files are resolved against the **working directory**, so the tests only pass when run from the
project root, and `load_settings()` converts a missing-field `ValidationError` into a `SystemExit`
naming the directory it searched. It re-raises anything that isn't a missing field, so a typo like
`ENTRA_SESSION_TTL=abc` still gets a real pydantic error.

`base_url` drives both `redirect_uri` and whether the session cookie is marked `Secure`, so changing it
to an `https://` URL requires adding the matching redirect URI to the app registration.

## Tests

pytest with `asyncio_mode = "auto"`, so async tests need no marker. Fixtures are in
[conftest.py](tests/conftest.py); token minting is in [helpers.py](tests/helpers.py) (`make_id_token`
takes claim overrides, and `None` drops a claim).

**The suite never touches the network** — `stub_entra` patches `EntraID._get_json` and serves the
discovery document and JWKS from memory. This means a green suite says nothing about whether real HTTP
works. After changing the HTTP client, TLS, or discovery, verify by hand: start the server and confirm
it logs no "could not reach Entra ID" warning, and that `GET /` redirects to an authorization endpoint
(that URL comes from the live discovery document, so it is real evidence).

Route tests reach into `main.pending_logins._pending` to recover the state/nonce a redirect issued,
which is what makes an end-to-end sign-in testable without a browser.

Two things about the `backend` fixture that are easy to break:

- Its stubbed `post_form` **awaits `asyncio.sleep(0)`**. A stub that never yields runs straight through,
  so concurrent callers never interleave and `test_concurrent_callers_share_one_request` passes even
  with the lock deleted. Verified by removing the lock and watching it fail.
- It replaces `_lock` with a fresh `asyncio.Lock`. The one built at import time binds to the first
  event loop that acquires it, and pytest-asyncio gives each test its own loop.

The `forwarding` fixture (which depends on `backend`) patches `main.proxy._client.request`, records the
`httpx2.Request`s the server would have sent, and returns a reassignable `handle.reply(request)`. It is
what makes it testable that a credential went out on *this* request and not on that one; the tests for
it are in [test_proxy.py](tests/test_proxy.py).

**The page has no Python test at all** — pytest never loads index.html. What covers it is
[page.js](tests/page.js): `node tests/page.js`, no dependencies and no runner, which runs the real
script from the HTML against a small DOM shim and asserts on what `fetch` was handed. That is what
proves the browser holds no credential at all and that only backend URLs go to `/api/send`. Its shim
models `document.write()` teardown one-way (`document.open()` discards the document, so afterwards
`getElementById` returns null) — the check for that must stay last, since nothing works after it.
Run it after touching the script, and extend the shim when the page starts using a DOM feature it does
not know about. It is not in `uv run pytest`; nothing runs it for you.
