"""The FastAPI application: routes, the auth dependency, and static file serving.

Unauthenticated requests are redirected to Entra ID. Entra posts the resulting
id_token back to /oauth2/token, where it is validated before a session cookie is
issued. That cookie carries the claims themselves, signed; the only state the
server keeps is the logins currently in flight.

App registration (Azure portal -> App registrations):
  * Redirect URI of type "Web": http://localhost:3000/oauth2/token
  * Under "Implicit grant and hybrid flows", tick "ID tokens".

No client secret is needed: this uses the implicit id_token flow with
response_mode=form_post, so the token arrives in a POST body rather than in a
URL that would end up in browser history and server logs.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import httpx2
from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel

from .oidc import ClientCredentials, EntraID, IdTokenClaims, TokenError
from .sessions import PendingLogins, SessionCookie
from .settings import CALLBACK_PATH, SESSION_COOKIE, env_files_found, settings

log = logging.getLogger(__name__)

# Browsers drop a cookie of about 4 KB; warn well before one goes silently missing.
MAX_COOKIE_BYTES = 3500

entra = EntraID(settings)
backend_credentials = ClientCredentials(settings, entra)
pending_logins = PendingLogins(settings.login_ttl)
sessions = SessionCookie(settings.cookie_secret.get_secret_value(), settings.session_ttl)


class NotAuthenticated(Exception):
    """No valid session. Handled by redirecting the visitor to Entra ID."""

    def __init__(self, next_path: str = "/") -> None:
        self.next_path = next_path


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    found = env_files_found()
    log.info("configuration from %s", ", ".join(str(path) for path in found) if found else "the environment")
    log.info("tenant %s, client %s", settings.tenant_id, settings.client_id)
    log.info("callback %s, serving %s", settings.redirect_uri, settings.static_root)
    if sessions.ephemeral:
        log.info("no ENTRA_COOKIE_SECRET set; session cookies are signed with a key for this process only")
    try:
        # Warm the cache so a misconfigured tenant shows up now, not on first sign-in.
        await entra.metadata()
    except Exception as error:
        log.warning("could not reach Entra ID at startup: %s", error)

    if settings.backend_enabled:
        log.info("backend %s, scope %s", settings.backend_url, settings.backend_scope)
        try:
            # Likewise: a bad client secret should surface at startup.
            await backend_credentials.access_token()
        except Exception as error:
            log.warning("could not get a backend access token at startup: %s", error)
    else:
        log.info("no backend credentials configured; requests are sent unauthenticated")
    yield
    await entra.close()


app = FastAPI(title="Authenticated static server", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def error_page(status_code: int, title: str, message: str) -> HTMLResponse:
    return HTMLResponse(
        status_code=status_code,
        content=(
            f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{title}</title>"
            "<style>body{background:#14161a;color:#e6e8ec;font:14px/1.6 system-ui,sans-serif;"
            "padding:48px;max-width:640px;margin:0 auto}a{color:#5b8cff}"
            "pre{white-space:pre-wrap;color:#9aa1ad}</style></head>"
            f"<body><h1>{title}</h1><pre>{message}</pre>"
            "<p><a href='/'>Back to the app</a></p></body></html>"
        ),
    )


def safe_next(target: str) -> str:
    """Only ever redirect back to a path on this server, never to another host."""
    return target if target.startswith("/") and not target.startswith("//") else "/"


def resolve_static_file(path: str) -> Path | None:
    """Map a request path to a file under the static directory, or None.

    Anything that escapes the directory (../..) or names a hidden file is
    refused; the project's own sources live outside it and are unreachable.
    """
    root = settings.static_root
    candidate = (root / (path or "index.html")).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None
    if any(part.startswith(".") for part in candidate.relative_to(root).parts):
        return None
    return candidate


async def current_user(
    request: Request,
    session: Annotated[str | None, Cookie()] = None,
) -> IdTokenClaims:
    """Dependency for anything that requires a signed-in visitor."""
    claims = sessions.read(session)
    if claims is None:
        raise NotAuthenticated(next_path=request.url.path)
    return claims


CurrentUser = Annotated[IdTokenClaims, Depends(current_user)]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.exception_handler(NotAuthenticated)
async def start_sign_in(request: Request, error: NotAuthenticated) -> Response:
    """Send visitors without a session to Entra ID to sign in."""
    try:
        state, nonce = pending_logins.start(safe_next(error.next_path))
        return RedirectResponse(await entra.authorization_url(state, nonce), status_code=302)
    except (httpx2.HTTPError, TokenError) as failure:
        log.exception("OpenID discovery failed")
        return error_page(503, "Sign-in unavailable", f"Could not reach Entra ID: {failure}")


@app.get("/oauth2/login", include_in_schema=False)
async def login(next: str = "/") -> Response:
    """Start a sign-in explicitly, rather than by hitting a protected page."""
    raise NotAuthenticated(next_path=next)


@app.get(CALLBACK_PATH, include_in_schema=False)
async def callback_is_post_only() -> Response:
    """Declared so a stray GET does not fall through to the static catch-all."""
    return error_page(405, "Method not allowed", "The callback is delivered by POST.")


@app.post(CALLBACK_PATH, include_in_schema=False)
async def callback(
    id_token: Annotated[str | None, Form()] = None,
    state: Annotated[str | None, Form()] = None,
    error: Annotated[str | None, Form()] = None,
    error_description: Annotated[str | None, Form()] = None,
) -> Response:
    """Receive the id_token that Entra ID posts back after sign-in."""
    if error:
        log.warning("Entra ID returned an error: %s", error)
        return error_page(400, "Sign-in failed", f"{error}: {error_description or ''}")

    pending = pending_logins.take(state or "")
    if pending is None:
        # Unknown, expired or already-used state: not a callback we started.
        return error_page(400, "Sign-in failed", "Invalid or expired state. Please start again.")
    nonce, next_path = pending

    if not id_token:
        return error_page(400, "Sign-in failed", "No id_token in the callback.")

    try:
        claims = await entra.verify_id_token(id_token, nonce)
    except TokenError as failure:
        log.warning("id_token rejected: %s", failure)
        return error_page(401, "Sign-in failed", f"The id_token is not valid: {failure}")
    except httpx2.HTTPError as failure:
        log.exception("could not fetch signing keys")
        return error_page(503, "Sign-in failed", f"Could not validate the id_token: {failure}")

    cookie, max_age = sessions.mint(claims)
    if len(cookie) > MAX_COOKIE_BYTES:
        # Entra can be configured to emit large claims (a groups claim, most often),
        # and the browser would drop the cookie without saying so.
        log.warning("session cookie is %d bytes; the browser may refuse it", len(cookie))
    log.info("signed in: %s", claims.preferred_username or claims.sub)

    response = RedirectResponse(next_path, status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        cookie,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=settings.cookies_are_secure,
        path="/",
    )
    return response


@app.get("/oauth2/logout", include_in_schema=False)
async def logout() -> Response:
    """Clear the session cookie.

    There is nothing else to clear: the session lives only in the cookie, so a copy
    of it taken beforehand stays valid until its own expiry. Revoking early would
    mean keeping a list of dead sessions, which is the server-side state this
    deliberately does without.
    """
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/oauth2/me")
async def me(user: CurrentUser) -> IdTokenClaims:
    """The claims of the validated id_token this session was created from."""
    return user


class BackendToken(BaseModel):
    """What the page needs in order to call the backend."""

    access_token: str
    expires_in: int
    backend_url: str


@app.get("/oauth2/backend-token")
async def backend_token(user: CurrentUser) -> BackendToken:
    """An access token for the backend API, for the page to send as a Bearer token.

    Only signed-in visitors get one, and `backend_url` tells the page the single
    prefix it may send the token to.
    """
    if not settings.backend_enabled:
        raise HTTPException(status_code=404, detail="No backend credentials are configured.")
    try:
        token = await backend_credentials.access_token()
    except (httpx2.HTTPError, TokenError) as failure:
        # The description names the misconfigured setting, which is for the log,
        # not for the browser.
        log.error("could not get a backend access token: %s", failure)
        raise HTTPException(status_code=503, detail="Could not get a backend access token.") from failure
    return BackendToken(
        access_token=token.access_token,
        expires_in=token.expires_in,
        backend_url=settings.backend_url,
    )


@app.get("/{path:path}", include_in_schema=False)
async def static_files(path: str, user: CurrentUser) -> Response:
    """Serve the site to signed-in visitors."""
    file = resolve_static_file(path)
    if file is None:
        return error_page(404, "Not found", "No such file.")
    return FileResponse(file, headers={"Cache-Control": "no-store"})
