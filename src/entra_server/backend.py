"""Sending a request to the backend API from here, rather than from the browser.

The page does not hold either credential. It posts what it wants sent to `/api/send`
and this makes the call: the application's access token in `Authorization`, the
signed-in visitor's id_token in `token`. Neither is ever served to a browser, so
there is nothing in the page for a typed-in URL to capture.

Only `settings.backend_url` can be reached this way, and here that rule is the whole
boundary rather than a convenience -- forwarding anything else would turn this into
an open proxy that attaches credentials, reachable from wherever the server sits.
"""

import httpx2
from pydantic import BaseModel

from .oidc import ClientCredentials
from .settings import Settings

# The methods the page offers. Anything else is refused rather than forwarded:
# the list exists so a typo cannot become a request nobody meant to make.
ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

# Meaningful only for the hop the browser made to us, and wrong for the one we make
# next. `host` and `content-length` are rebuilt by the client for the actual request.
SKIPPED_HEADERS = frozenset(
    {"connection", "content-length", "host", "keep-alive", "proxy-authenticate",
     "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}
)

DEFAULT_PORTS = {"http": 80, "https": 443}

# The whole body is read into memory and then into a JSON response, so it is capped.
# The tool displays text; a response larger than this is not one you read in a <pre>.
MAX_BODY_BYTES = 2_000_000


def _parse(url: str) -> httpx2.URL | None:
    """The URL as the client will actually request it, or None if it is not one.

    Parsed with the same library that sends it on purpose. `httpx2.URL` resolves
    `..` before the request is made, so checking anything else would be checking a
    URL that is not the one going out: `/api/../admin` is `/admin` by the time it
    leaves, and a check on the text would have seen it start with `/api/`.
    """
    try:
        parsed = httpx2.URL(url)
    except httpx2.InvalidURL:
        return None
    if parsed.scheme not in DEFAULT_PORTS or not parsed.host:
        return None
    return parsed


def targets_backend(url: str, backend_url: str) -> bool:
    """Whether a URL is at or below the backend prefix.

    The origin must match exactly -- scheme, host and port -- and the path must be
    below the prefix by whole segments, so `/apiXX` next to `/api` is not a match.
    """
    if not backend_url:
        return False
    target, base = _parse(url), _parse(backend_url)
    if target is None or base is None:
        return False
    if (target.scheme, target.host, target.port or DEFAULT_PORTS[target.scheme]) != (
        base.scheme,
        base.host,
        base.port or DEFAULT_PORTS[base.scheme],
    ):
        return False
    prefix = base.path if base.path.endswith("/") else base.path + "/"
    return (target.path + "/").startswith(prefix)


class Forwarded(BaseModel):
    """What the backend answered, as the page needs it to render the response."""

    status: int
    reason: str
    url: str
    # A list, not a dict: set-cookie and friends may appear more than once, and
    # collapsing them would quietly hide one.
    headers: list[tuple[str, str]]
    body: str
    # Which headers this server attached, so the page reports what was actually
    # sent rather than what it assumes was sent.
    added: list[str]
    truncated: bool = False


class BackendProxy:
    """Makes the call to the backend, with the credentials the browser never sees."""

    def __init__(self, settings: Settings, credentials: ClientCredentials) -> None:
        self.settings = settings
        self._credentials = credentials
        # Redirects are returned to the page, not followed: a Location may point
        # anywhere, and following it would take the credentials off the backend.
        self._client = httpx2.AsyncClient(timeout=settings.backend_timeout, follow_redirects=False)

    async def close(self) -> None:
        await self._client.aclose()

    async def send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: str | None,
        id_token: str,
    ) -> Forwarded:
        """Forward one request. The caller has already checked the URL and the method."""
        outgoing, added = await self._headers(headers, id_token)
        response = await self._client.request(
            method,
            url,
            headers=outgoing,
            content=body.encode() if body else None,
        )
        text = response.text
        return Forwarded(
            status=response.status_code,
            reason=response.reason_phrase,
            url=str(response.url),
            headers=list(response.headers.multi_items()),
            body=text[:MAX_BODY_BYTES],
            added=added,
            truncated=len(text) > MAX_BODY_BYTES,
        )

    async def _headers(self, typed: dict[str, str], id_token: str) -> tuple[dict[str, str], list[str]]:
        """The headers to send, and the names of the ones this server supplied.

        A header typed into the form wins, as it did when the page sent the request
        itself: the tool is for making the request you asked for.
        """
        outgoing = {name: value for name, value in typed.items() if name.lower() not in SKIPPED_HEADERS}
        present = {name.lower() for name in outgoing}
        added = []

        if "authorization" not in present:
            token = await self._credentials.access_token()
            outgoing["Authorization"] = f"Bearer {token.access_token}"
            added.append("Authorization")
        if "token" not in present:
            outgoing["token"] = id_token
            added.append("token")

        return outgoing, added
