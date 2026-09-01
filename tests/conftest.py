"""Fixtures shared by the tests.

The `stub_entra` fixture serves the tenant's discovery document and JWKS from
memory -- including on the refresh that an unknown kid triggers -- so no test
ever reaches the network.
"""

import asyncio
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

import httpx2
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from entra_server import main
from entra_server.settings import CALLBACK_PATH, settings
from tests.helpers import ISSUER, KID, SIGNING_KEY, jwks, make_id_token

TOKEN_ENDPOINT = "https://stub.invalid/oauth2/v2.0/token"
BACKEND_URL = "https://backend.invalid/api"


@pytest.fixture
def stub_entra():
    """Factory: serve a chosen key set from the tenant's endpoints."""

    @contextmanager
    def stub(published_key=None, kid=KID, issuer=ISSUER):
        metadata = {
            "issuer": issuer,
            "jwks_uri": "https://stub.invalid/discovery/keys",
            "authorization_endpoint": "https://stub.invalid/oauth2/v2.0/authorize",
            "token_endpoint": TOKEN_ENDPOINT,
        }
        key_set = jwks(published_key or SIGNING_KEY, kid=kid)

        async def fetch(url):
            return metadata if url == settings.discovery_url else key_set

        with (
            mock.patch.object(main.entra, "_get_json", mock.AsyncMock(side_effect=fetch)),
            mock.patch.object(main.entra, "_metadata", None),
            mock.patch.object(main.entra, "_metadata_fetched_at", 0.0),
            mock.patch.object(main.entra, "_keys", None),
        ):
            yield main.entra

    return stub


@pytest.fixture
def entra(stub_entra):
    """The application's EntraID instance, wired to the in-memory stub."""
    with stub_entra() as stubbed:
        yield stubbed


@pytest.fixture
def backend(entra, monkeypatch):
    """Configure a backend app registration and serve its tokens from memory.

    Returns a handle whose `.forms` lists every token request that was made, and
    whose `.reply` can be reassigned to make the token endpoint fail.
    """
    monkeypatch.setattr(settings, "backend_client_id", "backend-client")
    monkeypatch.setattr(settings, "backend_client_secret", SecretStr("the-client-secret"))
    monkeypatch.setattr(settings, "backend_scope", "api://backend/.default")
    monkeypatch.setattr(settings, "backend_url", BACKEND_URL)

    handle = SimpleNamespace(forms=[], reply=None)
    handle.reply = lambda: {
        "token_type": "Bearer",
        "expires_in": 3600,
        "access_token": f"backend-token-{len(handle.forms)}",
    }

    async def post_form(url, form):
        assert url == TOKEN_ENDPOINT
        # Yield to the event loop, as a real request would. Without this the
        # stub runs straight through and concurrent callers never interleave,
        # which would make the de-duplication test pass even with no lock.
        await asyncio.sleep(0)
        reply = handle.reply()  # numbered by the requests made *before* this one
        handle.forms.append(form)
        return reply

    monkeypatch.setattr(main.entra, "post_form", post_form)

    credentials = main.backend_credentials
    credentials._token, credentials._renew_at = None, 0.0
    # The lock is created at import time; each test runs in its own event loop,
    # and an asyncio.Lock may not be reused across loops.
    credentials._lock = asyncio.Lock()
    handle.credentials = credentials
    return handle


@pytest.fixture
def forwarding(backend, monkeypatch):
    """Answer the backend itself, and record what was sent to it.

    `.requests` lists every outbound request the proxy made, so a test can assert on
    the headers it attached -- and, just as much, that no request was made at all.
    `.reply` can be reassigned to answer differently, or raise.
    """
    handle = SimpleNamespace(requests=[], reply=None)
    handle.reply = lambda request: httpx2.Response(
        200,
        headers=[("content-type", "text/plain"), ("x-from", "the backend")],
        content=b"hello",
        request=request,
    )

    async def request(method, url, headers=None, content=None):
        outgoing = httpx2.Request(method, url, headers=headers, content=content)
        handle.requests.append(outgoing)
        return handle.reply(outgoing)

    monkeypatch.setattr(main.proxy._client, "request", request)
    return handle


@pytest.fixture(autouse=True)
def clean_state():
    """Keep pending logins and backend tokens from leaking between tests.

    Sessions need no cleanup: they live entirely in the cookies the test client holds.
    """
    yield
    main.pending_logins._pending.clear()
    main.backend_credentials._token = None
    main.backend_credentials._renew_at = 0.0


@pytest.fixture
def client(entra):
    """A test client that does not follow redirects, so they can be asserted on.

    Constructed without the lifespan context, so startup never calls out to Entra.
    """
    return TestClient(main.app, follow_redirects=False)


@pytest.fixture
def sign_in(client):
    """Take the client through a full, successful sign-in."""

    def _sign_in(next_path="/"):
        response = client.get(next_path)
        assert response.status_code == 302
        state = next(iter(main.pending_logins._pending))
        nonce = main.pending_logins._pending[state][0]
        callback = client.post(CALLBACK_PATH, data={"id_token": make_id_token(nonce=nonce), "state": state})
        assert callback.status_code == 303
        return callback

    return _sign_in
