"""Access tokens for the backend API, via the client credentials flow."""

import asyncio
import time

import pytest
from pydantic import SecretStr

from entra_server.oidc import ClientCredentials, TokenError
from entra_server.settings import settings
from tests.conftest import BACKEND_URL

# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------


async def test_token_is_requested_with_the_client_credentials_grant(backend):
    token = await backend.credentials.access_token()

    assert token.access_token == "backend-token-0"
    assert backend.forms == [
        {
            "grant_type": "client_credentials",
            "client_id": "backend-client",
            "client_secret": "the-client-secret",
            "scope": "api://backend/.default",
        }
    ]


async def test_token_is_cached_between_calls(backend):
    first = await backend.credentials.access_token()
    second = await backend.credentials.access_token()

    assert first.access_token == second.access_token
    assert len(backend.forms) == 1


async def test_concurrent_callers_share_one_request(backend):
    tokens = await asyncio.gather(*(backend.credentials.access_token() for _ in range(5)))

    # Without the lock each caller would fetch its own token.
    assert len({token.access_token for token in tokens}) == 1
    assert len(backend.forms) == 1


async def test_token_is_renewed_once_it_nears_expiry(backend):
    first = await backend.credentials.access_token()
    backend.credentials._renew_at = time.monotonic() - 1  # as if the margin had elapsed

    second = await backend.credentials.access_token()

    assert second.access_token != first.access_token
    assert len(backend.forms) == 2


# ---------------------------------------------------------------------------
# Renewal margin
# ---------------------------------------------------------------------------


async def test_renewal_is_scheduled_before_the_token_actually_expires(backend):
    token = await backend.credentials.access_token()
    assert token.expires_in == 3600 - ClientCredentials.RENEW_MARGIN


@pytest.mark.parametrize(
    ("expires_in", "renew_after"),
    [
        (3600, 3300),  # the usual case: renew five minutes early
        (600, 300),
        (60, 30),  # shorter than the margin: fall back to half the lifetime
        (10, 5),
    ],
)
async def test_short_tokens_are_not_refetched_on_every_request(backend, expires_in, renew_after):
    backend.reply = lambda: {"access_token": "short-lived", "expires_in": expires_in}
    token = await backend.credentials.access_token()
    assert token.expires_in == renew_after


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------


async def test_a_rejected_secret_is_reported(backend):
    backend.reply = lambda: {
        "error": "invalid_client",
        "error_description": "AADSTS7000215: Invalid client secret provided.",
    }
    with pytest.raises(TokenError) as caught:
        await backend.credentials.access_token()
    assert "invalid_client" in str(caught.value)


async def test_a_response_without_a_token_is_rejected(backend):
    backend.reply = lambda: {"token_type": "Bearer", "expires_in": 3600}
    with pytest.raises(TokenError):
        await backend.credentials.access_token()


async def test_a_failed_fetch_is_not_cached(backend):
    backend.reply = lambda: {"error": "temporarily_unavailable"}
    with pytest.raises(TokenError):
        await backend.credentials.access_token()

    backend.reply = lambda: {"access_token": "recovered", "expires_in": 3600}
    assert (await backend.credentials.access_token()).access_token == "recovered"


async def test_no_token_without_credentials(entra, monkeypatch):
    monkeypatch.setattr(settings, "backend_client_id", "")
    with pytest.raises(TokenError, match="no backend credentials"):
        await ClientCredentials(settings, entra).access_token()


@pytest.mark.parametrize(
    ("missing", "empty"),
    [
        ("backend_client_id", ""),
        ("backend_client_secret", SecretStr("")),
        ("backend_scope", ""),
        ("backend_url", ""),
    ],
)
def test_every_backend_setting_is_required(backend, monkeypatch, missing, empty):
    # Half a configuration must not enable the feature -- least of all a token
    # with no backend_url to confine it to.
    assert settings.backend_enabled
    monkeypatch.setattr(settings, missing, empty)
    assert not settings.backend_enabled


# ---------------------------------------------------------------------------
# The route
# ---------------------------------------------------------------------------


def test_token_route_requires_a_session(client, backend):
    assert client.get("/oauth2/backend-token").status_code == 302


def test_signed_in_visitor_gets_a_token(client, backend, sign_in):
    sign_in()
    response = client.get("/oauth2/backend-token")

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "backend-token-0",
        "expires_in": 3600 - ClientCredentials.RENEW_MARGIN,
        "backend_url": BACKEND_URL,
    }


def test_token_route_is_absent_when_no_backend_is_configured(client, sign_in, monkeypatch):
    monkeypatch.setattr(settings, "backend_client_id", "")
    sign_in()
    assert client.get("/oauth2/backend-token").status_code == 404


def test_token_route_reports_a_failure_without_leaking_the_reason(client, backend, sign_in):
    backend.reply = lambda: {
        "error": "invalid_client",
        "error_description": "AADSTS7000215: Invalid client secret provided.",
    }
    sign_in()
    response = client.get("/oauth2/backend-token")

    assert response.status_code == 503
    assert "AADSTS7000215" not in response.text  # that belongs in the log, not the browser
