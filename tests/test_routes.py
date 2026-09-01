"""The whole sign-in round trip, through the real FastAPI app."""

import time

import pytest

from entra_server import main
from entra_server.main import resolve_static_file, safe_next
from entra_server.oidc import unverified_claims
from entra_server.sessions import SessionCookie
from entra_server.settings import CALLBACK_PATH, SESSION_COOKIE, settings
from tests.helpers import make_id_token


def start_login(client, path="/"):
    """Follow a redirect to Entra and return the state/nonce it was issued."""
    response = client.get(path)
    assert response.status_code == 302
    state = next(iter(main.pending_logins._pending))
    return state, main.pending_logins._pending[state][0]


# ---------------------------------------------------------------------------
# Unauthenticated
# ---------------------------------------------------------------------------


def test_unauthenticated_visitor_is_sent_to_entra(client):
    response = client.get("/index.html")
    assert response.status_code == 302
    location = response.headers["location"]
    assert f"client_id={settings.client_id}" in location
    assert "response_type=id_token" in location
    assert "response_mode=form_post" in location
    assert "nonce=" in location


def test_callback_does_not_answer_get(client):
    assert client.get(CALLBACK_PATH).status_code == 405


def test_claims_endpoint_requires_a_session(client):
    assert client.get("/oauth2/me").status_code == 302


def test_explicit_login_route_starts_a_sign_in(client):
    response = client.get("/oauth2/login", params={"next": "/index.html"})
    assert response.status_code == 302
    state = next(iter(main.pending_logins._pending))
    assert main.pending_logins._pending[state][1] == "/index.html"


def test_login_route_will_not_redirect_offsite(client):
    client.get("/oauth2/login", params={"next": "https://evil.example.com/"})
    state = next(iter(main.pending_logins._pending))
    assert main.pending_logins._pending[state][1] == "/"


# ---------------------------------------------------------------------------
# The callback
# ---------------------------------------------------------------------------


def test_valid_callback_issues_a_session_cookie(client, sign_in):
    response = sign_in()
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    assert response.headers["location"] == "/"


def test_callback_returns_the_visitor_to_the_page_they_asked_for(client, sign_in):
    assert sign_in("/nested/page.html").headers["location"] == "/nested/page.html"


def test_callback_with_unknown_state_is_refused(client):
    response = client.post(CALLBACK_PATH, data={"id_token": make_id_token(), "state": "made-up"})
    assert response.status_code == 400
    assert "set-cookie" not in response.headers


def test_callback_with_invalid_token_is_refused(client):
    state, nonce = start_login(client)
    expired = make_id_token(nonce=nonce, exp=int(time.time()) - 3600)
    response = client.post(CALLBACK_PATH, data={"id_token": expired, "state": state})
    assert response.status_code == 401
    assert "set-cookie" not in response.headers


def test_callback_without_a_token_is_refused(client):
    state, _ = start_login(client)
    assert client.post(CALLBACK_PATH, data={"state": state}).status_code == 400


def test_callback_state_cannot_be_replayed(client):
    state, nonce = start_login(client)
    callback = {"id_token": make_id_token(nonce=nonce), "state": state}
    assert client.post(CALLBACK_PATH, data=callback).status_code == 303
    assert client.post(CALLBACK_PATH, data=callback).status_code == 400


def test_error_from_entra_is_shown(client):
    response = client.post(
        CALLBACK_PATH, data={"error": "access_denied", "error_description": "user cancelled"}
    )
    assert response.status_code == 400
    assert "access_denied" in response.text


# ---------------------------------------------------------------------------
# Signed in
# ---------------------------------------------------------------------------


def test_signed_in_visitor_gets_the_site(client, sign_in):
    sign_in()
    response = client.get("/index.html")
    assert response.status_code == 200
    assert "HTTP Request Sender" in response.text


def test_root_serves_the_index(client, sign_in):
    sign_in()
    assert "<!DOCTYPE html>" in client.get("/").text


def test_signed_in_visitor_can_read_their_claims(client, sign_in):
    sign_in()
    claims = client.get("/oauth2/me").json()
    assert claims["preferred_username"] == "test.user@example.com"
    assert claims["tid"] == settings.tenant_id


def test_the_session_still_carries_the_token_itself(client, sign_in):
    # No route hands it to a browser any more -- see tests/test_proxy.py -- but the
    # server needs it to identify the visitor to the backend, so it is in the cookie.
    sign_in()
    session = main.sessions.read(client.cookies[SESSION_COOKIE])

    assert session is not None
    assert unverified_claims(session.id_token).preferred_username == "test.user@example.com"


@pytest.mark.parametrize("path", ["/server.py", "/pyproject.toml", "/uv.lock", "/../pyproject.toml"])
def test_project_files_are_never_served(client, sign_in, path):
    sign_in()
    assert client.get(path).status_code == 404


def test_logout_ends_the_session(client, sign_in):
    sign_in()
    assert client.get("/oauth2/logout").status_code == 303
    assert client.get("/index.html").status_code == 302


def test_forged_session_cookie_is_not_accepted(client):
    client.cookies.set(SESSION_COOKIE, "a-cookie-we-never-issued")
    assert client.get("/index.html").status_code == 302


@pytest.mark.parametrize(
    ("secret_after_restart", "expected"), [("the-secret", 200), ("a-different-secret", 302)]
)
def test_a_session_outlives_a_restart_only_if_the_secret_does(
    client, sign_in, monkeypatch, secret_after_restart, expected
):
    # Nothing about the session is held here, so the cookie alone has to carry it
    # across a restart -- which it can only do if the same key verifies it.
    monkeypatch.setattr(main, "sessions", SessionCookie(secret="the-secret", ttl=3600))
    sign_in()

    monkeypatch.setattr(main, "sessions", SessionCookie(secret=secret_after_restart, ttl=3600))
    assert client.get("/oauth2/me").status_code == expected


# ---------------------------------------------------------------------------
# Path handling
# ---------------------------------------------------------------------------


def test_site_files_resolve():
    assert resolve_static_file("index.html").name == "index.html"
    assert resolve_static_file("").name == "index.html"


@pytest.mark.parametrize(
    "path", ["../app.py", "../../pyproject.toml", "../../../etc/passwd", ".hidden", "no/such/file"]
)
def test_traversal_and_private_files_do_not_resolve(path):
    assert resolve_static_file(path) is None


@pytest.mark.parametrize("target", ["/", "/index.html", "/deep/page"])
def test_local_paths_are_preserved(target):
    assert safe_next(target) == target


@pytest.mark.parametrize(
    "target", ["https://evil.example.com/", "//evil.example.com/", "http:/evil", "", "evil.com"]
)
def test_offsite_targets_fall_back_to_the_root(target):
    assert safe_next(target) == "/"
