"""Forwarding a request to the backend, which is where both credentials live.

Two things are being tested. That the request the page asked for is the request the
backend receives, with the tokens attached -- and that a URL which is not the backend
is refused before anything is sent to it. The second is the point: the page is only
ever a caller here, and the check that keeps this from being an open proxy with
credentials attached is the one in this process.
"""

import httpx2
import pytest

from entra_server.backend import targets_backend
from entra_server.settings import settings
from tests.conftest import BACKEND_URL

THINGS = f"{BACKEND_URL}/things"


def post(client, **payload):
    body = {"method": "GET", "url": THINGS, "headers": {}, "body": None} | payload
    return client.post("/api/send", json=body)


def sent(forwarding):
    """The one request that was forwarded."""
    assert len(forwarding.requests) == 1
    return forwarding.requests[0]


# ---------------------------------------------------------------------------
# Which URLs are the backend
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://backend.invalid/api",  # the prefix itself
        "https://backend.invalid/api/",
        "https://backend.invalid/api/things",
        "https://backend.invalid/api/things?q=1",
        "https://backend.invalid:443/api/things",  # the default port, spelled out
        "https://BACKEND.invalid/api/things",  # hosts are case-insensitive
    ],
)
def test_urls_at_or_below_the_prefix_are_the_backend(url):
    assert targets_backend(url, BACKEND_URL)


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.invalid/api/things",  # another host
        "https://backend.invalid.evil.com/api/things",  # a suffix of the host
        "https://backend.invalid/apiXX/things",  # a lookalike path, not a segment
        "https://backend.invalid/other",  # the right host, the wrong path
        "http://backend.invalid/api/things",  # the right host, the wrong scheme
        "https://backend.invalid:8443/api/things",  # the right host, another port
        "https://user@backend.invalid/api/../other",  # not normalised into the prefix
        "file:///etc/passwd",  # not http at all
        "//backend.invalid/api/things",  # no scheme
        "not a url",
        "",
    ],
)
def test_everything_else_is_not(url):
    assert not targets_backend(url, BACKEND_URL)


def test_nothing_is_the_backend_when_none_is_configured():
    assert not targets_backend(THINGS, "")


# ---------------------------------------------------------------------------
# The route
# ---------------------------------------------------------------------------


def test_the_request_is_made_with_both_credentials_attached(client, sign_in, forwarding):
    sign_in()
    response = post(client, headers={"Accept": "application/json"})

    assert response.status_code == 200
    request = sent(forwarding)
    assert str(request.url) == THINGS
    assert request.headers["authorization"] == "Bearer backend-token-0"
    # The visitor's own id_token, for the backend to validate as a token in its
    # own right. It is the one the session was created from.
    assert request.headers["token"].count(".") == 2
    assert request.headers["accept"] == "application/json"
    assert response.json()["added"] == ["Authorization", "token"]


def test_the_response_comes_back_whole(client, sign_in, forwarding):
    sign_in()
    body = post(client).json()

    assert body["status"] == 200
    assert body["reason"] == "OK"
    assert body["body"] == "hello"
    assert body["truncated"] is False
    # Every header, not the handful CORS would have exposed to the page.
    assert ["x-from", "the backend"] in [list(pair) for pair in body["headers"]]


def test_repeated_response_headers_are_all_returned(client, sign_in, forwarding):
    forwarding.reply = lambda request: httpx2.Response(
        200,
        headers=[("set-cookie", "a=1"), ("set-cookie", "b=2")],
        content=b"",
        request=request,
    )
    sign_in()
    headers = [pair for pair in post(client).json()["headers"] if pair[0] == "set-cookie"]

    assert headers == [["set-cookie", "a=1"], ["set-cookie", "b=2"]]


def test_a_body_is_forwarded(client, sign_in, forwarding):
    sign_in()
    post(client, method="POST", body='{"a":1}', headers={"Content-Type": "application/json"})

    assert sent(forwarding).content == b'{"a":1}'


def test_a_header_typed_into_the_form_wins(client, sign_in, forwarding):
    sign_in()
    body = post(client, headers={"Authorization": "Basic something", "token": "mine"}).json()

    request = sent(forwarding)
    assert request.headers["authorization"] == "Basic something"
    assert request.headers["token"] == "mine"
    assert body["added"] == []  # and the page is told that nothing was added


def test_per_hop_headers_are_not_passed_on(client, sign_in, forwarding):
    sign_in()
    post(client, headers={"Host": "elsewhere.invalid", "Connection": "close", "Content-Length": "99"})

    request = sent(forwarding)
    assert request.headers["host"] == "backend.invalid"  # rebuilt for the request we make
    assert "connection" not in request.headers
    assert request.headers.get("content-length") != "99"


# ---------------------------------------------------------------------------
# What is refused
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.invalid/api/things",
        "https://backend.invalid/apiXX/things",
        "http://backend.invalid/api/things",
        "http://169.254.169.254/latest/meta-data/",  # the cloud metadata service
        "file:///etc/passwd",
    ],
)
def test_a_url_that_is_not_the_backend_is_refused(client, sign_in, forwarding, url):
    sign_in()
    response = post(client, url=url)

    assert response.status_code == 400
    assert BACKEND_URL in response.json()["detail"]
    # Nothing was sent: the refusal is before the request, not after it.
    assert forwarding.requests == []


def test_an_unknown_method_is_refused(client, sign_in, forwarding):
    sign_in()
    response = post(client, method="TRACE")

    assert response.status_code == 400
    assert forwarding.requests == []


def test_forwarding_requires_a_session(client, forwarding):
    response = post(client)

    # 401 rather than the usual redirect: a fetch cannot follow one to Microsoft.
    assert response.status_code == 401
    assert "expired" in response.json()["detail"]
    assert forwarding.requests == []


def test_nothing_is_forwarded_without_a_backend(client, sign_in, monkeypatch):
    monkeypatch.setattr(settings, "backend_client_id", "")
    sign_in()
    assert post(client).status_code == 404


def test_a_backend_that_cannot_be_reached_is_reported(client, sign_in, forwarding):
    def refuse(request):
        raise httpx2.ConnectError("connection refused")

    forwarding.reply = refuse
    sign_in()
    response = post(client)

    assert response.status_code == 502
    assert "could not be reached" in response.json()["detail"]


def test_a_rejected_client_secret_is_reported_without_the_reason(client, sign_in, backend, forwarding):
    backend.reply = lambda: {
        "error": "invalid_client",
        "error_description": "AADSTS7000215: Invalid client secret provided.",
    }
    sign_in()
    response = post(client)

    assert response.status_code == 503
    assert "AADSTS7000215" not in response.text  # that belongs in the log, not the browser
    assert forwarding.requests == []


# ---------------------------------------------------------------------------
# Nothing hands a token to the browser
# ---------------------------------------------------------------------------


def test_where_the_backend_is_says_nothing_about_the_credentials(client, sign_in, backend):
    sign_in()
    response = client.get("/api/backend")

    assert response.json() == {"enabled": True, "url": BACKEND_URL}


def test_where_the_backend_is_requires_a_session(client, backend):
    assert client.get("/api/backend").status_code == 401


def test_no_backend_configured_reports_no_url(client, sign_in, backend, monkeypatch):
    # Without a URL the page has nothing to route to /api/send, which is the only
    # thing it could do with one.
    monkeypatch.setattr(settings, "backend_client_id", "")
    sign_in()
    assert client.get("/api/backend").json() == {"enabled": False, "url": ""}


@pytest.mark.parametrize("path", ["/oauth2/backend-token", "/oauth2/id-token"])
def test_the_routes_that_handed_out_tokens_are_gone(client, sign_in, backend, path):
    # They were the exposure: whatever the page could fetch, anything running in the
    # page could fetch too. Falls through to the static catch-all now, which has no
    # such file. If this ever passes again, the tokens are back in the browser.
    sign_in()
    assert client.get(path).status_code == 404


def test_the_session_cookie_is_not_passed_on_to_the_backend(client, sign_in, forwarding):
    sign_in()
    assert client.cookies.get(settings.session_cookie)  # the browser is holding one
    post(client)

    # Only what the page asked to be sent is forwarded. The request the browser made
    # to get here -- its cookies, its user agent -- goes no further.
    assert "cookie" not in sent(forwarding).headers
