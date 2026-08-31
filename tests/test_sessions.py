"""Bookkeeping for logins in flight, and the signed cookies they produce."""

import json
import time

import pytest

from entra_server.oidc import IdTokenClaims
from entra_server.sessions import PendingLogins, SessionCookie, _b64decode, _b64encode


def claims(exp=None, **overrides):
    return IdTokenClaims(sub="u", iat=int(time.time()), exp=int(exp or time.time() + 7200), **overrides)


# ---------------------------------------------------------------------------
# Pending logins
# ---------------------------------------------------------------------------


@pytest.fixture
def logins():
    return PendingLogins(ttl=600)


def test_state_and_nonce_are_unpredictable_and_unique(logins):
    pairs = [logins.start("/") for _ in range(20)]
    states, nonces = {s for s, _ in pairs}, {n for _, n in pairs}
    assert len(states) == len(nonces) == 20
    assert all(len(value) >= 32 for value in states | nonces)


def test_callback_carries_the_matching_nonce_and_destination(logins):
    state, nonce = logins.start("/wanted")
    assert logins.take(state) == (nonce, "/wanted")


def test_state_cannot_be_used_twice(logins):
    state, _ = logins.start("/")
    assert logins.take(state) is not None
    assert logins.take(state) is None


def test_unknown_state_is_not_accepted(logins):
    assert logins.take("state-we-never-issued") is None


def test_stale_state_is_not_accepted():
    expired = PendingLogins(ttl=-1)
    state, _ = expired.start("/")
    assert expired.take(state) is None


# ---------------------------------------------------------------------------
# The session cookie
# ---------------------------------------------------------------------------


@pytest.fixture
def sessions():
    return SessionCookie(secret="the-signing-secret", ttl=3600)


def repack(sessions, cookie, **changes):
    """Re-sign a cookie whose payload has been edited: what a key holder could mint."""
    payload, _, _ = cookie.partition(".")
    body = json.loads(_b64decode(payload))
    body.update(changes)
    edited = _b64encode(json.dumps(body).encode())
    return f"{edited}.{sessions._sign(edited)}"


def test_cookie_returns_the_claims_it_was_minted_from(sessions):
    cookie, _ = sessions.mint(claims(preferred_username="a@b.c", name="A B"))
    restored = sessions.read(cookie)
    assert restored.preferred_username == "a@b.c"
    assert restored.name == "A B"


def test_claims_the_model_does_not_name_survive_the_round_trip(sessions):
    # IdTokenClaims allows extras, and /oauth2/me hands back whatever Entra sent.
    cookie, _ = sessions.mint(claims(groups=["one", "two"]))
    assert sessions.read(cookie).groups == ["one", "two"]


def test_cookie_value_is_safe_to_put_in_a_header(sessions):
    cookie, _ = sessions.mint(claims(name="Zoë; Path=/"))
    assert not set(cookie) & set('; ,"\\')


@pytest.mark.parametrize("cookie", ["not-a-cookie", "no-signature.", ".", "", None])
def test_malformed_cookies_are_rejected(sessions, cookie):
    assert sessions.read(cookie) is None


def test_a_cookie_this_key_did_not_sign_is_rejected(sessions):
    minted_elsewhere, _ = SessionCookie(secret="another-secret", ttl=3600).mint(claims())
    assert sessions.read(minted_elsewhere) is None


def test_edited_claims_are_rejected(sessions):
    cookie, _ = sessions.mint(claims(preferred_username="a@b.c"))
    payload, _, signature = cookie.partition(".")
    body = json.loads(_b64decode(payload))
    body["claims"]["preferred_username"] = "admin@b.c"
    forged = f"{_b64encode(json.dumps(body).encode())}.{signature}"
    assert sessions.read(forged) is None


def test_expiry_is_not_taken_on_trust(sessions):
    # Signed, so only the expiry itself can reject it.
    assert sessions.read(repack(sessions, sessions.mint(claims())[0], exp=int(time.time()) - 1)) is None


def test_a_payload_that_is_not_claims_is_rejected(sessions):
    cookie, _ = sessions.mint(claims())
    assert sessions.read(repack(sessions, cookie, claims={"nothing": "useful"})) is None


def test_session_does_not_outlive_the_token(sessions):
    _, max_age = sessions.mint(claims(exp=time.time() + 30))
    assert max_age <= 30


def test_session_is_capped_at_the_configured_ttl(sessions):
    _, max_age = sessions.mint(claims(exp=time.time() + 10 * 24 * 3600))
    assert max_age == sessions.ttl


def test_the_same_secret_reads_cookies_across_instances():
    # What restarting the server with ENTRA_COOKIE_SECRET set has to do.
    cookie, _ = SessionCookie(secret="shared", ttl=3600).mint(claims(preferred_username="a@b.c"))
    assert SessionCookie(secret="shared", ttl=3600).read(cookie).preferred_username == "a@b.c"


def test_an_unset_secret_gives_each_process_its_own_key():
    first, second = SessionCookie(secret="", ttl=3600), SessionCookie(secret="", ttl=3600)
    cookie, _ = first.mint(claims())
    assert first.ephemeral and second.ephemeral
    assert first.read(cookie) is not None
    assert second.read(cookie) is None  # a restart signs everyone out
