"""Every way an id_token can be wrong should raise TokenError, not pass."""

import hashlib
import hmac
import time
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization

from entra_server.oidc import EntraID, TokenError, unverified_claims
from entra_server.settings import settings
from tests.helpers import (
    FOREIGN_KEY,
    ISSUER,
    KID,
    NONCE,
    SIGNING_KEY,
    b64,
    encode_unverified,
    make_id_token,
    signing_input,
)


async def assert_rejected(entra, token, reason, nonce=NONCE):
    with pytest.raises(TokenError) as caught:
        await entra.verify_id_token(token, nonce)
    assert reason.lower() in str(caught.value).lower()


# ---------------------------------------------------------------------------
# Accepted
# ---------------------------------------------------------------------------


async def test_valid_token_is_accepted(entra):
    claims = await entra.verify_id_token(make_id_token(), NONCE)
    assert claims.preferred_username == "test.user@example.com"
    assert claims.tid == settings.tenant_id


async def test_token_within_clock_skew_is_accepted(entra):
    # Small clock differences between us and Entra must not lock people out.
    just_expired = int(time.time()) - (settings.clock_skew - 10)
    claims = await entra.verify_id_token(make_id_token(exp=just_expired), NONCE)
    assert claims.sub == "00000000-user"


async def test_unlisted_claims_are_preserved(entra):
    claims = await entra.verify_id_token(make_id_token(roles=["admin"]), NONCE)
    assert claims.model_dump()["roles"] == ["admin"]


# ---------------------------------------------------------------------------
# Rejected
# ---------------------------------------------------------------------------


async def test_expired_token_is_rejected(entra):
    await assert_rejected(entra, make_id_token(exp=int(time.time()) - 3600), "expired")


async def test_future_token_is_rejected(entra):
    ahead = int(time.time()) + 3600
    await assert_rejected(entra, make_id_token(nbf=ahead, iat=ahead), "not yet valid")


async def test_token_for_another_audience_is_rejected(entra):
    await assert_rejected(entra, make_id_token(audience="some-other-app"), "audience")


async def test_token_from_another_issuer_is_rejected(entra):
    await assert_rejected(entra, make_id_token(issuer="https://evil.example.com/v2.0"), "issuer")


async def test_token_from_another_tenant_is_rejected(entra):
    other = "99999999-9999-9999-9999-999999999999"
    token = make_id_token(issuer=f"https://login.microsoftonline.com/{other}/v2.0")
    await assert_rejected(entra, token, "issuer")


async def test_token_signed_by_unknown_key_is_rejected(entra):
    await assert_rejected(entra, make_id_token(key=FOREIGN_KEY), "signature verification failed")


async def test_token_with_unpublished_kid_is_rejected(stub_entra):
    # Refreshing the key set does not turn up this kid either.
    with stub_entra(kid="some-other-kid") as entra:
        await assert_rejected(entra, make_id_token(), "no published signing key")


async def test_tampered_payload_is_rejected(entra):
    header, _original, signature = make_id_token().split(".")
    forged = encode_unverified(
        {"alg": "RS256", "kid": KID},
        {"iss": ISSUER, "aud": settings.client_id, "sub": "admin", "nonce": NONCE,
         "exp": int(time.time()) + 3600, "iat": int(time.time())},
    ).split(".")[1]
    await assert_rejected(entra, f"{header}.{forged}.{signature}", "signature verification failed")


async def test_missing_required_claim_is_rejected(entra):
    await assert_rejected(entra, make_id_token(exp=None), 'missing the "exp"')


async def test_token_without_nonce_is_rejected(entra):
    await assert_rejected(entra, make_id_token(nonce=None), 'missing the "nonce"')


async def test_replayed_token_from_another_login_is_rejected(entra):
    # Valid in every other respect, but not minted for the request we started.
    await assert_rejected(entra, make_id_token(nonce="a-different-nonce"), "nonce")


async def test_unsigned_token_is_rejected(entra):
    # alg=none: the classic "just drop the signature" attack.
    token = encode_unverified(
        {"alg": "none", "typ": "JWT", "kid": KID},
        {"iss": ISSUER, "aud": settings.client_id, "sub": "u", "nonce": NONCE,
         "iat": int(time.time()), "exp": int(time.time()) + 3600},
    )
    await assert_rejected(entra, token, "alg value is not allowed")


async def test_algorithm_confusion_is_rejected(entra):
    # HS256 signed with the RSA public key as the HMAC secret. Only works if the
    # verifier lets the token pick its own algorithm; ours pins RS256.
    public_pem = SIGNING_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    unsigned = encode_unverified(
        {"alg": "HS256", "typ": "JWT", "kid": KID},
        {"iss": ISSUER, "aud": settings.client_id, "sub": "u", "nonce": NONCE,
         "iat": int(time.time()), "exp": int(time.time()) + 3600},
    )
    mac = hmac.new(public_pem, signing_input(unsigned), hashlib.sha256).digest()
    token = f"{signing_input(unsigned).decode()}.{b64(mac).decode()}"
    await assert_rejected(entra, token, "alg value is not allowed")


# ---------------------------------------------------------------------------
# Re-reading a token that was validated when it arrived
# ---------------------------------------------------------------------------


def test_unverified_claims_reads_a_token_without_checking_its_signature():
    # Deliberate, and the reason its one caller is the session cookie: that token
    # was validated at sign-in, and the cookie's own signature vouches for it since.
    token = make_id_token(key=FOREIGN_KEY, preferred_username="a@b.c")
    assert unverified_claims(token).preferred_username == "a@b.c"


@pytest.mark.parametrize("value", ["", "not-a-jwt", "a.b.c"])
def test_unverified_claims_still_refuses_what_is_not_a_token(value):
    with pytest.raises(TokenError):
        unverified_claims(value)


def test_unverified_claims_requires_the_claims_it_is_typed_for():
    # No sub, so IdTokenClaims cannot be built and the session cannot be read back.
    with pytest.raises(ValueError):
        unverified_claims(make_id_token(sub=None))


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


async def test_metadata_from_the_wrong_tenant_is_rejected():
    # A discovery document that does not name our tenant means misconfiguration.
    wrong = {"issuer": "https://login.microsoftonline.com/someone-else/v2.0", "jwks_uri": "x"}
    entra = EntraID(settings)
    try:
        with (
            mock.patch.object(entra, "_get_json", mock.AsyncMock(return_value=wrong)),
            pytest.raises(TokenError) as caught,
        ):
            await entra.metadata()
    finally:
        await entra.close()
    assert "expected" in str(caught.value)


async def test_authorization_url_carries_the_request_parameters(entra):
    url = await entra.authorization_url("the-state", "the-nonce")
    assert url.startswith("https://stub.invalid/oauth2/v2.0/authorize?")
    for expected in (
        f"client_id={settings.client_id}",
        "response_type=id_token",
        "response_mode=form_post",
        "state=the-state",
        "nonce=the-nonce",
    ):
        assert expected in url


async def test_metadata_is_cached(entra):
    await entra.metadata()
    calls_after_first = entra._get_json.call_count
    await entra.metadata()
    assert entra._get_json.call_count == calls_after_first


async def test_signing_keys_are_not_refetched_per_token(entra):
    await entra.verify_id_token(make_id_token(), NONCE)
    calls_after_first = entra._get_json.call_count
    await entra.verify_id_token(make_id_token(), NONCE)
    assert entra._get_json.call_count == calls_after_first
