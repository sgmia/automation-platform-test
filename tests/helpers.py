"""Token helpers shared by the tests.

Throwaway RSA keys stand in for the tenant's signing keys, so nothing here
touches the network.
"""

import base64
import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from entra_server.settings import settings

KID = "stub-key"
NONCE = "nonce-from-the-authorization-request"
ISSUER = settings.issuer

# Generating RSA keys is slow, so do it once for the whole session.
SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
FOREIGN_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------


def jwks(*keys, kid=KID):
    """A JWKS document publishing the given public keys."""
    return {
        "keys": [
            json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())) | {"kid": kid, "use": "sig"}
            for key in keys
        ]
    }


def make_id_token(key=None, audience=None, issuer=ISSUER, kid=KID, **overrides):
    """Mint an id_token shaped like the ones Entra ID issues.

    Any claim can be overridden; passing None for a claim drops it entirely.
    """
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": audience or settings.client_id,
        "sub": "00000000-user",
        "tid": settings.tenant_id,
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "nonce": NONCE,
        "name": "Test User",
        "preferred_username": "test.user@example.com",
    }
    claims.update(overrides)
    claims = {name: value for name, value in claims.items() if value is not None}
    return jwt.encode(claims, key or SIGNING_KEY, algorithm="RS256", headers={"kid": kid})


def b64(raw: bytes) -> bytes:
    """base64url without padding, as JWTs use."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def encode_unverified(header, claims, signature=b""):
    """Build a JWT by hand, for signatures PyJWT refuses to produce."""
    parts = [b64(json.dumps(header).encode()), b64(json.dumps(claims).encode()), b64(signature)]
    return b".".join(parts).decode()


def signing_input(token: str) -> bytes:
    return token.rsplit(".", 1)[0].encode()
