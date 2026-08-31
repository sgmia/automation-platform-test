"""Logins in flight, and the signed cookie a finished login turns into.

`PendingLogins` is a plain dict with no locking, which is safe only because every
request handler is async on one thread. Its entries are lost on restart, which is
fine for a single process but would need a shared store behind more than one worker.

Sessions themselves are kept nowhere: the claims ride in a cookie the visitor
carries, signed so it cannot be forged.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time

from .oidc import IdTokenClaims


class PendingLogins:
    """The state/nonce pairs of logins that are currently in flight.

    This one cannot become a cookie: the callback is a cross-site POST from Entra,
    so a `SameSite=Lax` cookie is not sent with it and the check would never match.
    """

    def __init__(self, ttl: int) -> None:
        self.ttl = ttl
        self._pending: dict[str, tuple[str, str, float]] = {}

    def start(self, next_path: str) -> tuple[str, str]:
        """Register a login and return the (state, nonce) to send to Entra ID."""
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self._prune()
        self._pending[state] = (nonce, next_path, time.monotonic() + self.ttl)
        return state, nonce

    def take(self, state: str) -> tuple[str, str] | None:
        """Consume a pending login, returning (nonce, next_path).

        Single use, so a callback cannot be replayed.
        """
        self._prune()
        pending = self._pending.pop(state, None)
        return (pending[0], pending[1]) if pending else None

    def _prune(self) -> None:
        now = time.monotonic()
        self._pending = {state: entry for state, entry in self._pending.items() if entry[2] > now}


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SessionCookie:
    """The session, carried by the visitor in a signed cookie instead of held here.

    The value is `payload.signature`, both base64url: the payload is the claims plus
    an expiry, the signature is HMAC-SHA256 over the encoded payload. Nothing is
    encrypted -- these are the visitor's own id_token claims, which they can read out
    of the token anyway -- so the signature is only there to make the cookie
    unforgeable.

    Holding no server-side copy has two consequences worth knowing:

    * A session cannot be revoked before it expires. `/oauth2/logout` clears the
      cookie, but a copy taken beforehand keeps working until its `exp` passes.
    * Every session ends when the signing key changes, which with no configured
      `cookie_secret` means on every restart.
    """

    def __init__(self, secret: str, ttl: int) -> None:
        self.ttl = ttl
        # An unconfigured secret is generated per process, so sessions do not survive a
        # restart -- the same behaviour the in-memory store had, rather than a weaker one.
        self.ephemeral = not secret
        self._key = (secret or secrets.token_urlsafe(32)).encode()

    def mint(self, claims: IdTokenClaims) -> tuple[str, int]:
        """Build the cookie value for these claims, and how long it is good for."""
        # A session never outlives the token it was minted from.
        max_age = max(1, min(self.ttl, int(claims.exp - time.time())))
        body = {"exp": int(time.time()) + max_age, "claims": claims.model_dump(mode="json")}
        payload = _b64encode(json.dumps(body, separators=(",", ":")).encode())
        return f"{payload}.{self._sign(payload)}", max_age

    def read(self, cookie: str | None) -> IdTokenClaims | None:
        """The claims of a valid, unexpired cookie; None for anything else.

        Nothing in the cookie is trusted before the signature is checked, and the
        claims are re-validated afterwards in case an older version wrote them.
        """
        payload, _, signature = (cookie or "").partition(".")
        if not signature or not hmac.compare_digest(signature, self._sign(payload)):
            return None
        try:
            body = json.loads(_b64decode(payload))
            if body["exp"] <= time.time():
                return None
            return IdTokenClaims.model_validate(body["claims"])
        except (ValueError, KeyError, TypeError):  # pydantic's ValidationError is a ValueError
            return None

    def _sign(self, payload: str) -> str:
        return _b64encode(hmac.new(self._key, payload.encode(), hashlib.sha256).digest())
