"""Talking to Microsoft Entra ID: discovery, signing keys and id_token validation."""

import asyncio
import secrets
import time
from urllib.parse import urlencode

import httpx2
import jwt
from pydantic import BaseModel, ConfigDict

from .settings import Settings


class TokenError(Exception):
    """The id_token could not be validated."""


class IdTokenClaims(BaseModel):
    """The claims of a validated id_token. Unlisted claims are kept as-is."""

    model_config = ConfigDict(extra="allow")

    sub: str
    exp: int
    iat: int
    tid: str | None = None
    oid: str | None = None
    name: str | None = None
    preferred_username: str | None = None
    nonce: str | None = None


def unverified_claims(id_token: str) -> IdTokenClaims:
    """Read the claims of a token that was already validated when it arrived.

    The signature check is skipped deliberately, and this is only safe for that one
    case: the token came back out of a cookie this server signed, having passed
    `verify_id_token` before it went in. Anything arriving from a browser, a header
    or a form must go through `verify_id_token` instead.
    """
    try:
        return IdTokenClaims.model_validate(jwt.decode(id_token, options={"verify_signature": False}))
    except jwt.PyJWTError as error:
        raise TokenError(str(error)) from error


class EntraID:
    """The tenant's OpenID Connect endpoints, plus the validation of what they issue."""

    METADATA_TTL = 3600

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client = httpx2.AsyncClient(timeout=settings.http_timeout)
        self._metadata: dict | None = None
        self._metadata_fetched_at = 0.0
        self._keys: jwt.PyJWKSet | None = None

    async def close(self) -> None:
        await self._client.aclose()

    async def _get_json(self, url: str) -> dict:
        response = await self._client.get(url)
        response.raise_for_status()
        return response.json()

    async def post_form(self, url: str, form: dict[str, str]) -> dict:
        """POST a form and return the JSON body, error responses included.

        The token endpoint reports failures in the body (`error`,
        `error_description`) alongside a 4xx status, and that description is
        the only thing that says *which* setting is wrong.
        """
        response = await self._client.post(url, data=form)
        try:
            return response.json()
        except ValueError:
            response.raise_for_status()
            raise TokenError(f"{url} returned a non-JSON response") from None

    async def metadata(self) -> dict:
        """The tenant's OpenID configuration, cached for an hour."""
        if self._metadata is None or time.monotonic() - self._metadata_fetched_at > self.METADATA_TTL:
            metadata = await self._get_json(self.settings.discovery_url)
            if metadata.get("issuer") != self.settings.issuer:
                raise TokenError(
                    f"tenant publishes issuer {metadata.get('issuer')!r}, expected {self.settings.issuer!r}"
                )
            self._metadata = metadata
            self._metadata_fetched_at = time.monotonic()
        return self._metadata

    async def authorization_url(self, state: str, nonce: str) -> str:
        """Where to send someone to sign in."""
        endpoint = (await self.metadata())["authorization_endpoint"]
        query = urlencode(
            {
                "client_id": self.settings.client_id,
                "response_type": "id_token",
                "response_mode": "form_post",
                "redirect_uri": self.settings.redirect_uri,
                "scope": "openid profile email",
                "state": state,
                "nonce": nonce,
            }
        )
        return f"{endpoint}?{query}"

    async def verify_id_token(self, id_token: str, expected_nonce: str) -> IdTokenClaims:
        """Validate an id_token and return its claims.

        Checks the RS256 signature against the tenant's JWKS, the issuer, the
        audience (our client id), exp/nbf/iat, and the nonce we sent with the
        authorization request.
        """
        try:
            kid = jwt.get_unverified_header(id_token).get("kid")
            if not isinstance(kid, str):
                raise TokenError("token header has no kid")
            key = await self._signing_key(kid)
            claims = jwt.decode(
                id_token,
                key,
                algorithms=["RS256"],  # never let the token choose its own algorithm
                audience=self.settings.client_id,
                issuer=self.settings.issuer,
                leeway=self.settings.clock_skew,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
            )
        except jwt.PyJWTError as error:
            raise TokenError(str(error)) from error

        # The nonce ties this token to the authorization request we started, so a
        # token obtained elsewhere (or replayed) cannot be posted to our callback.
        if not secrets.compare_digest(str(claims.get("nonce")), expected_nonce):
            raise TokenError("nonce does not match the authorization request")

        return IdTokenClaims.model_validate(claims)

    async def _signing_key(self, kid: str) -> jwt.PyJWK:
        """Look up a published signing key, refetching once for an unknown kid.

        Entra rolls its signing keys regularly, so a kid we have never seen is
        expected rather than exceptional -- but only then do we go back out to
        the network.
        """
        key = self._cached_key(kid)
        if key is None:
            await self._refresh_keys()
            key = self._cached_key(kid)
        if key is None:
            raise TokenError(f"no published signing key for kid {kid!r}")
        return key

    def _cached_key(self, kid: str) -> jwt.PyJWK | None:
        if self._keys is None:
            return None
        return next((key for key in self._keys.keys if key.key_id == kid), None)

    async def _refresh_keys(self) -> None:
        jwks_uri = (await self.metadata())["jwks_uri"]
        self._keys = jwt.PyJWKSet.from_dict(await self._get_json(jwks_uri))


class AccessToken(BaseModel):
    """A backend access token, and how long it is still good for."""

    access_token: str
    expires_in: int


class ClientCredentials:
    """Access tokens for the backend API, via the OAuth2 client credentials flow.

    This is the application authenticating as itself -- a different, confidential
    app registration from the one users sign in with, in the same tenant. The
    token says nothing about who is signed in.

    The token is cached and renewed ahead of its expiry, so callers never hold
    one that expires in flight.
    """

    # Renew this long before the token actually expires.
    RENEW_MARGIN = 300

    def __init__(self, settings: Settings, entra: EntraID) -> None:
        self.settings = settings
        self._entra = entra  # shares its discovery cache and HTTP client
        self._token: str | None = None
        self._renew_at = 0.0
        # Fetching awaits, so two concurrent requests can interleave and each
        # decide to renew. Everything else in this app is lock-free; this is not.
        self._lock = asyncio.Lock()

    async def access_token(self) -> AccessToken:
        """A valid token for the backend, fetched or renewed as needed."""
        if not self.settings.backend_enabled:
            raise TokenError("no backend credentials are configured")

        cached = self._cached()
        if cached is not None:
            return cached
        async with self._lock:
            # Another request may have renewed it while we waited for the lock.
            return self._cached() or await self._fetch()

    def _cached(self) -> AccessToken | None:
        remaining = self._renew_at - time.monotonic()
        if self._token is None or remaining <= 0:
            return None
        return AccessToken(access_token=self._token, expires_in=int(remaining))

    async def _fetch(self) -> AccessToken:
        token_endpoint = (await self._entra.metadata())["token_endpoint"]
        payload = await self._entra.post_form(
            token_endpoint,
            {
                "grant_type": "client_credentials",
                "client_id": self.settings.backend_client_id,
                "client_secret": self.settings.backend_client_secret.get_secret_value(),
                "scope": self.settings.backend_scope,
            },
        )

        token, expires_in = payload.get("access_token"), payload.get("expires_in")
        if not isinstance(token, str) or not isinstance(expires_in, int):
            error = payload.get("error", "malformed response")
            raise TokenError(f"{error}: {payload.get('error_description', 'no access_token returned')}")

        # Renew early, but never inside half the lifetime: a short-lived token
        # would otherwise be refetched on nearly every request.
        lifetime = max(expires_in - self.RENEW_MARGIN, expires_in // 2)
        self._token = token
        self._renew_at = time.monotonic() + lifetime
        return AccessToken(access_token=token, expires_in=lifetime)
