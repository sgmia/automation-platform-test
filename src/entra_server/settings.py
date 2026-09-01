"""Configuration.

Values are read at startup from the env files listed in `ENV_FILES`, resolved
against the working directory, and can be overridden by ENTRA_* environment
variables. `.env` holds the configuration and is committed; `.env.local` holds
secrets and personal overrides and is not.
"""

from pathlib import Path

from pydantic import SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Read in order, so a value in .env.local wins over the same value in .env.
ENV_FILES = (".env", ".env.local")


def _path_body(value: str) -> str:
    """The inside of a configured path, with the slashes at either end taken off.

    The site root is refused. As a route it shadows the static site, and as a prefix
    it covers every request there is -- which would answer every expired session with
    a 401 instead of a redirect to Entra ID, and leave the page with nothing to load.
    """
    body = value.strip().strip("/")
    if not body:
        raise ValueError("must name a path below the site root, such as /api")
    return body


def env_files_found() -> list[Path]:
    """The env files that actually exist, for reporting at startup."""
    return [path for path in map(Path, ENV_FILES) if path.is_file()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ENTRA_",
        env_file=ENV_FILES,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # No defaults: there is no sane fallback for which directory to authenticate
    # against, and silently signing in to a stale tenant is worse than not starting.
    tenant_id: str
    client_id: str

    base_url: str = "http://localhost:3000"

    # Where Entra ID posts the id_token back to. It ends up in `redirect_uri`, so it
    # must match the redirect URI registered on the app registration.
    callback_path: str = "/oauth2/token"

    # The prefix the page's own fetch routes live under. A request below it is
    # answered 401 rather than redirected to Entra, because a fetch cannot follow a
    # redirect to Microsoft. Changing it means changing the paths in static/index.html
    # to match -- the page is a static file and cannot read this.
    api_prefix: str = "/api/"

    # The name of the signed session cookie. Renaming it signs everyone out, since the
    # cookie the browser is already holding is no longer looked for.
    session_cookie: str = "session"

    # Only this directory is ever served, so the project's own files stay private.
    static_dir: Path = Path(__file__).parent / "static"

    session_ttl: int = 8 * 60 * 60  # how long a signed-in session lasts
    login_ttl: int = 10 * 60  # how long a pending login (state/nonce) stays usable

    # Signs the session cookie, which is the only thing standing between a visitor
    # and a cookie of their own devising. Unset means a fresh key per process, so a
    # restart signs everyone out; set it in .env.local to keep sessions across one.
    cookie_secret: SecretStr = SecretStr("")

    clock_skew: int = 60  # leeway on exp/nbf/iat, in seconds
    http_timeout: float = 10.0

    # The backend API the tool calls. A second app registration in the same
    # tenant -- confidential this time, so its secret never leaves the server.
    backend_client_id: str = ""
    backend_client_secret: SecretStr = SecretStr("")
    backend_scope: str = ""  # usually api://<backend-app-id>/.default
    backend_url: str = ""  # the only prefix requests are ever forwarded to

    # How long to wait on the backend itself. Not part of `backend_enabled`: it has
    # a default, and an API can be slower to answer than Entra ID is.
    backend_timeout: float = 30.0

    @field_validator("callback_path")
    @classmethod
    def _absolute_path(cls, value: str) -> str:
        """A route path, leading slash and no trailing one: `/oauth2/token`."""
        return f"/{_path_body(value)}"

    @field_validator("api_prefix")
    @classmethod
    def _path_prefix(cls, value: str) -> str:
        """A prefix with slashes at both ends, so `f"{api_prefix}send"` is a path.

        It is matched with `startswith`, so the trailing slash is what keeps `/apix`
        from counting as being below `/api`.
        """
        return f"/{_path_body(value)}/"

    @property
    def issuer(self) -> str:
        """The only issuer we accept tokens from. Single tenant, so it is fixed."""
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    @property
    def redirect_uri(self) -> str:
        return f"{self.base_url.rstrip('/')}{self.callback_path}"

    @property
    def static_root(self) -> Path:
        return self.static_dir.resolve()

    @property
    def cookies_are_secure(self) -> bool:
        return self.base_url.startswith("https://")

    @property
    def backend_enabled(self) -> bool:
        """Whether backend access tokens can be issued at all.

        All four settings are required: without `backend_url` there is nothing
        to scope the token to, and handing it out unscoped would send it to
        whatever host happened to be typed into the tool.
        """
        return bool(
            self.backend_client_id
            and self.backend_client_secret.get_secret_value()
            and self.backend_scope
            and self.backend_url
        )


def load_settings() -> Settings:
    """Read the configuration, or exit with something more useful than a traceback.

    The env files are resolved against the working directory, so the usual way to
    get here is starting the server from somewhere else.
    """
    try:
        # Required fields come from the env files, which type checkers cannot see.
        return Settings()  # type: ignore[call-arg]
    except ValidationError as error:
        missing = [str(item["loc"][0]) for item in error.errors() if item["type"] == "missing"]
        if not missing:
            raise
        names = ", ".join(f"ENTRA_{name.upper()}" for name in missing)
        raise SystemExit(
            f"Missing configuration: {names}\n"
            f"Read from {' and '.join(ENV_FILES)} in the working directory "
            f"({Path.cwd()}), or from the environment.\n"
            f"Start the server from the project root, or copy .env into place."
        ) from error


settings = load_settings()
