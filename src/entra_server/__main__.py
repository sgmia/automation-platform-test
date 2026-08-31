"""Entry point: `uv run entra-static-server`, or `uv run python -m entra_server`."""

from urllib.parse import urlparse

import uvicorn

from .main import app
from .settings import settings


def main() -> None:
    url = urlparse(settings.base_url)
    uvicorn.run(app, host=url.hostname or "localhost", port=url.port or 3000)


if __name__ == "__main__":
    main()
