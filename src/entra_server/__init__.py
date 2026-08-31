"""Static web server protected by Microsoft Entra ID (OpenID Connect)."""

from .main import app
from .settings import settings

__all__ = ["app", "settings"]
