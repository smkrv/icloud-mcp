"""Authentication management for iCloud MCP server."""

from typing import Tuple, Optional
from urllib.parse import urlparse
from fastmcp import Context
from fastmcp.server.dependencies import get_http_headers
from .config import config


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


def require_trusted_url(url: str, base: str, kind: str) -> None:
    """Reject absolute URLs that point away from *base*'s host family.

    Object ids (calendar_id / event_id / contact_id) are caller-controlled
    URLs that get requested with the user's Basic-Auth credentials attached,
    so an absolute URL naming a foreign host leaks those credentials to that
    host. Relative paths resolve against the configured server and are fine.
    Provider partition hosts (e.g. p72-caldav.icloud.com) stay allowed via
    the shared parent domain.
    """
    parsed = urlparse(url)
    if not parsed.scheme and not parsed.netloc:
        return
    base_parsed = urlparse(base)
    host = parsed.hostname or ""
    base_host = base_parsed.hostname or ""
    base_domain = base_host.split(".", 1)[-1] if "." in base_host else base_host
    same_domain = host == base_host or host == base_domain or host.endswith("." + base_domain)
    if parsed.scheme != base_parsed.scheme or not same_domain:
        raise ValueError(
            f"{kind} must be a relative path or a {base_parsed.scheme} URL under "
            f"{base_domain}; refusing to send credentials to {parsed.scheme}://{host}"
        )


def get_credentials(context: Context) -> Tuple[str, str]:
    """Extract iCloud credentials from HTTP headers."""

    # Get HTTP headers using FastMCP's dependency function
    headers = get_http_headers()

    # Extract credentials from headers
    email: Optional[str] = headers.get("x-apple-email") or headers.get("X-Apple-Email")
    password: Optional[str] = headers.get("x-apple-app-specific-password") or headers.get("X-Apple-App-Specific-Password")

    # Fallback to environment variables
    if not email:
        email = config.FALLBACK_EMAIL
    if not password:
        password = config.FALLBACK_PASSWORD

    # Validate credentials
    if not email or not password:
        raise AuthenticationError(
            "Authentication required. Provide credentials via headers "
            "(X-Apple-Email, X-Apple-App-Specific-Password) or environment variables "
            "(ICLOUD_EMAIL, ICLOUD_APP_SPECIFIC_PASSWORD)"
        )

    return email, password


def require_auth(context: Context) -> Tuple[str, str]:
    """Decorator-friendly authentication check."""
    return get_credentials(context)
