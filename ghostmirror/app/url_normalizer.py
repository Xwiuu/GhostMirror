"""URL normalizer — ensures any user-provided target becomes a valid URL."""

from __future__ import annotations

from urllib.parse import urlparse


def normalize_url(target: str) -> str:
    """Normalize a user-provided target into a valid URL with scheme.

    Accepts:
        example.com
        www.example.com
        http://example.com
        https://example.com
        https://example.com/path?q=1

    Always returns a URL with a scheme (defaults to https://).
    """
    target = target.strip()

    if not target:
        raise ValueError("Target URL cannot be empty")

    has_scheme = target.startswith(("http://", "https://"))

    url_to_check = target if has_scheme else f"https://{target}"

    parsed = urlparse(url_to_check)

    if not parsed.hostname or "." not in parsed.hostname:
        if "localhost" not in parsed.hostname.lower() if parsed.hostname else True:
            raise ValueError(f"Invalid target URL: {target!r}")

    return url_to_check


def normalize_host(target: str) -> str:
    """Extract just the hostname from a target, normalizing it.

    Returns the domain or IP without scheme or path.
    """
    target = target.strip()

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    host = parsed.hostname

    if not host:
        raise ValueError(f"Could not extract hostname from {target!r}")

    return host.lower()
