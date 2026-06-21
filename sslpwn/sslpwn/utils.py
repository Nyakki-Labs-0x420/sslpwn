"""Utility functions used across the sslpwn package."""
import re
import socket
from urllib.parse import urlparse


def validate_target_url(url: str) -> str:
    """Validate that a URL is syntactically correct and uses HTTPS.
    Returns the URL with a trailing slash removed if present.
    Raises ValueError for invalid URLs.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS targets are supported.")
    if not parsed.hostname:
        raise ValueError("URL must contain a hostname.")
    # Normalise: remove path if it's just '/'
    if parsed.path == "/":
        return f"{parsed.scheme}://{parsed.hostname}{':' + str(parsed.port) if parsed.port else ''}"
    return url.rstrip("/")


def safe_filename(host: str) -> str:
    """Create a safe filename from a hostname."""
    # Replace non-alphanumeric with underscores
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', host)
    return safe


def get_ip_address(host: str) -> str:
    """Resolve a hostname to its IP address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {host}")