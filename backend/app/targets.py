"""What may be scanned: the practice targets that ship with the project, and the address check."""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from . import config

AUTHORIZATION_STATEMENT = (
    "I confirm that I own this target or have written authorization from its owner to run a "
    "security assessment against it."
)

# The system's own parts and cloud metadata addresses are never valid targets.
BLOCKED_HOSTS = {"langflow", "backend", "frontend", "scanners", "zap", "metadata.google.internal"}


def practice_targets() -> list[dict]:
    """The practice sites offered on the page. Each one is a folder under targets/ with a target.json.

    The permission box is still required for them: the person running the tool vouches for every scan.
    """
    found = []
    for file in sorted(config.TARGETS_DIR.glob("*/target.json")):
        try:
            target = json.loads(file.read_text(encoding="utf-8"))
            found.append({key: str(target[key]) for key in ("name", "url", "badge", "note")})
        except (OSError, ValueError, KeyError):
            continue  # a broken target file must not break the page
    return found


def normalize_target(raw: str) -> str:
    """Check a target address and return it in one tidy form. Raises ValueError with a message for the user."""
    parsed = urlparse(raw.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Target must be a full http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("Do not put credentials in the URL; use the test credential fields.")
    host = parsed.hostname.lower()
    if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", host):
        raise ValueError("Target host must be a plain hostname or IPv4 address.")
    if host in BLOCKED_HOSTS or host.startswith("169.254."):
        raise ValueError("That host is part of this platform or a metadata address and cannot be a target.")
    if host in ("localhost", "127.0.0.1"):
        # The scanners run in containers, where localhost is the container itself.
        host = "host.docker.internal"
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError as exc:
        raise ValueError("Invalid port in the target URL.") from exc
    return f"{parsed.scheme}://{host}{port}{parsed.path.rstrip('/')}"
