"""Small helpers the routes share: look a check up, or refuse the request."""
from __future__ import annotations

import re

from fastapi import Header, HTTPException

from . import config, db

# Test logins live here, in memory only, for the length of one check.
# They are never written to the database, never logged and never sent to the AI model.
CREDENTIALS: dict[str, tuple[str, str]] = {}


def require_scan(scan_id: str) -> dict:
    scan = db.get_scan(scan_id) if re.fullmatch(r"[0-9a-f]{32}", scan_id) else None
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


def require_report(scan_id: str) -> dict:
    scan = require_scan(scan_id)
    if not scan["report"]:
        raise HTTPException(404, f"No report yet; scan status is '{scan['status']}'.")
    return scan


def public_view(scan: dict) -> dict:
    """A check as the page sees it: everything except the (large) report itself."""
    return {key: value for key, value in scan.items() if key != "report"} | {"has_report": bool(scan["report"])}


def internal_only(x_internal_token: str = Header(default="")) -> None:
    """Guards the endpoints that only the agents and the scanner service may call."""
    if not config.INTERNAL_TOKEN or x_internal_token != config.INTERNAL_TOKEN:
        raise HTTPException(403, "Internal endpoint")
