"""Endpoints for the other containers only (agents and scanner service). They need the shared token.

The web server in front of the backend does not forward /internal/ at all.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from .. import db
from ..deps import CREDENTIALS, internal_only, require_scan
from ..schemas import Event

router = APIRouter(prefix="/internal/scans", dependencies=[Depends(internal_only)])


@router.get("/{scan_id}/authorization")
def authorization_record(scan_id: str) -> dict:
    """The scanner service asks this before every tool run. It is the only source of the target."""
    scan = require_scan(scan_id)
    return {
        "authorized": scan["authorized"] and scan["status"] == "running",
        "stop_requested": scan["stop_requested"],
        "target_url": scan["target_url"],
        "basic_auth": CREDENTIALS.get(scan_id),
    }


@router.post("/{scan_id}/events")
def add_event(scan_id: str, event: Event) -> dict:
    """The agents post their progress here, so the page can show it live."""
    require_scan(scan_id)
    db.add_event(scan_id, event.agent, event.message, event.data)
    return {"ok": True}
