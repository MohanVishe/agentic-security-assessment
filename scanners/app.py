"""Scanner tool service: one small HTTP API in front of nmap, ZAP, Nuclei and Nikto.

The Executor agent calls `POST /run/{tool}` with only a scan id. The target is
never taken from the caller: it is looked up from the backend's scan record,
and the run is refused unless that record carries an authorization.
"""
from __future__ import annotations

import os
import re
from collections import Counter
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from tools import TOOLS
from tools.common import Stopwatch, Target

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
INTERNAL_TOKEN = os.getenv("INTERNAL_TOKEN", "")
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))

app = FastAPI(title="Scanner tool service")


class RunRequest(BaseModel):
    scan_id: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/tools")
def list_tools() -> list[dict]:
    return [module.SPEC for module in TOOLS.values()]


@app.post("/run/{tool}")
def run_tool(tool: str, request: RunRequest) -> dict:
    if tool not in TOOLS:
        raise HTTPException(404, f"Unknown tool '{tool}'. Available: {', '.join(TOOLS)}")
    if not re.fullmatch(r"[0-9a-f]{32}", request.scan_id):
        raise HTTPException(400, "Invalid scan id")

    target = authorized_target(request.scan_id)
    workdir = DATA_DIR / "raw" / request.scan_id
    workdir.mkdir(parents=True, exist_ok=True)

    with Stopwatch() as watch:
        result = TOOLS[tool].run(target, workdir)

    result.update(tool=tool, target=target.url, duration_seconds=watch.seconds)
    result["summary"] = summarize(result)
    return result


def authorized_target(scan_id: str) -> Target:
    """No authorization on the scan record, no scan."""
    try:
        response = httpx.get(f"{BACKEND_URL}/internal/scans/{scan_id}/authorization",
                             headers={"X-Internal-Token": INTERNAL_TOKEN}, timeout=10)
    except httpx.HTTPError as exc:
        raise HTTPException(503, f"Could not verify authorization with the backend: {exc}") from exc
    if response.status_code != 200:
        raise HTTPException(403, "Unknown scan, or the backend rejected the authorization check")
    record = response.json()
    if not record.get("authorized"):
        raise HTTPException(403, "This scan has no recorded authorization; refusing to run")
    auth = record.get("basic_auth")
    return Target(url=record["target_url"], basic_auth=tuple(auth) if auth else None)


def summarize(result: dict) -> dict:
    """The compact view the Executor's LLM sees. Full findings travel separately, untouched."""
    findings = result["findings"]
    ratings = Counter((f["tool_severity"] or "unrated").lower() for f in findings)
    return {
        "tool": result["tool"],
        "status": result["status"],
        "duration_seconds": result["duration_seconds"],
        "finding_count": len(findings),
        "by_tool_rating": dict(ratings),
        "sample_titles": [f["title"][:90] for f in findings[:8]],
        "note": result.get("note", "")[:200],
    }
