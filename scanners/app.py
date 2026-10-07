"""Scanner tool service: one small HTTP API in front of nmap, ZAP, Nuclei and Nikto.

The Executor agent calls `POST /run/{tool}` with only a scan id. The target is
never taken from the caller: it is looked up from the backend's scan record,
and the run is refused unless that record carries an authorization.

Scanning puts load on a website, so the service also looks after the target:
it pauses between tools, checks that the target answers before a tool starts,
and reports it when the target stops answering during a tool.
"""
from __future__ import annotations

import os
import re
import time
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
ZAP_URL = os.getenv("ZAP_URL", "http://zap:8080")
COOL_DOWN_SECONDS = int(os.getenv("COOL_DOWN_SECONDS", "15"))  # breathing room for the target between tools

last_finished: dict[str, float] = {}  # scan id -> when its previous tool ended

app = FastAPI(title="Scanner tool service")


class RunRequest(BaseModel):
    scan_id: str


@app.get("/health")
def health() -> dict:
    """Ready when the ZAP daemon answers too (it is the slowest container to start)."""
    try:
        zap_ready = httpx.get(f"{ZAP_URL}/JSON/core/view/version/", timeout=5).status_code == 200
    except httpx.HTTPError:
        zap_ready = False
    return {"status": "ok", "zap_ready": zap_ready}


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

    # Give the target a moment after the previous tool, then make sure it answers.
    since_last = time.monotonic() - last_finished.get(request.scan_id, 0)
    if since_last < COOL_DOWN_SECONDS:
        time.sleep(COOL_DOWN_SECONDS - since_last)

    with Stopwatch() as watch:
        if answers(target, wait_seconds=60):
            result = TOOLS[tool].run(target, workdir)
            result["target_down"] = not answers(target, wait_seconds=10)
            if result["target_down"]:
                result["note"] = ("The target stopped answering during this scan. Results may be incomplete. "
                                  + result.get("note", "")).strip()
        else:
            result = {"status": "error", "command": "", "raw_file": None, "findings": [], "target_down": True,
                      "note": "The target did not answer, so this scan was not started."}
    last_finished[request.scan_id] = time.monotonic()

    result.update(tool=tool, target=target.url, duration_seconds=watch.seconds,
                  what_it_checks=TOOLS[tool].SPEC["description"])
    result["summary"] = summarize(result)
    return result


def answers(target: Target, wait_seconds: int) -> bool:
    """True when the target gives any HTTP answer. Keeps trying for up to `wait_seconds`."""
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            httpx.get(target.url, timeout=8, verify=False)
            return True
        except httpx.HTTPError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(4)


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
        "target_down": result["target_down"],
        "note": result.get("note", "")[:200],
    }
