"""FastAPI backend: scan records, the authorization gate, and the hand-off to Langflow.

Life of a scan:  created -> authorized -> running -> completed | failed

    POST /api/scans                  submit a target
    POST /api/scans/{id}/authorize   record the ownership / written-authorization confirmation
    POST /api/scans/{id}/start       start the assessment (refused until authorized)
    GET  /api/scans/{id}             poll status and live events
    GET  /api/scans/{id}/report      fetch the report (.json, .md or .pdf)
"""
from __future__ import annotations

import json
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from . import db, report

LANGFLOW_URL = os.getenv("LANGFLOW_URL", "http://langflow:7860")
LANGFLOW_API_KEY = os.getenv("LANGFLOW_API_KEY", "")
LANGFLOW_FLOW = os.getenv("LANGFLOW_FLOW", "security-assessment")
INTERNAL_TOKEN = os.getenv("INTERNAL_TOKEN", "")
RUN_TIMEOUT = int(os.getenv("ASSESSMENT_TIMEOUT_SECONDS", "2400"))
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))

AUTHORIZATION_STATEMENT = (
    "I confirm that I own this target or have written authorization from its owner to run a "
    "security assessment against it."
)

# Targets that are safe to scan out of the box. The checkbox is still required for them:
# the person running the tool is the one who vouches for every scan.
DEMO_TARGETS = [
    {"name": "OWASP Juice Shop (local container)", "url": "http://juice-shop:3000",
     "note": "Deliberately vulnerable app started by docker-compose. It is yours, so it is in scope."},
    {"name": "Acunetix test site (public)", "url": "http://testphp.vulnweb.com",
     "note": "Published by Acunetix for testing web scanners."},
]

# The stack's own services and cloud metadata addresses are never valid targets.
BLOCKED_HOSTS = {"langflow", "backend", "frontend", "scanners", "zap", "metadata.google.internal"}

# Test credentials live in memory only for the length of the run. They are never written to
# the database, never logged and never sent to the LLM.
CREDENTIALS: dict[str, tuple[str, str]] = {}

@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init()
    yield


app = FastAPI(title="Agentic Security Assessment API", lifespan=lifespan)


class ScanRequest(BaseModel):
    target_url: str
    scope_notes: str = Field(default="", max_length=2000)
    test_username: str = Field(default="", max_length=200)
    test_password: str = Field(default="", max_length=200)


class AuthorizationRequest(BaseModel):
    confirmed: bool
    authorized_by: str = Field(default="", max_length=200)


class Event(BaseModel):
    agent: str = Field(max_length=40)
    message: str = Field(max_length=2000)


# ---------------------------------------------------------------- public API

@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/config")
def config() -> dict:
    return {"demo_targets": DEMO_TARGETS, "authorization_statement": AUTHORIZATION_STATEMENT}


@app.post("/api/scans", status_code=201)
def submit_target(request: ScanRequest) -> dict:
    try:
        target_url = normalize_target(request.target_url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    has_credentials = bool(request.test_username and request.test_password)
    scan_id = db.create_scan(target_url, request.scope_notes.strip(), has_credentials)
    if has_credentials:
        CREDENTIALS[scan_id] = (request.test_username, request.test_password)
    return public_view(db.get_scan(scan_id))


@app.post("/api/scans/{scan_id}/authorize")
def confirm_authorization(scan_id: str, request: AuthorizationRequest, http: Request) -> dict:
    scan = require_scan(scan_id)
    if not request.confirmed:
        raise HTTPException(400, "Authorization was not confirmed. The assessment cannot run.")
    if scan["status"] != "created":
        raise HTTPException(409, f"Scan is already {scan['status']}.")
    confirmed_by = request.authorized_by.strip() or f"UI user at {http.client.host if http.client else 'unknown'}"
    db.update_scan(scan_id, status="authorized", authorized=1, authorized_at=db.now(),
                   authorized_by=confirmed_by, authorization_statement=AUTHORIZATION_STATEMENT)
    db.add_event(scan_id, "system", f"Authorization confirmed by {confirmed_by}.")
    return public_view(db.get_scan(scan_id))


@app.post("/api/scans/{scan_id}/start", status_code=202)
def start_assessment(scan_id: str, background: BackgroundTasks) -> dict:
    scan = require_scan(scan_id)
    if not scan["authorized"]:
        raise HTTPException(403, "Authorization has not been confirmed for this target. No tick, no scan.")
    if scan["status"] != "authorized":
        raise HTTPException(409, f"Scan is already {scan['status']}.")
    if db.any_running():
        raise HTTPException(409, "Another assessment is running. Wait for it to finish.")
    db.update_scan(scan_id, status="running", started_at=db.now())
    db.add_event(scan_id, "system", "Assessment started; handing over to the Langflow agents.")
    background.add_task(run_assessment, scan_id)
    return public_view(db.get_scan(scan_id))


@app.get("/api/scans")
def list_scans() -> list[dict]:
    return db.list_scans()


@app.get("/api/scans/{scan_id}")
def poll_status(scan_id: str) -> dict:
    scan = require_scan(scan_id)
    return {**public_view(scan), "events": db.get_events(scan_id)}


@app.get("/api/scans/{scan_id}/report")
def fetch_report(scan_id: str) -> dict:
    return require_report(scan_id)["report"]


@app.get("/api/scans/{scan_id}/report.md", response_class=PlainTextResponse)
def fetch_report_markdown(scan_id: str) -> str:
    return report.to_markdown(require_report(scan_id))


@app.get("/api/scans/{scan_id}/report.pdf")
def fetch_report_pdf(scan_id: str) -> Response:
    pdf = report.to_pdf(require_report(scan_id))
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="assessment-{scan_id[:8]}.pdf"'})


@app.get("/api/scans/{scan_id}/raw/{filename}")
def fetch_raw_output(scan_id: str, filename: str) -> FileResponse:
    """The untouched scanner output a finding was derived from."""
    require_scan(scan_id)
    if not re.fullmatch(r"(nmap\.xml|zap\.json|nuclei\.jsonl|nikto\.json)", filename):
        raise HTTPException(404, "No such raw output file")
    path = DATA_DIR / "raw" / scan_id / filename
    if not path.is_file():
        raise HTTPException(404, "That tool produced no raw output for this scan")
    return FileResponse(path, media_type="text/plain", filename=f"{scan_id[:8]}-{filename}")


# ------------------------------------- internal API (agents and scanner service)

def internal(x_internal_token: str = Header(default="")) -> None:
    if not INTERNAL_TOKEN or x_internal_token != INTERNAL_TOKEN:
        raise HTTPException(403, "Internal endpoint")


@app.get("/internal/scans/{scan_id}/authorization", dependencies=[Depends(internal)])
def authorization_record(scan_id: str) -> dict:
    """The scanner service asks this before every tool run; it is the source of the target."""
    scan = require_scan(scan_id)
    return {
        "authorized": scan["authorized"] and scan["status"] == "running",
        "target_url": scan["target_url"],
        "basic_auth": CREDENTIALS.get(scan_id),
    }


@app.post("/internal/scans/{scan_id}/events", dependencies=[Depends(internal)])
def add_event(scan_id: str, event: Event) -> dict:
    require_scan(scan_id)
    db.add_event(scan_id, event.agent, event.message)
    return {"ok": True}


# ------------------------------------------------------------------ helpers

def run_assessment(scan_id: str) -> None:
    """Background task: one blocking call to the Langflow flow, which runs all three agents."""
    scan = db.get_scan(scan_id)
    request = {
        "scan_id": scan_id,
        "target_url": scan["target_url"],
        "scope_notes": scan["scope_notes"],
        "credentials_provided": scan["credentials_provided"],
    }
    try:
        response = httpx.post(
            f"{LANGFLOW_URL}/api/v1/run/{LANGFLOW_FLOW}",
            params={"stream": "false"},
            headers={"x-api-key": LANGFLOW_API_KEY},
            json={"input_value": json.dumps(request), "input_type": "chat", "output_type": "chat",
                  "session_id": scan_id},
            timeout=httpx.Timeout(RUN_TIMEOUT, connect=15),
        )
        if response.status_code != 200:
            raise RuntimeError(f"Langflow returned {response.status_code}: {langflow_error(response)}")
        text = response.json()["outputs"][0]["outputs"][0]["results"]["message"]["text"]
        result = json.loads(text)
        if "findings" not in result:
            raise RuntimeError(f"The flow did not return a report: {text[:300]}")
        db.update_scan(scan_id, status="completed", finished_at=db.now(), report=result)
        db.add_event(scan_id, "system", "Assessment completed. Report is ready.")
    except Exception as exc:  # anything that goes wrong must end up on the scan record
        db.update_scan(scan_id, status="failed", finished_at=db.now(), error=str(exc)[:1500])
        db.add_event(scan_id, "system", f"Assessment failed: {str(exc)[:500]}")
    finally:
        CREDENTIALS.pop(scan_id, None)


def langflow_error(response: httpx.Response) -> str:
    try:
        detail = response.json().get("detail", response.text)
        if isinstance(detail, str) and detail.startswith("{"):
            detail = json.loads(detail).get("message", detail)
        return str(detail)[:1000]
    except ValueError:
        return response.text[:1000]


def normalize_target(raw: str) -> str:
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
    return {key: value for key, value in scan.items() if key != "report"} | {"has_report": bool(scan["report"])}
