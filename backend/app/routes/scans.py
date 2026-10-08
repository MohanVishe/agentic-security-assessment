"""The public API for checks: create one, confirm permission, start it, follow it, read the report.

    POST /api/scans                  submit a target
    POST /api/scans/{id}/authorize   record the permission confirmation
    POST /api/scans/{id}/start       start (refused until authorized)
    POST /api/scans/{id}/approve     approve or change the Planner's plan (only when review was asked for)
    POST /api/scans/{id}/stop        cancel before the scans start, or stop after the tool that is running
    GET  /api/scans/{id}             status and live events
    GET  /api/scans/{id}/report      the report (.md, .pdf and .sarif also exist)
    GET  /api/scans/{id}/compare     what changed since the previous check of the same target
"""
from __future__ import annotations

import re

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response

from .. import config, db, targets
from ..deps import CREDENTIALS, public_view, require_report, require_scan
from ..schemas import AuthorizationRequest, PlanApproval, ScanRequest
from ..services import agents, compare, report, sarif

router = APIRouter(prefix="/api/scans")


@router.post("", status_code=201)
def submit_target(request: ScanRequest) -> dict:
    try:
        target_url = targets.normalize_target(request.target_url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    has_credentials = bool(request.test_username and request.test_password)
    scan_id = db.create_scan(target_url, request.scope_notes.strip(), has_credentials, request.review_plan)
    if has_credentials:
        CREDENTIALS[scan_id] = (request.test_username, request.test_password)
    return public_view(db.get_scan(scan_id))


@router.post("/{scan_id}/authorize")
def confirm_authorization(scan_id: str, request: AuthorizationRequest, http: Request) -> dict:
    scan = require_scan(scan_id)
    if not request.confirmed:
        raise HTTPException(400, "Authorization was not confirmed. The assessment cannot run.")
    if scan["status"] != "created":
        raise HTTPException(409, f"Scan is already {scan['status']}.")
    confirmed_by = request.authorized_by.strip() or f"UI user at {http.client.host if http.client else 'unknown'}"
    db.update_scan(scan_id, status="authorized", authorized=1, authorized_at=db.now(),
                   authorized_by=confirmed_by, authorization_statement=targets.AUTHORIZATION_STATEMENT)
    db.add_event(scan_id, "system", f"Authorization confirmed by {confirmed_by}.")
    return public_view(db.get_scan(scan_id))


@router.post("/{scan_id}/start", status_code=202)
def start_assessment(scan_id: str, background: BackgroundTasks) -> dict:
    scan = require_scan(scan_id)
    if not scan["authorized"]:
        raise HTTPException(403, "Authorization has not been confirmed for this target. No tick, no scan.")
    if scan["status"] != "authorized":
        raise HTTPException(409, f"Scan is already {scan['status']}.")
    if db.any_busy():
        raise HTTPException(409, "Another assessment is running. Wait for it to finish.")

    if scan["review_plan"]:
        # Only the Planner runs now. The scanners wait until a person has approved the plan.
        db.update_scan(scan_id, status="planning", started_at=db.now())
        db.add_event(scan_id, "system", "Asking the Planner for a plan. You will review it before anything is scanned.")
        background.add_task(agents.propose_plan, scan_id)
    else:
        db.update_scan(scan_id, status="running", started_at=db.now())
        db.add_event(scan_id, "system", "Assessment started; handing over to the agents.")
        background.add_task(agents.run_assessment, scan_id)
    return public_view(db.get_scan(scan_id))


@router.post("/{scan_id}/approve", status_code=202)
def approve_plan(scan_id: str, approval: PlanApproval, background: BackgroundTasks) -> dict:
    """The reviewer's decision: run these tools. They may differ from what the Planner suggested."""
    scan = require_scan(scan_id)
    if scan["status"] != "awaiting_approval":
        raise HTTPException(409, f"There is no plan waiting for approval; scan status is '{scan['status']}'.")
    if db.any_busy():
        raise HTTPException(409, "Another assessment is running. Wait for it to finish.")
    catalog = [tool["name"] for tool in agents.tool_catalog()]
    if not catalog:
        raise HTTPException(503, "The scanner service is not reachable, so the tool list could not be checked.")
    unknown = [name for name in approval.tools if name not in catalog]
    if unknown:
        raise HTTPException(422, f"Unknown tool(s): {', '.join(unknown)}. Available: {', '.join(catalog)}")
    if not approval.tools:
        raise HTTPException(422, "Pick at least one tool, or cancel the check.")

    plan = agents.reviewed_plan(scan["proposed_plan"], approval.tools, catalog, scan["authorized_by"])
    db.update_scan(scan_id, status="running", started_at=db.now(), approved_plan=plan)
    changes = [f"added {', '.join(plan['review']['added'])}"] if plan["review"]["added"] else []
    changes += [f"removed {', '.join(plan['review']['removed'])}"] if plan["review"]["removed"] else []
    db.add_event(scan_id, "system", f"Plan approved by {scan['authorized_by']} "
                 f"({'; '.join(changes) or 'as the Planner suggested'}). Handing over to the agents.")
    background.add_task(agents.run_assessment, scan_id)
    return public_view(db.get_scan(scan_id))


@router.post("/{scan_id}/stop")
def stop_check(scan_id: str) -> dict:
    """Before the scans start this cancels the check. During the scans it stops after the current tool."""
    scan = require_scan(scan_id)
    if scan["status"] == "awaiting_approval":
        db.update_scan(scan_id, status="cancelled", finished_at=db.now())
        db.add_event(scan_id, "system", "Cancelled by the user. Nothing was scanned.")
        CREDENTIALS.pop(scan_id, None)
    elif scan["status"] == "running":
        db.update_scan(scan_id, stop_requested=1)
        db.add_event(scan_id, "system", "Stop requested. The tool that is running will finish; "
                     "no further tool will start, and the report will cover what ran.", {"type": "stop_requested"})
    else:
        raise HTTPException(409, f"Nothing to stop; scan status is '{scan['status']}'.")
    return public_view(db.get_scan(scan_id))


@router.get("")
def list_scans() -> list[dict]:
    return db.list_scans()


@router.get("/{scan_id}")
def poll_status(scan_id: str) -> dict:
    scan = require_scan(scan_id)
    return {**public_view(scan), "events": db.get_events(scan_id)}


@router.get("/{scan_id}/report")
def fetch_report(scan_id: str) -> dict:
    return require_report(scan_id)["report"]


@router.get("/{scan_id}/report.md", response_class=PlainTextResponse)
def fetch_report_markdown(scan_id: str) -> str:
    return report.to_markdown(require_report(scan_id))


@router.get("/{scan_id}/report.pdf")
def fetch_report_pdf(scan_id: str) -> Response:
    pdf = report.to_pdf(require_report(scan_id))
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="assessment-{scan_id[:8]}.pdf"'})


@router.get("/{scan_id}/report.sarif")
def fetch_report_sarif(scan_id: str) -> JSONResponse:
    return JSONResponse(sarif.to_sarif(require_report(scan_id)), media_type="application/sarif+json",
                        headers={"Content-Disposition": f'attachment; filename="assessment-{scan_id[:8]}.sarif"'})


@router.get("/{scan_id}/compare")
def compare_with_previous(scan_id: str) -> dict:
    """What changed since the last finished check of the same target. `previous` is null when there is none."""
    scan = require_report(scan_id)
    previous = db.previous_completed(scan)
    if not previous:
        return {"previous": None}
    return {"previous": {"id": previous["id"], "finished_at": previous["finished_at"]},
            **compare.compare(scan["report"], previous["report"])}


@router.get("/{scan_id}/raw/{filename}")
def fetch_raw_output(scan_id: str, filename: str) -> FileResponse:
    """The untouched scanner output a finding was derived from."""
    require_scan(scan_id)
    if not re.fullmatch(r"(nmap\.xml|zap\.json|nuclei\.jsonl|nikto\.json)", filename):
        raise HTTPException(404, "No such raw output file")
    path = config.DATA_DIR / "raw" / scan_id / filename
    if not path.is_file():
        raise HTTPException(404, "That tool produced no raw output for this scan")
    return FileResponse(path, media_type="text/plain", filename=f"{scan_id[:8]}-{filename}")
