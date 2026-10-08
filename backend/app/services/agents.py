"""The hand-off to the agents: start a flow in Langflow and put the result on the check's record.

Two flows exist in Langflow:
  - the plan flow runs the Planner alone, so a person can review its plan first;
  - the full flow runs Planner -> Executor -> Reporter and returns the finished report.
"""
from __future__ import annotations

import json

import httpx

from .. import config, db
from ..deps import CREDENTIALS
from . import evaluation


def tool_catalog() -> list[dict]:
    """The scanners that exist, as the scanner service describes them. Empty when it cannot be reached."""
    try:
        response = httpx.get(f"{config.SCANNERS_URL}/tools", timeout=8)
        return response.json() if response.status_code == 200 else []
    except (httpx.HTTPError, ValueError):
        return []


def propose_plan(scan_id: str) -> None:
    """Background task: ask the Planner for a plan, then wait for a person to review it."""
    scan = db.get_scan(scan_id)
    try:
        answer = _run_flow(config.PLAN_FLOW, _request_for(scan), session_id=f"{scan_id}-plan")
        db.update_scan(scan_id, status="awaiting_approval", proposed_plan=answer["plan"])
        db.add_event(scan_id, "system", "The plan is ready. Waiting for you to approve or change it.",
                     {"type": "awaiting_approval"})
    except Exception as exc:
        _fail(scan_id, exc)


def reviewed_plan(proposed: dict, chosen: list[str], catalog: list[str], reviewer: str) -> dict:
    """The plan a person approved: the Planner's plan, with the reviewer's additions and removals.

    Tools keep the order of the tool list (discovery first, the noisiest scanner last).
    """
    suggested = {step["tool"]: step for step in proposed.get("steps", [])}
    steps = [suggested.get(name) or {"tool": name, "reason": "Added by the reviewer."}
             for name in catalog if name in chosen]
    review = {"reviewed_by": reviewer,
              "added": [name for name in catalog if name in chosen and name not in suggested],
              "removed": [name for name in suggested if name not in chosen]}
    return {**proposed, "steps": steps, "review": review}


def run_assessment(scan_id: str) -> None:
    """Background task: one blocking call to the full flow, then check and save the report."""
    scan = db.get_scan(scan_id)
    try:
        report = _run_flow(config.FULL_FLOW, _request_for(scan), session_id=scan_id)
        if "findings" not in report:
            raise RuntimeError(f"The flow did not return a report: {json.dumps(report)[:300]}")

        # Check the finished report against the raw scanner output, and attach the scores to the trace.
        report["quality_checks"] = evaluation.evaluate(report, config.DATA_DIR / "raw" / scan_id)
        report["trace_url"] = evaluation.send_to_langfuse(scan_id, report["quality_checks"])

        db.update_scan(scan_id, status="completed", finished_at=db.now(), report=report)
        db.add_event(scan_id, "system", "Assessment completed. Report is ready.")
    except Exception as exc:
        _fail(scan_id, exc)
    finally:
        CREDENTIALS.pop(scan_id, None)


# ------------------------------------------------------------------ helpers

def _request_for(scan: dict) -> dict:
    """What the agents are told about a check. An approved plan, if there is one, travels with it."""
    request = {"scan_id": scan["id"], "target_url": scan["target_url"], "scope_notes": scan["scope_notes"]}
    if scan.get("approved_plan"):
        request["approved_plan"] = scan["approved_plan"]
    return request


def _run_flow(flow: str, request: dict, session_id: str) -> dict:
    """Run one Langflow flow and return the JSON object its last agent produced."""
    response = httpx.post(
        f"{config.LANGFLOW_URL}/api/v1/run/{flow}",
        params={"stream": "false"},
        headers={"x-api-key": config.LANGFLOW_API_KEY},
        json={"input_value": json.dumps(request), "input_type": "chat", "output_type": "chat",
              "session_id": session_id},
        timeout=httpx.Timeout(config.RUN_TIMEOUT, connect=15),
    )
    if response.status_code != 200:
        raise RuntimeError(f"Langflow returned {response.status_code}: {_langflow_error(response)}")
    return json.loads(response.json()["outputs"][0]["outputs"][0]["results"]["message"]["text"])


def _langflow_error(response: httpx.Response) -> str:
    try:
        detail = response.json().get("detail", response.text)
        if isinstance(detail, str) and detail.startswith("{"):
            detail = json.loads(detail).get("message", detail)
        return str(detail)[:1000]
    except ValueError:
        return response.text[:1000]


def _fail(scan_id: str, exc: Exception) -> None:
    """Anything that goes wrong must end up on the check's record, where the page can show it."""
    db.update_scan(scan_id, status="failed", finished_at=db.now(), error=str(exc)[:1500])
    db.add_event(scan_id, "system", f"Assessment failed: {str(exc)[:500]}")
    CREDENTIALS.pop(scan_id, None)
