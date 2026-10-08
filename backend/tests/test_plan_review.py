"""Human in the loop: review the Planner's plan before anything is scanned, and stop a check that is running."""
from app import db
from app.services import agents

from conftest import INTERNAL, PROPOSED, authorized


def awaiting_approval(client) -> str:
    scan_id = authorized(client, review_plan=True)
    client.post(f"/api/scans/{scan_id}/start")
    return scan_id


def test_with_review_only_the_planner_runs_and_the_scanners_stay_locked(client, calls):
    scan_id = awaiting_approval(client)
    assert calls == [("plan", scan_id)]  # the full flow was not started

    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "awaiting_approval" and scan["proposed_plan"] == PROPOSED
    # the scanner service asks this before every tool; while the plan waits, the answer is no
    record = client.get(f"/internal/scans/{scan_id}/authorization", headers=INTERNAL).json()
    assert record["authorized"] is False


def test_without_review_the_check_starts_straight_away(client, calls):
    scan_id = authorized(client)
    client.post(f"/api/scans/{scan_id}/start")
    assert calls == [("run", scan_id)]
    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "running"


def test_the_approved_tools_are_the_ones_that_run(client, calls):
    scan_id = awaiting_approval(client)
    # the Planner suggested zap and nuclei; the reviewer drops nuclei and adds nmap
    response = client.post(f"/api/scans/{scan_id}/approve", json={"tools": ["zap", "nmap"]})
    assert response.status_code == 202 and calls[-1] == ("run", scan_id)

    plan = response.json()["approved_plan"]
    assert [step["tool"] for step in plan["steps"]] == ["nmap", "zap"]  # tool-list order, not click order
    assert plan["steps"][0]["reason"] == "Added by the reviewer."
    assert plan["steps"][1]["reason"] == "web baseline"                 # the Planner's reason is kept
    assert plan["review"] == {"reviewed_by": "Test Operator", "added": ["nmap"], "removed": ["nuclei"]}

    # the approved plan travels to the agents with the request
    request = agents._request_for(db.get_scan(scan_id))
    assert request["approved_plan"] == plan
    assert client.get(f"/internal/scans/{scan_id}/authorization", headers=INTERNAL).json()["authorized"] is True


def test_approval_is_checked(client, calls):
    scan_id = awaiting_approval(client)
    assert client.post(f"/api/scans/{scan_id}/approve", json={"tools": ["sqlmap"]}).status_code == 422
    assert client.post(f"/api/scans/{scan_id}/approve", json={"tools": []}).status_code == 422
    assert calls == [("plan", scan_id)]

    not_reviewed = authorized(client)
    assert client.post(f"/api/scans/{not_reviewed}/approve", json={"tools": ["zap"]}).status_code == 409


def test_cancelling_at_the_review_scans_nothing(client, calls):
    scan_id = awaiting_approval(client)
    assert client.post(f"/api/scans/{scan_id}/stop").json()["status"] == "cancelled"
    assert calls == [("plan", scan_id)]
    assert client.post(f"/api/scans/{scan_id}/approve", json={"tools": ["zap"]}).status_code == 409
    assert client.post(f"/api/scans/{scan_id}/start").status_code == 409


def test_stop_is_passed_to_the_scanner_service(client):
    scan_id = authorized(client)
    assert client.post(f"/api/scans/{scan_id}/stop").status_code == 409  # nothing is running yet

    client.post(f"/api/scans/{scan_id}/start")
    assert client.post(f"/api/scans/{scan_id}/stop").json()["stop_requested"] is True
    record = client.get(f"/internal/scans/{scan_id}/authorization", headers=INTERNAL).json()
    assert record["stop_requested"] is True
    assert client.get(f"/api/scans/{scan_id}").json()["events"][-1]["data"] == {"type": "stop_requested"}
