"""The authorization gate and target validation."""
import pytest

from app import db, targets
from app.deps import CREDENTIALS
from app.routes import system

from conftest import INTERNAL, authorized, submit


@pytest.mark.parametrize("url", [
    "juice-shop:3000", "ftp://example.com", "http://", "http://user:pw@example.com",
    "http://zap:8080", "http://backend:8000", "http://frontend:8000", "http://169.254.169.254/latest/meta-data",
    "http://exa mple.com", "http://[::1]:3000",
])
def test_bad_targets_are_rejected(client, url):
    assert client.post("/api/scans", json={"target_url": url}).status_code == 422


def test_localhost_is_rewritten_for_the_scanner_containers():
    assert targets.normalize_target("http://localhost:3001/") == "http://host.docker.internal:3001"
    assert targets.normalize_target(" https://Example.com/app/?q=1#x ") == "https://example.com/app"


def test_no_tick_no_scan(client, calls):
    scan_id = submit(client)["id"]

    # start before any authorization
    assert client.post(f"/api/scans/{scan_id}/start").status_code == 403
    # an unticked box is not an authorization
    assert client.post(f"/api/scans/{scan_id}/authorize", json={"confirmed": False}).status_code == 400
    assert client.post(f"/api/scans/{scan_id}/start").status_code == 403
    # the scanner service would be refused too
    record = client.get(f"/internal/scans/{scan_id}/authorization", headers=INTERNAL).json()
    assert record["authorized"] is False
    assert calls == []


def test_authorization_is_stored_with_the_scan_record(client, calls):
    scan_id = submit(client)["id"]
    response = client.post(f"/api/scans/{scan_id}/authorize",
                           json={"confirmed": True, "authorized_by": "Test Operator"})
    scan = response.json()
    assert scan["authorized"] is True and scan["authorized_by"] == "Test Operator"
    assert scan["authorized_at"] and "written authorization" in scan["authorization_statement"]

    assert client.post(f"/api/scans/{scan_id}/start").status_code == 202
    assert calls == [("run", scan_id)]
    record = client.get(f"/internal/scans/{scan_id}/authorization", headers=INTERNAL).json()
    assert record == {"authorized": True, "stop_requested": False,
                      "target_url": "http://juice-shop:3000", "basic_auth": None}
    # a scan cannot be started twice
    assert client.post(f"/api/scans/{scan_id}/start").status_code == 409


def test_only_one_assessment_runs_at_a_time(client):
    first, second = authorized(client), authorized(client)
    assert client.post(f"/api/scans/{first}/start").status_code == 202
    assert client.post(f"/api/scans/{second}/start").status_code == 409


def test_credentials_stay_out_of_the_scan_record(client):
    scan = submit(client, test_username="alice", test_password="s3cret")
    assert scan["credentials_provided"] is True
    assert "s3cret" not in client.get(f"/api/scans/{scan['id']}").text
    assert CREDENTIALS[scan["id"]] == ("alice", "s3cret")


def test_internal_endpoints_need_the_shared_token(client):
    scan_id = submit(client)["id"]
    assert client.get(f"/internal/scans/{scan_id}/authorization").status_code == 403
    assert client.post(f"/internal/scans/{scan_id}/events", json={"agent": "x", "message": "y"},
                       headers={"X-Internal-Token": "wrong"}).status_code == 403


def test_report_is_404_until_the_scan_completes(client):
    scan_id = submit(client)["id"]
    for path in ("report", "report.md", "report.pdf", "report.sarif", "compare"):
        assert client.get(f"/api/scans/{scan_id}/{path}").status_code == 404
    assert client.get("/api/scans/not-a-real-id").status_code == 404


def test_agent_events_keep_their_structured_data(client):
    scan_id = submit(client)["id"]
    client.post(f"/internal/scans/{scan_id}/events", headers=INTERNAL,
                json={"agent": "planner", "message": "Plan: zap.", "data": {"type": "plan", "steps": [{"tool": "zap"}]}})
    event = client.get(f"/api/scans/{scan_id}").json()["events"][-1]
    assert event["agent"] == "planner" and event["data"]["steps"] == [{"tool": "zap"}]


def test_responses_carry_a_content_security_policy(client):
    policy = client.get("/api/health").headers["Content-Security-Policy"]
    assert "default-src 'self'" in policy and "script-src" not in policy  # so scripts are 'self' only


def test_status_says_what_is_not_ready(client, monkeypatch):
    monkeypatch.setattr(system, "_is_up", lambda url: False)
    monkeypatch.setattr(system, "_get_json", lambda url: {})
    status = client.get("/api/status").json()
    assert status["ready"] is False
    assert status["services"] == {"langflow": False, "scanners": False, "zap": False}


def test_the_page_offers_only_the_practice_targets_in_the_targets_folder(client):
    offered = client.get("/api/config").json()["demo_targets"]
    assert [target["url"] for target in offered] == ["http://juice-shop:3000"]
    assert set(offered[0]) == {"name", "url", "badge", "note"}


def test_a_database_from_the_first_release_gets_the_newer_columns(client):
    with db.connect() as conn:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
    assert set(db.NEWER_COLUMNS) <= columns
    db.init()  # running it again must be harmless
