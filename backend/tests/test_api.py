"""The authorization gate and target validation, without Langflow or scanners running."""
import os
import tempfile

os.environ["DATA_DIR"] = tempfile.mkdtemp()
os.environ["INTERNAL_TOKEN"] = "test-token"

import pytest
from fastapi.testclient import TestClient

from app import main

INTERNAL = {"X-Internal-Token": "test-token"}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(main, "run_assessment", lambda scan_id: None)  # do not call Langflow
    with TestClient(main.app) as test_client:
        yield test_client


def submit(client, **body):
    return client.post("/api/scans", json={"target_url": "http://juice-shop:3000", **body})


@pytest.mark.parametrize("url", [
    "juice-shop:3000", "ftp://example.com", "http://", "http://user:pw@example.com",
    "http://zap:8080", "http://backend:8000", "http://169.254.169.254/latest/meta-data",
    "http://exa mple.com", "http://[::1]:3000",
])
def test_bad_targets_are_rejected(client, url):
    assert client.post("/api/scans", json={"target_url": url}).status_code == 422


def test_localhost_is_rewritten_for_the_scanner_containers():
    assert main.normalize_target("http://localhost:3001/") == "http://host.docker.internal:3001"
    assert main.normalize_target(" https://Example.com/app/?q=1#x ") == "https://example.com/app"


def test_no_tick_no_scan(client):
    scan_id = submit(client).json()["id"]

    # start before any authorization
    assert client.post(f"/api/scans/{scan_id}/start").status_code == 403
    # an unticked box is not an authorization
    assert client.post(f"/api/scans/{scan_id}/authorize", json={"confirmed": False}).status_code == 400
    assert client.post(f"/api/scans/{scan_id}/start").status_code == 403
    # the scanner service would be refused too
    record = client.get(f"/internal/scans/{scan_id}/authorization", headers=INTERNAL).json()
    assert record["authorized"] is False


def test_authorization_is_stored_with_the_scan_record(client):
    scan_id = submit(client).json()["id"]
    response = client.post(f"/api/scans/{scan_id}/authorize",
                           json={"confirmed": True, "authorized_by": "Test Operator"})
    scan = response.json()
    assert scan["authorized"] is True and scan["authorized_by"] == "Test Operator"
    assert scan["authorized_at"] and "written authorization" in scan["authorization_statement"]

    assert client.post(f"/api/scans/{scan_id}/start").status_code == 202
    record = client.get(f"/internal/scans/{scan_id}/authorization", headers=INTERNAL).json()
    assert record == {"authorized": True, "target_url": "http://juice-shop:3000", "basic_auth": None}
    # one assessment at a time, and a scan cannot be started twice
    assert client.post(f"/api/scans/{scan_id}/start").status_code == 409
    main.db.update_scan(scan_id, status="failed")


def test_credentials_stay_out_of_the_scan_record(client):
    scan = submit(client, test_username="alice", test_password="s3cret").json()
    assert scan["credentials_provided"] is True
    assert "s3cret" not in client.get(f"/api/scans/{scan['id']}").text
    assert main.CREDENTIALS[scan["id"]] == ("alice", "s3cret")


def test_internal_endpoints_need_the_shared_token(client):
    scan_id = submit(client).json()["id"]
    assert client.get(f"/internal/scans/{scan_id}/authorization").status_code == 403
    assert client.post(f"/internal/scans/{scan_id}/events", json={"agent": "x", "message": "y"},
                       headers={"X-Internal-Token": "wrong"}).status_code == 403


def test_report_is_404_until_the_scan_completes(client):
    scan_id = submit(client).json()["id"]
    assert client.get(f"/api/scans/{scan_id}/report").status_code == 404
    assert client.get("/api/scans/not-a-real-id").status_code == 404
