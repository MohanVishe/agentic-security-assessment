"""Shared test set-up. Nothing here needs Langflow, the scanners or Docker to be running."""
import os
import tempfile
from pathlib import Path

# Set before the app is imported: it reads its settings once.
os.environ["DATA_DIR"] = tempfile.mkdtemp()
os.environ["INTERNAL_TOKEN"] = "test-token"
os.environ["TARGETS_DIR"] = str(Path(__file__).resolve().parents[2] / "targets")

import pytest
from fastapi.testclient import TestClient

from app import db, main
from app.services import agents

INTERNAL = {"X-Internal-Token": "test-token"}
CATALOG = [{"name": name, "description": "", "typical_duration": ""} for name in ("nmap", "zap", "nuclei", "nikto")]
PROPOSED = {"steps": [{"tool": "zap", "reason": "web baseline"}, {"tool": "nuclei", "reason": "known checks"}],
            "model": "test-model", "notes": ""}


@pytest.fixture()
def calls(monkeypatch) -> list:
    """Stands in for the agents. Records which background job the API started, instead of calling Langflow."""
    started = []

    def fake_propose_plan(scan_id):
        started.append(("plan", scan_id))
        db.update_scan(scan_id, status="awaiting_approval", proposed_plan=PROPOSED)

    monkeypatch.setattr(agents, "propose_plan", fake_propose_plan)
    monkeypatch.setattr(agents, "run_assessment", lambda scan_id: started.append(("run", scan_id)))
    monkeypatch.setattr(agents, "tool_catalog", lambda: CATALOG)
    return started


@pytest.fixture()
def client(calls):
    with TestClient(main.app) as test_client:
        yield test_client
    # Only one check may be busy at a time, so leave nothing busy behind for the next test.
    with db.connect() as conn:
        conn.execute("UPDATE scans SET status='failed' WHERE status IN ('planning', 'running')")


def submit(client, **body) -> dict:
    return client.post("/api/scans", json={"target_url": "http://juice-shop:3000", **body}).json()


def authorized(client, **body) -> str:
    """A check that has its permission confirmed and is ready to start."""
    scan_id = submit(client, **body)["id"]
    client.post(f"/api/scans/{scan_id}/authorize", json={"confirmed": True, "authorized_by": "Test Operator"})
    return scan_id
