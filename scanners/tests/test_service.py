"""The scanner service's own rules: authorization first, and look after the target."""
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import app as service
from tools.common import Target

SCAN_ID = "a" * 32


class FakeTool:
    SPEC = {"name": "fake", "description": "A stand-in scanner."}
    calls = 0

    @classmethod
    def run(cls, target, workdir):
        cls.calls += 1
        return {"status": "ok", "command": "fake", "note": "", "raw_file": None, "findings": []}


@pytest.fixture()
def client(monkeypatch, tmp_path):
    FakeTool.calls = 0
    monkeypatch.setattr(service, "TOOLS", {"fake": FakeTool})
    monkeypatch.setattr(service, "DATA_DIR", tmp_path)
    monkeypatch.setattr(service, "COOL_DOWN_SECONDS", 0)
    monkeypatch.setattr(service, "authorized_target", lambda scan_id: Target(url="http://t:3000"))
    monkeypatch.setattr(service, "answers", lambda target, wait_seconds: True)
    return TestClient(service.app)


def test_a_scan_without_authorization_is_refused(client, monkeypatch):
    def refuse(scan_id):
        raise HTTPException(403, "This scan has no recorded authorization; refusing to run")

    monkeypatch.setattr(service, "authorized_target", refuse)
    assert client.post("/run/fake", json={"scan_id": SCAN_ID}).status_code == 403
    assert FakeTool.calls == 0


def test_unknown_tools_and_bad_scan_ids_are_rejected(client):
    assert client.post("/run/sqlmap", json={"scan_id": SCAN_ID}).status_code == 404
    assert client.post("/run/fake", json={"scan_id": "../../etc"}).status_code == 400


def test_a_healthy_run_is_not_flagged(client):
    result = client.post("/run/fake", json={"scan_id": SCAN_ID}).json()
    assert result["status"] == "ok" and result["target_down"] is False and FakeTool.calls == 1


def test_a_tool_is_not_started_when_the_target_does_not_answer(client, monkeypatch):
    monkeypatch.setattr(service, "answers", lambda target, wait_seconds: False)
    result = client.post("/run/fake", json={"scan_id": SCAN_ID}).json()
    assert result["status"] == "error" and result["target_down"] is True
    assert FakeTool.calls == 0


def test_a_target_that_goes_down_during_a_scan_is_reported(client, monkeypatch):
    answers = iter([True, False])  # up before the tool, down after it
    monkeypatch.setattr(service, "answers", lambda target, wait_seconds: next(answers))
    result = client.post("/run/fake", json={"scan_id": SCAN_ID}).json()
    assert result["target_down"] is True and result["summary"]["target_down"] is True
    assert "stopped answering" in result["note"]
