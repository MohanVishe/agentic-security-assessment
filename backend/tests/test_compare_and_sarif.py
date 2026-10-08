"""Comparing two checks of the same target, and the SARIF export."""
from app import db
from app.services import compare, sarif

from conftest import authorized
from test_evaluation import make_report


def finding(finding_id: str, tool: str, severity: str = "Medium") -> dict:
    return {"id": finding_id, "tool": tool, "title": f"Title of {finding_id}", "severity": severity}


def report_with(tools: list[str], findings: list[dict]) -> dict:
    return {"tool_runs": [{"tool": tool, "status": "ok"} for tool in tools], "findings": findings}


def test_new_gone_and_still_there():
    before = report_with(["zap", "nuclei"], [finding("ZAP-1", "zap"), finding("ZAP-2", "zap"), finding("NUC-1", "nuclei")])
    now = report_with(["zap", "nuclei"], [finding("ZAP-2", "zap"), finding("NUC-1", "nuclei"), finding("NUC-9", "nuclei")])
    result = compare.compare(now, before)
    assert [f["id"] for f in result["new"]] == ["NUC-9"]
    assert [f["id"] for f in result["no_longer_reported"]] == ["ZAP-1"]
    assert result["still_there"] == 2 and result["tools_not_compared"] == []


def test_a_tool_that_ran_only_once_is_not_compared():
    # Nikto ran last time only. Its finding is not "gone": nobody looked for it this time.
    before = report_with(["zap", "nikto"], [finding("ZAP-1", "zap"), finding("NIKTO-1", "nikto")])
    now = report_with(["zap", "nmap"], [finding("ZAP-1", "zap"), finding("NMAP-1", "nmap")])
    result = compare.compare(now, before)
    assert result["new"] == [] and result["no_longer_reported"] == []
    assert result["tools_compared"] == ["zap"] and result["tools_not_compared"] == ["nikto", "nmap"]


def test_a_tool_that_failed_is_not_compared():
    before = report_with(["zap"], [finding("ZAP-1", "zap")])
    now = {"tool_runs": [{"tool": "zap", "status": "error"}], "findings": []}
    assert compare.compare(now, before)["no_longer_reported"] == []


def complete(scan_id: str, report: dict, created_at: str) -> None:
    db.update_scan(scan_id, status="completed", created_at=created_at, finished_at=created_at, report=report)


def test_the_api_compares_with_the_previous_check_of_the_same_target(client):
    first, second = authorized(client), authorized(client)
    other_site = client.post("/api/scans", json={"target_url": "http://example.com"}).json()["id"]
    complete(first, report_with(["zap"], [finding("ZAP-1", "zap")]), "2026-01-01T10:00:00+00:00")
    complete(other_site, report_with(["zap"], [finding("ZAP-7", "zap")]), "2026-01-02T10:00:00+00:00")
    complete(second, report_with(["zap"], [finding("ZAP-2", "zap")]), "2026-01-03T10:00:00+00:00")

    assert client.get(f"/api/scans/{first}/compare").json() == {"previous": None}
    result = client.get(f"/api/scans/{second}/compare").json()
    assert result["previous"]["id"] == first  # not the check of the other site
    assert [f["id"] for f in result["new"]] == ["ZAP-2"]
    assert [f["id"] for f in result["no_longer_reported"]] == ["ZAP-1"]


def test_sarif_has_one_run_per_scanner_and_keeps_the_finding_ids(client):
    scan = {"id": "a" * 32, "target_url": "http://t", "report": make_report()}
    document = sarif.to_sarif(scan)
    assert document["version"] == "2.1.0"
    assert [run["tool"]["driver"]["name"] for run in document["runs"]] == ["zap", "nuclei"]

    zap = document["runs"][0]
    assert zap["results"][0]["ruleId"] == "ZAP-10038-1" == zap["tool"]["driver"]["rules"][0]["id"]
    assert zap["results"][0]["level"] == "warning"                    # Medium
    assert document["runs"][1]["results"][0]["level"] == "note"       # Info
    assert zap["properties"] == {"target": "http://t", "status": "ok", "detection_only": True}


def test_the_sarif_download(client):
    scan_id = authorized(client)
    complete(scan_id, make_report(), "2026-02-01T10:00:00+00:00")
    response = client.get(f"/api/scans/{scan_id}/report.sarif")
    assert response.status_code == 200 and response.headers["content-type"].startswith("application/sarif+json")
    assert ".sarif" in response.headers["content-disposition"]
    assert sum(len(run["results"]) for run in response.json()["runs"]) == 2
