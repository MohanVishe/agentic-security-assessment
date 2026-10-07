"""The quality checks and the report formats, run on a small hand-made report and raw scanner files."""
from app import evaluation
from app import report as rendering


def make_report(**changes) -> dict:
    report = {
        "plan": {"steps": [{"tool": "zap", "reason": "web baseline"}, {"tool": "nuclei", "reason": "templates"}],
                 "model": "test-model", "notes": ""},
        "execution": {"driver": "llm tool calling", "model": "test-model", "skipped": [], "stop_reason": ""},
        "tool_runs": [
            {"tool": "zap", "status": "ok", "duration_seconds": 60, "finding_count": 1, "note": "", "target_down": False},
            {"tool": "nuclei", "status": "ok", "duration_seconds": 90, "finding_count": 1, "note": "", "target_down": False},
        ],
        "severity_counts": {"Medium": 1, "Info": 1},
        "executive_summary": "Two issues were reported. Start with ZAP-10038-1.",
        "fix_first": [{"action": "Set a Content-Security-Policy header.", "finding_ids": ["ZAP-10038-1"]}],
        "not_tested": ["Active attack testing"],
        "findings": [
            {"id": "ZAP-10038-1", "tool": "zap", "title": "CSP Header Not Set", "severity": "Medium",
             "severity_basis": "zap rated it 'medium'", "raw_file": "zap.json", "remediation": "Set the header.",
             "ai_remediation": ""},
            {"id": "NUCLEI-tech-detect:nginx", "tool": "nuclei", "title": "nginx", "severity": "Info",
             "severity_basis": "nuclei rated it 'info'", "raw_file": "nuclei.jsonl", "remediation": "",
             "ai_remediation": ""},
        ],
    }
    report.update(changes)
    return report


def write_raw(folder):
    (folder / "zap.json").write_text('[{"alertRef": "10038-1", "pluginId": "10038"}]')
    (folder / "nuclei.jsonl").write_text('{"template-id": "tech-detect", "matcher-name": "nginx"}')


def scores(report, folder) -> dict:
    return {check["name"]: check["score"] for check in evaluation.evaluate(report, folder)}


def test_a_clean_run_passes_every_check(tmp_path):
    write_raw(tmp_path)
    assert set(scores(make_report(), tmp_path).values()) == {1.0}


def test_a_finding_missing_from_the_raw_output_is_caught(tmp_path):
    write_raw(tmp_path)
    report = make_report()
    report["findings"].append({"id": "ZAP-99999", "tool": "zap", "title": "Made up", "severity": "Low",
                               "raw_file": "zap.json", "remediation": "", "ai_remediation": ""})
    assert scores(report, tmp_path)["findings_traceable"] == 0.67


def test_ai_text_that_names_an_unknown_finding_or_cve_is_caught(tmp_path):
    write_raw(tmp_path)
    report = make_report(executive_summary="See ZAP-40012 and CVE-2021-44228.")
    assert scores(report, tmp_path)["ai_text_grounded"] == 0


def test_a_skipped_tool_and_a_target_that_went_down_are_caught(tmp_path):
    write_raw(tmp_path)
    report = make_report()
    report["tool_runs"] = [dict(report["tool_runs"][0], target_down=True)]
    result = scores(report, tmp_path)
    assert result["plan_followed"] == 0.5 and result["target_stayed_up"] == 0


def test_the_markdown_and_pdf_reports_carry_the_run_notes_and_the_checks(tmp_path):
    write_raw(tmp_path)
    report = make_report()
    report["execution"].update(skipped=["nikto"], stop_reason="The target went down.")
    report["quality_checks"] = evaluation.evaluate(report, tmp_path)
    scan = {"id": "a" * 32, "target_url": "http://t", "scope_notes": "", "authorized_by": "Tester",
            "authorized_at": "2026-01-01T00:00:00+00:00", "report": report}
    markdown = rendering.to_markdown(scan)
    assert "Planned but not run: nikto" in markdown and "findings_traceable" in markdown
    assert "## 2. Fix these first" in markdown and "confirmed by Tester" in markdown
    assert rendering.to_pdf(scan).startswith(b"%PDF")
