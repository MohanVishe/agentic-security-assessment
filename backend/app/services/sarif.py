"""Export a report as SARIF 2.1.0, the standard file format for the results of analysis tools.

Many trackers and dashboards can import SARIF (GitHub code scanning, DefectDojo and others),
so this is the way to get the findings out of this tool and into the one your team already uses.
One SARIF "run" is written per scanner, because each scanner is the tool that made its findings.
"""
from __future__ import annotations

# SARIF knows three levels. Critical and High become "error", Medium "warning", the rest "note".
LEVELS = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}


def to_sarif(scan: dict) -> dict:
    report = scan["report"]
    runs = []
    for tool_run in report.get("tool_runs", []):
        findings = [finding for finding in report["findings"] if finding["tool"] == tool_run["tool"]]
        runs.append({
            "tool": {"driver": {"name": tool_run["tool"],
                                "rules": [_rule(finding) for finding in findings]}},
            "results": [_result(finding) for finding in findings],
            "properties": {"target": scan["target_url"], "status": tool_run.get("status"),
                           "detection_only": True},
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs}


def _rule(finding: dict) -> dict:
    rule = {"id": finding["id"], "name": finding["title"],
            "shortDescription": {"text": finding["title"]},
            "properties": {key: finding[key] for key in ("cwe", "owasp") if finding.get(key)}}
    if finding.get("description"):
        rule["fullDescription"] = {"text": finding["description"]}
    if finding.get("remediation"):
        rule["help"] = {"text": finding["remediation"]}
    return rule


def _result(finding: dict) -> dict:
    result = {
        "ruleId": finding["id"],
        "level": LEVELS.get(finding["severity"], "note"),
        "message": {"text": finding.get("evidence") or finding["title"]},
        "properties": {"severity": finding["severity"], "severity_basis": finding.get("severity_basis", ""),
                       "likely_false_alarm": bool(finding.get("likely_false_alarm"))},
    }
    if finding.get("url"):
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": finding["url"]}}}]
    return result
