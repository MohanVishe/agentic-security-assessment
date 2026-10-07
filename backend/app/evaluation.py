"""Quality checks that run on every finished assessment.

These are plain code, not an LLM judging an LLM. Each check gives a score from
0 to 1 and a one-line explanation. They are stored in the report, shown in the
UI, and (when Langfuse is configured) attached to the run's trace as scores so
runs can be compared over time.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path

import httpx

LANGFUSE_HOST = os.getenv("LANGFUSE_HOST", "").rstrip("/")
LANGFUSE_AUTH = (os.getenv("LANGFUSE_PUBLIC_KEY", ""), os.getenv("LANGFUSE_SECRET_KEY", ""))
# The address a person's browser uses for Langfuse (containers reach it under another name).
LANGFUSE_UI_URL = (os.getenv("LANGFUSE_UI_URL") or LANGFUSE_HOST.replace("host.docker.internal", "localhost")).rstrip("/")

FINDING_ID = re.compile(r"\b(?:NMAP|ZAP|NUCLEI|NIKTO)-[\w.:-]+")


def tracing_enabled() -> bool:
    return bool(LANGFUSE_HOST and all(LANGFUSE_AUTH))


def evaluate(report: dict, raw_dir: Path) -> list[dict]:
    planned = [step["tool"] for step in report["plan"]["steps"]]
    runs = report["tool_runs"]
    ran = [run["tool"] for run in runs]
    findings = report["findings"]
    known_ids = {finding["id"] for finding in findings}

    checks = []

    def check(name: str, passed: int, total: int, detail: str) -> None:
        checks.append({"name": name, "score": round(passed / total, 2) if total else 1.0, "detail": detail})

    done = [tool for tool in planned if tool in ran]
    check("plan_followed", len(done), len(planned), f"{len(done)} of {len(planned)} planned tools ran")

    outside = [tool for tool in ran if tool not in planned]
    check("stayed_in_scope", 0 if outside else 1, 1,
          f"tools outside the plan: {', '.join(outside)}" if outside else "no tool ran outside the approved plan")

    finished = [run for run in runs if run["status"] != "error"]
    check("tools_completed", len(finished), len(runs), f"{len(finished)} of {len(runs)} tool runs finished without error")

    went_down = [run["tool"] for run in runs if run.get("target_down")]
    check("target_stayed_up", 0 if went_down else 1, 1,
          f"the target stopped answering during: {', '.join(went_down)}" if went_down
          else "the target kept answering through every scan")

    # The strongest check: look each finding up again in the scanner's untouched output file.
    raw_text: dict[str, str] = {}
    traceable = 0
    for finding in findings:
        name = finding.get("raw_file") or ""
        if name not in raw_text:
            path = raw_dir / name
            raw_text[name] = path.read_text(encoding="utf-8", errors="replace") if name and path.is_file() else ""
        if re.search(_raw_pattern(finding), raw_text[name]):
            traceable += 1
    check("findings_traceable", traceable, len(findings),
          f"{traceable} of {len(findings)} findings found again in the raw scanner output")

    ai_text = " ".join([report.get("executive_summary", "")]
                       + [item["action"] for item in report.get("fix_first", [])]
                       + [finding.get("ai_remediation", "") for finding in findings])
    scanner_text = " ".join(str(value) for finding in findings for key, value in finding.items()
                            if key != "ai_remediation")
    invented = [ref for ref in FINDING_ID.findall(ai_text) if ref.rstrip(".:,") not in known_ids]
    invented += [cve for cve in re.findall(r"CVE-\d{4}-\d+", ai_text) if cve not in scanner_text]
    invented += [fid for item in report.get("fix_first", []) for fid in item["finding_ids"] if fid not in known_ids]
    check("ai_text_grounded", 0 if invented else 1, 1,
          f"AI text mentions things no scanner reported: {', '.join(sorted(set(invented))[:5])}" if invented
          else "AI-written text refers only to findings and CVEs the scanners reported")

    serious = [f for f in findings if f["severity"] in ("Critical", "High", "Medium")]
    advised = [f for f in serious if f.get("remediation") or f.get("ai_remediation")]
    check("fix_advice_coverage", len(advised), len(serious),
          f"{len(advised)} of {len(serious)} findings rated Medium or above come with fix advice")

    return checks


def _raw_pattern(finding: dict) -> str:
    """A pattern that must appear in the scanner's raw output if the finding is real."""
    tool, key = finding["tool"], finding["id"].split("-", 1)[1]
    if tool == "nmap":  # NMAP-3000-tcp
        return rf'portid="{re.escape(key.split("-")[0])}"'
    if tool == "zap":  # ZAP-10038-1 (alert reference) or a bare plugin id
        return rf'"(?:alertRef|pluginId)"\s*:\s*"{re.escape(key)}"'
    if tool == "nuclei":  # NUCLEI-template-id[:matcher]
        return rf'"template-id"\s*:\s*"{re.escape(key.split(":")[0])}"'
    if tool == "nikto":  # NIKTO-000287 or NIKTO-000287-2
        return rf'"id"\s*:\s*"?{re.escape(key.split("-")[0])}"?'
    return r"(?!)"  # unknown tool: never matches


def send_to_langfuse(session_id: str, checks: list[dict]) -> str | None:
    """Attach the checks to the run's Langfuse trace as scores. Returns the trace's URL."""
    if not tracing_enabled():
        return None
    try:
        with httpx.Client(base_url=LANGFUSE_HOST, auth=LANGFUSE_AUTH, timeout=15) as langfuse:
            trace = None
            for _ in range(10):  # Langfuse ingests traces asynchronously; give it a moment
                trace = _find_trace(langfuse, session_id)
                if trace:
                    break
                time.sleep(3)
            if not trace:
                return None
            trace_id, project_id = trace
            for item in checks:
                langfuse.post("/api/public/scores", json={
                    "id": f"{trace_id}-{item['name']}", "traceId": trace_id, "name": item["name"],
                    "value": item["score"], "dataType": "NUMERIC", "comment": item["detail"]})
            return f"{LANGFUSE_UI_URL}/project/{project_id}/traces/{trace_id}"
    except (httpx.HTTPError, ValueError, KeyError):
        return None  # tracing is a convenience; it must never fail a run


def _find_trace(langfuse: httpx.Client, session_id: str) -> tuple[str, str] | None:
    """(trace id, project id) of the run. Langflow uses our scan id as the Langfuse session id.

    Langfuse v4 lists observations; older servers list traces. Try the new endpoint first.
    """
    for path, trace_key in (("/api/public/v2/observations", "traceId"), ("/api/public/traces", "id")):
        found = langfuse.get(path, params={"sessionId": session_id, "limit": 1})
        if found.status_code == 200 and found.json().get("data"):
            row = found.json()["data"][0]
            return row[trace_key], row["projectId"]
    return None
