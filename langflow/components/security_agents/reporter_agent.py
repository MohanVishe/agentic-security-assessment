import json
import re
from datetime import datetime, timezone

from agent_common import chat, notify, parse_json
from lfx.custom.custom_component.component import Component
from lfx.io import MessageTextInput, MultilineInput, Output
from lfx.schema.message import Message

REPORTER_PROMPT = """You are the Reporter in a three-agent security assessment team.
You receive the findings the scanners produced. Each one already has an ID, the tool that
found it, a title and a CVSS severity band.

Rules:
- Use only the findings you are given. Never add a vulnerability, a CVE number or a
  detail that is not in the list.
- Refer to findings by their exact ID.

Reply with only a JSON object:
{"executive_summary": "<4 to 6 sentences for a non-specialist: overall posture, the most
  important issues, what to fix first>",
 "remediation": {"<finding id>": "<one or two concrete sentences on how to fix it>"}}

Write a remediation entry for every finding rated Medium or above, and for Low findings
where the fix is not obvious. Skip purely informational findings."""

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
TOOL_RATING_TO_BAND = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
                       "info": "Info", "informational": "Info", "unknown": "Info"}
MAX_FINDINGS_FOR_LLM = 30  # keeps the prompt inside free-tier token limits


def cvss_band(score: float) -> str:
    """CVSS qualitative severity scale; the thresholds are the same in v3.1 and v4.0."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low" if score > 0 else "Info"


def rate(finding: dict) -> tuple[str, str]:
    """Map a finding to a CVSS severity band, and say what the rating is based on."""
    tool, score = finding["tool"], finding.get("cvss_score")
    if score:
        return cvss_band(float(score)), f"CVSS score {score} reported by {tool}"
    rating = (finding.get("tool_severity") or "").lower()
    if rating in TOOL_RATING_TO_BAND:
        return TOOL_RATING_TO_BAND[rating], f"{tool} rated it '{rating}'; mapped to the matching CVSS band"
    if tool == "nmap":
        return "Info", "open port, reported for information"
    return "Low", f"{tool} does not rate findings; listed as Low by default"


class ReporterAgent(Component):
    display_name = "Reporter Agent"
    description = "Maps findings to CVSS severity, adds remediation guidance and writes the report."
    icon = "file-text"
    name = "ReporterAgent"

    inputs = [
        MessageTextInput(name="results", display_name="Tool Results", info="Output of the Executor Agent."),
        MultilineInput(name="instructions", display_name="Instructions", value=REPORTER_PROMPT),
    ]
    outputs = [Output(display_name="Report", name="report", method="write_report")]

    async def write_report(self) -> Message:
        state = json.loads(self.results)
        request, tool_runs = state["request"], state["tool_runs"]
        scan_id = request["scan_id"]

        # Findings are copied from tool output by code, never retyped by the LLM, so every
        # finding in the report traces back to a scanner result and its raw output file.
        findings = []
        for run in tool_runs:
            for finding in run["findings"]:
                severity, basis = rate(finding)
                findings.append({**finding, "severity": severity, "severity_basis": basis,
                                 "raw_file": run.get("raw_file"), "ai_remediation": ""})
        findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["tool"], f["id"]))
        counts = {level: sum(f["severity"] == level for f in findings) for level in SEVERITY_ORDER}
        await notify(scan_id, "reporter", f"Rated {len(findings)} finding(s); writing the report.")

        summary, summary_source, model = "", "not generated", ""
        if findings:
            try:
                reply, model = await chat([
                    {"role": "system", "content": self.instructions},
                    {"role": "user", "content": json.dumps({
                        "target_url": request["target_url"],
                        "severity_counts": counts,
                        "findings": [{"id": f["id"], "tool": f["tool"], "severity": f["severity"],
                                      "title": f["title"][:120], "cwe": f.get("cwe")}
                                     for f in findings[:MAX_FINDINGS_FOR_LLM]],
                    })},
                ], max_tokens=3000)
                written = parse_json(reply.content)
                summary = str(written.get("executive_summary", "")).strip()
                # Guidance is attached only to IDs that exist; anything else is dropped.
                guidance = written.get("remediation") or {}
                for finding in findings:
                    if isinstance(guidance.get(finding["id"]), str):
                        finding["ai_remediation"] = guidance[finding["id"]].strip()[:600]
                # A CVE in the summary that no scanner reported means the model made it up.
                known = json.dumps(findings)
                if any(cve not in known for cve in re.findall(r"CVE-\d{4}-\d+", summary)):
                    summary, summary_source = "", "discarded: it mentioned a CVE no scanner reported"
                else:
                    summary_source = "llm"
            except Exception as exc:
                summary_source = f"not generated: {str(exc)[:200]}"
                await notify(scan_id, "reporter", "LLM unavailable; the report lists the tool findings without AI guidance.")
        else:
            summary = "The scanners that ran reported no findings for this target."
            summary_source = "fixed text"

        report = {
            "scan_id": scan_id,
            "target_url": request["target_url"],
            "scope_notes": request.get("scope_notes", ""),
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "plan": state["plan"],
            "execution": state["execution"],
            "tool_runs": [{key: run.get(key) for key in
                           ("tool", "status", "command", "duration_seconds", "raw_file", "note")}
                          | {"finding_count": len(run["findings"])} for run in tool_runs],
            "severity_counts": counts,
            "executive_summary": summary,
            "summary_source": summary_source,
            "reporter_model": model,
            "findings": findings,
        }
        await notify(scan_id, "reporter", "Report written.")
        self.status = {"findings": len(findings), **counts}
        return Message(text=json.dumps(report))
