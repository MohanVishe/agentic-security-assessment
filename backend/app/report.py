"""Render a finished scan as Markdown or PDF. Pure formatting: nothing here adds findings.

Both formats follow the same order, from "what do I need to know" to "show me the detail":
summary, what to fix first, findings at a glance, what ran, what was not tested, details.
"""
from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_COLORS = {"Critical": "#7b1fa2", "High": "#c62828", "Medium": "#ef6c00",
                   "Low": "#b58900", "Info": "#1565c0"}
SEVERITY_ICONS = {"Critical": "🟣", "High": "🔴", "Medium": "🟠", "Low": "🟡", "Info": "🔵"}

DISCLAIMER = (
    "This is an automated, detection-only check. The findings come from open-source scanners "
    "and have not been confirmed by a person or by exploiting them, so some may be false alarms "
    "and real problems may be missing. It does not replace a manual penetration test."
)


def _cell(text: str) -> str:
    """Text made safe for a one-line Markdown table cell."""
    return str(text or "").replace("|", "\\|").replace("\n", " ").strip()


def _run_notes(report: dict) -> list[str]:
    """Plain sentences about anything that did not go to plan: time limits, a target that went down, skipped tools."""
    notes = [f"{run['tool']}: {run['note']}" for run in report.get("tool_runs", [])
             if run.get("note") and (run["status"] != "ok" or run.get("target_down"))]
    execution = report.get("execution", {})
    if execution.get("skipped"):
        reason = execution.get("stop_reason") or "no reason given"
        notes.append(f"Planned but not run: {', '.join(execution['skipped'])}. The Executor's reason: {reason}")
    return notes


def _counts_line(counts: dict) -> str:
    parts = [f"{SEVERITY_ICONS[level]} {counts.get(level, 0)} {level}" for level in SEVERITIES if counts.get(level)]
    return " · ".join(parts) or "none"


# ------------------------------------------------------------------ Markdown

def to_markdown(scan: dict) -> str:
    report = scan["report"]
    counts, findings = report.get("severity_counts", {}), report["findings"]
    lines = [
        "# Security Assessment Report",
        "",
        "| | |",
        "|---|---|",
        f"| **Target** | {_cell(scan['target_url'])} |",
        f"| **Date** | {report.get('generated_at', '')[:16].replace('T', ' ')} UTC |",
        f"| **Findings** | {len(findings)} total: {_counts_line(counts)} |",
        f"| **Tools run** | {', '.join(run['tool'] for run in report.get('tool_runs', [])) or 'none'} |",
        f"| **Scope notes** | {_cell(scan['scope_notes']) or 'none'} |",
        f"| **Permission** | confirmed by {_cell(scan['authorized_by'])} at {scan['authorized_at']} |",
        "",
        f"> {DISCLAIMER}",
        "",
        "## 1. Summary",
        "",
        report.get("executive_summary") or "_No AI summary was produced for this run._",
        "",
    ]

    if report.get("fix_first"):
        lines += ["## 2. Fix these first", ""]
        for number, item in enumerate(report["fix_first"], 1):
            ids = ", ".join(f"`{fid}`" for fid in item["finding_ids"])
            lines.append(f"{number}. **{_cell(item['action'])}**  \n   Related findings: {ids}")
        lines += ["", "_This list was written by the Reporter agent from the findings below._", ""]

    lines += ["## 3. Findings at a glance", ""]
    if findings:
        lines += ["| # | Severity | Finding | Tool | Seen |", "|---:|---|---|---|---:|"]
        for number, item in enumerate(findings, 1):
            lines.append(f"| {number} | {SEVERITY_ICONS[item['severity']]} {item['severity']} | "
                         f"{_cell(item['title'])} | {item['tool']} | {item.get('instances', 1)}× |")
    else:
        lines.append("_The scanners reported no findings._")

    lines += ["", "## 4. What ran", "", "The Planner agent chose these tools:", ""]
    for step in report.get("plan", {}).get("steps", []):
        lines.append(f"- **{step['tool']}**: {step.get('reason', '')}")
    lines += ["", "| Tool | What it checks | Result | Time | Findings |", "|---|---|---|---:|---:|"]
    for run in report.get("tool_runs", []):
        lines.append(f"| {run['tool']} | {_cell(run.get('what_it_checks', ''))} | {run['status']} | "
                     f"{run.get('duration_seconds', '?')} s | {run.get('finding_count', 0)} |")
    if _run_notes(report):
        lines += ["", "Things to know about this run:", ""] + [f"- {_cell(note)}" for note in _run_notes(report)]

    lines += ["", "## 5. What was not tested", ""]
    lines += [f"- {item}" for item in report.get("not_tested", [])]

    lines += ["", "## 6. Finding details", ""]
    for number, item in enumerate(findings, 1):
        score = f" (CVSS {item['cvss_score']})" if item.get("cvss_score") else ""
        lines += [
            f"### {number}. {SEVERITY_ICONS[item['severity']]} {item['severity']}: {item['title']}",
            "",
            f"- **ID:** `{item['id']}` · **Found by:** {item['tool']} · **Severity:** {item['severity']}{score}",
            f"- **Why this severity:** {item.get('severity_basis', '')}",
        ]
        if item.get("cwe"):
            lines.append(f"- **Weakness type:** {item['cwe']}")
        if item.get("url"):
            lines.append(f"- **Where:** `{item['url']}` (seen {item.get('instances', 1)}×)")
        if item.get("description"):
            lines += ["", item["description"]]
        if item.get("evidence"):
            lines += ["", f"**Evidence from {item['tool']}:** `{_cell(item['evidence'])}`"]
        if item.get("remediation"):
            lines += ["", f"**How to fix (from {item['tool']}):** {item['remediation']}"]
        if item.get("ai_remediation"):
            lines += ["", f"**How to fix (AI-written):** {item['ai_remediation']}"]
        if item.get("references"):
            lines += ["", "**Read more:** " + ", ".join(item["references"])]
        lines.append("")

    if report.get("quality_checks"):
        lines += ["## 7. Quality checks on this report", "",
                  "Automatic checks run by code after the agents finish. 1.0 is a full pass.", "",
                  "| Check | Score | Detail |", "|---|---:|---|"]
        for check in report["quality_checks"]:
            lines.append(f"| {check['name']} | {check['score']:.2f} | {_cell(check['detail'])} |")
        lines.append("")

    lines += ["---", f"Scan ID `{scan['id']}` · Planner model: {report.get('plan', {}).get('model', '?')} · "
              f"Reporter model: {report.get('reporter_model') or 'none'}", ""]
    return "\n".join(lines)


# ----------------------------------------------------------------------- PDF

def to_pdf(scan: dict) -> bytes:
    report = scan["report"]
    findings = report["findings"]
    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8.5, leading=11.5, textColor=colors.HexColor("#444444"))
    mono = ParagraphStyle("mono", parent=small, fontName="Courier", wordWrap="CJK")
    h1, h2 = styles["Title"], styles["Heading2"]
    finding_title = ParagraphStyle("finding", parent=styles["Heading3"], fontSize=11, leading=14, spaceAfter=3)
    grid = [("FONTSIZE", (0, 0), (-1, -1), 9), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc"))]

    def p(text, style=body):
        return Paragraph(escape(str(text or "")).replace("\n", "<br/>"), style)

    def labelled(label, text, style=body):
        return Paragraph(f"<b>{escape(label)}</b> {escape(str(text))}".replace("\n", "<br/>"), style)

    story = [Paragraph("Security Assessment Report", h1), Spacer(1, 4 * mm)]

    meta = [
        ["Target", scan["target_url"]],
        ["Date", f"{report.get('generated_at', '')[:16].replace('T', ' ')} UTC"],
        ["Tools run", ", ".join(run["tool"] for run in report.get("tool_runs", [])) or "none"],
        ["Scope notes", scan["scope_notes"] or "none"],
        ["Permission", f"Confirmed by {scan['authorized_by']} at {scan['authorized_at']}"],
        ["Scan ID", scan["id"]],
    ]
    table = Table([[p(k, small), p(v, body)] for k, v in meta], colWidths=[32 * mm, 138 * mm])
    table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd"))]))
    story += [table, Spacer(1, 3 * mm), p(DISCLAIMER, small), Spacer(1, 5 * mm)]

    counts = report.get("severity_counts", {})
    summary = Table([SEVERITIES, [str(counts.get(s, 0)) for s in SEVERITIES]], colWidths=[34 * mm] * 5)
    summary.setStyle(TableStyle(
        [("ALIGN", (0, 0), (-1, -1), "CENTER"), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
         ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 1), (-1, 1), 16),
         ("BOTTOMPADDING", (0, 1), (-1, 1), 10), ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#bbbbbb"))]
        + [("BACKGROUND", (i, 0), (i, 0), colors.HexColor(SEVERITY_COLORS[s])) for i, s in enumerate(SEVERITIES)]
    ))
    story += [Paragraph("1. Summary", h2), summary, Spacer(1, 4 * mm),
              p(report.get("executive_summary") or "No AI summary was produced for this run."),
              Spacer(1, 4 * mm)]

    if report.get("fix_first"):
        story.append(Paragraph("2. Fix these first", h2))
        for number, item in enumerate(report["fix_first"], 1):
            story.append(labelled(f"{number}.", item["action"]))
            story.append(p("Related findings: " + ", ".join(item["finding_ids"]), small))
        story += [p("Written by the Reporter agent from the findings below.", small), Spacer(1, 4 * mm)]

    story.append(Paragraph("3. What ran", h2))
    for step in report.get("plan", {}).get("steps", []):
        story.append(labelled(f"{step['tool']}:", step.get("reason", "")))
    runs = [["Tool", "What it checks", "Result", "Time", "Findings"]] + [
        [run["tool"], p(run.get("what_it_checks", ""), small), run["status"],
         f"{run.get('duration_seconds', '?')} s", str(run.get("finding_count", 0))]
        for run in report.get("tool_runs", [])
    ]
    runs_table = Table(runs, colWidths=[20 * mm, 96 * mm, 20 * mm, 17 * mm, 17 * mm])
    runs_table.setStyle(TableStyle(grid))
    story += [Spacer(1, 3 * mm), runs_table, Spacer(1, 2 * mm)]
    story += [p(f"Note: {note}", small) for note in _run_notes(report)]
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("4. What was not tested", h2))
    story += [p(f"- {item}") for item in report.get("not_tested", [])]
    story.append(Spacer(1, 5 * mm))

    heading = [Paragraph("5. Findings", h2)]
    if not findings:
        story += heading + [p("The scanners reported no findings.")]
    for number, item in enumerate(findings, 1):
        color = SEVERITY_COLORS.get(item["severity"], "#555555")
        score = f" · CVSS {item['cvss_score']}" if item.get("cvss_score") else ""
        block = heading + [
            Paragraph(f'{number}. <font color="{color}"><b>[{escape(item["severity"])}]</b></font> '
                      f'{escape(item["title"])}', finding_title),
            p(f"{item['id']} · {item['tool']}{score} · {item.get('severity_basis', '')}"
              + (f" · {item['cwe']}" if item.get("cwe") else ""), small),
        ]
        if item.get("url"):
            block.append(labelled("Where:", f"{item['url']} (seen {item.get('instances', 1)}x)", mono))
        if item.get("description"):
            block.append(p(item["description"]))
        if item.get("evidence"):
            block.append(labelled(f"Evidence from {item['tool']}:", item["evidence"], mono))
        if item.get("remediation"):
            block.append(labelled(f"How to fix (from {item['tool']}):", item["remediation"]))
        if item.get("ai_remediation"):
            block.append(labelled("How to fix (AI-written):", item["ai_remediation"]))
        block.append(Spacer(1, 4 * mm))
        story.append(KeepTogether(block))
        heading = []

    if report.get("quality_checks"):
        checks = [["Check", "Score", "Detail"]] + [
            [check["name"], f"{check['score']:.2f}", p(check["detail"], small)] for check in report["quality_checks"]]
        checks_table = Table(checks, colWidths=[42 * mm, 16 * mm, 112 * mm])
        checks_table.setStyle(TableStyle(grid))
        story.append(KeepTogether([Paragraph("6. Quality checks on this report", h2),
                                   p("Automatic checks run by code after the agents finish. 1.0 is a full pass.", small),
                                   Spacer(1, 2 * mm), checks_table]))

    buffer = BytesIO()
    SimpleDocTemplate(buffer, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                      topMargin=18 * mm, bottomMargin=18 * mm,
                      title="Security Assessment Report", author="Agentic Security Assessment Platform"
                      ).build(story)
    return buffer.getvalue()
