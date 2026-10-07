"""Render a finished scan as Markdown or PDF. Pure formatting: nothing here adds findings."""
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
                   "Low": "#f9a825", "Info": "#1565c0"}

DISCLAIMER = (
    "Automated, detection-only assessment. Findings come from open-source scanners and have not "
    "been manually verified or exploited; expect false positives and missed issues. "
    "This is not a substitute for a manual penetration test."
)


# ------------------------------------------------------------------ Markdown

def to_markdown(scan: dict) -> str:
    report = scan["report"]
    counts = report.get("severity_counts", {})
    lines = [
        "# Security Assessment Report",
        "",
        f"- **Target:** {scan['target_url']}",
        f"- **Scan ID:** `{scan['id']}`",
        f"- **Generated:** {report.get('generated_at', '')}",
        f"- **Authorization:** confirmed by {scan['authorized_by']} at {scan['authorized_at']}",
        f"- **Scope notes:** {scan['scope_notes'] or 'none'}",
        "",
        f"> {DISCLAIMER}",
        "",
        "## Summary",
        "",
        "| " + " | ".join(SEVERITIES) + " |",
        "|" + "---|" * len(SEVERITIES),
        "| " + " | ".join(str(counts.get(s, 0)) for s in SEVERITIES) + " |",
        "",
        report.get("executive_summary") or "_No AI summary was produced for this run._",
        "",
        "## Plan and tool runs",
        "",
    ]
    for step in report.get("plan", {}).get("steps", []):
        lines.append(f"- **{step['tool']}**: {step.get('reason', '')}")
    lines += ["", "| Tool | Status | Duration | Findings | Raw output |", "|---|---|---|---|---|"]
    for run in report.get("tool_runs", []):
        lines.append(f"| {run['tool']} | {run['status']} | {run.get('duration_seconds', '?')}s | "
                     f"{run.get('finding_count', 0)} | {run.get('raw_file') or '-'} |")
    lines += ["", "## Findings", ""]
    if not report["findings"]:
        lines.append("_The scanners reported no findings._")
    for item in report["findings"]:
        score = f" (CVSS {item['cvss_score']})" if item.get("cvss_score") else ""
        lines += [
            f"### [{item['severity']}] {item['title']}",
            "",
            f"- **ID:** `{item['id']}` · **Tool:** {item['tool']} · **Severity:** {item['severity']}{score}",
            f"- **Severity basis:** {item.get('severity_basis', '')}",
        ]
        if item.get("cwe"):
            lines.append(f"- **Weakness:** {item['cwe']}")
        if item.get("url"):
            lines.append(f"- **Where:** {item['url']} ({item.get('instances', 1)} instance(s))")
        if item.get("description"):
            lines += ["", item["description"]]
        if item.get("evidence"):
            lines += ["", f"**Evidence (from {item['tool']}):** `{item['evidence']}`"]
        if item.get("remediation"):
            lines += ["", f"**Remediation (from {item['tool']}):** {item['remediation']}"]
        if item.get("ai_remediation"):
            lines += ["", f"**Remediation guidance (AI-written):** {item['ai_remediation']}"]
        if item.get("references"):
            lines += ["", "**References:** " + ", ".join(item["references"])]
        lines.append("")
    return "\n".join(lines)


# ----------------------------------------------------------------------- PDF

def to_pdf(scan: dict) -> bytes:
    report = scan["report"]
    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8.5, leading=11.5, textColor=colors.HexColor("#444444"))
    mono = ParagraphStyle("mono", parent=small, fontName="Courier", wordWrap="CJK")
    h1, h2 = styles["Title"], styles["Heading2"]
    finding_title = ParagraphStyle("finding", parent=styles["Heading3"], fontSize=11, leading=14, spaceAfter=3)

    def p(text, style=body):
        return Paragraph(escape(str(text or "")).replace("\n", "<br/>"), style)

    def labelled(label, text, style=body):
        return Paragraph(f"<b>{escape(label)}</b> {escape(str(text))}".replace("\n", "<br/>"), style)

    story = [Paragraph("Security Assessment Report", h1), Spacer(1, 4 * mm)]

    meta = [
        ["Target", scan["target_url"]],
        ["Scan ID", scan["id"]],
        ["Generated", report.get("generated_at", "")],
        ["Authorization", f"Confirmed by {scan['authorized_by']} at {scan['authorized_at']}"],
        ["Scope notes", scan["scope_notes"] or "none"],
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
    story += [Paragraph("Summary", h2), summary, Spacer(1, 4 * mm),
              p(report.get("executive_summary") or "No AI summary was produced for this run."),
              Spacer(1, 4 * mm)]

    story.append(Paragraph("Plan and tool runs", h2))
    for step in report.get("plan", {}).get("steps", []):
        story.append(labelled(f"{step['tool']}:", step.get("reason", "")))
    runs = [["Tool", "Status", "Duration", "Findings", "Raw output"]] + [
        [run["tool"], run["status"], f"{run.get('duration_seconds', '?')}s",
         str(run.get("finding_count", 0)), run.get("raw_file") or "-"]
        for run in report.get("tool_runs", [])
    ]
    runs_table = Table(runs, colWidths=[30 * mm, 28 * mm, 28 * mm, 28 * mm, 56 * mm])
    runs_table.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 9),
                                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
                                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc"))]))
    story += [Spacer(1, 3 * mm), runs_table, Spacer(1, 5 * mm)]

    heading = [Paragraph("Findings", h2)]
    if not report["findings"]:
        story += heading + [p("The scanners reported no findings.")]
    for item in report["findings"]:
        color = SEVERITY_COLORS.get(item["severity"], "#555555")
        score = f" · CVSS {item['cvss_score']}" if item.get("cvss_score") else ""
        block = heading + [
            Paragraph(f'<font color="{color}"><b>[{escape(item["severity"])}]</b></font> '
                      f'{escape(item["title"])}', finding_title),
            p(f"{item['id']} · {item['tool']}{score} · {item.get('severity_basis', '')}"
              + (f" · {item['cwe']}" if item.get("cwe") else ""), small),
        ]
        if item.get("url"):
            block.append(labelled("Where:", f"{item['url']} ({item.get('instances', 1)} instance(s))", mono))
        if item.get("description"):
            block.append(p(item["description"]))
        if item.get("evidence"):
            block.append(labelled(f"Evidence (from {item['tool']}):", item["evidence"], mono))
        if item.get("remediation"):
            block.append(labelled(f"Remediation (from {item['tool']}):", item["remediation"]))
        if item.get("ai_remediation"):
            block.append(labelled("Remediation guidance (AI-written):", item["ai_remediation"]))
        block.append(Spacer(1, 4 * mm))
        story.append(KeepTogether(block))
        heading = []

    buffer = BytesIO()
    SimpleDocTemplate(buffer, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                      topMargin=18 * mm, bottomMargin=18 * mm,
                      title="Security Assessment Report", author="Agentic Security Assessment Platform"
                      ).build(story)
    return buffer.getvalue()
