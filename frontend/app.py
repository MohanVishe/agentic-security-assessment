"""Streamlit UI: submit a target, tick the authorization box, watch the agents, read the report."""
import os

import requests
import streamlit as st

API = os.getenv("BACKEND_URL", "http://backend:8000")
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_ICONS = {"Critical": "🟣", "High": "🔴", "Medium": "🟠", "Low": "🟡", "Info": "🔵"}
AGENT_ICONS = {"planner": "🧭", "executor": "🛠️", "reporter": "📝", "system": "⚙️"}

st.set_page_config(page_title="Agentic Security Assessment", page_icon="🛡️", layout="wide")


def api(method: str, path: str, **kwargs) -> requests.Response:
    return requests.request(method, f"{API}{path}", timeout=60, **kwargs)


def error_text(response: requests.Response) -> str:
    try:
        return str(response.json().get("detail", response.text))
    except ValueError:
        return response.text


# ------------------------------------------------------------------ sidebar

with st.sidebar:
    st.header("Assessments")
    if st.button("➕ New assessment", use_container_width=True):
        st.session_state.pop("scan_id", None)
        st.rerun()
    try:
        history = api("GET", "/api/scans").json()
    except requests.RequestException:
        history = []
        st.error("Backend is not reachable yet.")
    for item in history:
        label = f"{item['target_url']}\n\n{item['status']} · {item['created_at'][:16].replace('T', ' ')}"
        if st.button(label, key=item["id"], use_container_width=True):
            st.session_state["scan_id"] = item["id"]
            st.rerun()

st.title("🛡️ Agentic Security Assessment")
st.caption("Planner → Executor → Reporter agents (Langflow) driving nmap, OWASP ZAP, Nuclei and Nikto. "
           "Detection and reporting only.")


# ------------------------------------------------------------- new assessment

def new_assessment_form() -> None:
    config = api("GET", "/api/config").json()
    demos = {demo["name"]: demo for demo in config["demo_targets"]}

    st.subheader("1. Target")
    choice = st.selectbox("Target", [*demos, "Custom URL"])
    if choice == "Custom URL":
        target_url = st.text_input("Target URL", placeholder="https://staging.example.com")
    else:
        target_url = demos[choice]["url"]
        st.caption(f"`{target_url}` — {demos[choice]['note']}")

    scope_notes = st.text_area(
        "Scope notes (the Planner agent treats these as binding)",
        placeholder="Examples: 'Full baseline including web server checks.'  "
                    "'Web checks only, no port scanning.'  'Quick passive check.'",
    )
    with st.expander("Optional test credentials (HTTP Basic auth only)"):
        st.caption("Held in memory for the length of the run. Never stored, logged or sent to the LLM.")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

    st.subheader("2. Authorization")
    st.warning("Scanning systems without permission is illegal in most countries. "
               "Only assess targets you own or are authorized in writing to test.")
    authorized_by = st.text_input("Your name (recorded with the authorization)")
    confirmed = st.checkbox(config["authorization_statement"])

    if st.button("▶ Run assessment", type="primary", disabled=not (confirmed and target_url)):
        created = api("POST", "/api/scans", json={
            "target_url": target_url, "scope_notes": scope_notes,
            "test_username": username, "test_password": password})
        if created.status_code != 201:
            st.error(error_text(created))
            return
        scan_id = created.json()["id"]
        # The backend enforces the same gate: /start is refused unless /authorize succeeded.
        for step, body in (("authorize", {"confirmed": confirmed, "authorized_by": authorized_by}), ("start", None)):
            response = api("POST", f"/api/scans/{scan_id}/{step}", json=body)
            if response.status_code >= 400:
                st.error(error_text(response))
                return
        st.session_state["scan_id"] = scan_id
        st.rerun()
    if not confirmed:
        st.caption("Tick the authorization box to enable the run button. No tick, no scan.")


# -------------------------------------------------------------- live status

@st.fragment(run_every=3)
def live_status(scan_id: str) -> None:
    scan = api("GET", f"/api/scans/{scan_id}").json()
    if scan["status"] in ("completed", "failed"):
        st.rerun()  # full rerun switches the page to the report / error view
    st.info(f"Status: **{scan['status']}** — the page updates every few seconds. "
            "A full run takes roughly 5 to 10 minutes.")
    show_events(scan["events"])


def show_events(events: list[dict]) -> None:
    for event in events:
        icon = AGENT_ICONS.get(event["agent"], "•")
        st.markdown(f"`{event['at'][11:19]}` {icon} **{event['agent']}** — {event['message']}")


# -------------------------------------------------------------------- report

def show_report(scan: dict) -> None:
    scan_id = scan["id"]
    report = api("GET", f"/api/scans/{scan_id}/report").json()

    st.success(f"Assessment of **{scan['target_url']}** completed.")
    st.caption(f"Authorization confirmed by {scan['authorized_by']} at {scan['authorized_at']} · Scan `{scan_id}`")

    columns = st.columns(len(SEVERITIES))
    for column, level in zip(columns, SEVERITIES):
        column.metric(f"{SEVERITY_ICONS[level]} {level}", report["severity_counts"].get(level, 0))

    downloads = st.columns(3)
    downloads[0].download_button("⬇ PDF report", api("GET", f"/api/scans/{scan_id}/report.pdf").content,
                                 file_name=f"assessment-{scan_id[:8]}.pdf", mime="application/pdf")
    downloads[1].download_button("⬇ Markdown", api("GET", f"/api/scans/{scan_id}/report.md").text,
                                 file_name=f"assessment-{scan_id[:8]}.md")
    downloads[2].download_button("⬇ JSON", api("GET", f"/api/scans/{scan_id}/report").text,
                                 file_name=f"assessment-{scan_id[:8]}.json")

    st.subheader("Executive summary")
    st.write(report["executive_summary"] or f"_No AI summary ({report['summary_source']})._")
    if report["summary_source"] == "llm":
        st.caption(f"Written by the Reporter agent ({report['reporter_model']}) from the findings below.")

    st.subheader("Plan and tool runs")
    for step in report["plan"]["steps"]:
        st.markdown(f"- **{step['tool']}** — {step['reason']}")
    st.caption(f"Planner: {report['plan']['model']} · Executor driven by: {report['execution']['driver']}")
    st.dataframe(
        [{"Tool": run["tool"], "Status": run["status"], "Seconds": run["duration_seconds"],
          "Findings": run["finding_count"], "Command": run["command"]} for run in report["tool_runs"]],
        use_container_width=True, hide_index=True)

    st.subheader(f"Findings ({len(report['findings'])})")
    shown = st.multiselect("Severity", SEVERITIES, default=SEVERITIES)
    for finding in report["findings"]:
        if finding["severity"] not in shown:
            continue
        score = f" · CVSS {finding['cvss_score']}" if finding.get("cvss_score") else ""
        header = f"{SEVERITY_ICONS[finding['severity']]} {finding['severity']} · {finding['title']} · {finding['tool']}"
        with st.expander(header):
            st.caption(f"`{finding['id']}`{score} · {finding['severity_basis']}"
                       + (f" · {finding['cwe']}" if finding.get("cwe") else ""))
            if finding.get("url"):
                st.markdown(f"**Where:** `{finding['url']}` ({finding['instances']} instance(s))")
            if finding.get("description"):
                st.write(finding["description"])
            if finding.get("evidence"):
                st.markdown(f"**Evidence (from {finding['tool']}):**")
                st.code(finding["evidence"], language=None)
            if finding.get("remediation"):
                st.markdown(f"**Remediation (from {finding['tool']}):** {finding['remediation']}")
            if finding.get("ai_remediation"):
                st.markdown(f"**Remediation guidance (AI-written):** {finding['ai_remediation']}")
            if finding.get("raw_file"):
                st.caption(f"Raw scanner output: `GET /api/scans/{scan_id}/raw/{finding['raw_file']}`")

    with st.expander("Run log"):
        show_events(scan["events"])


# ---------------------------------------------------------------------- page

scan_id = st.session_state.get("scan_id")
if not scan_id:
    new_assessment_form()
else:
    scan = api("GET", f"/api/scans/{scan_id}").json()
    if scan["status"] == "completed":
        show_report(scan)
    elif scan["status"] == "failed":
        st.error(f"Assessment of {scan['target_url']} failed: {scan['error']}")
        show_events(scan["events"])
    else:
        st.subheader(f"Assessing {scan['target_url']}")
        live_status(scan_id)
