"use strict";
/* The whole web page: plain JavaScript, no framework, no build step.
   Every piece of text that comes from the server is passed through esc() before it
   goes into the page, because finding titles and evidence come from scanned websites. */

const app = document.getElementById("app");
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

const AGENTS = [
  { id: "planner", name: "Planner", icon: "🧭", does: "Reads your target and notes, then picks which tools to run." },
  { id: "executor", name: "Executor", icon: "🛠️", does: "Runs each chosen tool, one after another, and collects the results." },
  { id: "reporter", name: "Reporter", icon: "📝", does: "Rates every finding and writes the report with fix advice." },
];

const TOOLS = {
  nmap: { plain: "Knocks on the server's network doors (ports) to see which ones are open.", time: "about 15 seconds" },
  zap: { plain: "Browses the site like a visitor and notes risky settings in what the site sends back.", time: "about 1 minute" },
  nuclei: { plain: "Runs a library of known checks for exposed files, admin pages and bad settings.", time: "about 2 minutes" },
  nikto: { plain: "Checks the web server for leftover files and old, unsafe configuration.", time: "about 2.5 minutes" },
};

const CHECK_LABELS = {
  plan_followed: "Followed the plan",
  stayed_in_scope: "Stayed inside the approved plan",
  tools_completed: "Tools finished without errors",
  target_stayed_up: "Target stayed up during the scans",
  findings_traceable: "Findings match the raw scanner output",
  ai_text_grounded: "AI text sticks to the findings",
  fix_advice_coverage: "Fix advice for the important findings",
};

const PRESETS = [
  ["Full check", "Full baseline check, including web server checks."],
  ["Web only, no port scan", "Web application checks only. Do not port scan."],
  ["Quick check", "Quick check. Keep it short and skip slow or noisy scanners."],
];

const state = { config: null, status: null, filters: new Set(SEVERITIES), reports: {}, timer: null };

// ------------------------------------------------------------------ helpers

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    method: options.method || "GET",
    headers: { "Content-Type": "application/json" },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (!response.ok) {
    let detail = response.statusText;
    try { detail = (await response.json()).detail || detail; } catch { /* not JSON */ }
    throw new Error(typeof detail === "string" ? detail : "Please check the values you entered.");
  }
  return response.json();
}

function when(iso) {
  return iso ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "";
}

function elapsed(fromIso, toIso) {
  const seconds = Math.max(0, Math.round(((toIso ? new Date(toIso) : new Date()) - new Date(fromIso)) / 1000));
  return `${Math.floor(seconds / 60)} min ${String(seconds % 60).padStart(2, "0")} s`;
}

function setActiveNav(name) {
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.nav === name));
}

// ------------------------------------------------------------- stack status

async function refreshStatus() {
  const pill = document.getElementById("status");
  try {
    state.status = await api("/api/status");
    const { ready, services, llm } = state.status;
    const down = Object.entries(services).filter(([, up]) => !up).map(([name]) => name);
    if (ready) {
      pill.className = "pill pill-ok";
      pill.textContent = `Ready · ${llm.model}`;
      pill.title = "All parts are running.";
    } else if (!llm.key_set) {
      pill.className = "pill pill-bad";
      pill.textContent = "No LLM key set";
      pill.title = "Put your key in LLM_API_KEY in the .env file, then run: docker compose up -d";
    } else {
      pill.className = "pill pill-wait";
      pill.textContent = `Starting: ${down.join(", ")}`;
      pill.title = "The containers are still starting. This can take a minute or two.";
    }
  } catch {
    pill.className = "pill pill-bad";
    pill.textContent = "Backend not reachable";
  }
  const start = document.getElementById("start");
  if (start) updateStartButton();
  setTimeout(refreshStatus, state.status?.ready ? 30000 : 4000);
}

// ---------------------------------------------------------------- new check

function viewNew() {
  setActiveNav("new");
  const demos = state.config.demo_targets;
  app.innerHTML = `
    <section class="intro">
      <h1>Check a website for common security problems</h1>
      <p>Three AI agents plan the check, run well-known open-source scanners and write you a report.
         It only looks for problems: no attack is launched and nothing is exploited.</p>
    </section>

    <div class="flow-strip">
      <div><b>1. You choose</b><span>a website and confirm you may test it</span></div>
      <div><b>2. Planner</b><span>picks the right tools for your request</span></div>
      <div><b>3. Executor</b><span>runs the tools and gathers results</span></div>
      <div><b>4. Reporter</b><span>explains what was found and how to fix it</span></div>
    </div>

    <form id="new-form">
      <div class="card">
        <div class="step-title"><span class="step-number">1</span><h2 style="margin:0">What should we check?</h2></div>
        <div class="options">
          ${demos.map((demo, i) => `
            <label class="option">
              <input type="radio" name="target" value="${esc(demo.url)}" ${i === 0 ? "checked" : ""}>
              <span class="name">${esc(demo.name)}</span> <span class="tag">${esc(demo.badge)}</span>
              <p class="note">${esc(demo.note)}</p>
              <p class="note"><code>${esc(demo.url)}</code></p>
            </label>`).join("")}
          <label class="option">
            <input type="radio" name="target" value="custom">
            <span class="name">Another website</span> <span class="tag">your own</span>
            <p class="note">A site you own or have written permission to test.</p>
            <input type="url" id="custom-url" placeholder="https://staging.example.com" aria-label="Website address">
          </label>
        </div>

        <label class="field" for="scope">Anything the agents should know? <span class="muted small">(optional)</span></label>
        <textarea id="scope" placeholder="Plain words are fine. The Planner follows these notes when it picks the tools."></textarea>
        <div class="chips">
          ${PRESETS.map(([label, text]) => `<button type="button" class="chip" data-action="preset" data-text="${esc(text)}">${esc(label)}</button>`).join("")}
        </div>

        <details style="margin-top:14px">
          <summary class="small muted">Optional: test login (HTTP Basic only)</summary>
          <p class="small muted" style="margin-top:8px">Kept in memory only while the check runs. Never stored, logged or sent to the AI model.</p>
          <div class="grid-2">
            <input type="text" id="username" placeholder="Username" autocomplete="off">
            <input type="password" id="password" placeholder="Password" autocomplete="off">
          </div>
        </details>
      </div>

      <div class="card">
        <div class="step-title"><span class="step-number">2</span><h2 style="margin:0">Do you have permission?</h2></div>
        <div class="notice notice-warn">Scanning a website without permission is illegal in most countries.
          Only check sites you own or are allowed in writing to test.</div>
        <label class="field" for="who">Your name <span class="muted small">(saved with this check as the person who confirmed)</span></label>
        <input type="text" id="who" placeholder="e.g. Priya Sharma" autocomplete="name">
        <label class="check">
          <input type="checkbox" id="confirm">
          <span>${esc(state.config.authorization_statement)}</span>
        </label>
      </div>

      <div class="card start-row">
        <span class="step-number">3</span>
        <button type="submit" class="primary" id="start" disabled>Start the check</button>
        <span class="muted small" id="start-hint"></span>
      </div>
      <div id="form-error"></div>
    </form>`;

  document.getElementById("confirm").addEventListener("change", updateStartButton);
  document.getElementById("new-form").addEventListener("submit", startCheck);
  document.getElementById("custom-url").addEventListener("focus", () => {
    document.querySelector('input[name="target"][value="custom"]').checked = true;
  });
  updateStartButton();
}

function updateStartButton() {
  const start = document.getElementById("start");
  const hint = document.getElementById("start-hint");
  if (!start) return;
  const ticked = document.getElementById("confirm").checked;
  const ready = Boolean(state.status?.ready);
  start.disabled = !(ticked && ready);
  hint.textContent = !ticked ? "Tick the permission box first. No tick, no scan."
    : !ready ? "Waiting for all parts to start (see the status at the top right)."
    : "The standard check of the demo shop takes about 5 minutes, a full check about 8.";
}

async function startCheck(event) {
  event.preventDefault();
  const errorBox = document.getElementById("form-error");
  const start = document.getElementById("start");
  errorBox.innerHTML = "";
  const choice = document.querySelector('input[name="target"]:checked').value;
  const target = choice === "custom" ? document.getElementById("custom-url").value : choice;
  start.disabled = true;
  try {
    const scan = await api("/api/scans", { method: "POST", body: {
      target_url: target,
      scope_notes: document.getElementById("scope").value,
      test_username: document.getElementById("username").value,
      test_password: document.getElementById("password").value,
    } });
    // Two separate calls on purpose: the server refuses to start a check that was not authorized.
    await api(`/api/scans/${scan.id}/authorize`, { method: "POST", body: {
      confirmed: document.getElementById("confirm").checked,
      authorized_by: document.getElementById("who").value,
    } });
    await api(`/api/scans/${scan.id}/start`, { method: "POST" });
    location.hash = `#/scan/${scan.id}`;
  } catch (error) {
    errorBox.innerHTML = `<div class="notice notice-bad">${esc(error.message)}</div>`;
    updateStartButton();
  }
}

// ------------------------------------------------------- running and report

async function viewScan(scanId) {
  setActiveNav("");
  let scan;
  try {
    scan = await api(`/api/scans/${scanId}`);
  } catch (error) {
    app.innerHTML = `<div class="notice notice-bad">${esc(error.message)}</div>`;
    return;
  }
  if (location.hash !== `#/scan/${scanId}`) return; // the user moved on while we were loading

  if (scan.status === "completed") {
    state.reports[scanId] ??= await api(`/api/scans/${scanId}/report`);
    renderReport(scan, state.reports[scanId]);
  } else {
    renderProgress(scan);
    if (scan.status === "running" || scan.status === "authorized") {
      state.timer = setTimeout(() => viewScan(scanId), 2500);
    }
  }
}

/** Work out where the run is from the event list the agents posted. */
function progressOf(scan) {
  const stage = { planner: "waiting", executor: "waiting", reporter: "waiting" };
  const tools = {};
  let steps = null;
  for (const event of scan.events) {
    const data = event.data || {};
    if (data.type === "agent_start") {
      stage[event.agent] = "working";
      if (event.agent === "executor") stage.planner = "done";
      if (event.agent === "reporter") { stage.planner = "done"; stage.executor = "done"; }
    }
    if (data.type === "plan") { steps = data.steps; stage.planner = "done"; }
    if (data.type === "tool_start") tools[data.tool] = { status: "running" };
    if (data.type === "tool_done") tools[data.tool] = data;
    if (data.type === "tools_skipped") data.tools.forEach((tool) => { tools[tool] = { status: "skipped" }; });
    if (data.type === "agent_done") stage[event.agent] = "done";
  }
  if (scan.status === "failed") {
    for (const agent of Object.keys(stage)) if (stage[agent] === "working") stage[agent] = "failed";
    if (Object.values(stage).every((s) => s === "waiting")) stage.planner = "failed";
  }
  return { stage, tools, steps };
}

function renderProgress(scan) {
  const { stage, tools, steps } = progressOf(scan);
  const failed = scan.status === "failed";
  const stateLabel = { waiting: "waiting", working: '<span class="spinner"></span>working', done: "✓ done", failed: "✗ stopped" };

  const toolRows = steps === null
    ? `<p class="muted">The Planner is still deciding which tools to run.</p>`
    : steps.length === 0
      ? `<p class="muted">The Planner chose no tools: the scope notes rule them all out.</p>`
      : steps.map((step) => {
          const run = tools[step.tool];
          const result = !run ? `<span class="state waiting">waiting</span>`
            : run.status === "running" ? `<span class="state working"><span class="spinner"></span>running, ${esc(TOOLS[step.tool]?.time || "a moment")}</span>`
            : run.status === "error" ? `<span class="state failed">✗ error</span>`
            : run.status === "skipped" ? `<span class="state failed">not run</span>`
            : `<span class="state done">✓ ${esc(run.findings)} finding(s) in ${esc(run.seconds)} s${run.status === "timeout" ? " (time limit)" : ""}</span>`;
          return `<div class="tool-row">
              <span class="name">${esc(step.tool)}</span>
              <span><span>${esc(TOOLS[step.tool]?.plain || "")}</span><br>
                    <span class="muted small">Why the Planner chose it: ${esc(step.reason)}</span></span>
              ${result}
            </div>`;
        }).join("");

  app.innerHTML = `
    <section class="intro">
      <h1>${failed ? "The check stopped" : "Checking"} <code>${esc(scan.target_url)}</code></h1>
      <p>${failed ? "Something went wrong. Details are below."
          : `Running for ${esc(elapsed(scan.started_at || scan.created_at))}. This page updates by itself.`}</p>
    </section>

    ${failed ? `<div class="notice notice-bad"><b>What happened:</b> ${esc(scan.error)}</div>
      <div class="notice notice-info">Common causes: the LLM key in <code>.env</code> is missing or wrong, the free
        tier hit its rate limit, or a container is still starting. Fix it, then <a href="#/">start a new check</a>.</div>` : ""}

    <div class="card">
      <h2>The three agents</h2>
      <div class="pipeline">
        ${AGENTS.map((agent, i) => `
          ${i ? '<span class="arrow">→</span>' : ""}
          <div class="agent ${stage[agent.id]}">
            <div class="head"><span class="icon">${agent.icon}</span>${agent.name}
              <span class="state ${stage[agent.id]}">${stateLabel[stage[agent.id]]}</span></div>
            <p>${agent.does}</p>
          </div>`).join("")}
      </div>
    </div>

    <div class="card">
      <h2>Tools in this check</h2>
      ${toolRows}
    </div>

    <div class="card">
      <h2>Activity log</h2>
      ${logHtml(scan.events)}
    </div>`;
}

function logHtml(events) {
  return `<div class="log">${events.map((event) => `
    <div><span class="muted mono">${esc(new Date(event.at).toLocaleTimeString([], { hour12: false }))}</span>
         <span class="who">${esc(event.agent)}</span>
         <span class="what">${esc(event.message)}</span></div>`).join("")}</div>`;
}

function renderReport(scan, report) {
  const counts = report.severity_counts;
  const total = report.findings.length;
  const byTool = report.tool_runs.map((run) => [run.tool, run.finding_count]);
  const maxTool = Math.max(1, ...byTool.map(([, n]) => n));

  app.innerHTML = `
    <div class="report-head">
      <div>
        <h1>Report for <code>${esc(scan.target_url)}</code></h1>
        <p class="muted">${esc(when(report.generated_at))} · took ${esc(elapsed(scan.started_at, scan.finished_at))} ·
           permission confirmed by ${esc(scan.authorized_by)}</p>
      </div>
      <div class="actions">
        <a class="button" href="/api/scans/${esc(scan.id)}/report.md" download="assessment-${esc(scan.id.slice(0, 8))}.md">Markdown</a>
        <a class="button" href="/api/scans/${esc(scan.id)}/report.pdf">PDF</a>
        <a class="button" href="/api/scans/${esc(scan.id)}/report" download="assessment-${esc(scan.id.slice(0, 8))}.json">JSON</a>
      </div>
    </div>

    <div class="notice notice-info">These are scanner results, not confirmed break-ins. Nothing was exploited.
      Treat each finding as something to check and fix.</div>

    <div class="card">
      <h2>${total} finding${total === 1 ? "" : "s"}</h2>
      <div class="tiles">
        ${SEVERITIES.map((level) => `
          <div class="tile sev-${level}"><div class="n">${counts[level] || 0}</div><div class="l">${level}</div></div>`).join("")}
      </div>
      ${total ? `<div class="stack" role="img" aria-label="Share of findings by severity">
        ${SEVERITIES.filter((level) => counts[level]).map((level) =>
          `<span class="sev-${level}" style="flex:${counts[level]}" title="${level}: ${counts[level]}"></span>`).join("")}
      </div>` : ""}
    </div>

    <div class="grid-2 spaced">
      <div class="card">
        <h2>Summary</h2>
        <p>${esc(report.executive_summary) || `<span class="muted">No AI summary (${esc(report.summary_source)}).</span>`}</p>
        ${report.summary_source === "llm" ? `<p class="muted small">Written by the Reporter agent (${esc(report.reporter_model)}) from the findings below.</p>` : ""}
      </div>
      <div class="card">
        <h2>Fix these first</h2>
        ${report.fix_first?.length ? `<ol class="fix">${report.fix_first.map((item) => `
            <li>${esc(item.action)}
              <span class="ids">${item.finding_ids.map((id) => `<code>${esc(id)}</code>`).join(" ")}</span></li>`).join("")}</ol>`
          : `<p class="muted">No prioritised list for this run.</p>`}
      </div>
    </div>

    <div class="card">
      <h2>What ran</h2>
      <div class="table-wrap"><table>
        <tr><th>Tool</th><th>In plain words</th><th>Why the Planner chose it</th><th>Result</th><th class="num">Time</th><th class="num">Findings</th></tr>
        ${report.tool_runs.map((run) => {
          const step = report.plan.steps.find((s) => s.tool === run.tool) || {};
          return `<tr><td><b>${esc(run.tool)}</b></td><td>${esc(TOOLS[run.tool]?.plain || run.what_it_checks)}</td>
            <td>${esc(step.reason)}</td>
            <td>${run.status === "ok" ? "✓ finished" : run.status === "timeout" ? "stopped at time limit" : "✗ error"}</td>
            <td class="num">${esc(run.duration_seconds)} s</td><td class="num">${esc(run.finding_count)}</td></tr>`;
        }).join("")}
      </table></div>
      ${runNotes(report).map((note) => `<div class="notice notice-warn" style="margin-top:10px">${esc(note)}</div>`).join("")}
      <p class="muted small" style="margin-top:10px">Planner: ${esc(report.plan.model)} · Executor: ${esc(report.execution.driver)}
        ${report.plan.notes ? ` · Planner's note: ${esc(report.plan.notes)}` : ""}</p>
      <div class="bars" style="margin-top:14px">
        ${byTool.map(([tool, n]) => `<div class="bar-row"><b>${esc(tool)}</b>
          <div class="track"><div class="fill" style="width:${(n / maxTool) * 100}%"></div></div><span class="num">${n}</span></div>`).join("")}
      </div>
    </div>

    <div class="card">
      <h2>Findings</h2>
      <div class="chips" style="margin:0 0 14px">
        ${SEVERITIES.map((level) => `<button type="button" class="chip ${state.filters.has(level) ? "on" : ""}"
            data-action="filter" data-level="${level}">${level} (${counts[level] || 0})</button>`).join("")}
      </div>
      <div id="findings">${findingsHtml(scan, report)}</div>
    </div>

    <div class="grid-2 spaced">
      <div class="card">
        <h2>What was not tested</h2>
        <ul class="plain">${(report.not_tested || []).map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
      </div>
      <div class="card checks">
        <h2>Quality checks on this report</h2>
        <p class="muted small">Run by code after the agents finish. A full bar is a full pass.</p>
        ${(report.quality_checks || []).map((check) => `
          <div class="check-row">
            <b>${esc(CHECK_LABELS[check.name] || check.name)}</b>
            <div class="meter" title="${esc(check.score)}"><span class="${check.score < 1 ? "low" : ""}" style="width:${check.score * 100}%"></span></div>
            <span class="muted small">${esc(check.detail)}</span>
          </div>`).join("")}
        ${report.trace_url ? `<p style="margin-top:12px"><a href="${esc(report.trace_url)}" target="_blank" rel="noopener">Open this run's trace in Langfuse →</a></p>` : ""}
      </div>
    </div>

    <details class="card">
      <summary><b>Activity log</b></summary>
      <div style="margin-top:12px">${logHtml(scan.events)}</div>
    </details>`;
}

/** Anything that did not go to plan: time limits, a target that went down, skipped tools. */
function runNotes(report) {
  const notes = report.tool_runs
    .filter((run) => run.note && (run.status !== "ok" || run.target_down))
    .map((run) => `${run.tool}: ${run.note}`);
  if (report.execution.skipped?.length) {
    notes.push(`Planned but not run: ${report.execution.skipped.join(", ")}. `
      + `The Executor's reason: ${report.execution.stop_reason || "no reason given"}`);
  }
  return notes;
}

function findingsHtml(scan, report) {
  const shown = report.findings.filter((finding) => state.filters.has(finding.severity));
  if (!shown.length) return `<p class="muted">No findings match the selected severities.</p>`;
  return shown.map((finding) => `
    <details class="finding sev-${finding.severity}">
      <summary>
        <span class="badge sev-${finding.severity}">${finding.severity}</span>
        <span class="title">${esc(finding.title)}</span>
        <span class="tag">${esc(finding.tool)}</span>
      </summary>
      <div class="body">
        <h4>Why this severity</h4>
        <p>${esc(finding.severity_basis)}${finding.cvss_score ? ` · CVSS ${esc(finding.cvss_score)}` : ""}${finding.cwe ? ` · ${esc(finding.cwe)}` : ""}</p>
        ${finding.url ? `<h4>Where</h4><p><code>${esc(finding.url)}</code> · seen ${esc(finding.instances)}×</p>` : ""}
        ${finding.description ? `<h4>What it means</h4><p>${esc(finding.description)}</p>` : ""}
        ${finding.evidence ? `<h4>Evidence from ${esc(finding.tool)}</h4><p><code>${esc(finding.evidence)}</code></p>` : ""}
        ${finding.remediation ? `<h4>How to fix (from ${esc(finding.tool)})</h4><p>${esc(finding.remediation)}</p>` : ""}
        ${finding.ai_remediation ? `<h4>How to fix (AI-written)</h4><p class="ai">${esc(finding.ai_remediation)}</p>` : ""}
        <h4>Trace it back</h4>
        <p class="small">Finding <code>${esc(finding.id)}</code>${finding.raw_file
          ? ` · <a href="/api/scans/${esc(scan.id)}/raw/${esc(finding.raw_file)}" target="_blank" rel="noopener">raw ${esc(finding.tool)} output</a>` : ""}</p>
      </div>
    </details>`).join("");
}

// ------------------------------------------------------------------ history

async function viewHistory() {
  setActiveNav("history");
  const scans = await api("/api/scans");
  const label = { completed: "pill-ok", failed: "pill-bad" };
  app.innerHTML = `
    <section class="intro"><h1>Past checks</h1><p>Every check keeps its report and its permission record.</p></section>
    <div class="card">
      ${scans.length ? `<div class="table-wrap"><table>
        <tr><th>Target</th><th>Started</th><th>Status</th><th></th></tr>
        ${scans.map((scan) => `<tr>
          <td><code>${esc(scan.target_url)}</code></td><td>${esc(when(scan.created_at))}</td>
          <td><span class="pill ${label[scan.status] || "pill-wait"}">${esc(scan.status)}</span></td>
          <td><a href="#/scan/${esc(scan.id)}">Open</a></td></tr>`).join("")}
      </table></div>` : `<p class="muted">Nothing yet. <a href="#/">Start your first check.</a></p>`}
    </div>`;
}

// ------------------------------------------------------------- how it works

function viewHow() {
  setActiveNav("how");
  app.innerHTML = `
    <section class="intro">
      <h1>How it works, in plain words</h1>
      <p>A security check is like a home inspection: someone walks around, tries the doors and windows, and
         writes down what looks unsafe. Here three AI agents do the organising and four scanner tools do the looking.</p>
    </section>

    <h2>Pen testing, and where this tool fits</h2>
    <div class="card">
      <p>A <b>penetration test</b> ("pen test") is a planned and permitted attempt to find the weak spots in a website
         before a criminal does. It is needed because every system has mistakes, and attackers scan the internet for
         them all day.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>Stage of a pen test</th><th>In plain words</th><th>Here</th></tr></thead>
        <tbody>
          <tr><td>1. Planning and scope</td><td>Agree what may be tested, and get permission</td><td><b>Yes</b>: the permission box and your notes</td></tr>
          <tr><td>2. Information gathering</td><td>Learn what is there: open ports, software in use</td><td><b>Yes</b>: nmap, ZAP, Nuclei</td></tr>
          <tr><td>3. Scanning for weaknesses</td><td>Compare it against known weaknesses and risky settings</td><td><b>Yes</b>: ZAP, Nuclei, Nikto</td></tr>
          <tr><td>4. Exploitation</td><td>Use a weakness to actually get in</td><td><b>No</b>, on purpose</td></tr>
          <tr><td>5. After getting in</td><td>See how far an attacker could go</td><td><b>No</b></td></tr>
          <tr><td>6. Reporting</td><td>Each finding, how serious it is, how to fix it</td><td><b>Yes</b>: the Reporter agent</td></tr>
        </tbody>
      </table></div>
      <p class="muted small">So this is the finding and reporting half of a pen test, often called a vulnerability
         assessment. Breaking in is left out because it can damage a system. A clean report does not mean "secure".</p>
    </div>

    <h2>The three agents</h2>
    <div class="explain spaced">
      ${AGENTS.map((agent) => `<div class="card"><div class="icon">${agent.icon}</div><h3>${agent.name}</h3><p>${agent.does}</p>
        <p class="muted small">${{
          planner: "Like the inspector reading your instructions. If you say \"no port scanning\", it leaves that tool out.",
          executor: "Like the person doing the walk-round. It can only use the tools on the plan and only on your target.",
          reporter: "Like the person writing the inspection report. It can explain findings but cannot add new ones.",
        }[agent.id]}</p></div>`).join("")}
    </div>

    <h2>The four scanner tools</h2>
    <div class="explain tools spaced">
      ${Object.entries(TOOLS).map(([name, tool]) => `<div class="card"><h3>${name}</h3><p>${tool.plain}</p>
        <p class="muted small">Takes ${tool.time} on the demo shop.</p></div>`).join("")}
    </div>

    <h2>Reading the report</h2>
    <div class="card">
      <ul class="plain">
        <li><b>Severity</b> says how serious a finding could be: Critical, High, Medium, Low, or Info (just good to know).</li>
        <li><b>Evidence</b> is the exact thing the scanner saw. You can open the scanner's raw output for every finding.</li>
        <li><b>How to fix</b> comes from the scanner where it has advice, and from the AI where marked "AI-written".</li>
        <li><b>Findings are leads, not proof.</b> Nothing is exploited, so some findings can be false alarms.</li>
        <li><b>Quality checks</b> are automatic tests on the report itself, for example that every finding really
            appears in the scanner's raw output.</li>
      </ul>
    </div>

    <h2>Guard rails: limits the AI cannot cross</h2>
    <div class="card">
      <ul class="plain">
        <li><b>No tick, no scan.</b> The page, the server and the scanners each check for your saved permission.</li>
        <li><b>The target is fixed.</b> The scanners read it from your saved check. Nothing the AI writes can change it.</li>
        <li><b>Only planned tools run.</b> The Planner can pick only tools that exist. The Executor can call only the
            planned ones, once each, and cannot skip one silently.</li>
        <li><b>The AI cannot invent a finding.</b> Code copies findings from the scanners and sets the severity.
            The AI only adds the summary and fix advice.</li>
        <li><b>Looking only.</b> No attack input, no forms submitted, and the tools are slowed down so the site stays up.</li>
        <li><b>Text from the scanned site is treated as data,</b> never as instructions to the AI.</li>
      </ul>
    </div>

    <h2>Why you must confirm permission</h2>
    <div class="card"><p>Scanning a website you do not own, without written permission, is illegal in most countries.
      The check will not start until you tick the box, and your confirmation is saved with the report.
      The scanners double-check this themselves before every tool run.</p></div>`;
}

// ------------------------------------------------------------------- router

async function route() {
  clearTimeout(state.timer);
  const hash = location.hash || "#/";
  const scan = hash.match(/^#\/scan\/([0-9a-f]{32})$/);
  try {
    if (scan) await viewScan(scan[1]);
    else if (hash === "#/history") await viewHistory();
    else if (hash === "#/how") viewHow();
    else viewNew();
  } catch (error) {
    app.innerHTML = `<div class="notice notice-bad">${esc(error.message)}</div>`;
  }
  window.scrollTo(0, 0);
}

app.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  if (!target) return;
  if (target.dataset.action === "preset") {
    document.getElementById("scope").value = target.dataset.text;
  }
  if (target.dataset.action === "filter") {
    const level = target.dataset.level;
    state.filters.has(level) ? state.filters.delete(level) : state.filters.add(level);
    target.classList.toggle("on");
    const scanId = location.hash.split("/")[2];
    document.getElementById("findings").innerHTML = findingsHtml({ id: scanId }, state.reports[scanId]);
  }
});

(async function start() {
  try {
    state.config = await api("/api/config");
  } catch {
    app.innerHTML = `<div class="notice notice-bad">The backend is not reachable. Is the stack running?</div>`;
    return;
  }
  refreshStatus();
  window.addEventListener("hashchange", route);
  route();
})();
