/* Page 2: one check while it is in progress.

   A check moves through these states, and this page shows each of them:

     planning           the Planner is choosing tools
     awaiting_approval  the plan is ready and waits for you (tick boxes, Approve, Cancel)
     running            the Executor runs the tools (Stop button), then the Reporter writes
     completed          the report is shown instead (see report.js)
     failed, cancelled  what happened, and how to start again
*/

import { api } from "../api.js";
import { AGENTS, TOOLS, app, elapsed, esc, logHtml, setActiveNav, showError, state } from "../ui.js";
import { renderReport } from "./report.js";

const IN_PROGRESS = ["authorized", "planning", "running"];
const REFRESH_EVERY_MS = 2500;

export async function viewCheck(scanId) {
  setActiveNav("");
  const scan = await api(`/api/scans/${scanId}`);
  if (location.hash !== `#/scan/${scanId}`) return;  // the user moved on while we were loading

  if (scan.status === "completed") {
    state.reports[scanId] ??= await api(`/api/scans/${scanId}/report`);
    state.comparisons[scanId] ??= await api(`/api/scans/${scanId}/compare`);
    renderReport(scan, state.reports[scanId], state.comparisons[scanId]);
    return;
  }

  // The tick boxes of the plan review need the list of tools that exist.
  const catalog = scan.status === "awaiting_approval" ? await api("/api/tools") : [];
  renderProgress(scan, catalog);

  // Refresh while the agents work. Not while the plan waits for you: that would reset your ticks.
  if (IN_PROGRESS.includes(scan.status)) {
    state.timer = setTimeout(() => viewCheck(scanId).catch(showError), REFRESH_EVERY_MS);
  }
}

/** Work out where the run is from the list of events the system and the agents posted. */
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

function renderProgress(scan, catalog) {
  const { stage, tools, steps } = progressOf(scan);
  const stateLabel = { waiting: "waiting", working: '<span class="spinner"></span>working', done: "✓ done", failed: "✗ stopped" };

  app.innerHTML = `
    ${headingHtml(scan)}

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

    ${scan.status === "awaiting_approval" ? reviewHtml(scan, catalog) : `
      <div class="card">
        <div class="card-head">
          <h2>Tools in this check</h2>
          ${stopButtonHtml(scan, stage)}
        </div>
        ${toolRowsHtml(steps, tools)}
      </div>`}

    <div class="card">
      <h2>Activity log</h2>
      ${logHtml(scan.events)}
    </div>`;

  document.getElementById("approve")?.addEventListener("click", () => approvePlan(scan.id));
  document.getElementById("cancel")?.addEventListener("click", () => stopCheck(scan.id));
  document.getElementById("stop")?.addEventListener("click", () => stopCheck(scan.id));
}

/** The title and the message at the top. They depend on the state of the check. */
function headingHtml(scan) {
  const target = `<code>${esc(scan.target_url)}</code>`;
  if (scan.status === "failed") {
    return `<section class="intro"><h1>The check stopped</h1><p>Something went wrong with ${target}. Details are below.</p></section>
      <div class="notice notice-bad"><b>What happened:</b> ${esc(scan.error)}</div>
      <div class="notice notice-info">Common causes: the LLM key in <code>.env</code> is missing or wrong, the free
        tier hit its rate limit, or a container is still starting. Fix it, then <a href="#/">start a new check</a>.</div>`;
  }
  if (scan.status === "cancelled") {
    return `<section class="intro"><h1>Check cancelled</h1><p>You cancelled the check of ${target} at the plan review.
      Nothing was scanned. <a href="#/">Start a new check</a>.</p></section>`;
  }
  if (scan.status === "awaiting_approval") {
    return `<section class="intro"><h1>Review the plan for ${target}</h1>
      <p>The Planner has made its suggestion. Nothing has been scanned yet, and nothing will be until you approve.</p></section>`;
  }
  return `<section class="intro"><h1>Checking ${target}</h1>
    <p>Running for ${esc(elapsed(scan.started_at || scan.created_at))}. This page updates by itself.</p></section>`;
}

/** The plan review: every tool that exists as a tick box, ticked where the Planner suggested it. */
function reviewHtml(scan, catalog) {
  const plan = scan.proposed_plan || { steps: [] };
  const suggested = Object.fromEntries(plan.steps.map((step) => [step.tool, step.reason]));
  return `
    <div class="card review">
      <h2>The Planner's plan</h2>
      <p class="muted">Ticked tools will run, in this order. Untick a tool to leave it out, or tick one the Planner
         left out. Your changes are saved with the report.</p>
      ${scan.scope_notes ? `<p class="small"><b>Your notes:</b> ${esc(scan.scope_notes)}</p>` : ""}
      ${catalog.map((tool) => `
        <label class="tool-row pick">
          <span class="name"><input type="checkbox" name="plan-tool" value="${esc(tool.name)}"
                 ${tool.name in suggested ? "checked" : ""}> ${esc(tool.name)}</span>
          <span><span>${esc(TOOLS[tool.name]?.plain || tool.description)}</span><br>
                <span class="muted small">${tool.name in suggested
                  ? `Why the Planner chose it: ${esc(suggested[tool.name])}`
                  : "The Planner left this one out."}</span></span>
          <span class="muted small">${esc(tool.typical_duration)}</span>
        </label>`).join("")}
      ${plan.notes ? `<p class="muted small" style="margin-top:10px">Planner's note: ${esc(plan.notes)}</p>` : ""}
      <div class="start-row" style="margin-top:16px">
        <button type="button" class="primary" id="approve">Approve and start scanning</button>
        <button type="button" id="cancel">Cancel this check</button>
        <span class="muted small">Planned by ${esc(plan.model || "the Planner")}.</span>
      </div>
      <div id="review-error"></div>
    </div>`;
}

/** One row per planned tool: what it does, why it was chosen, and how it is going. */
function toolRowsHtml(steps, tools) {
  if (steps === null) return `<p class="muted">The Planner is still deciding which tools to run.</p>`;
  if (!steps.length) return `<p class="muted">The Planner chose no tools: the scope notes rule them all out.</p>`;
  return steps.map((step) => {
    const run = tools[step.tool];
    const result = !run ? `<span class="state waiting">waiting</span>`
      : run.status === "running" ? `<span class="state working"><span class="spinner"></span>running, ${esc(TOOLS[step.tool]?.time || "a moment")}</span>`
      : run.status === "error" ? `<span class="state failed">✗ error</span>`
      : run.status === "skipped" ? `<span class="state failed">not run</span>`
      : `<span class="state done">✓ ${esc(run.findings)} finding(s) in ${esc(run.seconds)} s${run.status === "timeout" ? " (time limit)" : ""}</span>`;
    return `<div class="tool-row">
        <span class="name">${esc(step.tool)}</span>
        <span><span>${esc(TOOLS[step.tool]?.plain || "")}</span><br>
              <span class="muted small">Why it is in the plan: ${esc(step.reason)}</span></span>
        ${result}
      </div>`;
  }).join("");
}

/** Stop is offered while the scanners run. Once the Reporter is writing there is nothing left to stop. */
function stopButtonHtml(scan, stage) {
  if (scan.status !== "running" || stage.reporter !== "waiting") return "";
  if (scan.stop_requested) return `<span class="state failed">stopping after the current tool</span>`;
  return `<button type="button" id="stop" title="The tool that is running finishes. No further tool starts. You still get a report of what ran.">Stop after the current tool</button>`;
}

async function approvePlan(scanId) {
  const chosen = [...document.querySelectorAll('input[name="plan-tool"]:checked')].map((box) => box.value);
  try {
    await api(`/api/scans/${scanId}/approve`, { method: "POST", body: { tools: chosen } });
    await viewCheck(scanId);
  } catch (error) {
    document.getElementById("review-error").innerHTML = `<div class="notice notice-bad" style="margin-top:12px">${esc(error.message)}</div>`;
  }
}

async function stopCheck(scanId) {
  clearTimeout(state.timer);
  try {
    await api(`/api/scans/${scanId}/stop`, { method: "POST" });
  } catch { /* the check moved on by itself; the refresh below shows where it is */ }
  await viewCheck(scanId).catch(showError);
}
