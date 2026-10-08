/* Page 3: the finished report.

   Top to bottom: downloads, severity counts, what changed since the last check, summary,
   what ran, the findings, what was not tested, quality checks, activity log. */

import { CHECK_LABELS, SEVERITIES, TOOLS, app, elapsed, esc, logHtml, state, when } from "../ui.js";

export function renderReport(scan, report, comparison) {
  const counts = report.severity_counts;
  const total = report.findings.length;
  const byTool = report.tool_runs.map((run) => [run.tool, run.finding_count]);
  const maxTool = Math.max(1, ...byTool.map(([, n]) => n));
  const file = `assessment-${scan.id.slice(0, 8)}`;

  app.innerHTML = `
    <div class="report-head">
      <div>
        <h1>Report for <code>${esc(scan.target_url)}</code></h1>
        <p class="muted">${esc(when(report.generated_at))} · took ${esc(elapsed(scan.started_at, scan.finished_at))} ·
           permission confirmed by ${esc(scan.authorized_by)}</p>
      </div>
      <div class="actions">
        <button type="button" data-action="check-again" title="Start a new check of the same website, for example after fixing things">Check again</button>
        <a class="button" href="/api/scans/${esc(scan.id)}/report.pdf">PDF</a>
        <a class="button" href="/api/scans/${esc(scan.id)}/report.md" download="${esc(file)}.md">Markdown</a>
        <a class="button" href="/api/scans/${esc(scan.id)}/report" download="${esc(file)}.json">JSON</a>
        <a class="button" href="/api/scans/${esc(scan.id)}/report.sarif" title="A standard format that code hosting sites and security dashboards can import">SARIF</a>
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
      ${owaspHtml(report)}
    </div>

    ${comparisonHtml(comparison)}

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
        <tr><th>Tool</th><th>In plain words</th><th>Why it was in the plan</th><th>Result</th><th class="num">Time</th><th class="num">Findings</th></tr>
        ${report.tool_runs.map((run) => {
          const step = report.plan.steps.find((s) => s.tool === run.tool) || {};
          return `<tr><td><b>${esc(run.tool)}</b></td><td>${esc(TOOLS[run.tool]?.plain || run.what_it_checks)}</td>
            <td>${esc(step.reason)}</td>
            <td>${run.status === "ok" ? "✓ finished" : run.status === "timeout" ? "stopped at time limit" : "✗ error"}</td>
            <td class="num">${esc(run.duration_seconds)} s</td><td class="num">${esc(run.finding_count)}</td></tr>`;
        }).join("")}
      </table></div>
      ${reviewNote(report) ? `<div class="notice notice-info" style="margin-top:10px">${esc(reviewNote(report))}</div>` : ""}
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
      <div id="findings">${findingsHtml(scan.id, report)}</div>
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

/** The list of findings, limited to the severities that are switched on. */
export function findingsHtml(scanId, report) {
  const shown = report.findings.filter((finding) => state.filters.has(finding.severity));
  if (!shown.length) return `<p class="muted">No findings match the selected severities.</p>`;
  return shown.map((finding) => `
    <details class="finding sev-${finding.severity}">
      <summary>
        <span class="badge sev-${finding.severity}">${finding.severity}</span>
        <span class="title">${esc(finding.title)}</span>
        ${finding.owasp ? `<span class="tag" title="OWASP Top 10 category, as given by ${esc(finding.tool)}">${esc(finding.owasp.split(" ")[0])}</span>` : ""}
        <span class="tag">${esc(finding.tool)}</span>
      </summary>
      <div class="body">
        <h4>Why this severity</h4>
        <p>${esc(finding.severity_basis)}${finding.cvss_score ? ` · CVSS ${esc(finding.cvss_score)}` : ""}${finding.cwe ? ` · ${esc(finding.cwe)}` : ""}</p>
        ${finding.owasp ? `<h4>OWASP Top 10 category (from ${esc(finding.tool)})</h4><p>${esc(finding.owasp)}</p>` : ""}
        ${finding.url ? `<h4>Where</h4><p><code>${esc(finding.url)}</code> · seen ${esc(finding.instances)}×</p>` : ""}
        ${finding.description ? `<h4>What it means</h4><p>${esc(finding.description)}</p>` : ""}
        ${finding.evidence ? `<h4>Evidence from ${esc(finding.tool)}</h4><p><code>${esc(finding.evidence)}</code></p>` : ""}
        ${finding.remediation ? `<h4>How to fix (from ${esc(finding.tool)})</h4><p>${esc(finding.remediation)}</p>` : ""}
        ${finding.ai_remediation ? `<h4>How to fix (AI-written)</h4><p class="ai">${esc(finding.ai_remediation)}</p>` : ""}
        <h4>Trace it back</h4>
        <p class="small">Finding <code>${esc(finding.id)}</code>${finding.raw_file
          ? ` · <a href="/api/scans/${esc(scanId)}/raw/${esc(finding.raw_file)}" target="_blank" rel="noopener">raw ${esc(finding.tool)} output</a>` : ""}</p>
      </div>
    </details>`).join("");
}

/** How many findings fall into each OWASP Top 10 category. Only scanners that name a category are counted. */
function owaspHtml(report) {
  const perCategory = {};
  for (const finding of report.findings) {
    if (finding.owasp) perCategory[finding.owasp] = (perCategory[finding.owasp] || 0) + 1;
  }
  const categories = Object.entries(perCategory).sort(([a], [b]) => a.localeCompare(b));
  if (!categories.length) return "";
  return `<p class="muted small" style="margin:16px 0 6px">OWASP Top 10 categories, as named by the scanner (ZAP):</p>
    <div class="chips" style="margin-top:0">
      ${categories.map(([name, n]) => `<span class="tag">${esc(name)} · ${n}</span>`).join("")}
    </div>`;
}

/** "What changed since the last check": the retest view. Shown only when an earlier check exists. */
function comparisonHtml(comparison) {
  if (!comparison?.previous) return "";
  const list = (findings) => findings.length
    ? `<ul class="plain">${findings.map((f) => `<li><span class="badge sev-${esc(f.severity)}">${esc(f.severity)}</span> ${esc(f.title)} <span class="tag">${esc(f.tool)}</span></li>`).join("")}</ul>`
    : `<p class="muted small">None.</p>`;
  return `
    <div class="card">
      <h2>What changed since the last check</h2>
      <p class="muted small">Compared with <a href="#/scan/${esc(comparison.previous.id)}">the check that finished
        ${esc(when(comparison.previous.finished_at))}</a>. Only tools that ran both times are compared:
        ${esc(comparison.tools_compared.join(", ") || "none")}.
        ${comparison.tools_not_compared.length ? `Not compared, because it ran only one of the two times: ${esc(comparison.tools_not_compared.join(", "))}.` : ""}</p>
      <div class="tiles three">
        <div class="tile" style="--c: var(--bad)"><div class="n">${comparison.new.length}</div><div class="l">New</div></div>
        <div class="tile" style="--c: var(--ok)"><div class="n">${comparison.no_longer_reported.length}</div><div class="l">No longer reported</div></div>
        <div class="tile" style="--c: var(--muted)"><div class="n">${esc(comparison.still_there)}</div><div class="l">Still there</div></div>
      </div>
      ${comparison.new.length || comparison.no_longer_reported.length ? `
        <div class="grid-2" style="margin-top:14px">
          <div><h4>New</h4>${list(comparison.new)}</div>
          <div><h4>No longer reported</h4>${list(comparison.no_longer_reported)}</div>
        </div>` : ""}
      <p class="muted small" style="margin-top:10px">"No longer reported" means the scanner did not see it this time.
        That is a good sign after a fix, but scanners can also miss things from one run to the next.</p>
    </div>`;
}

/** Who reviewed the plan and what they changed, when the check had a plan review. */
function reviewNote(report) {
  const review = report.plan.review;
  if (!review) return "";
  const changes = [];
  if (review.added.length) changes.push(`added ${review.added.join(", ")}`);
  if (review.removed.length) changes.push(`removed ${review.removed.join(", ")}`);
  return `The plan was reviewed by ${review.reviewed_by} before any scanner ran: `
    + `${changes.join("; ") || "approved as the Planner suggested"}.`;
}

/** Anything that did not go to plan: time limits, a target that went down, tools that did not run. */
function runNotes(report) {
  const notes = report.tool_runs
    .filter((run) => run.note && (run.status !== "ok" || run.target_down))
    .map((run) => `${run.tool}: ${run.note}`);
  if (report.execution.skipped?.length) {
    notes.push(`Planned but not run: ${report.execution.skipped.join(", ")}. `
      + `Reason: ${report.execution.stop_reason || "no reason given"}`);
  }
  return notes;
}
