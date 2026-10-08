/* Page 4: the list of past checks. */

import { api } from "../api.js";
import { app, esc, setActiveNav, when } from "../ui.js";

// How each state is shown: [colour class, words for the reader].
const STATUS = {
  created: ["pill-wait", "not started"],
  authorized: ["pill-wait", "starting"],
  planning: ["pill-wait", "planning"],
  awaiting_approval: ["pill-wait", "waiting for your approval"],
  running: ["pill-wait", "running"],
  completed: ["pill-ok", "completed"],
  failed: ["pill-bad", "failed"],
  cancelled: ["pill-bad", "cancelled"],
};

export async function viewHistory() {
  setActiveNav("history");
  const scans = await api("/api/scans");
  app.innerHTML = `
    <section class="intro"><h1>Past checks</h1><p>Every check keeps its report and its permission record.
      Checking the same website again shows what changed since the last time.</p></section>
    <div class="card">
      ${scans.length ? `<div class="table-wrap"><table>
        <tr><th>Target</th><th>Started</th><th>Status</th><th></th></tr>
        ${scans.map((scan) => {
          const [colour, words] = STATUS[scan.status] || ["pill-wait", scan.status];
          return `<tr>
            <td><code>${esc(scan.target_url)}</code></td><td>${esc(when(scan.created_at))}</td>
            <td><span class="pill ${colour}">${esc(words)}</span></td>
            <td><a href="#/scan/${esc(scan.id)}">Open</a></td></tr>`;
        }).join("")}
      </table></div>` : `<p class="muted">Nothing yet. <a href="#/">Start your first check.</a></p>`}
    </div>`;
}
