/* Where the page starts. It does three things:

   1. loads the settings from the backend,
   2. shows the page that matches the address (#/, #/scan/<id>, #/history, #/how),
   3. handles the few buttons that live inside generated HTML (marked with data-action). */

import { api } from "./api.js";
import { refreshStatus } from "./status.js";
import { app, showError, state } from "./ui.js";
import { viewCheck } from "./views/check.js";
import { viewHistory } from "./views/history.js";
import { viewHowItWorks } from "./views/how-it-works.js";
import { viewNewCheck } from "./views/new-check.js";
import { findingsHtml } from "./views/report.js";

async function route() {
  clearTimeout(state.timer);
  const hash = location.hash || "#/";
  const check = hash.match(/^#\/scan\/([0-9a-f]{32})$/);
  try {
    if (check) await viewCheck(check[1]);
    else if (hash === "#/history") await viewHistory();
    else if (hash === "#/how") viewHowItWorks();
    else viewNewCheck();
  } catch (error) {
    showError(error);
  }
  window.scrollTo(0, 0);
}

const ACTIONS = {
  /** Put an example sentence into the notes box of the form. */
  "note-example": (button) => {
    document.getElementById("scope").value = button.dataset.text;
  },

  /** Switch one severity on or off in the findings list of a report. */
  "filter": (button) => {
    const level = button.dataset.level;
    state.filters.has(level) ? state.filters.delete(level) : state.filters.add(level);
    button.classList.toggle("on");
    const scanId = location.hash.split("/")[2];
    document.getElementById("findings").innerHTML = findingsHtml(scanId, state.reports[scanId]);
  },

  /** From a report: open the form with the same website and notes filled in. */
  "check-again": async () => {
    const scan = await api(`/api/scans/${location.hash.split("/")[2]}`);
    state.prefill = { target: scan.target_url, notes: scan.scope_notes };
    location.hash = "#/";
  },
};

app.addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (button) ACTIONS[button.dataset.action]?.(button);
});

async function start() {
  try {
    state.config = await api("/api/config");
  } catch {
    app.innerHTML = `<div class="notice notice-bad">The backend is not reachable. Is the stack running?</div>`;
    return;
  }
  refreshStatus();
  window.addEventListener("hashchange", route);
  route();
}

start();
