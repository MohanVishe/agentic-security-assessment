/* Things every page shares: the page element, a little state, fixed texts and small helpers.

   Every piece of text that comes from the server goes through esc() before it is put into
   the page, because finding titles and evidence come from scanned websites. */

export const app = document.getElementById("app");

/** What the page remembers between views. */
export const state = {
  config: null,                    // practice targets and the permission sentence, from /api/config
  status: null,                    // are all parts running? from /api/status
  filters: new Set(["Critical", "High", "Medium", "Low", "Info"]),
  reports: {},                     // finished reports, by check id
  comparisons: {},                 // "what changed since last time", by check id
  prefill: null,                   // target and notes for "check again"
  timer: null,                     // the refresh timer of the page that is open
};

export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

export const AGENTS = [
  { id: "planner", name: "Planner", icon: "🧭", does: "Reads your target and notes, then picks which tools to run." },
  { id: "executor", name: "Executor", icon: "🛠️", does: "Runs each chosen tool, one after another, and collects the results." },
  { id: "reporter", name: "Reporter", icon: "📝", does: "Rates every finding and writes the report with fix advice." },
];

export const TOOLS = {
  nmap: { plain: "Knocks on the server's network doors (ports) to see which ones are open.", time: "about 15 seconds" },
  zap: { plain: "Browses the site like a visitor and notes risky settings in what the site sends back.", time: "about 1 minute" },
  nuclei: { plain: "Runs a library of known checks for exposed files, admin pages and bad settings.", time: "about 2 minutes" },
  nikto: { plain: "Checks the web server for leftover files and old, unsafe configuration.", time: "about 2.5 minutes" },
};

export const CHECK_LABELS = {
  plan_followed: "Followed the plan",
  stayed_in_scope: "Stayed inside the approved plan",
  tools_completed: "Tools finished without errors",
  target_stayed_up: "Target stayed up during the scans",
  findings_traceable: "Findings match the raw scanner output",
  ai_text_grounded: "AI text sticks to the findings",
  fix_advice_coverage: "Fix advice for the important findings",
};

/** Make any value safe to put into HTML. */
export function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/** A date and time the way the reader's own computer writes them. */
export function when(iso) {
  return iso ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "";
}

/** How long something took, e.g. "7 min 19 s". With no end time it counts up to now. */
export function elapsed(fromIso, toIso) {
  const seconds = Math.max(0, Math.round(((toIso ? new Date(toIso) : new Date()) - new Date(fromIso)) / 1000));
  return `${Math.floor(seconds / 60)} min ${String(seconds % 60).padStart(2, "0")} s`;
}

/** Highlight the current page in the menu at the top. */
export function setActiveNav(name) {
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.nav === name));
}

/** The activity log: one line per event the system or an agent posted. */
export function logHtml(events) {
  return `<div class="log">${events.map((event) => `
    <div><span class="muted mono">${esc(new Date(event.at).toLocaleTimeString([], { hour12: false }))}</span>
         <span class="who">${esc(event.agent)}</span>
         <span class="what">${esc(event.message)}</span></div>`).join("")}</div>`;
}

export function showError(error) {
  app.innerHTML = `<div class="notice notice-bad">${esc(error.message)}</div>`;
}
