/* Page 1: the form that starts a check. Three steps: what to check, permission, start. */

import { api } from "../api.js";
import { app, esc, setActiveNav, state } from "../ui.js";

const NOTE_EXAMPLES = [
  ["Full check", "Full baseline check, including web server checks."],
  ["Web only, no port scan", "Web application checks only. Do not port scan."],
  ["Quick check", "Quick check. Keep it short and skip slow or noisy scanners."],
];

export function viewNewCheck() {
  setActiveNav("new");
  const practice = state.config.demo_targets;
  const again = state.prefill;  // set by "Check again" on a report
  state.prefill = null;
  const isPractice = again && practice.some((target) => target.url === again.target);

  app.innerHTML = `
    <section class="intro">
      <h1>Check a website for common security problems</h1>
      <p>Three AI agents plan the check, run well-known open-source scanners and write you a report.
         It only looks for problems: no attack is launched and nothing is exploited.</p>
    </section>

    <div class="flow-strip">
      <div><b>1. You choose</b><span>a website and confirm you may test it</span></div>
      <div><b>2. Planner</b><span>picks the tools, and you can review its plan</span></div>
      <div><b>3. Executor</b><span>runs the tools and gathers results</span></div>
      <div><b>4. Reporter</b><span>explains what was found and how to fix it</span></div>
    </div>

    <form id="new-form">
      <div class="card">
        <div class="step-title"><span class="step-number">1</span><h2 style="margin:0">What should we check?</h2></div>
        <div class="options">
          ${practice.map((target, i) => `
            <label class="option">
              <input type="radio" name="target" value="${esc(target.url)}"
                     ${(again ? again.target === target.url : i === 0) ? "checked" : ""}>
              <span class="name">${esc(target.name)}</span> <span class="tag">${esc(target.badge)}</span>
              <p class="note">${esc(target.note)}</p>
              <p class="note"><code>${esc(target.url)}</code></p>
            </label>`).join("")}
          <label class="option">
            <input type="radio" name="target" value="custom" ${(again && !isPractice) || !practice.length ? "checked" : ""}>
            <span class="name">Another website</span> <span class="tag">your own</span>
            <p class="note">A site you own or have written permission to test. If it runs on a hosting
               platform, check that the host allows security scanning.</p>
            <input type="url" id="custom-url" placeholder="https://staging.example.com" aria-label="Website address"
                   value="${again && !isPractice ? esc(again.target) : ""}">
          </label>
        </div>

        <label class="field" for="scope">Anything the agents should know? <span class="muted small">(optional)</span></label>
        <textarea id="scope" placeholder="Plain words are fine. The Planner follows these notes when it picks the tools.">${esc(again?.notes || "")}</textarea>
        <div class="chips">
          ${NOTE_EXAMPLES.map(([label, text]) => `<button type="button" class="chip" data-action="note-example" data-text="${esc(text)}">${esc(label)}</button>`).join("")}
        </div>

        <label class="check">
          <input type="checkbox" id="review" checked>
          <span>Show me the plan first. <span class="muted">Nothing is scanned until I approve it, and I can add or remove tools.</span></span>
        </label>

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

/** The start button works only when the permission box is ticked and every part of the system is up. */
export function updateStartButton() {
  const start = document.getElementById("start");
  const hint = document.getElementById("start-hint");
  if (!start) return;  // the form is not on screen
  const ticked = document.getElementById("confirm").checked;
  const ready = Boolean(state.status?.ready);
  start.disabled = !(ticked && ready);
  hint.textContent = !ticked ? "Tick the permission box first. No tick, no scan."
    : !ready ? "Waiting for all parts to start (see the status at the top right)."
    : "The standard check of the practice shop takes about 5 minutes, a full check about 8.";
}

async function startCheck(event) {
  event.preventDefault();
  const errorBox = document.getElementById("form-error");
  errorBox.innerHTML = "";
  const choice = document.querySelector('input[name="target"]:checked').value;
  const target = choice === "custom" ? document.getElementById("custom-url").value : choice;
  document.getElementById("start").disabled = true;
  try {
    const scan = await api("/api/scans", { method: "POST", body: {
      target_url: target,
      scope_notes: document.getElementById("scope").value,
      test_username: document.getElementById("username").value,
      test_password: document.getElementById("password").value,
      review_plan: document.getElementById("review").checked,
    } });
    // Separate calls on purpose: the server refuses to start a check that was not authorized.
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
