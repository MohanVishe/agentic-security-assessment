/* Page 5: the explanation page. Fixed text only, nothing is loaded from the server. */

import { AGENTS, TOOLS, app, setActiveNav } from "../ui.js";

const AGENT_COMPARISON = {
  planner: "Like the inspector reading your instructions. If you say \"no port scanning\", it leaves that tool out.",
  executor: "Like the person doing the walk-round. It can only use the tools on the plan and only on your target.",
  reporter: "Like the person writing the inspection report. It can explain findings but cannot add new ones.",
};

export function viewHowItWorks() {
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
          <tr><td>1. Planning and scope</td><td>Agree what may be tested, and get permission</td><td><b>Yes</b>: the permission box, your notes and the plan review</td></tr>
          <tr><td>2. Information gathering</td><td>Learn what is there: open ports, software in use</td><td><b>Yes</b>: nmap, ZAP, Nuclei</td></tr>
          <tr><td>3. Scanning for weaknesses</td><td>Compare it against known weaknesses and risky settings</td><td><b>Yes</b>: ZAP, Nuclei, Nikto</td></tr>
          <tr><td>4. Exploitation</td><td>Use a weakness to actually get in</td><td><b>No</b>, on purpose</td></tr>
          <tr><td>5. After getting in</td><td>See how far an attacker could go</td><td><b>No</b></td></tr>
          <tr><td>6. Reporting</td><td>Each finding, how serious it is, how to fix it</td><td><b>Yes</b>: the Reporter agent</td></tr>
          <tr><td>7. Retest</td><td>Check again after fixing, and see what changed</td><td><b>Yes</b>: "Check again" compares with the last report</td></tr>
        </tbody>
      </table></div>
      <p class="muted small">So this is the finding and reporting half of a pen test, often called a vulnerability
         assessment. Breaking in is left out because it can damage a system. A clean report does not mean "secure".</p>
    </div>

    <h2>The three agents</h2>
    <div class="explain spaced">
      ${AGENTS.map((agent) => `<div class="card"><div class="icon">${agent.icon}</div><h3>${agent.name}</h3><p>${agent.does}</p>
        <p class="muted small">${AGENT_COMPARISON[agent.id]}</p></div>`).join("")}
    </div>

    <h2>You stay in charge</h2>
    <div class="card">
      <ul class="plain">
        <li><b>Review the plan.</b> The Planner shows which tools it wants to run and why. Nothing is scanned until you
            approve, and you can add or remove tools first.</li>
        <li><b>Stop when you want.</b> While the scanners run, "Stop after the current tool" ends the check early.
            You still get a report of what ran.</li>
        <li><b>Check again.</b> After fixing things, run the same check again. The report shows what is new,
            what is no longer reported, and what is still there.</li>
      </ul>
    </div>

    <h2>The four scanner tools</h2>
    <div class="explain tools spaced">
      ${Object.entries(TOOLS).map(([name, tool]) => `<div class="card"><h3>${name}</h3><p>${tool.plain}</p>
        <p class="muted small">Takes ${tool.time} on the practice shop.</p></div>`).join("")}
    </div>

    <h2>Reading the report</h2>
    <div class="card">
      <ul class="plain">
        <li><b>Severity</b> says how serious a finding could be: Critical, High, Medium, Low, or Info (just good to know).</li>
        <li><b>OWASP Top 10 category</b> is the well-known list of the ten most common kinds of website weakness.
            It is shown only where the scanner itself names the category.</li>
        <li><b>Evidence</b> is the exact thing the scanner saw. You can open the scanner's raw output for every finding.</li>
        <li><b>How to fix</b> comes from the scanner where it has advice, and from the AI where marked "AI-written".</li>
        <li><b>Findings are leads, not proof.</b> Nothing is exploited, so some findings can be false alarms.</li>
        <li><b>Quality checks</b> are automatic tests on the report itself, for example that every finding really
            appears in the scanner's raw output.</li>
        <li><b>Downloads:</b> PDF and Markdown for people, JSON and SARIF for other programs. SARIF is a standard
            format that code hosting sites and security dashboards can import.</li>
      </ul>
    </div>

    <h2>Guard rails: limits the AI cannot cross</h2>
    <div class="card">
      <ul class="plain">
        <li><b>No tick, no scan.</b> The page, the server and the scanners each check for your saved permission.</li>
        <li><b>The target is fixed.</b> The scanners read it from your saved check. Nothing the AI writes can change it.</li>
        <li><b>Only planned tools run.</b> The Planner can pick only tools that exist. The Executor can call only the
            planned ones, once each, and cannot skip one silently.</li>
        <li><b>An approved plan is final.</b> When you review a plan, the tools you approve are the ones that run.
            The AI cannot change the list afterwards.</li>
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
