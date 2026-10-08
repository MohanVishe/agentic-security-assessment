# How this project compares with AI pen testing products

This page looks at the products that offer "pen testing with AI" today: how they are built,
what their screens look like, and what features they give the user. It then says honestly
where this project stands next to them, what was added because of the comparison, and what
is left out on purpose.

Product details were read from each vendor's own pages and public repositories in October
2026. Products change fast, so treat the details as a snapshot. Sources are at the end.

---

## 1. The short version

| | The products | This project |
|---|---|---|
| **Goal** | Find a weakness and **prove it by exploiting it** | Find and **report**; never exploit |
| **Agents** | A coordinator plus many specialist agents, often running in parallel | Three agents in a fixed line: Planner, Executor, Reporter |
| **Tools** | Browser, HTTP proxy, shell, code sandbox, plus scanners | Four scanners: nmap, ZAP, Nuclei, Nikto |
| **Run time** | 1 hour to several days | 5 to 8 minutes |
| **Cost** | From about $50 a run to enterprise contracts; open-source ones cost LLM tokens | Free: open-source tools and a free LLM tier |

This project is the **finding and reporting half** of a pen test. The products do the whole
thing. That difference is a deliberate choice, explained in section 6.

---

## 2. The products

### Commercial

| Product | What it is | How it is built | What stands out |
|---|---|---|---|
| **XBOW** | Autonomous pen testing platform for web applications | A coordinator starts many agents in parallel. Stages: learn the app, map it, coordinate, attack, prove | Separate validator agents re-check every finding, so only proven ones are reported. Every agent action is logged for audit |
| **Aikido Attack** | AI pen test sold per run, part of a wider security platform | Many agents work at once; separate agents re-exploit each finding to confirm it | Scope set by domain ("may attack" vs "may only reach"). Pre-flight checks. A **panic button** stops all agents. Free retest. Fix suggestions as code changes. Reports for managers, customers and auditors |
| **Horizon3 NodeZero**, **Pentera** | Autonomous testing of internal networks and Windows domains | Chains weaknesses together into attack paths | Aimed at networks, not at one website. Run again and again to check fixes |
| **RunSybil**, **Terra** | Continuous AI pen testing | An orchestrator with specialist agents | Replay an attack to retest it. Feedback on code changes |
| **Escape** | API and web application security testing | Its own agent engine | Publishes a public comparison of the open-source tools below |

### Open source

| Product | What it is | How it is built | What stands out |
|---|---|---|---|
| **PentAGI** | Self-hosted autonomous pen testing system (MIT licence) | An orchestrator with many specialist agents (planner, researcher, coder, reporter, adviser and more). Over 20 tools in sandboxed Docker containers | Web page with flows, tasks and sub-tasks, and a live terminal. The user can stop a task or change the planned sub-tasks. Long-term memory. Langfuse and Grafana for monitoring. A model can be set per agent |
| **Strix** | AI agents that test an app like a hacker would | A graph of agents for recon, exploitation and validation, with a browser, HTTP proxy, shell and Python sandbox | Runs from the command line. A mode for CI pipelines that fails the build. Findings get CVSS scores and OWASP categories. Authorization is the user's own responsibility |
| **Shannon** (Keygraph) | Autonomous web pen tester that reads the source code first | Recon, then one analysis agent per kind of weakness, then exploitation, then reporting | "No exploit, no report." Reports as PDF, Markdown, JSON and **SARIF**. Takes 1 to 1.5 hours a run. Warns against running it on a live production site |

---

## 3. What they have in common

**Structure.** Nearly every product uses the same shape: one coordinator and several
specialist agents, with a separate step that checks each finding before it is reported.

**Interface.** The screens differ, but the same parts keep appearing:

1. **A scope screen**: which addresses may be tested, and a permission or ownership step.
2. **A live view**: what each agent is doing right now, often with the raw tool output.
3. **Controls**: stop the run, and in some products change the plan or answer a question.
4. **A findings list**: severity, evidence, a standard category, and fix advice.
5. **Downloads**: a PDF for people, and a machine format for other tools.
6. **History and retest**: past runs, and a second run that shows what changed.

**What users are told to look for.** A public test of the open-source tools (same LLM, same
target, 20 known weaknesses) found 9, 6 and 1 of them with the three open-source tools, and
15 with the vendor's own product. The conclusion of that test: the model matters less than **how the agents are organised**, and
**false alarms matter as much as misses**. Scope control was the other deciding point.

---

## 4. Feature by feature

Legend: ✅ has it · ◐ has part of it · ➕ added because of this comparison · ❌ not there

| What a user expects | The products | This project |
|---|---|---|
| **Permission before any scan** | ◐ Varies. Some verify domain ownership; some leave it to the user | ✅ Tick box and name, saved with the check, enforced in three places |
| **Scope in plain words** | ◐ Mostly config files or domain lists | ✅ Free-text notes that the Planner follows |
| **See and change the plan before it runs** | ◐ PentAGI lets the user change sub-tasks | ➕ **Plan review**: tick boxes, approve or cancel, changes saved with the report |
| **Stop a run** | ✅ Aikido's panic button; PentAGI's stop | ➕ **Stop after the current tool**; the report covers what ran |
| **Live view of the agents** | ✅ | ✅ Agent status, tool status and an activity log |
| **Findings backed by evidence** | ✅ By exploiting them | ✅ By the scanner's raw output, linked from every finding |
| **Protection against invented findings** | ✅ Validator agents | ✅ Code copies findings from the scanners; the AI cannot add one. Seven automatic quality checks |
| **Severity** | ✅ CVSS | ✅ CVSS bands, with the reason shown |
| **Standard category (OWASP Top 10)** | ✅ | ➕ Shown where the scanner itself names the category (ZAP does) |
| **Fix advice** | ✅ Some open code changes | ✅ From the scanner, plus AI-written advice, marked as such |
| **Report for people** | ✅ PDF | ✅ PDF and Markdown |
| **Report for other tools** | ✅ JSON, SARIF | ✅ JSON · ➕ **SARIF 2.1.0** |
| **Retest: what changed since last time** | ✅ | ➕ **Check again** and a comparison: new, no longer reported, still there |
| **History of past runs** | ✅ | ✅ |
| **Tracing of every AI step** | ✅ XBOW's audit log; PentAGI's Langfuse | ✅ Langfuse trace per run, with quality scores |
| **A model per agent** | ✅ PentAGI | ✅ |
| **Care for the target** | ◐ Shannon and others warn about production use | ✅ Throttled tools, pauses, health checks, stops if the site goes down |
| **Exploitation and proof of concept** | ✅ | ❌ On purpose |
| **Testing behind a login** | ✅ Login flows, 2FA | ◐ HTTP Basic only |
| **Reading the source code** | ✅ Shannon, Strix, Aikido | ❌ |
| **Many agents in parallel** | ✅ | ❌ One tool at a time, to be gentle on the target |
| **Run from a CI pipeline** | ✅ Strix, Shannon | ◐ The API can be called from a script; no ready-made pipeline step |
| **Compliance reports and attestation letters** | ✅ Aikido, XBOW | ❌ |
| **Memory across runs** | ✅ PentAGI | ◐ Only the comparison with the last report |

---

## 5. What was added because of this comparison

Five features that the products have, that make sense for a detection-only tool, and that
were missing here:

| Added | What the user sees | Why it matters |
|---|---|---|
| **Plan review** | The Planner's plan as tick boxes. Approve it, change it, or cancel. Nothing is scanned before approval | A person decides what runs against the target, not the AI alone |
| **Stop** | A "Stop after the current tool" button during the scans | The user must always be able to end a run |
| **Check again and compare** | A "Check again" button, and a card: new, no longer reported, still there | Fixing and re-checking is the reason to scan at all |
| **OWASP Top 10 category** | A category on each finding where the scanner names one, and a count per category | The common language of web security reports |
| **SARIF export** | A SARIF download next to PDF, Markdown and JSON | The findings can go into the tracker a team already uses |

One thing was removed: the public practice website in the target list. It was no longer
reachable, so offering it only led to a failed check. The practice target is now the local
Juice Shop only.

Each addition keeps the project's rules. For example the comparison only compares tools
that ran both times, so a tool that was left out never looks like a fixed problem. And the
OWASP category is read from the scanner's own output; the AI never assigns one.

---

## 6. What is left out on purpose

| Not in this project | Why |
|---|---|
| **Exploitation** | Breaking in can damage a system and needs a far stricter safety set-up. The assignment asks for detection and reporting only |
| **A shell, browser or code sandbox for the AI** | They exist to exploit. With scanners only, the AI can pick and run fixed tools but cannot write an attack |
| **Many agents in parallel** | Parallel scanners overload a small target. One at a time, with pauses, keeps the site up |
| **Compliance reports** | They need an audited process behind them, not just a template |

These are listed as future work in the README where they could be added safely.

---

## 7. Where this project is ahead for its size

- **The permission gate is enforced by code in three places**, including in the scanner
  service itself. Some open-source products leave authorization entirely to the user.
- **The AI cannot change the target.** Scanner tools take no address; they read it from the
  saved, authorized check.
- **The AI cannot add a finding.** In the products this is handled by a second AI that
  re-checks the first. Here it is handled by code, which costs nothing and cannot be talked
  out of it.
- **It runs in minutes on a free LLM tier**, where the products take an hour or more and
  real money per run.
- **It says what it did not test.** Every report has a "what was not tested" section.

---

## Sources

- XBOW platform: <https://xbow.com/platform>
- Aikido Attack: <https://www.aikido.dev/attack/aipentest>
- Strix: <https://github.com/usestrix/strix>
- PentAGI: <https://github.com/vxcontrol/pentagi>
- Shannon: <https://github.com/KeygraphHQ/shannon>
- Escape, benchmark of open-source AI pen testing tools:
  <https://escape.tech/blog/benchmarking-agentic-ai-pentesting-tools>
- Market overviews: <https://www.getastra.com>, <https://www.synack.com>,
  <https://www.firecompass.com>, <https://strobes.co>, <https://www.codeant.ai>
