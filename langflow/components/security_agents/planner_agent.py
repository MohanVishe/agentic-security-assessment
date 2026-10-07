import json

import httpx
from agent_common import SCANNERS_URL, chat, notify, parse_json
from lfx.custom.custom_component.component import Component
from lfx.io import MessageTextInput, MultilineInput, Output
from lfx.schema.message import Message

PLANNER_PROMPT = """You are the Planner in a three-agent security assessment team.
Decide which scanners to run against one authorized web target. This is a detection-only
assessment: nothing is exploited.

You receive the target URL, the user's scope notes and the catalog of available tools.

Rules:
- Pick tools only from the catalog.
- Scope notes are binding. If they exclude something ("no port scanning", "passive only",
  "quick check"), leave the matching tools out.
- With no restrictions, a sensible plan is discovery first (nmap), then the web baseline
  (zap), then template checks (nuclei). nikto is noisy and optional: add it when the scope
  notes ask for a thorough run or for web server checks.
- Put discovery before deeper checks.

Reply with only a JSON object:
{"steps": [{"tool": "<name>", "reason": "<one sentence>"}],
 "notes": "<one sentence on how the scope shaped this plan>"}"""


class PlannerAgent(Component):
    display_name = "Planner Agent"
    description = "Reads the target and scope notes, then decides which scanners to run."
    icon = "list-checks"
    name = "PlannerAgent"

    inputs = [
        MessageTextInput(name="request", display_name="Assessment Request",
                         info="JSON from the backend: scan_id, target_url, scope_notes."),
        MultilineInput(name="instructions", display_name="Instructions", value=PLANNER_PROMPT),
    ]
    outputs = [Output(display_name="Plan", name="plan", method="make_plan")]

    async def make_plan(self) -> Message:
        request = json.loads(self.request)
        scan_id = request["scan_id"]
        await notify(scan_id, "planner", f"Planning the assessment of {request['target_url']}.")

        async with httpx.AsyncClient(timeout=15) as client:
            catalog = (await client.get(f"{SCANNERS_URL}/tools")).json()
        available = [tool["name"] for tool in catalog]

        # No plan, no scan: if the LLM is unavailable the run stops here rather than guess the scope.
        reply, model = await chat([
            {"role": "system", "content": self.instructions},
            {"role": "user", "content": json.dumps({
                "target_url": request["target_url"],
                "scope_notes": request.get("scope_notes") or "none given",
                "test_credentials_provided": request.get("credentials_provided", False),
                "available_tools": catalog,
            })},
        ])
        proposed = parse_json(reply.content)

        # Keep only real tools, once each, in the order the Planner chose.
        steps = []
        for step in proposed.get("steps", []):
            if isinstance(step, dict) and step.get("tool") in available \
                    and step["tool"] not in [s["tool"] for s in steps]:
                steps.append({"tool": step["tool"], "reason": str(step.get("reason", ""))[:300]})
        plan = {"steps": steps, "notes": str(proposed.get("notes", ""))[:400], "model": model}

        chosen = ", ".join(step["tool"] for step in steps) or "no tools (scope excludes them all)"
        await notify(scan_id, "planner", f"Plan: {chosen}. {plan['notes']}")
        self.status = plan
        return Message(text=json.dumps({"request": request, "plan": plan}))
