import json

import httpx
from agent_common import SCANNERS_URL, assistant_turn, chat, notify, plain_text
from lfx.custom.custom_component.component import Component
from lfx.io import MessageTextInput, MultilineInput, Output
from lfx.schema.message import Message

EXECUTOR_PROMPT = """You are the Executor in a three-agent security assessment team.
The Planner approved a list of scanners. Run them by calling the matching tools, one at a
time, in the planned order.

Rules:
- Call only the tools you are given, each at most once. The target is fixed by the system.
- Read each result summary before continuing. If discovery shows the web service is not
  reachable, you may stop early and say so instead of running the remaining scans.
- Never invent results. When you are done, reply with a short plain-text note (two
  sentences) on how the runs went: what succeeded, failed or timed out."""


class ExecutorAgent(Component):
    display_name = "Executor Agent"
    description = "Calls the scanner tool wrappers the plan asks for and collects their raw structured output."
    icon = "terminal"
    name = "ExecutorAgent"

    inputs = [
        MessageTextInput(name="plan", display_name="Plan", info="Output of the Planner Agent."),
        MultilineInput(name="instructions", display_name="Instructions", value=EXECUTOR_PROMPT),
    ]
    outputs = [Output(display_name="Tool Results", name="results", method="execute_plan")]

    async def execute_plan(self) -> Message:
        state = json.loads(self.plan)
        scan_id = state["request"]["scan_id"]
        planned = [step["tool"] for step in state["plan"]["steps"]]
        runs: dict[str, dict] = {}

        async def run_tool(tool: str) -> dict:
            """Call one tool wrapper. The full result is kept here; the LLM only sees the summary."""
            await notify(scan_id, "executor", f"Running {tool}...")
            try:
                async with httpx.AsyncClient(timeout=900) as client:
                    response = await client.post(f"{SCANNERS_URL}/run/{tool}", json={"scan_id": scan_id})
                if response.status_code != 200:
                    raise RuntimeError(response.json().get("detail", response.text))
                result = response.json()
            except Exception as exc:
                note = str(exc)[:300]
                result = {"tool": tool, "status": "error", "command": "", "note": note, "raw_file": None,
                          "duration_seconds": 0, "findings": [],
                          "summary": {"tool": tool, "status": "error", "finding_count": 0, "note": note}}
            runs[tool] = result
            await notify(scan_id, "executor",
                         f"{tool} finished: {result['status']}, {len(result['findings'])} finding(s) "
                         f"in {result['duration_seconds']}s.")
            return result["summary"]

        # Each planned scanner becomes one callable tool. No target argument: the tool service
        # reads the target from the authorized scan record, so the LLM cannot redirect a scan.
        tools = [{
            "type": "function",
            "function": {
                "name": f"run_{tool}",
                "description": f"Run the {tool} scanner against the authorized target.",
                "parameters": {"type": "object", "properties": {
                    "reason": {"type": "string", "description": "Why this scan is being run now."}}},
            },
        } for tool in planned]
        messages = [
            {"role": "system", "content": self.instructions},
            {"role": "user", "content": json.dumps({"target_url": state["request"]["target_url"],
                                                    "approved_plan": state["plan"]["steps"]})},
        ]

        notes, model, driver = "", "", "llm tool calling"
        try:
            for _ in range(len(planned) + 2):
                if not planned:
                    break
                reply, model = await chat(messages, tools=tools)
                messages.append(assistant_turn(reply))
                if not reply.tool_calls:
                    notes = plain_text(reply.content)
                    break
                for call in reply.tool_calls:
                    tool = call.function.name.removeprefix("run_")
                    if tool not in planned:
                        outcome = {"error": f"{tool} is not in the approved plan."}
                    elif tool in runs:
                        outcome = {"error": f"{tool} already ran; do not run it twice."}
                    else:
                        outcome = await run_tool(tool)
                    messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(outcome)})
        except Exception as exc:
            # The plan is already approved, so if the LLM drops out (free-tier rate limits)
            # the remaining steps are run in order without it.
            driver = "plan order (LLM unavailable)"
            await notify(scan_id, "executor", f"LLM unavailable ({str(exc)[:150]}); running the rest of the plan in order.")
            for tool in planned:
                if tool not in runs:
                    await run_tool(tool)

        skipped = [tool for tool in planned if tool not in runs]
        if skipped:
            await notify(scan_id, "executor", f"Not run: {', '.join(skipped)}. {notes}")
        self.status = {tool: run["summary"] for tool, run in runs.items()}
        return Message(text=json.dumps({
            **state,
            "tool_runs": list(runs.values()),
            "execution": {"driver": driver, "model": model, "notes": notes[:600], "skipped": skipped},
        }))
