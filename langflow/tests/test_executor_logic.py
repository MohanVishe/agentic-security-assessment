"""The Executor's guard rails, tested with a scripted stand-in for the AI model and the scanners.

Needs Langflow's own packages, so it is skipped where they are missing. To run it, use the Langflow image:

    docker run --rm -v ./langflow:/work:ro --entrypoint python langflowai/langflow:1.12.5         -m pytest -q -p no:cacheprovider /work/tests
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("lfx")
LANGFLOW = Path(__file__).parent.parent
sys.path[:0] = [str(LANGFLOW / "agentlib"), str(LANGFLOW / "components" / "security_agents")]

import agent_common  # noqa: E402
import executor_agent  # noqa: E402
from langchain_core.messages import AIMessage  # noqa: E402

PLAN = {"request": {"scan_id": "a" * 32, "target_url": "http://t:3000"},
        "plan": {"steps": [{"tool": "nmap", "reason": "discovery"}, {"tool": "zap", "reason": "web baseline"}]}}


def call(tool: str) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": f"run_{tool}", "args": {"reason": "planned"}, "id": f"call-{tool}"}])


def run_executor(monkeypatch, replies, down_after=()):
    """Run the Executor with scripted model replies. Returns (output, tools that ran, model turns used)."""
    ran, turns = [], []

    async def fake_chat(messages, **_):
        turns.append(len(messages))
        reply = replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply, "test-model"

    async def fake_notify(*_, **__):
        return None

    class FakeScannerService:
        def __init__(self, **_): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *_): return False

        async def post(self, url, json):
            tool = url.rsplit("/", 1)[-1]
            ran.append(tool)
            down = tool in down_after

            class Response:
                status_code = 200
                def json(self):
                    return {"tool": tool, "status": "ok", "duration_seconds": 1, "findings": [], "target_down": down,
                            "summary": {"tool": tool, "status": "ok", "finding_count": 0, "target_down": down}}
            return Response()

    monkeypatch.setattr(executor_agent, "chat", fake_chat)
    monkeypatch.setattr(executor_agent, "notify", fake_notify)
    monkeypatch.setattr(executor_agent.httpx, "AsyncClient", FakeScannerService)
    monkeypatch.setattr(executor_agent, "tracing", lambda component: {})

    agent = executor_agent.ExecutorAgent()
    agent.plan, agent.instructions, agent.model_name = json.dumps(PLAN), "test instructions", ""
    output = json.loads(asyncio.run(agent.execute_plan()).text)
    return output, ran, len(turns)


def test_a_model_that_stops_early_is_reminded_and_finishes_the_plan(monkeypatch):
    replies = [call("nmap"), AIMessage(content="All scans completed."), call("zap"), AIMessage(content="DONE")]
    output, ran, _ = run_executor(monkeypatch, replies)
    assert ran == ["nmap", "zap"] and output["execution"]["skipped"] == []


def test_a_model_that_still_stops_has_its_skip_recorded(monkeypatch):
    replies = [call("nmap"), AIMessage(content="All scans completed."), AIMessage(content="I will not run zap.")]
    output, ran, _ = run_executor(monkeypatch, replies)
    assert ran == ["nmap"]
    assert output["execution"]["skipped"] == ["zap"] and output["execution"]["stop_reason"] == "I will not run zap."


def test_stopping_because_the_target_went_down_needs_no_reminder(monkeypatch):
    replies = [call("nmap"), AIMessage(content="The target stopped answering, so I am stopping.")]
    output, ran, turns = run_executor(monkeypatch, replies, down_after=("nmap",))
    assert ran == ["nmap"] and turns == 2 and output["execution"]["skipped"] == ["zap"]


def test_a_tool_outside_the_plan_and_a_repeat_are_both_refused(monkeypatch):
    replies = [call("nikto"), call("nmap"), call("nmap"), call("zap"), AIMessage(content="DONE")]
    _, ran, _ = run_executor(monkeypatch, replies)
    assert ran == ["nmap", "zap"]


def test_the_plan_still_runs_in_order_when_the_model_is_unavailable(monkeypatch):
    output, ran, _ = run_executor(monkeypatch, [RuntimeError("rate limited")])
    assert ran == ["nmap", "zap"] and output["execution"]["driver"].startswith("plan order")


def test_each_agent_can_be_given_its_own_model(monkeypatch):
    monkeypatch.setenv("LLM_MODEL_EXECUTOR", "small-model")
    assert agent_common.model_for("executor") == "small-model"
    assert agent_common.model_for("executor", "chosen-on-canvas") == "chosen-on-canvas"
    assert agent_common.model_for("planner") == ""  # empty means LLM_MODEL
