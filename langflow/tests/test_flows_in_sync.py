"""A flow file embeds a copy of each agent's code. This fails when that copy is stale,
which means someone edited a component and forgot to run `python langflow/build_flow.py`."""
import json
from pathlib import Path

import pytest

LANGFLOW = Path(__file__).parent.parent
COMPONENT_FILES = {"PlannerAgent": "planner_agent.py", "ExecutorAgent": "executor_agent.py",
                   "ReporterAgent": "reporter_agent.py"}


@pytest.mark.parametrize("flow_file", sorted((LANGFLOW / "flows").glob("*.json")), ids=lambda path: path.name)
def test_flow_embeds_the_current_component_code(flow_file):
    flow = json.loads(flow_file.read_text(encoding="utf-8"))
    agents = [node["data"] for node in flow["data"]["nodes"] if node["data"]["type"] in COMPONENT_FILES]
    assert agents, "the flow has no agent nodes"
    for agent in agents:
        source = (LANGFLOW / "components" / "security_agents" / COMPONENT_FILES[agent["type"]]).read_text(encoding="utf-8")
        assert agent["node"]["template"]["code"]["value"] == source, f"{agent['type']} is stale in {flow_file.name}"
