"""Regenerate the flow files under flows/ from the component code.

A flow file embeds a copy of each component's code and field definitions, so
the files must be rebuilt after editing anything under components/. With the
stack up:

    docker compose restart langflow      # so Langflow loads the edited components
    python langflow/build_flow.py
    docker compose restart langflow      # so Langflow loads the rebuilt flows

It asks the running Langflow for its component catalog (which includes the three
custom agents), then wires the nodes of each flow in a line:

    security_assessment.json   Chat Input -> Planner -> Executor -> Reporter -> Chat Output
    planner_only.json          Chat Input -> Planner -> Chat Output   (used by evals/)

You can do the same by hand in the Langflow canvas and export the flow; this
script just makes the result reproducible.
"""
from __future__ import annotations

import gzip
import json
import os
import urllib.request
from pathlib import Path

LANGFLOW_URL = os.getenv("LANGFLOW_URL", "http://localhost:7860")
ENV_FILE = Path(__file__).parent.parent / ".env"


def api_key() -> str:
    """LANGFLOW_API_KEY from the environment, else from the repo's .env, else the compose default."""
    if os.getenv("LANGFLOW_API_KEY"):
        return os.environ["LANGFLOW_API_KEY"]
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith("LANGFLOW_API_KEY="):
                return line.split("=", 1)[1].strip()
    return "change-me-langflow-key"

FLOWS_DIR = Path(__file__).parent / "flows"

# Each flow is a chain of (node id, component name in the catalog, input field that receives
# the previous node's output). The ids are fixed, so reloading updates a flow in place.
FLOWS = [
    {
        "file": "security_assessment.json",
        "id": "5ec0a55e-55a1-4f10-9a11-a6e17c5ec001",
        "name": "Security Assessment",
        "endpoint_name": "security-assessment",
        "description": "Planner -> Executor -> Reporter. Plans a detection-only assessment of an "
                       "authorized web target, runs open-source scanners, writes a findings report.",
        "chain": [
            ("ChatInput-req01", "ChatInput", None),
            ("PlannerAgent-pln01", "PlannerAgent", "request"),
            ("ExecutorAgent-exe01", "ExecutorAgent", "plan"),
            ("ReporterAgent-rep01", "ReporterAgent", "results"),
            ("ChatOutput-out01", "ChatOutput", "input_value"),
        ],
    },
    {
        "file": "planner_only.json",
        "id": "5ec0a55e-55a1-4f10-9a11-a6e17c5ec002",
        "name": "Security Assessment - Planner only",
        "endpoint_name": "security-assessment-plan",
        "description": "Only the Planner: returns the plan and runs no scanner. "
                       "Used by evals/ to test the Planner's decisions.",
        "chain": [
            ("ChatInput-req01", "ChatInput", None),
            ("PlannerAgent-pln01", "PlannerAgent", "request"),
            ("ChatOutput-out01", "ChatOutput", "input_value"),
        ],
    },
]


def catalog() -> dict:
    request = urllib.request.Request(f"{LANGFLOW_URL}/api/v1/all",
                                     headers={"x-api-key": api_key(), "Accept-Encoding": "gzip"})
    with urllib.request.urlopen(request, timeout=60) as response:
        body = response.read()
        if response.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
    components = {}
    for category in json.loads(body).values():
        for key, component in category.items():
            if isinstance(component, dict) and "template" in component:
                # custom components are keyed like "ext:security_agents:PlannerAgent@extra"
                components[key.split(":")[-1].split("@")[0]] = component
    return components


def handle(value: dict) -> str:
    """Langflow stores edge handles as JSON with the quotes swapped for 'œ'."""
    return json.dumps(value, separators=(",", ":")).replace('"', "œ")


def build(flow: dict, components: dict) -> dict:
    chain = flow["chain"]
    nodes, edges = [], []
    for index, (node_id, name, _) in enumerate(chain):
        component = components[name]
        nodes.append({
            "id": node_id,
            "type": "genericNode",
            "position": {"x": 80 + index * 420, "y": 200},
            "data": {"id": node_id, "type": name, "node": component, "showNode": True,
                     "display_name": component["display_name"], "description": component["description"],
                     "selected_output": component["outputs"][0]["name"]},
        })

    for (source_id, source_name, _), (target_id, target_name, field) in zip(chain, chain[1:]):
        output = components[source_name]["outputs"][0]
        target_field = components[target_name]["template"][field]
        source = {"dataType": source_name, "id": source_id, "name": output["name"],
                  "output_types": output["types"]}
        target = {"fieldName": field, "id": target_id, "inputTypes": target_field["input_types"],
                  "type": target_field["type"]}
        edges.append({
            "id": f"xy-edge__{source_id}-{target_id}",
            "source": source_id, "target": target_id,
            "sourceHandle": handle(source), "targetHandle": handle(target),
            "data": {"sourceHandle": source, "targetHandle": target},
            "animated": False, "className": "", "selected": False,
        })

    return {
        "id": flow["id"],
        "name": flow["name"],
        "description": flow["description"],
        "endpoint_name": flow["endpoint_name"],
        "is_component": False,
        "tags": ["agents", "security"],
        "data": {"nodes": nodes, "edges": edges, "viewport": {"x": 0, "y": 0, "zoom": 0.6}},
    }


if __name__ == "__main__":
    FLOWS_DIR.mkdir(exist_ok=True)
    components = catalog()
    for flow in FLOWS:
        out_file = FLOWS_DIR / flow["file"]
        out_file.write_text(json.dumps(build(flow, components), indent=1, ensure_ascii=False), encoding="utf-8", newline="\n")
        print(f"Wrote {out_file}")
