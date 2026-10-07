"""Regenerate flows/security_assessment.json from the component code.

The flow file embeds a copy of each component's code and field definitions, so
it must be rebuilt after editing anything under components/. With the stack up:

    python langflow/build_flow.py
    docker compose restart langflow

It asks the running Langflow for its component catalog (which includes the three
custom agents), then wires five nodes in a line:

    Chat Input -> Planner Agent -> Executor Agent -> Reporter Agent -> Chat Output

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

OUT_FILE = Path(__file__).parent / "flows" / "security_assessment.json"
FLOW_ID = "5ec0a55e-55a1-4f10-9a11-a6e17c5ec001"  # fixed, so reloading updates the flow in place

# (node id, component name in the catalog, input field that receives the previous node's output)
CHAIN = [
    ("ChatInput-req01", "ChatInput", None),
    ("PlannerAgent-pln01", "PlannerAgent", "request"),
    ("ExecutorAgent-exe01", "ExecutorAgent", "plan"),
    ("ReporterAgent-rep01", "ReporterAgent", "results"),
    ("ChatOutput-out01", "ChatOutput", "input_value"),
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


def build() -> dict:
    components = catalog()
    nodes, edges = [], []
    for index, (node_id, name, _) in enumerate(CHAIN):
        component = components[name]
        nodes.append({
            "id": node_id,
            "type": "genericNode",
            "position": {"x": 80 + index * 420, "y": 200},
            "data": {"id": node_id, "type": name, "node": component, "showNode": True,
                     "display_name": component["display_name"], "description": component["description"],
                     "selected_output": component["outputs"][0]["name"]},
        })

    for (source_id, source_name, _), (target_id, target_name, field) in zip(CHAIN, CHAIN[1:]):
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
        "id": FLOW_ID,
        "name": "Security Assessment",
        "description": "Planner -> Executor -> Reporter. Plans a detection-only assessment of an "
                       "authorized web target, runs open-source scanners, writes a findings report.",
        "endpoint_name": "security-assessment",
        "is_component": False,
        "tags": ["agents", "security"],
        "data": {"nodes": nodes, "edges": edges, "viewport": {"x": 0, "y": 0, "zoom": 0.6}},
    }


if __name__ == "__main__":
    OUT_FILE.parent.mkdir(exist_ok=True)
    OUT_FILE.write_text(json.dumps(build(), indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {OUT_FILE}")
