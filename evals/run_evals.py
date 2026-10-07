"""Test the Planner agent's decisions on a fixed set of cases, across one or more models.

Each case in planner_cases.json is a set of scope notes plus what a correct plan must
contain. This script sends every case to the "Planner only" flow in Langflow (no scanner
runs, so it is fast and safe), checks the plan with plain code, and prints a table.

    python evals/run_evals.py                                   # the model in .env
    python evals/run_evals.py openai/gpt-oss-120b qwen/qwen3.8-27b

Needs the stack running (docker compose up -d). Standard library only.
If Langfuse is configured in .env, each case is also scored on its trace there.
"""
from __future__ import annotations

import base64
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).parent.parent
CASES = json.loads((Path(__file__).parent / "planner_cases.json").read_text(encoding="utf-8"))
RESULTS_FILE = Path(__file__).parent / "results.md"
LANGFLOW_URL = "http://localhost:7860"
TARGET = "http://juice-shop:3000"
PAUSE_SECONDS = 3  # stay under free-tier rate limits


def read_env() -> dict:
    env_file = ROOT / ".env"
    if not env_file.exists():
        return {}
    pairs = (line.split("=", 1) for line in env_file.read_text().splitlines()
             if "=" in line and not line.lstrip().startswith("#"))
    return {key.strip(): value.strip() for key, value in pairs}


ENV = read_env()


def http(url: str, *, body: dict | None = None, headers: dict | None = None, timeout: int = 240) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def ask_planner(case: dict, model: str, session_id: str) -> dict:
    """Run the Planner-only flow for one case and return the plan."""
    request = {"scan_id": session_id, "target_url": TARGET, "scope_notes": case["scope_notes"]}
    reply = http(f"{LANGFLOW_URL}/api/v1/run/security-assessment-plan?stream=false",
                 headers={"x-api-key": ENV.get("LANGFLOW_API_KEY", "change-me-langflow-key")},
                 body={"input_value": json.dumps(request), "input_type": "chat", "output_type": "chat",
                       "session_id": session_id,
                       "tweaks": {"PlannerAgent-pln01": {"model_name": model}}})
    return json.loads(reply["outputs"][0]["outputs"][0]["results"]["message"]["text"])["plan"]


def judge(case: dict, plan: dict) -> list[str]:
    """Return what is wrong with the plan. An empty list means the case passed."""
    tools = [step["tool"] for step in plan["steps"]]
    text = json.dumps(plan).lower()
    problems = []
    for tool in case.get("must_include", []):
        if tool not in tools:
            problems.append(f"missing {tool}")
    for tool in case.get("must_exclude", []):
        if tool in tools:
            problems.append(f"should not run {tool}")
    if case.get("first") and tools[:1] != [case["first"]]:
        problems.append(f"{case['first']} should come first")
    if "max_tools" in case and len(tools) > case["max_tools"]:
        problems.append(f"more than {case['max_tools']} tools")
    if len(tools) < case.get("min_tools", 0):
        problems.append(f"fewer than {case['min_tools']} tools")
    for word in case.get("notes_mention", []):
        if word.lower() not in plan["notes"].lower():
            problems.append(f"notes do not mention {word}")
    for phrase in case.get("must_not_contain", []):
        if phrase.lower() in text:
            problems.append(f"output contains '{phrase}'")
    return problems


def score_in_langfuse(session_id: str, case: dict, problems: list[str]) -> None:
    """Attach the result to the case's trace. Skipped quietly when Langfuse is not configured."""
    host = ENV.get("LANGFUSE_HOST", "").replace("host.docker.internal", "localhost").rstrip("/")
    public, secret = ENV.get("LANGFUSE_PUBLIC_KEY"), ENV.get("LANGFUSE_SECRET_KEY")
    if not (host and public and secret):
        return
    auth = {"Authorization": "Basic " + base64.b64encode(f"{public}:{secret}".encode()).decode()}
    try:
        for _ in range(6):  # traces arrive a few seconds after the run
            found = http(f"{host}/api/public/v2/observations?sessionId={session_id}&limit=1", headers=auth, timeout=15)
            if found.get("data"):
                trace_id = found["data"][0]["traceId"]
                http(f"{host}/api/public/scores", headers=auth, timeout=15, body={
                    "id": f"{trace_id}-planner_case", "traceId": trace_id, "name": "planner_case_passed",
                    "value": 0 if problems else 1, "dataType": "NUMERIC",
                    "comment": f"{case['name']}: {'; '.join(problems) or 'plan matches the expectation'}"})
                return
            time.sleep(2)
    except (urllib.error.URLError, KeyError, ValueError):
        pass


def main() -> None:
    models = sys.argv[1:] or [ENV.get("LLM_MODEL", "openai/gpt-oss-120b")]
    run_id = uuid.uuid4().hex[:8]
    rows, passed = [], {model: 0 for model in models}

    for case in CASES:
        row = {"case": case["name"], "notes": case["scope_notes"] or "(none)"}
        for model in models:
            session_id = f"eval-{run_id}-{case['name']}-{model.split('/')[-1]}"
            try:
                plan = ask_planner(case, model, session_id)
                problems = judge(case, plan)
                if plan["model"] != model:
                    problems.append(f"answered by fallback model {plan['model']}")
                chosen = ", ".join(step["tool"] for step in plan["steps"]) or "(no tools)"
            except Exception as exc:  # a failed call is a failed case, not a crashed run
                problems, chosen = [f"call failed: {str(exc)[:80]}"], "-"
            passed[model] += not problems
            row[model] = f"{'PASS' if not problems else 'FAIL'}: {chosen}" + (f" ({'; '.join(problems)})" if problems else "")
            print(f"{case['name']:<32} {model:<24} {row[model]}", flush=True)
            score_in_langfuse(session_id, case, problems)
            time.sleep(PAUSE_SECONDS)
        rows.append(row)

    lines = [
        "# Planner evaluation results",
        "",
        f"Run `{run_id}` on {time.strftime('%Y-%m-%d')}. {len(CASES)} cases from `planner_cases.json`, "
        "checked by code in `run_evals.py`.",
        "",
        "| Model | Passed |", "|---|---|",
        *[f"| `{model}` | {passed[model]} / {len(CASES)} |" for model in models],
        "",
        "| Case | Scope notes | " + " | ".join(f"`{model}`" for model in models) + " |",
        "|---|---|" + "---|" * len(models),
        *["| " + " | ".join([row["case"], row["notes"].replace("|", "/")] + [row[model] for model in models]) + " |"
          for row in rows],
        "",
    ]
    RESULTS_FILE.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print("\n" + "\n".join(f"{model}: {passed[model]} / {len(CASES)} passed" for model in models))
    print(f"Table written to {RESULTS_FILE}")


if __name__ == "__main__":
    main()
