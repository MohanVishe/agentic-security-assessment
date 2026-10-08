"""Settings, read once from environment variables. docker-compose.yml fills them in."""
from __future__ import annotations

import os
from pathlib import Path

# Where the other parts of the system live.
LANGFLOW_URL = os.getenv("LANGFLOW_URL", "http://langflow:7860")
LANGFLOW_API_KEY = os.getenv("LANGFLOW_API_KEY", "")
SCANNERS_URL = os.getenv("SCANNERS_URL", "http://scanners:8001")

# The two agent flows in Langflow, by endpoint name.
FULL_FLOW = os.getenv("LANGFLOW_FLOW", "security-assessment")            # Planner -> Executor -> Reporter
PLAN_FLOW = os.getenv("LANGFLOW_PLAN_FLOW", "security-assessment-plan")  # Planner only

# Shared secret for the calls the agents and the scanner service make to this backend.
INTERNAL_TOKEN = os.getenv("INTERNAL_TOKEN", "")

RUN_TIMEOUT = int(os.getenv("ASSESSMENT_TIMEOUT_SECONDS", "2400"))
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))        # database and raw scanner output
TARGETS_DIR = Path(os.getenv("TARGETS_DIR", "/srv/targets"))  # one folder per practice target

# Shown on the page so the user knows which model is in use. The key itself is never passed in.
LLM_MODEL = os.getenv("LLM_MODEL", "")
LLM_KEY_SET = bool(os.getenv("LLM_KEY_SET", ""))
