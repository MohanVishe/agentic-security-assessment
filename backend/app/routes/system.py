"""What the page needs to know about the system itself: is it ready, what can be scanned, which tools exist."""
from __future__ import annotations

import httpx
from fastapi import APIRouter

from .. import config, targets
from ..services import agents, evaluation

router = APIRouter(prefix="/api")


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/config")
def page_config() -> dict:
    return {"demo_targets": targets.practice_targets(), "authorization_statement": targets.AUTHORIZATION_STATEMENT}


@router.get("/tools")
def tools() -> list[dict]:
    """The scanners that exist. The plan review on the page lists them as tick boxes."""
    return agents.tool_catalog()


@router.get("/status")
def status() -> dict:
    """Is every part up? The page shows this and holds the start button until it is."""
    langflow = _is_up(f"{config.LANGFLOW_URL}/health")
    scanners = _get_json(f"{config.SCANNERS_URL}/health")
    services = {"langflow": langflow, "scanners": bool(scanners), "zap": bool(scanners.get("zap_ready"))}
    return {"ready": all(services.values()) and config.LLM_KEY_SET, "services": services,
            "llm": {"model": config.LLM_MODEL, "key_set": config.LLM_KEY_SET},
            "tracing": evaluation.tracing_enabled()}


def _is_up(url: str) -> bool:
    try:
        return httpx.get(url, timeout=4).status_code == 200
    except httpx.HTTPError:
        return False


def _get_json(url: str) -> dict:
    try:
        response = httpx.get(url, timeout=8)
        return response.json() if response.status_code == 200 else {}
    except (httpx.HTTPError, ValueError):
        return {}
