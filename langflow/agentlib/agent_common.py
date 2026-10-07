"""Small helpers shared by the three agent components.

Kept outside the components so each node's code in the Langflow canvas stays
short: this file is mounted into the Langflow container and put on PYTHONPATH.

The LLM is any OpenAI-compatible chat endpoint (Groq, Gemini, OpenRouter,
Ollama...). Set LLM_BASE_URL / LLM_API_KEY / LLM_MODEL, and optionally the
same three with an LLM_FALLBACK_ prefix for when the first one is rate limited.
One agent can use a different model from the same provider: LLM_MODEL_PLANNER,
LLM_MODEL_EXECUTOR, LLM_MODEL_REPORTER.

Every call goes through LangChain with the callbacks Langflow hands to the
component, which is what makes each LLM turn and tool run appear in Langfuse.
Ask the component for its callbacks right before the call (`tracing(self)`),
not at the top of the method: Langflow opens the component's trace span a
moment after the method starts.
"""
from __future__ import annotations

import asyncio
import json
import os
import re

import httpx
from langchain_openai import ChatOpenAI
from openai import APIConnectionError, APIStatusError, RateLimitError

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
SCANNERS_URL = os.getenv("SCANNERS_URL", "http://scanners:8001")
INTERNAL_TOKEN = os.getenv("INTERNAL_TOKEN", "")


def providers(model_override: str = "") -> list[dict]:
    """Primary provider first, optional fallback second."""
    found = []
    for prefix in ("LLM", "LLM_FALLBACK"):
        base_url, model = os.getenv(f"{prefix}_BASE_URL"), os.getenv(f"{prefix}_MODEL")
        if prefix == "LLM" and model_override:
            model = model_override
        if base_url and model:
            found.append({"base_url": base_url, "model": model,
                          "api_key": os.getenv(f"{prefix}_API_KEY") or "not-needed"})
    return found


def model_for(agent: str, chosen_on_canvas: str = "") -> str:
    """The model one agent asks for: its canvas field, else LLM_MODEL_<AGENT>, else "" (meaning LLM_MODEL)."""
    return chosen_on_canvas or os.getenv(f"LLM_MODEL_{agent.upper()}", "")


def tracing(component) -> dict:
    """The LangChain config that files a call under this component in the trace."""
    return {"callbacks": component.get_langchain_callbacks()}


async def chat(messages: list, *, tools: list | None = None, config: dict | None = None,
               model: str = "", max_tokens: int = 2000):
    """One model turn. Returns (reply, model_name).

    Rate limits and server errors are retried, then the fallback provider is tried.
    """
    if not providers(model):
        raise RuntimeError("No LLM configured. Set LLM_BASE_URL, LLM_API_KEY and LLM_MODEL in .env.")
    last_error: Exception | None = None
    for provider in providers(model):
        llm = ChatOpenAI(base_url=provider["base_url"], api_key=provider["api_key"], model=provider["model"],
                         temperature=0.1, max_tokens=max_tokens, max_retries=0, timeout=180)
        runnable = llm.bind_tools(tools) if tools else llm
        for attempt in range(3):
            try:
                reply = await runnable.ainvoke(messages, config=config)
                return reply, provider["model"]
            except RateLimitError as exc:
                last_error = exc
                await asyncio.sleep(_retry_after(exc, default=15 * (attempt + 1)))
            except APIConnectionError as exc:
                last_error = exc
                await asyncio.sleep(3)
            except APIStatusError as exc:
                last_error = exc
                if exc.status_code < 500:
                    break  # bad key, unknown model...: retrying will not help, try the fallback
                await asyncio.sleep(5)
    raise RuntimeError(f"LLM call failed: {last_error}. Check LLM_BASE_URL, LLM_API_KEY and LLM_MODEL in .env.")


async def chat_json(messages: list, *, config: dict | None = None, model: str = "",
                    max_tokens: int = 2000) -> tuple[dict, str]:
    """A model turn that must answer with one JSON object. Asks once more if it does not parse."""
    reply, used = await chat(messages, config=config, model=model, max_tokens=max_tokens)
    try:
        return parse_json(text_of(reply)), used
    except ValueError:
        retry = [*messages, reply, {"role": "user", "content":
                 "That was not a single valid JSON object. Reply again with only the JSON object."}]
        reply, used = await chat(retry, config=config, model=model, max_tokens=max_tokens)
        return parse_json(text_of(reply)), used


def _retry_after(exc: RateLimitError, default: float) -> float:
    try:
        return min(float(exc.response.headers.get("retry-after", default)), 60)
    except (TypeError, ValueError):
        return default


def text_of(reply) -> str:
    """The reply's text, without any <think>...</think> reasoning block."""
    content = reply.content
    if isinstance(content, list):  # some providers return a list of content blocks
        content = "".join(block.get("text", "") if isinstance(block, dict) else str(block) for block in content)
    return re.sub(r"<think>.*?</think>", "", content or "", flags=re.DOTALL).strip()


def parse_json(text: str) -> dict:
    """Pull the JSON object out of a model reply (tolerates code fences and stray prose)."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError(f"Model did not return JSON: {text[:200]!r}")
    parsed = json.loads(text[start:end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("Model returned JSON that is not an object")
    return parsed


async def notify(scan_id: str, agent: str, message: str, **data) -> None:
    """Post a live status line to the backend. Best effort: status must never break a run.

    `data` is a small machine-readable version of the same event (which tool started,
    how many findings...) that the web page uses to draw the pipeline.
    """
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(f"{BACKEND_URL}/internal/scans/{scan_id}/events",
                              headers={"X-Internal-Token": INTERNAL_TOKEN},
                              json={"agent": agent, "message": message[:2000], "data": data})
    except httpx.HTTPError:
        pass
