"""Small helpers shared by the three agent components.

Kept outside the components so each node's code in the Langflow canvas stays
short: this file is mounted into the Langflow container and put on PYTHONPATH.

The LLM is any OpenAI-compatible chat endpoint (Groq, Gemini, OpenRouter,
Ollama...). Set LLM_BASE_URL / LLM_API_KEY / LLM_MODEL, and optionally the
same three with an LLM_FALLBACK_ prefix for when the first one is rate limited.
"""
from __future__ import annotations

import asyncio
import json
import os
import re

import httpx
from openai import APIConnectionError, APIStatusError, AsyncOpenAI, RateLimitError

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
SCANNERS_URL = os.getenv("SCANNERS_URL", "http://scanners:8001")
INTERNAL_TOKEN = os.getenv("INTERNAL_TOKEN", "")


def providers() -> list[dict]:
    found = []
    for prefix in ("LLM", "LLM_FALLBACK"):
        base_url, model = os.getenv(f"{prefix}_BASE_URL"), os.getenv(f"{prefix}_MODEL")
        if base_url and model:
            found.append({"base_url": base_url, "model": model,
                          "api_key": os.getenv(f"{prefix}_API_KEY") or "not-needed"})
    return found


async def chat(messages: list[dict], tools: list[dict] | None = None, max_tokens: int = 2000):
    """One chat completion. Returns (assistant_message, model_name).

    Rate limits and server errors are retried, then the fallback provider is tried.
    """
    if not providers():
        raise RuntimeError("No LLM configured. Set LLM_BASE_URL, LLM_API_KEY and LLM_MODEL in .env.")
    last_error: Exception | None = None
    for provider in providers():
        client = AsyncOpenAI(base_url=provider["base_url"], api_key=provider["api_key"],
                             max_retries=0, timeout=180)
        for attempt in range(3):
            try:
                kwargs = {"model": provider["model"], "messages": messages,
                          "temperature": 0.1, "max_tokens": max_tokens}
                if tools:
                    kwargs["tools"] = tools
                response = await client.chat.completions.create(**kwargs)
                return response.choices[0].message, provider["model"]
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


def _retry_after(exc: RateLimitError, default: float) -> float:
    try:
        return min(float(exc.response.headers.get("retry-after", default)), 60)
    except (TypeError, ValueError):
        return default


def assistant_turn(message) -> dict:
    """The assistant message as a plain dict, so it can go back into the conversation."""
    turn = {"role": "assistant", "content": message.content or ""}
    if message.tool_calls:
        turn["tool_calls"] = [
            {"id": call.id, "type": "function",
             "function": {"name": call.function.name, "arguments": call.function.arguments or "{}"}}
            for call in message.tool_calls
        ]
    return turn


def plain_text(text: str | None) -> str:
    """Model reply without any <think>...</think> reasoning block."""
    return re.sub(r"<think>.*?</think>", "", text or "", flags=re.DOTALL).strip()


def parse_json(text: str | None) -> dict:
    """Pull the JSON object out of a model reply (tolerates reasoning blocks and code fences)."""
    text = plain_text(text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError(f"Model did not return JSON: {text[:200]!r}")
    return json.loads(text[start:end + 1])


async def notify(scan_id: str, agent: str, message: str) -> None:
    """Post a live status line to the backend. Best effort: status must never break a run."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(f"{BACKEND_URL}/internal/scans/{scan_id}/events",
                              headers={"X-Internal-Token": INTERNAL_TOKEN},
                              json={"agent": agent, "message": message[:2000]})
    except httpx.HTTPError:
        pass
