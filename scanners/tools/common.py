"""Shared helpers for the tool wrappers.

Every wrapper returns the same shape so the agents never have to know a
scanner's native format:

    {"status": "ok" | "timeout" | "error", "command": "...", "note": "...",
     "raw_file": "nmap.xml", "findings": [finding, ...]}

A finding keeps the scanner's *own* rating (`tool_severity`, `cvss_score`).
Mapping that to a CVSS severity band is the Reporter agent's job.
"""
from __future__ import annotations

import base64
import subprocess
import time
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Target:
    """The authorized target, always taken from the backend's scan record."""

    url: str
    basic_auth: tuple[str, str] | None = None

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""

    @property
    def port(self) -> int:
        parsed = urlparse(self.url)
        return parsed.port or (443 if parsed.scheme == "https" else 80)

    @property
    def basic_auth_header(self) -> str | None:
        if not self.basic_auth:
            return None
        token = base64.b64encode(":".join(self.basic_auth).encode()).decode()
        return f"Basic {token}"


def finding(
    *,
    id: str,
    tool: str,
    title: str,
    tool_severity: str | None = None,
    cvss_score: float | None = None,
    cvss_vector: str | None = None,
    cwe: str | None = None,
    url: str = "",
    description: str = "",
    evidence: str = "",
    remediation: str = "",
    references: list[str] | None = None,
    instances: int = 1,
) -> dict:
    return {
        "id": id,
        "tool": tool,
        "title": clip(title, 200),
        "tool_severity": tool_severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe": cwe,
        "url": url,
        "description": clip(description, 1200),
        "evidence": clip(evidence, 400),
        "remediation": clip(remediation, 1200),
        "references": (references or [])[:5],
        "instances": instances,
    }


def clip(text: str | None, limit: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def run_command(cmd: list[str], timeout: int) -> tuple[str, str, str]:
    """Run a scanner without a shell. Returns (status, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return "ok", proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        return "timeout", _text(exc.stdout), _text(exc.stderr)
    except OSError as exc:
        return "error", "", str(exc)


def _text(value: bytes | str | None) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value or ""


class Stopwatch:
    def __enter__(self):
        self.start = time.monotonic()
        return self

    def __exit__(self, *_):
        self.seconds = round(time.monotonic() - self.start, 1)
