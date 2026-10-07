"""Nikto: web server misconfiguration checks (optional, time-boxed)."""
from __future__ import annotations

import json
import os
import re
import uuid
from collections import Counter
from pathlib import Path

import httpx

from .common import Target, finding, run_command

SPEC = {
    "name": "nikto",
    "title": "Nikto web server checks",
    "description": "Checks the web server for leftover files, outdated software banners and "
    "common misconfigurations. Detection test classes only. Noisy and optional; "
    "time-boxed to two and a half minutes.",
    "typical_duration": "about 2.5 minutes",
}

NIKTO = "/opt/nikto/program/nikto.pl"
MAXTIME = "150s"
TIMEOUT = 230
# Seconds to wait between requests. Unthrottled, Nikto sends about 70 requests a second,
# which is more than a small test server can keep up with.
PAUSE = os.getenv("NIKTO_PAUSE_SECONDS", "0.03")
# Only the test classes that look for things: interesting files (1), misconfiguration (2),
# information disclosure (3), software identification (b), admin consoles (e).
# Left out on purpose: injection, denial of service, command execution, SQL injection,
# file upload, authentication bypass and file retrieval tests.
TUNING = "123be"


def run(target: Target, workdir: Path) -> dict:
    out_file = workdir / "nikto.json"
    out_file.unlink(missing_ok=True)
    cmd = ["perl", NIKTO, "-h", target.url, "-Format", "json", "-o", str(out_file),
           "-Tuning", TUNING, "-maxtime", MAXTIME, "-Pause", PAUSE, "-nointeractive", "-ask", "no"]
    shown = " ".join(cmd)
    if target.basic_auth:
        cmd += ["-id", ":".join(target.basic_auth)]
        shown += " -id ***"

    status, _, stderr = run_command(cmd, TIMEOUT)
    raw = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""
    note = stderr.strip()[:300]
    if status == "ok" and not raw.strip():
        status = "error"
    elif "maximum execution time" in stderr:
        status, note = "timeout", f"Stopped at the {MAXTIME} time box; results are partial."
    findings = parse(raw)
    mark_false_alarms(findings, target)
    return {"status": status, "command": shown, "note": note,
            "raw_file": "nikto.json", "findings": findings}


def mark_false_alarms(findings: list[dict], target: Target) -> None:
    """Flag "file found" results on sites that answer every path with the same page.

    Many single-page apps return their home page for any address. Nikto then reports files
    such as /.htpasswd that are not really there. One plain GET per finding settles it: if the
    path returns exactly what a made-up path returns, the finding is marked as a likely false alarm.
    """
    headers = {"Authorization": target.basic_auth_header} if target.basic_auth_header else {}
    try:
        with httpx.Client(timeout=8, verify=False, headers=headers) as client:
            made_up = client.get(f"{target.origin}/{uuid.uuid4().hex}")
            if made_up.status_code != 200:
                return  # the site says "not found" properly, so Nikto's results can be taken as they are
            for item in findings:
                path = item["evidence"].split(" ", 1)[-1]
                if not path.startswith("/") or path == "/":
                    continue
                page = client.get(f"{target.origin}{path}")
                if page.status_code == 200 and page.content == made_up.content:
                    item["likely_false_alarm"] = True
                    item["description"] += (" Checked: this address returns the same page as a made-up "
                                            "address, so the file is probably not really there.")
    except httpx.HTTPError:
        pass  # the check is a bonus; without it the findings stay as Nikto reported them


def parse(raw: str) -> list[dict]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Nikto can leave a trailing comma when it stops at -maxtime.
        try:
            data = json.loads(re.sub(r",\s*([\]}])", r"\1", raw))
        except json.JSONDecodeError:
            return []
    hosts = data if isinstance(data, list) else [data]

    findings, seen, per_id = [], set(), Counter()
    for host in hosts:
        if not isinstance(host, dict):
            continue
        base = f"{host.get('host', '')}:{host.get('port', '')}"
        for item in host.get("vulnerabilities", []):
            # Nikto reuses one test id for several URLs, so the URL is part of the key.
            test_id = str(item.get("id", "0"))
            key = (test_id, item.get("url", ""))
            if key in seen:
                continue
            seen.add(key)
            per_id[test_id] += 1
            references = item.get("references") or ""
            path, message = item.get("url", ""), item.get("msg", "Nikto finding")
            title = message if not path or path == "/" or message.startswith(path) else f"{path}: {message}"
            findings.append(finding(
                id=f"NIKTO-{test_id}" + (f"-{per_id[test_id]}" if per_id[test_id] > 1 else ""),
                tool="nikto",
                title=title,
                url=f"{base}{path}",
                description=message,
                evidence=f"{item.get('method', 'GET')} {item.get('url', '')}",
                references=[references] if isinstance(references, str) and references else list(references or []),
            ))
    return findings
