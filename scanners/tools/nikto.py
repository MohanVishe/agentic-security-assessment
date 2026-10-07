"""Nikto: web server misconfiguration checks (optional, time-boxed)."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from .common import Target, finding, run_command

SPEC = {
    "name": "nikto",
    "title": "Nikto web server checks",
    "description": "Checks the web server for dangerous files, outdated software banners and "
    "common misconfigurations. Noisy and optional; time-boxed to two minutes.",
    "typical_duration": "about 2 minutes",
}

NIKTO = "/opt/nikto/program/nikto.pl"
MAXTIME = "120s"
TIMEOUT = 200


def run(target: Target, workdir: Path) -> dict:
    out_file = workdir / "nikto.json"
    out_file.unlink(missing_ok=True)
    cmd = ["perl", NIKTO, "-h", target.url, "-Format", "json", "-o", str(out_file),
           "-maxtime", MAXTIME, "-nointeractive", "-ask", "no"]
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
    return {"status": status, "command": shown, "note": note,
            "raw_file": "nikto.json", "findings": parse(raw)}


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
