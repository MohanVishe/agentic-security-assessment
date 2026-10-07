"""Nuclei: template-based checks, limited to detection-style template folders."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .common import Target, finding, run_command

SPEC = {
    "name": "nuclei",
    "title": "Nuclei template checks",
    "description": "Runs community detection templates for technologies, misconfigurations, "
    "exposed files and exposed admin panels. Intrusive, brute-force and DoS templates are excluded.",
    "typical_duration": "2 to 5 minutes",
}

TEMPLATES = ["http/technologies", "http/misconfiguration", "http/exposures", "http/exposed-panels"]
EXCLUDED_TAGS = "intrusive,dos,fuzz,brute-force,default-login"
TIMEOUT = 360
RATE_LIMIT = os.getenv("NUCLEI_RATE_LIMIT", "40")  # requests per second, kept gentle on purpose


def run(target: Target, workdir: Path) -> dict:
    out_file = workdir / "nuclei.jsonl"
    out_file.unlink(missing_ok=True)
    cmd = ["nuclei", "-u", target.url, "-jsonl", "-o", str(out_file), "-silent", "-no-color",
           "-disable-update-check", "-no-interactsh", "-omit-raw",
           "-rate-limit", RATE_LIMIT, "-timeout", "5", "-retries", "0",
           "-exclude-tags", EXCLUDED_TAGS]
    for folder in TEMPLATES:
        cmd += ["-t", folder]
    shown = " ".join(cmd)
    if target.basic_auth_header:
        cmd += ["-H", f"Authorization: {target.basic_auth_header}"]
        shown += " -H 'Authorization: Basic ***'"

    status, _, stderr = run_command(cmd, TIMEOUT)
    # Nuclei writes results as it goes, so a timeout still leaves usable output.
    raw = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""
    note = "Stopped at the time limit; results are partial." if status == "timeout" else stderr.strip()[:300]
    return {"status": status, "command": shown, "note": note,
            "raw_file": "nuclei.jsonl", "findings": parse(raw)}


def parse(jsonl: str) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    for line in jsonl.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = item.get("template-id", "unknown")
        if item.get("matcher-name"):
            key += f":{item['matcher-name']}"
        grouped.setdefault(key, []).append(item)

    findings = []
    for key, group in grouped.items():
        first = group[0]
        info = first.get("info", {})
        classification = info.get("classification") or {}
        extracted = first.get("extracted-results") or []
        cwe = classification.get("cwe-id")
        cwe = cwe[0] if isinstance(cwe, list) and cwe else cwe
        findings.append(finding(
            id=f"NUCLEI-{key}",
            tool="nuclei",
            title=info.get("name", key) + (f" ({first['matcher-name']})" if first.get("matcher-name") else ""),
            tool_severity=info.get("severity"),  # info / low / medium / high / critical
            cvss_score=classification.get("cvss-score"),
            cvss_vector=classification.get("cvss-metrics"),
            cwe=cwe.upper() if isinstance(cwe, str) and cwe else None,
            url=first.get("matched-at") or first.get("host", ""),
            description=info.get("description", ""),
            evidence=", ".join(map(str, extracted)) or f"Template matched at {first.get('matched-at', '')}",
            remediation=info.get("remediation", ""),
            references=info.get("reference") or [],
            instances=len(group),
        ))
    return findings
