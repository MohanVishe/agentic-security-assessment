"""OWASP ZAP baseline: spider the target, then read what the passive scanner flagged.

This is the same thing `zap-baseline.py -j` does (spider + AJAX spider + passive
rules, no active attacks), driven through the API of a ZAP daemon running in its
own container. The AJAX spider drives a headless browser, which is what finds
the API calls of a single-page app such as Juice Shop.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx

from .common import Target, finding

SPEC = {
    "name": "zap",
    "title": "OWASP ZAP baseline scan",
    "description": "Spiders the web app for about a minute and runs ZAP's passive rules on every "
    "response: missing security headers, cookie flags, information leaks. No active attacks, no form submissions.",
    "typical_duration": "1 to 3 minutes",
}

ZAP_URL = os.getenv("ZAP_URL", "http://zap:8080")
SPIDER_MINUTES = int(os.getenv("ZAP_SPIDER_MINUTES", "1"))
AJAX_SECONDS = int(os.getenv("ZAP_AJAX_SPIDER_SECONDS", "60"))  # 0 turns the AJAX spider off
TIMEOUT = 420


def run(target: Target, workdir: Path) -> dict:
    deadline = time.monotonic() + TIMEOUT
    status, note = "ok", ""
    with httpx.Client(base_url=ZAP_URL, timeout=60) as zap:
        def call(path: str, **params) -> dict:
            response = zap.get(path, params=params)
            response.raise_for_status()
            return response.json()

        rule_added = False
        try:
            # A fresh session, so alerts from an earlier assessment never leak into this one.
            call("/JSON/core/action/newSession/", name="", overwrite="true")
            if target.basic_auth_header:
                call("/JSON/replacer/action/addRule/", description="assessment-auth", enabled="true",
                     matchType="REQ_HEADER", matchRegex="false", matchString="Authorization",
                     replacement=target.basic_auth_header)
                rule_added = True
            call("/JSON/spider/action/setOptionMaxDuration/", Integer=SPIDER_MINUTES)
            # Look, do not touch: the spiders follow links and click, but never submit a form or type into one.
            call("/JSON/spider/action/setOptionPostForm/", Boolean="false")
            call("/JSON/ajaxSpider/action/setOptionRandomInputs/", Boolean="false")
            scan = call("/JSON/spider/action/scan/", url=target.url, recurse="true")["scan"]

            while int(call("/JSON/spider/view/status/", scanId=scan)["status"]) < 100:
                if time.monotonic() > deadline:
                    status, note = "timeout", "Spider stopped at the time limit."
                    call("/JSON/spider/action/stop/", scanId=scan)
                    break
                time.sleep(2)

            if AJAX_SECONDS and status == "ok":
                # One browser keeps memory down; the spider is stopped by the clock, not by coverage.
                call("/JSON/ajaxSpider/action/setOptionNumberOfBrowsers/", Integer=1)
                call("/JSON/ajaxSpider/action/scan/", url=target.url)
                stop_at = time.monotonic() + AJAX_SECONDS
                while call("/JSON/ajaxSpider/view/status/")["status"] == "running":
                    if time.monotonic() > stop_at:
                        call("/JSON/ajaxSpider/action/stop/")
                        break
                    time.sleep(2)

            while int(call("/JSON/pscan/view/recordsToScan/")["recordsToScan"]) > 0:
                if time.monotonic() > deadline:
                    status, note = "timeout", "Passive scan stopped at the time limit."
                    break
                time.sleep(2)

            alerts = call("/JSON/alert/view/alerts/", baseurl=target.url)["alerts"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            return {"status": "error", "command": _command(target), "note": f"ZAP API error: {exc}",
                    "raw_file": None, "findings": []}
        finally:
            if rule_added:
                try:
                    call("/JSON/replacer/action/removeRule/", description="assessment-auth")
                except httpx.HTTPError:
                    pass

    (workdir / "zap.json").write_text(json.dumps(alerts, indent=1), encoding="utf-8")
    return {"status": status, "command": _command(target), "note": note,
            "raw_file": "zap.json", "findings": parse(alerts)}


def parse(alerts: list[dict]) -> list[dict]:
    """One finding per alert type; the individual URLs become `instances`."""
    grouped: dict[str, list[dict]] = {}
    for alert in alerts:
        grouped.setdefault(alert.get("alertRef") or alert.get("pluginId", "0"), []).append(alert)

    findings = []
    for ref, group in grouped.items():
        first = group[0]
        cwe = first.get("cweid", "")
        findings.append(finding(
            id=f"ZAP-{ref}",
            tool="zap",
            title=first.get("name") or first.get("alert", "ZAP alert"),
            tool_severity=first.get("risk"),  # High / Medium / Low / Informational
            cwe=f"CWE-{cwe}" if cwe and cwe not in ("-1", "0") else None,
            url=first.get("url", ""),
            description=first.get("description", ""),
            evidence=first.get("evidence") or first.get("param") or first.get("other", ""),
            remediation=first.get("solution", ""),
            references=[r for r in first.get("reference", "").split("\n") if r.strip()],
            instances=len(group),
        ))
    return findings


def _command(target: Target) -> str:
    ajax = f" + AJAX spider ({AJAX_SECONDS}s)" if AJAX_SECONDS else ""
    return f"ZAP API: spider (max {SPIDER_MINUTES} min){ajax} + passive scan of {target.url}"
