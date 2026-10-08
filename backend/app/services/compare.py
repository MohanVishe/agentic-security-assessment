"""Compare two reports of the same target: what is new, what is gone, what is still there.

This is the "retest" step of a security check: after fixing things, run the check again and
see what changed. A finding can only be compared when its scanner ran both times. If Nikto
ran last time and not this time, its findings are not "gone", they were simply not looked for.
"""
from __future__ import annotations

FINISHED = ("ok", "timeout")  # a tool that reached its time limit still looked


def compare(current: dict, previous: dict) -> dict:
    now, before = _by_id(current), _by_id(previous)
    tools_now, tools_before = _tools_that_ran(current), _tools_that_ran(previous)
    both = tools_now & tools_before

    return {
        "tools_compared": sorted(both),
        "tools_not_compared": sorted(tools_now ^ tools_before),
        "new": [_brief(f) for fid, f in now.items() if fid not in before and f["tool"] in both],
        "no_longer_reported": [_brief(f) for fid, f in before.items() if fid not in now and f["tool"] in both],
        "still_there": sum(1 for fid in now if fid in before),
    }


def _by_id(report: dict) -> dict[str, dict]:
    return {finding["id"]: finding for finding in report.get("findings", [])}


def _tools_that_ran(report: dict) -> set[str]:
    return {run["tool"] for run in report.get("tool_runs", []) if run.get("status") in FINISHED}


def _brief(finding: dict) -> dict:
    return {key: finding.get(key) for key in ("id", "title", "severity", "tool")}
