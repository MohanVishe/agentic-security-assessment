"""SQLite storage for checks ("scans") and their status events. Standard library only.

Life of a check:

    created -> authorized -> running -> completed | failed
                    \\-> planning -> awaiting_approval -> running        (when the user asked to review the plan)
                                            \\-> cancelled
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("DATA_DIR", "/data")) / "assessments.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    scope_notes TEXT NOT NULL DEFAULT '',
    credentials_provided INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'created',
    authorized INTEGER NOT NULL DEFAULT 0,
    authorized_at TEXT,
    authorized_by TEXT,
    authorization_statement TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    report TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    at TEXT NOT NULL,
    agent TEXT NOT NULL,
    message TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}'
);
"""

# Columns added after the first release. They are added to an existing database at start-up.
NEWER_COLUMNS = {
    "review_plan": "INTEGER NOT NULL DEFAULT 0",    # 1: wait for a person to approve the plan
    "proposed_plan": "TEXT",                        # what the Planner suggested (JSON)
    "approved_plan": "TEXT",                        # what the reviewer approved (JSON)
    "stop_requested": "INTEGER NOT NULL DEFAULT 0",  # 1: the user pressed stop
}
JSON_COLUMNS = ("report", "proposed_plan", "approved_plan")
FLAG_COLUMNS = ("authorized", "credentials_provided", "review_plan", "stop_requested")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(SCHEMA)
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
        for name, definition in NEWER_COLUMNS.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {definition}")
        # A restart kills the background task, so anything the agents were working on can never finish.
        conn.execute("UPDATE scans SET status='failed', error='Backend restarted during the run', "
                     "finished_at=? WHERE status IN ('planning', 'running')", (now(),))


def create_scan(target_url: str, scope_notes: str, credentials_provided: bool, review_plan: bool = False) -> str:
    scan_id = uuid.uuid4().hex
    with connect() as conn:
        conn.execute("INSERT INTO scans (id, target_url, scope_notes, credentials_provided, review_plan, created_at) "
                     "VALUES (?, ?, ?, ?, ?, ?)",
                     (scan_id, target_url, scope_notes, int(credentials_provided), int(review_plan), now()))
    return scan_id


def get_scan(scan_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return _to_dict(row) if row else None


def list_scans(limit: int = 30) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT id, target_url, status, created_at, finished_at FROM scans "
                            "ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def previous_completed(scan: dict) -> dict | None:
    """The most recent finished check of the same target before this one, if there is one."""
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE target_url=? AND status='completed' AND created_at<? "
                           "ORDER BY created_at DESC LIMIT 1", (scan["target_url"], scan["created_at"])).fetchone()
    return _to_dict(row) if row else None


def update_scan(scan_id: str, **fields) -> None:
    for name in JSON_COLUMNS:
        if fields.get(name) is not None:
            fields[name] = json.dumps(fields[name])
    columns = ", ".join(f"{name}=?" for name in fields)
    with connect() as conn:
        conn.execute(f"UPDATE scans SET {columns} WHERE id=?", (*fields.values(), scan_id))


def any_busy() -> bool:
    """True while the agents are working on any check. Only one check runs at a time."""
    with connect() as conn:
        return conn.execute("SELECT 1 FROM scans WHERE status IN ('planning', 'running')").fetchone() is not None


def add_event(scan_id: str, agent: str, message: str, data: dict | None = None) -> None:
    with connect() as conn:
        conn.execute("INSERT INTO events (scan_id, at, agent, message, data) VALUES (?, ?, ?, ?, ?)",
                     (scan_id, now(), agent, message, json.dumps(data or {})))


def get_events(scan_id: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT at, agent, message, data FROM events WHERE scan_id=? ORDER BY id",
                            (scan_id,)).fetchall()
    return [dict(row) | {"data": json.loads(row["data"])} for row in rows]


def _to_dict(row: sqlite3.Row) -> dict:
    scan = dict(row)
    for name in FLAG_COLUMNS:
        scan[name] = bool(scan[name])
    for name in JSON_COLUMNS:
        scan[name] = json.loads(scan[name]) if scan[name] else None
    return scan
